import logging
import sqlite3
import threading
import time

from shred import config
from shred.storage import remove_blob, remove_blob_path, remove_partial

logger = logging.getLogger("shred.cleanup")

# Kept open for the process lifetime so the flock is held (released on exit).
_cleanup_lock_file = None

# Orphan sweep ignores blobs younger than this: an upload finish writes the blob
# just before inserting its row, so a fresh blob may legitimately have no row yet.
_ORPHAN_GRACE_SECONDS = 600


def _older_than_grace(path, now):
    """True if the file is old enough that its DB row should exist by now."""
    try:
        return path.stat().st_mtime <= now - _ORPHAN_GRACE_SECONDS
    except OSError:
        return False


def run_cleanup_once():
    """One cleanup pass. Split from the loop so tests (and operators) can run it directly."""
    db = sqlite3.connect(str(config.DB_PATH))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout = 5000")
    try:
        now = int(time.time())
        rows = db.execute("SELECT id FROM files WHERE expiry < ?", (now,)).fetchall()
        for row in rows:
            remove_blob(row["id"])
            db.execute("DELETE FROM files WHERE id = ?", (row["id"],))
        db.execute("DELETE FROM tokens WHERE expires < ?", (now,))

        # rate_limit() only prunes the bucket it checks, so idle IPs need reaping here too.
        db.execute("DELETE FROM rate_limit_hits WHERE ts < ?", (now - config.RATE_WINDOW,))

        if config.REPORTS_RETENTION_SECONDS > 0:
            db.execute(
                "DELETE FROM reports WHERE created < ?",
                (now - config.REPORTS_RETENTION_SECONDS,),
            )

        # admin_auth_log is written from an unauthenticated endpoint, so it needs
        # both a retention window and a hard row cap; otherwise a client can grow
        # it until the disk fills and downloads start failing (they need DB writes).
        if config.ADMIN_AUTH_LOG_RETENTION > 0:
            db.execute(
                "DELETE FROM admin_auth_log WHERE created < ?",
                (now - config.ADMIN_AUTH_LOG_RETENTION,),
            )
        if config.ADMIN_AUTH_LOG_MAX > 0:
            db.execute(
                "DELETE FROM admin_auth_log WHERE id <= "
                "(SELECT COALESCE(MAX(id), 0) FROM admin_auth_log) - ?",
                (config.ADMIN_AUTH_LOG_MAX,),
            )

        # Reaps uploads abandoned mid-transfer that never reached /api/upload/finish.
        stale_cutoff = now - config.PENDING_UPLOAD_TTL
        pending = db.execute(
            "SELECT upload_id FROM pending_uploads WHERE created < ?", (stale_cutoff,)
        ).fetchall()
        for row in pending:
            remove_partial(row["upload_id"])
            db.execute("DELETE FROM pending_uploads WHERE upload_id = ?", (row["upload_id"],))

        db.commit()

        # Orphan sweep for blobs and partial files whose DB row vanished (e.g. a
        # burn-after-reading file whose stream never ran, or a late chunk arriving
        # after finish renamed the partial away) would otherwise sit on disk forever.
        known = {r["id"] for r in db.execute("SELECT id FROM files").fetchall()}
        for path in config.UPLOAD_DIR.glob("*/*/*.enc"):
            file_id = path.name[: -len(".enc")]
            if not config.ID_PATTERN.match(file_id) or file_id in known:
                continue
            if not _older_than_grace(path, now):
                continue
            remove_blob_path(path)

        # partial/ needs its own sweep: remove_partial() only runs for upload_ids
        # that still have a pending_uploads row, so any .part orphaned by another
        # path (finish racing a late chunk, a crash between file and row creation)
        # leaked permanently.
        known_pending = {
            r["upload_id"] for r in db.execute("SELECT upload_id FROM pending_uploads").fetchall()
        }
        for path in config.UPLOAD_DIR.glob("partial/*.part"):
            upload_id = path.name[: -len(".part")]
            if not config.UPLOAD_ID_PATTERN.match(upload_id) or upload_id in known_pending:
                continue
            if not _older_than_grace(path, now):
                continue
            try:
                path.unlink()
            except OSError:
                pass
    finally:
        db.close()


def cleanup_expired():
    while True:
        time.sleep(config.CLEANUP_INTERVAL)
        try:
            run_cleanup_once()
        except Exception:
            logger.exception("cleanup thread error")


def start_cleanup_thread():
    """Starts the cleanup loop, but in only one process: gunicorn runs several
    workers, each calling create_app(), so guard with a non-blocking flock."""
    global _cleanup_lock_file
    try:
        import fcntl
    except ImportError:
        fcntl = None  # Windows dev machine — just run the loop.

    if fcntl is not None:
        try:
            # Must stay open for the process lifetime — closing releases the lock.
            _cleanup_lock_file = open(config.DATA_DIR / ".cleanup.lock", "w")  # noqa: SIM115
            fcntl.flock(_cleanup_lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # Another worker already runs the cleanup loop.
            try:
                if _cleanup_lock_file:
                    _cleanup_lock_file.close()
            except OSError:
                pass
            _cleanup_lock_file = None
            return

    t = threading.Thread(target=cleanup_expired, daemon=True)
    t.start()
