import logging
import sqlite3
import threading
import time

from shred import config
from shred.storage import remove_blob, remove_partial

logger = logging.getLogger("shred.cleanup")

# Kept open for the process lifetime so the flock is held (released on exit).
_cleanup_lock_file = None

# Orphan sweep ignores blobs younger than this: an upload finish writes the blob
# just before inserting its row, so a fresh blob may legitimately have no row yet.
_ORPHAN_GRACE_SECONDS = 600


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

        # Reaps uploads abandoned mid-transfer that never reached /api/upload/finish.
        stale_cutoff = now - config.PENDING_UPLOAD_TTL
        pending = db.execute(
            "SELECT upload_id FROM pending_uploads WHERE created < ?", (stale_cutoff,)
        ).fetchall()
        for row in pending:
            remove_partial(row["upload_id"])
            db.execute("DELETE FROM pending_uploads WHERE upload_id = ?", (row["upload_id"],))

        db.commit()

        # Orphan sweep: blobs whose DB row vanished (e.g. a deleted burn-after-reading
        # file whose stream never ran) would otherwise sit on disk forever.
        known = {r["id"] for r in db.execute("SELECT id FROM files").fetchall()}
        for path in config.UPLOAD_DIR.glob("*/*/*.enc"):
            file_id = path.name[: -len(".enc")]
            if not config.ID_PATTERN.match(file_id) or file_id in known:
                continue
            try:
                if path.stat().st_mtime > now - _ORPHAN_GRACE_SECONDS:
                    continue
            except OSError:
                continue
            remove_blob(file_id)
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
