import logging
import sqlite3
import threading
import time

from shred import config
from shred.storage import remove_blob, remove_partial

logger = logging.getLogger("shred.cleanup")


def cleanup_expired():
    while True:
        time.sleep(config.CLEANUP_INTERVAL)
        try:
            db = sqlite3.connect(str(config.DB_PATH))
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA busy_timeout = 5000")
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
            db.close()
        except Exception:
            logger.exception("cleanup thread error")


def start_cleanup_thread():
    t = threading.Thread(target=cleanup_expired, daemon=True)
    t.start()
