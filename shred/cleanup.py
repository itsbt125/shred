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
            now = int(time.time())
            rows = db.execute("SELECT id FROM files WHERE expiry < ?", (now,)).fetchall()
            for row in rows:
                remove_blob(row["id"])
                db.execute("DELETE FROM files WHERE id = ?", (row["id"],))
            db.execute("DELETE FROM tokens WHERE expires < ?", (now,))

            # rate_limit() only prunes the specific bucket it's currently
            # checking, so an IP that stops making requests would
            # otherwise leave its old hit rows behind forever.
            db.execute("DELETE FROM rate_limit_hits WHERE ts < ?", (now - config.RATE_WINDOW,))

            # Chunked uploads abandoned mid-transfer (browser closed, network
            # died) never reach /api/upload/finish, so their partial file
            # and DB row would otherwise sit around forever.
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
