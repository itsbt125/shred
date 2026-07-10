import logging
import sqlite3
import threading
import time

from shred import config
from shred.storage import remove_blob

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
            db.commit()
            db.close()
        except Exception:
            logger.exception("cleanup thread error")


def start_cleanup_thread():
    t = threading.Thread(target=cleanup_expired, daemon=True)
    t.start()
