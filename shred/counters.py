import time

from shred.db import get_db

# Not persisted — "uptime" means time since this worker last started.
_start_time = time.time()

# Persisted in kv (not in-memory) so counts don't diverge across gunicorn worker processes.


def _increment(key):
    db = get_db()
    db.execute(
        "INSERT INTO kv (key, value) VALUES (?, '1') "
        "ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1",
        (key,),
    )
    db.commit()


def _read(key):
    db = get_db()
    row = db.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
    return int(row["value"]) if row else 0


def record_upload():
    _increment("total_uploads")


def record_download():
    _increment("total_downloads")


def get_counters():
    return _start_time, _read("total_uploads"), _read("total_downloads")
