import time

from shred.db import get_db

# Process start time only — this deliberately is NOT persisted. "uptime" on
# the status/admin pages means time since this worker last started, same
# convention as most status pages; a genuine restart should reset it.
_start_time = time.time()

# Lifetime totals ARE persisted (in the kv table) rather than kept as
# in-memory counters. With multiple gunicorn worker processes (gthread),
# each worker has its own separate memory — an in-memory counter would
# silently diverge between workers instead of reflecting the true total,
# and would reset to zero on every restart regardless. Both problems go
# away by treating the DB as the single source of truth; these are only
# written once per completed upload/download, not per chunk, so the extra
# write is negligible.


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
