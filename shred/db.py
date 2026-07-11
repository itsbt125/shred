import secrets
import sqlite3

from flask import g

from shred import config


def init_db():
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(config.DB_PATH))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode = WAL")
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            encrypted_filename BLOB NOT NULL,
            iv BLOB NOT NULL,
            size INTEGER NOT NULL,
            expiry INTEGER NOT NULL,
            max_downloads INTEGER DEFAULT 0,
            downloads INTEGER DEFAULT 0,
            has_password INTEGER DEFAULT 0,
            salt BLOB,
            wrapped_key BLOB,
            suspended INTEGER DEFAULT 0,
            created INTEGER NOT NULL
        )
    """)
    cols = [r["name"] for r in db.execute("PRAGMA table_info(files)").fetchall()]
    if "suspended" not in cols:
        db.execute("ALTER TABLE files ADD COLUMN suspended INTEGER DEFAULT 0")
    db.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT NOT NULL,
            reason TEXT,
            ip TEXT,
            existed INTEGER DEFAULT 0,
            created INTEGER NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            window_start INTEGER PRIMARY KEY,
            token TEXT NOT NULL,
            created INTEGER NOT NULL,
            expires INTEGER NOT NULL
        )
    """)
    db.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT)")
    # A plain in-memory rate limiter breaks under multiple gunicorn worker
    # processes — each process has its own separate memory, so the
    # effective limit silently multiplies by the worker count instead of
    # being enforced globally. The DB is the only state shared across
    # workers, so it's the source of truth here too.
    db.execute("""
        CREATE TABLE IF NOT EXISTS rate_limit_hits (
            bucket TEXT NOT NULL,
            ts REAL NOT NULL
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_rate_limit_bucket_ts ON rate_limit_hits(bucket, ts)")
    db.execute("""
        CREATE TABLE IF NOT EXISTS pending_uploads (
            upload_id TEXT PRIMARY KEY,
            bytes_received INTEGER NOT NULL DEFAULT 0,
            next_chunk_index INTEGER NOT NULL DEFAULT 0,
            encrypted_filename BLOB NOT NULL,
            iv BLOB NOT NULL,
            size INTEGER NOT NULL,
            expiry INTEGER NOT NULL,
            max_downloads INTEGER DEFAULT 0,
            has_password INTEGER DEFAULT 0,
            salt BLOB,
            wrapped_key BLOB,
            created INTEGER NOT NULL
        )
    """)
    db.commit()
    db.close()


def ensure_admin_token():
    if config.UPLOAD_TOKEN_ROTATION <= 0 or config.ADMIN_TOKEN:
        return
    db = sqlite3.connect(str(config.DB_PATH))
    db.row_factory = sqlite3.Row
    row = db.execute("SELECT value FROM kv WHERE key = 'admin_token'").fetchone()
    if row:
        config.ADMIN_TOKEN = row["value"]
    else:
        config.ADMIN_TOKEN = secrets.token_urlsafe(24)
        db.execute("INSERT OR REPLACE INTO kv (key, value) VALUES ('admin_token', ?)", (config.ADMIN_TOKEN,))
        db.commit()
    db.close()
    print(
        f"[shred] upload-token rotation enabled every {config.UPLOAD_TOKEN_ROTATION}s;"
        f" admin token: {config.ADMIN_TOKEN}",
        flush=True,
    )


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(str(config.DB_PATH))
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode = WAL")
        # Every rate-limited request (upload/download/report/admin) and every
        # download/chunk takes a BEGIN IMMEDIATE write lock, and with multiple
        # gunicorn workers + threads these serialize on SQLite's single-writer
        # lock. Without a busy timeout a writer that can't grab the lock
        # immediately raises "database is locked"; 5s lets it wait its turn
        # instead of erroring out under normal contention.
        g.db.execute("PRAGMA busy_timeout = 5000")
    return g.db


def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()
