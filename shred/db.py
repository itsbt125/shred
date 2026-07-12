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
    for col, ddl in (
        ("content_kind", "ALTER TABLE files ADD COLUMN content_kind TEXT NOT NULL DEFAULT 'file'"),
        ("delete_token_hash", "ALTER TABLE files ADD COLUMN delete_token_hash TEXT"),
        ("group_id", "ALTER TABLE files ADD COLUMN group_id TEXT"),
        ("group_index", "ALTER TABLE files ADD COLUMN group_index INTEGER NOT NULL DEFAULT 0"),
        ("group_count", "ALTER TABLE files ADD COLUMN group_count INTEGER NOT NULL DEFAULT 1"),
        ("upload_via", "ALTER TABLE files ADD COLUMN upload_via TEXT"),
        ("invite_token_id", "ALTER TABLE files ADD COLUMN invite_token_id INTEGER"),
    ):
        if col not in cols:
            db.execute(ddl)
    db.execute("CREATE INDEX IF NOT EXISTS idx_files_group_id ON files(group_id)")
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_files_group_id_index "
        "ON files(group_id, group_index) WHERE group_id IS NOT NULL"
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_files_invite_token_id ON files(invite_token_id)")
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
    # DB-backed so rate limits are shared across gunicorn worker processes.
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
    pending_cols = [r["name"] for r in db.execute("PRAGMA table_info(pending_uploads)").fetchall()]
    for col, ddl in (
        ("content_kind", "ALTER TABLE pending_uploads ADD COLUMN content_kind TEXT NOT NULL DEFAULT 'file'"),
        ("group_id", "ALTER TABLE pending_uploads ADD COLUMN group_id TEXT"),
        ("group_index", "ALTER TABLE pending_uploads ADD COLUMN group_index INTEGER NOT NULL DEFAULT 0"),
        ("group_count", "ALTER TABLE pending_uploads ADD COLUMN group_count INTEGER NOT NULL DEFAULT 1"),
        ("upload_via", "ALTER TABLE pending_uploads ADD COLUMN upload_via TEXT"),
        ("invite_token_id", "ALTER TABLE pending_uploads ADD COLUMN invite_token_id INTEGER"),
    ):
        if col not in pending_cols:
            db.execute(ddl)

    db.execute("""
        CREATE TABLE IF NOT EXISTS invite_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            last_used INTEGER
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
        # Without a busy timeout, concurrent BEGIN IMMEDIATE writers raise "database is locked".
        g.db.execute("PRAGMA busy_timeout = 5000")
    return g.db


def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()
