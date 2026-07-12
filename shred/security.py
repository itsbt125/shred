import hashlib
import secrets
import time

from flask import jsonify, request

from shred import config
from shred.db import get_db


def hash_token(raw):
    # Plain SHA-256 is fine: these are high-entropy tokens, not passwords, so brute-forcing isn't the threat model.
    return hashlib.sha256(raw.encode()).hexdigest()


def safe_compare(a, b):
    # compare_digest raises TypeError on non-ASCII input; treat that as a mismatch, not a 500.
    try:
        return secrets.compare_digest(a, b)
    except TypeError:
        return False


def rate_limit(key, max_count):
    now = time.time()
    cutoff = now - config.RATE_WINDOW

    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("DELETE FROM rate_limit_hits WHERE bucket = ? AND ts < ?", (key, cutoff))
        count = db.execute(
            "SELECT COUNT(*) AS c FROM rate_limit_hits WHERE bucket = ?", (key,)
        ).fetchone()["c"]
        if count >= max_count:
            db.execute("ROLLBACK")
            return False
        db.execute("INSERT INTO rate_limit_hits (bucket, ts) VALUES (?, ?)", (key, now))
        db.execute("COMMIT")
        return True
    except Exception:
        try:
            db.execute("ROLLBACK")
        except Exception:
            pass
        raise


def get_current_rotating_token(db):
    now = int(time.time())
    R = config.UPLOAD_TOKEN_ROTATION
    window_start = (now // R) * R
    row = db.execute("SELECT token, expires FROM tokens WHERE window_start = ?", (window_start,)).fetchone()
    if row is None:
        token = secrets.token_urlsafe(24)
        expires = window_start + 2 * R
        db.execute(
            "INSERT OR IGNORE INTO tokens (window_start, token, created, expires) VALUES (?, ?, ?, ?)",
            (window_start, token, now, expires),
        )
        db.commit()
        row = db.execute("SELECT token, expires FROM tokens WHERE window_start = ?", (window_start,)).fetchone()
    return row["token"], row["expires"]


def rotating_token_valid(provided):
    if config.UPLOAD_TOKEN_ROTATION <= 0 or not provided:
        return False
    db = get_db()
    now = int(time.time())
    rows = db.execute("SELECT token FROM tokens WHERE expires > ?", (now,)).fetchall()
    ok = False
    for r in rows:
        if safe_compare(provided, r["token"]):
            ok = True
    return ok


def invite_token_valid(provided):
    if not provided:
        return False
    db = get_db()
    h = hash_token(provided)
    match = None
    for row in db.execute("SELECT id, token_hash FROM invite_tokens WHERE revoked = 0").fetchall():
        if safe_compare(h, row["token_hash"]):
            match = row
    if not match:
        return False
    db.execute("UPDATE invite_tokens SET last_used = ? WHERE id = ?", (int(time.time()), match["id"]))
    db.commit()
    return True


def any_invite_tokens_exist():
    # Deliberately ignores revoked=0: revoking the last invite must not silently re-open ungated uploads.
    db = get_db()
    row = db.execute("SELECT 1 FROM invite_tokens LIMIT 1").fetchone()
    return row is not None


def token_gating_effective():
    return config.token_gating_enabled() or any_invite_tokens_exist()


def upload_token_valid(provided):
    if config.UPLOAD_TOKEN and safe_compare(provided, config.UPLOAD_TOKEN):
        return True
    if rotating_token_valid(provided):
        return True
    return invite_token_valid(provided)


def require_admin():
    ip = request.remote_addr or "unknown"
    if not rate_limit("admin:" + ip, config.ADMIN_RATE_LIMIT):
        return jsonify({"error": "rate limit exceeded"}), 429
    # Header only — a query param would leak into proxy access logs and Referer headers.
    provided = request.headers.get("X-Admin-Token", "")
    if not config.ADMIN_TOKEN or not safe_compare(provided, config.ADMIN_TOKEN):
        return jsonify({"error": "unauthorized"}), 401
    return None
