import secrets
import time

from flask import jsonify, request

from shred import config
from shred.db import get_db


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
        if secrets.compare_digest(provided, r["token"]):
            ok = True
    return ok


def upload_token_valid(provided):
    if config.UPLOAD_TOKEN and secrets.compare_digest(provided, config.UPLOAD_TOKEN):
        return True
    return rotating_token_valid(provided)


def require_admin():
    ip = request.remote_addr or "unknown"
    if not rate_limit("admin:" + ip, config.ADMIN_RATE_LIMIT):
        return jsonify({"error": "rate limit exceeded"}), 429
    provided = request.headers.get("X-Admin-Token") or request.args.get("admin_token", "")
    if not config.ADMIN_TOKEN or not secrets.compare_digest(provided, config.ADMIN_TOKEN):
        return jsonify({"error": "unauthorized"}), 401
    return None
