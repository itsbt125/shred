import secrets
import time

from flask import jsonify, request

from shred import config
from shred.db import get_db


def _safe_compare(a, b):
    # secrets.compare_digest raises TypeError on a str containing non-ASCII
    # (e.g. a header with latin-1 bytes > 0x7f). Treat that as a mismatch
    # rather than letting it bubble up as a 500.
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
        if _safe_compare(provided, r["token"]):
            ok = True
    return ok


def upload_token_valid(provided):
    if config.UPLOAD_TOKEN and _safe_compare(provided, config.UPLOAD_TOKEN):
        return True
    return rotating_token_valid(provided)


def require_admin():
    ip = request.remote_addr or "unknown"
    if not rate_limit("admin:" + ip, config.ADMIN_RATE_LIMIT):
        return jsonify({"error": "rate limit exceeded"}), 429
    # Header only — never a query param. A token in the query string leaks
    # into reverse-proxy access logs, browser history, and Referer headers.
    # admin.js already sends it as X-Admin-Token.
    provided = request.headers.get("X-Admin-Token", "")
    if not config.ADMIN_TOKEN or not _safe_compare(provided, config.ADMIN_TOKEN):
        return jsonify({"error": "unauthorized"}), 401
    return None
