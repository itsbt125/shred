import secrets
import threading
import time
from collections import defaultdict

from flask import jsonify, request

from shred import config
from shred.db import get_db

_rate_limits = defaultdict(list)
_rate_lock = threading.Lock()


def rate_limit(key, max_count):
    now = time.time()
    with _rate_lock:
        entries = _rate_limits[key]
        while entries and entries[0] < now - config.RATE_WINDOW:
            entries.pop(0)
        if len(entries) >= max_count:
            return False
        entries.append(now)
        return True


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
