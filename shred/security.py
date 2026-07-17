import hashlib
import secrets
import threading
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


def rate_limit(key, max_count, window=None):
    """DB-backed limit. Used for IP-less buckets (e.g. per-upload_id chunk throttling)
    that must be shared across gunicorn workers."""
    if window is None:
        window = config.RATE_WINDOW
    now = time.time()
    cutoff = now - window

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


# In-memory rate limiter for IP-keyed buckets. IPs are never written to disk — they live
# only in this process for the duration of the sliding window. Trades cross-worker sharing
# (each gunicorn worker enforces its own limit) for a zero-disk-footprint privacy posture.
_memory_lock = threading.Lock()
_memory_hits = {}


def rate_limit_mem(key, max_count, window=None):
    if window is None:
        window = config.RATE_WINDOW
    now = time.time()
    cutoff = now - window
    with _memory_lock:
        hits = _memory_hits.get(key)
        if hits is None:
            hits = []
        hits = [t for t in hits if t > cutoff]
        if len(hits) >= max_count:
            _memory_hits[key] = hits
            return False
        hits.append(now)
        _memory_hits[key] = hits
        return True


# Admin access-attempt log. Stored IP-less (success / reason / timestamp only). Persisted to
# the DB unless NO_LOGS is on, in which case it lives only in this in-memory ring buffer.
_admin_ring_lock = threading.Lock()
_admin_ring = []


def record_admin_auth(success, reason):
    entry = {"success": success, "reason": reason, "created": int(time.time())}
    with _admin_ring_lock:
        _admin_ring.append(entry)
        if len(_admin_ring) > 200:
            _admin_ring.pop(0)
    if not config.NO_LOGS:
        try:
            db = get_db()
            db.execute(
                "INSERT INTO admin_auth_log (success, reason, created) VALUES (?, ?, ?)",
                (success, reason, entry["created"]),
            )
            db.commit()
        except Exception:
            pass


def get_admin_auth_log(limit=100):
    if config.NO_LOGS:
        with _admin_ring_lock:
            return [dict(e) for e in reversed(_admin_ring)][:limit]
    db = get_db()
    rows = db.execute(
        "SELECT success, reason, created FROM admin_auth_log ORDER BY created DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [{"success": r["success"], "reason": r["reason"], "created": r["created"]} for r in rows]


def get_current_rotating_token(db):
    # Rotating tokens are stored raw (unlike invite/delete tokens, which are
    # hashed) because the admin must be able to retrieve and reveal the current
    # one. Exposure is bounded by the token's ≤2×R lifetime and by the database
    # file being 0600 (see db._restrict_permissions).
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


def matching_invite_token(provided):
    """Returns the matched invite_tokens row (and bumps last_used) or None."""
    if not provided:
        return None
    db = get_db()
    h = hash_token(provided)
    match = None
    for row in db.execute("SELECT id, name, token_hash FROM invite_tokens WHERE revoked = 0").fetchall():
        if safe_compare(h, row["token_hash"]):
            match = row
    if not match:
        return None
    db.execute("UPDATE invite_tokens SET last_used = ? WHERE id = ?", (int(time.time()), match["id"]))
    db.commit()
    return match


def any_invite_tokens_exist():
    # Deliberately ignores revoked=0: revoking the last invite must not silently re-open ungated uploads.
    db = get_db()
    row = db.execute("SELECT 1 FROM invite_tokens LIMIT 1").fetchone()
    return row is not None


def token_gating_effective():
    return config.token_gating_enabled() or any_invite_tokens_exist()


def resolve_upload_credential(provided):
    """Identifies which credential authorized an upload, for attribution.
    Returns (valid, upload_via, invite_token_id) — upload_via is one of
    "static"/"rotating"/"invite"/None, invite_token_id only set for "invite".
    """
    if config.UPLOAD_TOKEN and safe_compare(provided, config.UPLOAD_TOKEN):
        return True, "static", None
    if rotating_token_valid(provided):
        return True, "rotating", None
    invite = matching_invite_token(provided)
    if invite:
        return True, "invite", invite["id"]
    return False, None, None


def require_admin():
    ip = request.remote_addr or "unknown"
    if not rate_limit_mem("admin:" + ip, config.ADMIN_RATE_LIMIT, config.RATE_WINDOW):
        record_admin_auth(0, "rate-limited")
        return jsonify({"error": "rate limit exceeded"}), 429
    # Header only — a query param would leak into proxy access logs and Referer headers.
    provided = request.headers.get("X-Admin-Token", "")
    if not config.ADMIN_TOKEN or not safe_compare(provided, config.ADMIN_TOKEN):
        record_admin_auth(0, "unauthorized")
        return jsonify({"error": "unauthorized"}), 401
    record_admin_auth(1, "ok")
    return None
