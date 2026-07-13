import secrets
import shutil
import time

from flask import Blueprint, jsonify, request

from shred import config
from shred.counters import get_counters
from shred.db import get_db
from shred.security import (
    get_admin_auth_log,
    get_current_rotating_token,
    hash_token,
    require_admin,
    token_gating_effective,
)
from shred.storage import remove_blob, valid_id

bp = Blueprint("admin", __name__)


def _parse_limit(default=100):
    try:
        return min(max(int(request.args.get("limit", default)), 1), 500)
    except (TypeError, ValueError):
        return default


def _parse_offset():
    try:
        return max(int(request.args.get("offset", 0)), 0)
    except (TypeError, ValueError):
        return 0


@bp.route("/api/admin/overview")
def api_admin_overview():
    guard = require_admin()
    if guard:
        return guard

    db = get_db()
    now = int(time.time())
    stats = db.execute(
        "SELECT COUNT(*) AS c, COALESCE(SUM(size), 0) AS total FROM files WHERE expiry > ?",
        (now,),
    ).fetchone()
    suspended_count = db.execute(
        "SELECT COUNT(*) AS c FROM files WHERE expiry > ? AND suspended = 1", (now,)
    ).fetchone()["c"]
    report_count = db.execute("SELECT COUNT(*) AS c FROM reports").fetchone()["c"]
    start_time, up, dl = get_counters()

    try:
        du = shutil.disk_usage(str(config.UPLOAD_DIR))
        disk = {"total": du.total, "used": du.used, "free": du.free, "min_free": config.MIN_FREE_DISK_BYTES}
    except OSError:
        disk = None

    rotation = None
    if config.UPLOAD_TOKEN_ROTATION > 0:
        rotation = {
            "interval_seconds": config.UPLOAD_TOKEN_ROTATION,
            "next_rotation_seconds": config.UPLOAD_TOKEN_ROTATION - (now % config.UPLOAD_TOKEN_ROTATION),
        }

    return jsonify({
        "uptime": int(time.time() - start_time),
        "files_stored": stats["c"],
        "suspended": suspended_count,
        "total_bytes": stats["total"],
        "total_uploads": up,
        "total_downloads": dl,
        "reports": report_count,
        "disk": disk,
        "gating": {
            "token_required": token_gating_effective(),
            "static_token": bool(config.UPLOAD_TOKEN),
            "ip_restricted": bool(config.UPLOAD_IP_ALLOWLIST),
            "rotation": rotation,
        },
    })


@bp.route("/api/admin/token")
def api_admin_token():
    guard = require_admin()
    if guard:
        return guard
    if config.UPLOAD_TOKEN_ROTATION <= 0:
        return jsonify({"error": "token rotation is not enabled"}), 404

    db = get_db()
    now = int(time.time())
    db.execute("DELETE FROM tokens WHERE expires < ?", (now,))
    db.commit()
    token, expires = get_current_rotating_token(db)
    return jsonify({
        "token": token,
        "expires": expires,
        "expires_in": max(0, expires - now),
        "rotation_interval": config.UPLOAD_TOKEN_ROTATION,
    })


@bp.route("/api/admin/token/rotate", methods=["POST"])
def api_admin_rotate_token():
    guard = require_admin()
    if guard:
        return guard
    if config.UPLOAD_TOKEN_ROTATION <= 0:
        return jsonify({"error": "token rotation is not enabled"}), 404

    db = get_db()
    now = int(time.time())
    db.execute("DELETE FROM tokens")
    db.commit()
    token, expires = get_current_rotating_token(db)
    return jsonify({
        "token": token,
        "expires": expires,
        "expires_in": max(0, expires - now),
        "rotation_interval": config.UPLOAD_TOKEN_ROTATION,
    })


@bp.route("/api/admin/authlog")
def api_admin_authlog():
    guard = require_admin()
    if guard:
        return guard
    limit = _parse_limit()
    return jsonify({"log": get_admin_auth_log(limit)})


@bp.route("/api/admin/files")
def api_admin_files():
    guard = require_admin()
    if guard:
        return guard

    limit = _parse_limit()
    offset = _parse_offset()
    invite_id = request.args.get("invite_id")

    db = get_db()
    now = int(time.time())
    where = "f.expiry > ?"
    params = [now]
    if invite_id:
        where += " AND f.invite_token_id = ?"
        params.append(invite_id)

    total = db.execute(f"SELECT COUNT(*) AS c FROM files f WHERE {where}", params).fetchone()["c"]
    rows = db.execute(
        f"""SELECT f.id, f.size, f.created, f.expiry, f.downloads, f.max_downloads, f.has_password,
                   f.suspended, f.upload_via, f.invite_token_id, i.name AS invite_name
            FROM files f LEFT JOIN invite_tokens i ON f.invite_token_id = i.id
            WHERE {where} ORDER BY f.suspended DESC, f.created DESC LIMIT ? OFFSET ?""",
        params + [limit, offset],
    ).fetchall()
    files = [{
        "id": r["id"],
        "size": r["size"],
        "created": r["created"],
        "expiry": r["expiry"],
        "downloads": r["downloads"],
        "max_downloads": r["max_downloads"],
        "has_password": bool(r["has_password"]),
        "suspended": bool(r["suspended"]),
        "upload_via": r["upload_via"],
        "invite_token_id": r["invite_token_id"],
        "invite_name": r["invite_name"],
    } for r in rows]
    return jsonify({"files": files, "now": now, "total": total, "offset": offset})


@bp.route("/api/admin/files/<file_id>", methods=["DELETE"])
def api_admin_delete_file(file_id):
    guard = require_admin()
    if guard:
        return guard
    if not valid_id(file_id):
        return jsonify({"error": "invalid file id"}), 400

    db = get_db()
    row = db.execute("SELECT id FROM files WHERE id = ?", (file_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    remove_blob(file_id)
    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    return jsonify({"status": "deleted"})


def _admin_set_suspended(file_id, value):
    if not valid_id(file_id):
        return jsonify({"error": "invalid file id"}), 400
    db = get_db()
    row = db.execute("SELECT id FROM files WHERE id = ?", (file_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    db.execute("UPDATE files SET suspended = ? WHERE id = ?", (value, file_id))
    db.commit()
    return jsonify({"status": "suspended" if value else "restored"})


@bp.route("/api/admin/files/<file_id>/suspend", methods=["POST"])
def api_admin_suspend_file(file_id):
    guard = require_admin()
    if guard:
        return guard
    return _admin_set_suspended(file_id, 1)


@bp.route("/api/admin/files/<file_id>/restore", methods=["POST"])
def api_admin_restore_file(file_id):
    guard = require_admin()
    if guard:
        return guard
    return _admin_set_suspended(file_id, 0)


@bp.route("/api/admin/reports")
def api_admin_reports():
    guard = require_admin()
    if guard:
        return guard

    limit = _parse_limit()
    offset = _parse_offset()

    db = get_db()
    total = db.execute("SELECT COUNT(*) AS c FROM reports").fetchone()["c"]
    rows = db.execute(
        "SELECT file_id, reason, ip, existed, created FROM reports ORDER BY created DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    reports = [{
        "file_id": r["file_id"],
        "reason": r["reason"],
        "ip": r["ip"],
        "existed": bool(r["existed"]),
        "created": r["created"],
    } for r in rows]
    return jsonify({"reports": reports, "total": total, "offset": offset})


@bp.route("/api/status")
def api_status():
    db = get_db()
    now = int(time.time())
    stats = db.execute("""
        SELECT
            COUNT(*) AS files_count,
            COALESCE(SUM(size), 0) AS total_size,
            COALESCE(MIN(created), ?) AS oldest,
            COALESCE(MAX(created), ?) AS newest
        FROM files WHERE expiry > ?
    """, (now, now, now)).fetchone()
    start_time, up, dl = get_counters()
    age_min = max(0, now - stats["oldest"]) if stats["oldest"] < now else 0
    age_max = max(0, now - stats["newest"]) if stats["newest"] < now else 0

    rotation = None
    if config.UPLOAD_TOKEN_ROTATION > 0:
        rotation = {
            "interval_seconds": config.UPLOAD_TOKEN_ROTATION,
            "next_rotation_seconds": config.UPLOAD_TOKEN_ROTATION - (now % config.UPLOAD_TOKEN_ROTATION),
        }

    return jsonify({
        "status": "operational",
        "uptime": int(time.time() - start_time),
        "files_stored": stats["files_count"],
        "total_bytes": stats["total_size"],
        "oldest_age_seconds": age_max,
        "newest_age_seconds": age_min,
        "total_uploads_total": up,
        "total_downloads_total": dl,
        "limits": {
            "max_file_size_bytes": config.MAX_FILE_SIZE,
            "max_file_size_display": config.format_bytes(config.MAX_FILE_SIZE),
            "uploads_per_minute": config.UPLOAD_RATE_LIMIT,
            "downloads_per_minute": config.DOWNLOAD_RATE_LIMIT,
        },
        "uploads": {
            "gated": token_gating_effective() or bool(config.UPLOAD_IP_ALLOWLIST),
            "token_required": token_gating_effective(),
            "ip_restricted": bool(config.UPLOAD_IP_ALLOWLIST),
            "rotation": rotation,
        },
    })


@bp.route("/api/admin/invites")
def api_admin_list_invites():
    guard = require_admin()
    if guard:
        return guard
    db = get_db()
    now = int(time.time())
    rows = db.execute(
        """SELECT i.id, i.name, i.created, i.revoked, i.last_used,
                  COUNT(f.id) AS active_files, COALESCE(SUM(f.size), 0) AS active_bytes
           FROM invite_tokens i
           LEFT JOIN files f ON f.invite_token_id = i.id AND f.expiry > ?
           GROUP BY i.id ORDER BY i.created DESC""",
        (now,),
    ).fetchall()
    return jsonify({"invites": [{
        "id": r["id"], "name": r["name"], "created": r["created"],
        "revoked": bool(r["revoked"]), "last_used": r["last_used"],
        "active_files": r["active_files"], "active_bytes": r["active_bytes"],
    } for r in rows]})


@bp.route("/api/admin/invites", methods=["POST"])
def api_admin_create_invite():
    guard = require_admin()
    if guard:
        return guard
    name = (request.form.get("name") or "").strip()[:100]
    if not name:
        return jsonify({"error": "name is required"}), 400

    raw_token = secrets.token_urlsafe(24)
    db = get_db()
    db.execute(
        "INSERT INTO invite_tokens (name, token_hash, created, revoked) VALUES (?, ?, ?, 0)",
        (name, hash_token(raw_token), int(time.time())),
    )
    db.commit()
    # Only the hash is persisted — this response is the only chance to hand out the raw token.
    return jsonify({"name": name, "token": raw_token})


@bp.route("/api/admin/invites/<int:invite_id>/revoke", methods=["POST"])
def api_admin_revoke_invite(invite_id):
    guard = require_admin()
    if guard:
        return guard
    db = get_db()
    row = db.execute("SELECT id FROM invite_tokens WHERE id = ?", (invite_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    db.execute("UPDATE invite_tokens SET revoked = 1 WHERE id = ?", (invite_id,))
    db.commit()
    return jsonify({"status": "revoked"})
