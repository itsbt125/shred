import base64
import errno
import os
import shutil
import time

from flask import Blueprint, Response, jsonify, request

from shred import config
from shred.config import ip_allowed
from shred.counters import record_download, record_upload
from shred.db import get_db
from shred.security import rate_limit, upload_token_valid
from shred.storage import (
    generate_id,
    remove_blob,
    safe_storage_path,
    storage_path,
    valid_id,
)

bp = Blueprint("files", __name__)


@bp.route("/api/upload", methods=["POST"])
def api_upload():
    ip = request.remote_addr or "unknown"

    if not ip_allowed(ip):
        return jsonify({"error": "uploads are not permitted from your network"}), 403

    if not rate_limit("upload:" + ip, config.UPLOAD_RATE_LIMIT):
        return jsonify({"error": "rate limit exceeded"}), 429

    if config.token_gating_enabled():
        provided = request.headers.get("X-Upload-Token") or request.form.get("upload_token", "")
        if not upload_token_valid(provided):
            return jsonify({"error": "a valid upload token is required"}), 403

    if "file" not in request.files:
        return jsonify({"error": "no file"}), 400

    file = request.files["file"]

    iv_b64 = request.form.get("iv")
    encrypted_filename_b64 = request.form.get("encrypted_filename")
    size_str = request.form.get("size")
    expiry_str = request.form.get("expiry")
    max_downloads_str = request.form.get("max_downloads", "0")
    has_password_str = request.form.get("has_password", "0")
    salt_b64 = request.form.get("salt")
    wrapped_key_b64 = request.form.get("wrapped_key")

    if not iv_b64 or not encrypted_filename_b64 or not size_str or not expiry_str:
        return jsonify({"error": "missing metadata"}), 400

    try:
        iv = base64.b64decode(iv_b64)
        if len(iv) != 12:
            return jsonify({"error": "invalid iv"}), 400
    except Exception:
        return jsonify({"error": "invalid iv"}), 400

    try:
        encrypted_filename = base64.b64decode(encrypted_filename_b64)
        if len(encrypted_filename) > 1024 or len(encrypted_filename) < 29:
            return jsonify({"error": "invalid encrypted_filename"}), 400
    except Exception:
        return jsonify({"error": "invalid encrypted_filename"}), 400

    try:
        size = int(size_str)
        if size < 0 or size > config.MAX_FILE_SIZE:
            return jsonify({"error": "invalid size"}), 400
    except Exception:
        return jsonify({"error": "invalid size"}), 400

    try:
        expiry = int(expiry_str)
        now = int(time.time())
        if expiry < now or expiry > now + config.MAX_EXPIRY_SECONDS:
            return jsonify({"error": "invalid expiry"}), 400
    except Exception:
        return jsonify({"error": "invalid expiry"}), 400

    try:
        max_downloads = int(max_downloads_str)
        if max_downloads < 0 or max_downloads > config.MAX_DOWNLOADS_CAP:
            return jsonify({"error": "invalid max_downloads"}), 400
    except Exception:
        return jsonify({"error": "invalid max_downloads"}), 400

    has_password = 1 if has_password_str == "1" else 0

    salt = None
    wrapped_key = None
    if has_password:
        if not salt_b64 or not wrapped_key_b64:
            return jsonify({"error": "password-protected file missing salt or wrapped_key"}), 400
        try:
            salt = base64.b64decode(salt_b64)
            if len(salt) != 16:
                return jsonify({"error": "invalid salt"}), 400
        except Exception:
            return jsonify({"error": "invalid salt"}), 400
        try:
            wrapped_key = base64.b64decode(wrapped_key_b64)
            if len(wrapped_key) > 256:
                return jsonify({"error": "invalid wrapped_key"}), 400
        except Exception:
            return jsonify({"error": "invalid wrapped_key"}), 400

    try:
        if shutil.disk_usage(str(config.UPLOAD_DIR)).free < config.MIN_FREE_DISK_BYTES:
            return jsonify({"error": "server storage full, try again later"}), 507
    except OSError:
        pass

    fd = None
    for _ in range(5):
        file_id = generate_id()
        s_path = storage_path(file_id)
        s_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(s_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            fd = None
    if fd is None:
        return jsonify({"error": "could not allocate id"}), 500

    total_written = 0
    try:
        with os.fdopen(fd, "wb") as f:
            while True:
                chunk = file.stream.read(65536)
                if not chunk:
                    break
                total_written += len(chunk)
                if total_written > config.MAX_CIPHERTEXT_SIZE:
                    f.close()
                    os.remove(s_path)
                    return jsonify({"error": "file too large"}), 413
                f.write(chunk)
    except OSError as e:
        try:
            os.remove(s_path)
        except OSError:
            pass
        if e.errno == errno.ENOSPC:
            return jsonify({"error": "server storage full, try again later"}), 507
        return jsonify({"error": "storage failed"}), 500
    except Exception:
        try:
            os.remove(s_path)
        except OSError:
            pass
        return jsonify({"error": "storage failed"}), 500

    if total_written == 0:
        try:
            os.remove(s_path)
        except OSError:
            pass
        return jsonify({"error": "empty file"}), 400

    db = get_db()
    try:
        db.execute(
            """INSERT INTO files
               (id, encrypted_filename, iv, size, expiry,
                max_downloads, downloads, has_password, salt, wrapped_key, created)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)""",
            (file_id, encrypted_filename, iv, size, expiry,
             max_downloads, has_password, salt, wrapped_key, int(time.time()))
        )
        db.commit()
    except Exception:
        try:
            os.remove(s_path)
        except OSError:
            pass
        return jsonify({"error": "database failed"}), 500

    record_upload()
    return jsonify({"id": file_id})


@bp.route("/api/meta/<file_id>")
def api_meta(file_id):
    if not valid_id(file_id):
        return jsonify({"error": "not found"}), 404

    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    if not row:
        return jsonify({"error": "not found"}), 410

    if row["expiry"] < int(time.time()):
        remove_blob(file_id)
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        db.commit()
        return jsonify({"error": "expired"}), 410

    if row["suspended"]:
        return jsonify({"error": "suspended"}), 451

    return jsonify({
        "id": row["id"],
        "iv": base64.b64encode(row["iv"]).decode(),
        "encrypted_filename": base64.b64encode(row["encrypted_filename"]).decode(),
        "size": row["size"],
        "expiry": row["expiry"],
        "has_password": bool(row["has_password"]),
        "salt": base64.b64encode(row["salt"]).decode() if row["salt"] else None,
        "wrapped_key": base64.b64encode(row["wrapped_key"]).decode() if row["wrapped_key"] else None,
        "max_downloads": row["max_downloads"],
        "downloads": row["downloads"],
        "created": row["created"],
    })


@bp.route("/api/file/<file_id>")
def api_file(file_id):
    if not valid_id(file_id):
        return jsonify({"error": "not found"}), 404

    ip = request.remote_addr or "unknown"
    if not rate_limit("download:" + ip, config.DOWNLOAD_RATE_LIMIT):
        return jsonify({"error": "rate limit exceeded"}), 429

    db = get_db()

    db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if not row:
            db.execute("ROLLBACK")
            return jsonify({"error": "not found"}), 410

        if row["expiry"] < int(time.time()):
            remove_blob(file_id)
            db.execute("DELETE FROM files WHERE id = ?", (file_id,))
            db.execute("COMMIT")
            return jsonify({"error": "expired"}), 410

        if row["suspended"]:
            db.execute("ROLLBACK")
            return jsonify({"error": "suspended"}), 451

        max_dl = row["max_downloads"]
        current_dl = row["downloads"]
        if max_dl > 0 and current_dl >= max_dl:
            db.execute("ROLLBACK")
            return jsonify({"error": "expired"}), 410

        new_dl = current_dl + 1
        delete_after = max_dl > 0 and new_dl >= max_dl

        if delete_after:
            db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        else:
            db.execute("UPDATE files SET downloads = ? WHERE id = ?", (new_dl, file_id))

        db.execute("COMMIT")
    except Exception:
        try:
            db.execute("ROLLBACK")
        except Exception:
            pass
        raise

    s_path = storage_path(file_id)
    if not safe_storage_path(s_path) or not s_path.exists():
        return jsonify({"error": "not found"}), 410

    def generate():
        try:
            with open(s_path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    yield chunk
        finally:
            if delete_after:
                remove_blob(file_id)

    record_download()

    response = Response(generate(), mimetype="application/octet-stream")
    response.headers["Content-Disposition"] = 'attachment; filename="' + file_id + '"'
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/api/report", methods=["POST"])
def api_report():
    ip = request.remote_addr or "unknown"
    if not rate_limit("report:" + ip, config.REPORT_RATE_LIMIT):
        return jsonify({"error": "rate limit exceeded"}), 429

    file_id = request.form.get("file_id", "")
    reason = (request.form.get("reason") or "").strip()[:2000]

    if not valid_id(file_id):
        return jsonify({"error": "invalid file id"}), 400

    db = get_db()
    row = db.execute("SELECT id FROM files WHERE id = ?", (file_id,)).fetchone()

    db.execute(
        "INSERT INTO reports (file_id, reason, ip, existed, created) VALUES (?, ?, ?, ?, ?)",
        (file_id, reason, ip, 1 if row else 0, int(time.time())),
    )
    if row:
        db.execute("UPDATE files SET suspended = 1 WHERE id = ?", (file_id,))
    db.commit()

    return jsonify({"status": "reported"})
