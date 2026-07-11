import base64
import errno
import os
import secrets
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
    partial_storage_path,
    remove_blob,
    remove_partial,
    safe_partial_path,
    safe_storage_path,
    storage_path,
    valid_id,
    valid_upload_id,
)

bp = Blueprint("files", __name__)


def _validate_upload_metadata(form):
    """Shared validation for the metadata fields an upload declares up
    front, at /api/upload/init. Returns (metadata_dict, None) or
    (None, (error_response, status)).
    """
    iv_b64 = form.get("iv")
    encrypted_filename_b64 = form.get("encrypted_filename")
    size_str = form.get("size")
    expiry_str = form.get("expiry")
    max_downloads_str = form.get("max_downloads", "0")
    has_password_str = form.get("has_password", "0")
    salt_b64 = form.get("salt")
    wrapped_key_b64 = form.get("wrapped_key")

    if not iv_b64 or not encrypted_filename_b64 or not size_str or not expiry_str:
        return None, ({"error": "missing metadata"}, 400)

    try:
        iv = base64.b64decode(iv_b64)
        if len(iv) != 12:
            return None, ({"error": "invalid iv"}, 400)
    except Exception:
        return None, ({"error": "invalid iv"}, 400)

    try:
        encrypted_filename = base64.b64decode(encrypted_filename_b64)
        if len(encrypted_filename) > 1024 or len(encrypted_filename) < 29:
            return None, ({"error": "invalid encrypted_filename"}, 400)
    except Exception:
        return None, ({"error": "invalid encrypted_filename"}, 400)

    try:
        size = int(size_str)
        if size < 0 or size > config.MAX_FILE_SIZE:
            return None, ({"error": "invalid size"}, 400)
    except Exception:
        return None, ({"error": "invalid size"}, 400)

    try:
        expiry = int(expiry_str)
        now = int(time.time())
        if expiry < now or expiry > now + config.MAX_EXPIRY_SECONDS:
            return None, ({"error": "invalid expiry"}, 400)
    except Exception:
        return None, ({"error": "invalid expiry"}, 400)

    try:
        max_downloads = int(max_downloads_str)
        if max_downloads < 0 or max_downloads > config.MAX_DOWNLOADS_CAP:
            return None, ({"error": "invalid max_downloads"}, 400)
    except Exception:
        return None, ({"error": "invalid max_downloads"}, 400)

    has_password = 1 if has_password_str == "1" else 0

    salt = None
    wrapped_key = None
    if has_password:
        if not salt_b64 or not wrapped_key_b64:
            return None, ({"error": "password-protected file missing salt or wrapped_key"}, 400)
        try:
            salt = base64.b64decode(salt_b64)
            if len(salt) != 16:
                return None, ({"error": "invalid salt"}, 400)
        except Exception:
            return None, ({"error": "invalid salt"}, 400)
        try:
            wrapped_key = base64.b64decode(wrapped_key_b64)
            if len(wrapped_key) > 256:
                return None, ({"error": "invalid wrapped_key"}, 400)
        except Exception:
            return None, ({"error": "invalid wrapped_key"}, 400)

    return {
        "iv": iv,
        "encrypted_filename": encrypted_filename,
        "size": size,
        "expiry": expiry,
        "max_downloads": max_downloads,
        "has_password": has_password,
        "salt": salt,
        "wrapped_key": wrapped_key,
    }, None


# Uploads are chunked (encrypt one ~1MiB ciphertext chunk client-side, POST
# it, release it, repeat) rather than one large multipart POST, for two
# reasons: it keeps client memory flat regardless of file size, and it
# avoids Werkzeug spooling an entire multi-GB request body to a temp file
# before the view function ever runs. init is rate-limited and token-gated
# like the old single-shot endpoint; chunk/finish are authorized purely by
# possession of the unguessable upload_id (same bearer-token pattern the
# content encryption key already uses in this app) and are deliberately
# NOT rate-limited per-request — a 2GB upload is ~2000 chunks, which would
# blow through any reasonable per-minute limit even for a single well-
# behaved upload. Abuse is bounded instead by strict in-order chunk
# indexing, a cumulative size cap, and reaping abandoned sessions in
# cleanup.py.
@bp.route("/api/upload/init", methods=["POST"])
def api_upload_init():
    ip = request.remote_addr or "unknown"

    if not ip_allowed(ip):
        return jsonify({"error": "uploads are not permitted from your network"}), 403

    if not rate_limit("upload:" + ip, config.UPLOAD_RATE_LIMIT):
        return jsonify({"error": "rate limit exceeded"}), 429

    if config.token_gating_enabled():
        provided = request.headers.get("X-Upload-Token") or request.form.get("upload_token", "")
        if not upload_token_valid(provided):
            return jsonify({"error": "a valid upload token is required"}), 403

    metadata, error = _validate_upload_metadata(request.form)
    if error:
        return jsonify(error[0]), error[1]

    try:
        if shutil.disk_usage(str(config.UPLOAD_DIR)).free < config.MIN_FREE_DISK_BYTES:
            return jsonify({"error": "server storage full, try again later"}), 507
    except OSError:
        pass

    upload_id = secrets.token_urlsafe(32)
    partial_path = partial_storage_path(upload_id)
    partial_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.close(os.open(str(partial_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    except OSError:
        return jsonify({"error": "could not start upload"}), 500

    db = get_db()
    try:
        db.execute(
            """INSERT INTO pending_uploads
               (upload_id, bytes_received, next_chunk_index, encrypted_filename, iv, size,
                expiry, max_downloads, has_password, salt, wrapped_key, created)
               VALUES (?, 0, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (upload_id, metadata["encrypted_filename"], metadata["iv"], metadata["size"],
             metadata["expiry"], metadata["max_downloads"], metadata["has_password"],
             metadata["salt"], metadata["wrapped_key"], int(time.time()))
        )
        db.commit()
    except Exception:
        remove_partial(upload_id)
        return jsonify({"error": "database failed"}), 500

    return jsonify({"upload_id": upload_id})


@bp.route("/api/upload/chunk", methods=["POST"])
def api_upload_chunk():
    upload_id = request.form.get("upload_id", "")
    chunk_index_str = request.form.get("chunk_index", "")
    if not valid_upload_id(upload_id) or not chunk_index_str.isdigit():
        return jsonify({"error": "missing upload_id or chunk_index"}), 400
    if "chunk" not in request.files:
        return jsonify({"error": "no chunk"}), 400

    partial_path = partial_storage_path(upload_id)
    if not safe_partial_path(partial_path):
        return jsonify({"error": "invalid upload"}), 400

    chunk_index = int(chunk_index_str)
    chunk_file = request.files["chunk"]

    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute("SELECT * FROM pending_uploads WHERE upload_id = ?", (upload_id,)).fetchone()
        if not row:
            db.execute("ROLLBACK")
            return jsonify({"error": "unknown or expired upload"}), 404

        if chunk_index != row["next_chunk_index"]:
            db.execute("ROLLBACK")
            return jsonify({"error": "unexpected chunk index"}), 409

        written = 0
        try:
            with open(partial_path, "ab") as f:
                while True:
                    data = chunk_file.stream.read(65536)
                    if not data:
                        break
                    if row["bytes_received"] + written + len(data) > config.MAX_CIPHERTEXT_SIZE:
                        db.execute("ROLLBACK")
                        return jsonify({"error": "file too large"}), 413
                    written += len(data)
                    f.write(data)
        except OSError as e:
            db.execute("ROLLBACK")
            if e.errno == errno.ENOSPC:
                return jsonify({"error": "server storage full, try again later"}), 507
            return jsonify({"error": "storage failed"}), 500

        db.execute(
            "UPDATE pending_uploads SET bytes_received = ?, next_chunk_index = ? WHERE upload_id = ?",
            (row["bytes_received"] + written, chunk_index + 1, upload_id),
        )
        db.execute("COMMIT")
    except Exception:
        try:
            db.execute("ROLLBACK")
        except Exception:
            pass
        raise

    return jsonify({"received": chunk_index + 1})


@bp.route("/api/upload/finish", methods=["POST"])
def api_upload_finish():
    upload_id = request.form.get("upload_id", "")
    if not valid_upload_id(upload_id):
        return jsonify({"error": "missing upload_id"}), 400

    partial_path = partial_storage_path(upload_id)
    if not safe_partial_path(partial_path):
        return jsonify({"error": "invalid upload"}), 400

    db = get_db()
    row = db.execute("SELECT * FROM pending_uploads WHERE upload_id = ?", (upload_id,)).fetchone()
    if not row:
        return jsonify({"error": "unknown or expired upload"}), 404

    if row["bytes_received"] == 0 or not partial_path.exists():
        db.execute("DELETE FROM pending_uploads WHERE upload_id = ?", (upload_id,))
        db.commit()
        remove_partial(upload_id)
        return jsonify({"error": "empty file"}), 400

    file_id = None
    for _ in range(5):
        candidate = generate_id()
        s_path = storage_path(candidate)
        s_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.close(os.open(str(s_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            file_id = candidate
            break
        except FileExistsError:
            continue
    if file_id is None:
        return jsonify({"error": "could not allocate id"}), 500

    final_path = storage_path(file_id)
    try:
        os.replace(str(partial_path), str(final_path))
    except OSError:
        try:
            os.remove(final_path)
        except OSError:
            pass
        return jsonify({"error": "storage failed"}), 500

    try:
        db.execute(
            """INSERT INTO files
               (id, encrypted_filename, iv, size, expiry,
                max_downloads, downloads, has_password, salt, wrapped_key, created)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)""",
            (file_id, row["encrypted_filename"], row["iv"], row["size"], row["expiry"],
             row["max_downloads"], row["has_password"], row["salt"], row["wrapped_key"],
             int(time.time()))
        )
        db.execute("DELETE FROM pending_uploads WHERE upload_id = ?", (upload_id,))
        db.commit()
    except Exception:
        try:
            os.remove(final_path)
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

    file_size = s_path.stat().st_size

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
    response.headers["Content-Length"] = str(file_size)
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
