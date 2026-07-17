import base64
import errno
import math
import os
import secrets
import shutil
import sqlite3
import threading
import time

from flask import Blueprint, Response, jsonify, request

from shred import config
from shred.config import ip_allowed
from shred.counters import record_download, record_upload
from shred.db import get_db
from shred.security import (
    hash_token,
    rate_limit,
    rate_limit_mem,
    resolve_upload_credential,
    safe_compare,
    token_gating_effective,
)
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

# Per-IP in-flight chunk-upload concurrency cap (in-memory, per worker). Bounds how many
# simultaneous /api/upload/chunk requests one client can have open, so a single IP can't
# saturate the worker pool. IPs are held only in this dict for the life of in-flight requests.
_chunk_ip_lock = threading.Lock()
_chunk_ip_count = {}


def _acquire_chunk_ip(ip):
    with _chunk_ip_lock:
        n = _chunk_ip_count.get(ip, 0)
        if n >= config.MAX_CONCURRENT_CHUNKS_PER_IP:
            return False
        _chunk_ip_count[ip] = n + 1
        return True


def _release_chunk_ip(ip):
    with _chunk_ip_lock:
        n = _chunk_ip_count.get(ip, 0)
        if n <= 1:
            _chunk_ip_count.pop(ip, None)
        else:
            _chunk_ip_count[ip] = n - 1


def _expected_ciphertext_size(plaintext_size):
    """Ciphertext length for a declared plaintext size: one GCM tag per
    CHUNK_SIZE chunk (min one chunk, even for an empty file). Shared by the
    chunk handler (cap) and finish (verification) so the formula can't drift."""
    chunk_count = math.ceil(plaintext_size / config.CHUNK_SIZE) if plaintext_size > 0 else 1
    return plaintext_size + chunk_count * config.GCM_TAG_SIZE


def _validate_upload_metadata(form):
    """Returns (metadata_dict, None) or (None, (error_response, status))."""
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

    content_kind = form.get("content_kind", "file")
    if content_kind not in ("file", "paste"):
        return None, ({"error": "invalid content_kind"}, 400)

    try:
        size = int(size_str)
        size_cap = config.MAX_PASTE_SIZE if content_kind == "paste" else config.MAX_FILE_SIZE
        if size < 0 or size > size_cap:
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

    group_id = form.get("group_id") or None
    if group_id is not None and not valid_upload_id(group_id):
        return None, ({"error": "invalid group_id"}, 400)

    try:
        group_index = int(form.get("group_index", "0"))
        group_count = int(form.get("group_count", "1"))
        if group_index < 0 or group_count < 1 or group_index >= group_count or group_count > 500:
            return None, ({"error": "invalid group index/count"}, 400)
    except Exception:
        return None, ({"error": "invalid group index/count"}, 400)

    return {
        "iv": iv,
        "encrypted_filename": encrypted_filename,
        "size": size,
        "expiry": expiry,
        "max_downloads": max_downloads,
        "has_password": has_password,
        "salt": salt,
        "wrapped_key": wrapped_key,
        "content_kind": content_kind,
        "group_id": group_id,
        "group_index": group_index,
        "group_count": group_count,
    }, None


# chunk/finish are intentionally not rate-limited per-request (a large upload
# is thousands of chunks); abuse is bounded by in-order indexing, size caps,
# and reaping abandoned sessions in cleanup.py.
@bp.route("/api/upload/init", methods=["POST"])
def api_upload_init():
    ip = request.remote_addr or "unknown"

    if not ip_allowed(ip):
        return jsonify({"error": "uploads are not permitted from your network"}), 403

    if not rate_limit_mem("upload:" + ip, config.UPLOAD_RATE_LIMIT, config.RATE_WINDOW):
        return jsonify({"error": "rate limit exceeded"}), 429

    db = get_db()
    if config.MAX_PENDING_UPLOADS > 0:
        try:
            pending = db.execute("SELECT COUNT(*) AS c FROM pending_uploads").fetchone()["c"]
        except Exception:
            pending = 0
        if pending >= config.MAX_PENDING_UPLOADS:
            return jsonify({"error": "server busy, try again later"}), 429

    upload_via = None
    invite_token_id = None
    if token_gating_effective():
        provided = request.headers.get("X-Upload-Token") or request.form.get("upload_token", "")
        valid, upload_via, invite_token_id = resolve_upload_credential(provided)
        if not valid:
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

    try:
        db.execute(
            """INSERT INTO pending_uploads
               (upload_id, bytes_received, next_chunk_index, encrypted_filename, iv, size,
                expiry, max_downloads, has_password, salt, wrapped_key, created,
                content_kind, group_id, group_index, group_count, upload_via, invite_token_id)
               VALUES (?, 0, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (upload_id, metadata["encrypted_filename"], metadata["iv"], metadata["size"],
             metadata["expiry"], metadata["max_downloads"], metadata["has_password"],
             metadata["salt"], metadata["wrapped_key"], int(time.time()),
             metadata["content_kind"], metadata["group_id"], metadata["group_index"],
             metadata["group_count"], upload_via, invite_token_id)
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

    ip = request.remote_addr or "unknown"
    if not _acquire_chunk_ip(ip):
        return jsonify({"error": "too many concurrent uploads"}), 429
    try:
        if not rate_limit("chunk:" + upload_id, config.CHUNK_RATE_LIMIT, config.CHUNK_RATE_WINDOW):
            return jsonify({"error": "chunk rate limit exceeded"}), 429

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

            # Cap appends at the ciphertext length implied by the declared plaintext
            # size — not the global MAX_CIPHERTEXT_SIZE — so a session that declares
            # 1 KB can't stream gigabytes into its partial file.
            expected = _expected_ciphertext_size(row["size"])

            try:
                if shutil.disk_usage(str(config.UPLOAD_DIR)).free < config.MIN_FREE_DISK_BYTES:
                    db.execute("ROLLBACK")
                    return jsonify({"error": "server storage full, try again later"}), 507
            except OSError:
                pass

            # Must truncate the partial file back to bytes_received on any failed
            # append, or its on-disk length drifts and later chunks land at the wrong offset.
            base_len = row["bytes_received"]

            def _truncate_back():
                try:
                    with open(partial_path, "r+b") as tf:
                        tf.truncate(base_len)
                except OSError:
                    pass

            written = 0
            try:
                with open(partial_path, "ab") as f:
                    while True:
                        data = chunk_file.stream.read(65536)
                        if not data:
                            break
                        if base_len + written + len(data) > expected:
                            f.close()
                            _truncate_back()
                            db.execute("ROLLBACK")
                            return jsonify({"error": "file too large"}), 413
                        written += len(data)
                        f.write(data)
            except OSError as e:
                _truncate_back()
                db.execute("ROLLBACK")
                if e.errno == errno.ENOSPC:
                    return jsonify({"error": "server storage full, try again later"}), 507
                return jsonify({"error": "storage failed"}), 500

            db.execute(
                "UPDATE pending_uploads SET bytes_received = ?, next_chunk_index = ? WHERE upload_id = ?",
                (base_len + written, chunk_index + 1, upload_id),
            )
            db.execute("COMMIT")
        except Exception:
            try:
                db.execute("ROLLBACK")
            except Exception:
                pass
            raise

        return jsonify({"received": chunk_index + 1})
    finally:
        _release_chunk_ip(ip)


@bp.route("/api/upload/finish", methods=["POST"])
def api_upload_finish():
    upload_id = request.form.get("upload_id", "")
    if not valid_upload_id(upload_id):
        return jsonify({"error": "missing upload_id"}), 400

    partial_path = partial_storage_path(upload_id)
    if not safe_partial_path(partial_path):
        return jsonify({"error": "invalid upload"}), 400

    ip = request.remote_addr or "unknown"
    if not rate_limit_mem("finish:" + ip, config.UPLOAD_RATE_LIMIT, config.RATE_WINDOW):
        return jsonify({"error": "rate limit exceeded"}), 429

    db = get_db()
    row = db.execute("SELECT * FROM pending_uploads WHERE upload_id = ?", (upload_id,)).fetchone()
    if not row:
        return jsonify({"error": "unknown or expired upload"}), 404

    # C1: the declared plaintext size must match the ciphertext actually received.
    # The client encrypts in CHUNK_SIZE plaintext chunks and AES-GCM appends a
    # GCM_TAG_SIZE auth tag to each, so the on-disk ciphertext is larger than the
    # declared plaintext by exactly one tag per chunk (min one chunk, even for an
    # empty file). Comparing raw bytes to plaintext size would fail every upload.
    expected_ciphertext = _expected_ciphertext_size(row["size"])
    if row["bytes_received"] != expected_ciphertext:
        db.execute("DELETE FROM pending_uploads WHERE upload_id = ?", (upload_id,))
        db.commit()
        remove_partial(upload_id)
        return jsonify({"error": "size mismatch"}), 400

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

    delete_token = secrets.token_urlsafe(24)
    delete_token_hash = hash_token(delete_token)

    try:
        db.execute(
            """INSERT INTO files
               (id, encrypted_filename, iv, size, expiry,
                max_downloads, downloads, has_password, salt, wrapped_key, created,
                content_kind, group_id, group_index, group_count, delete_token_hash,
                upload_via, invite_token_id)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (file_id, row["encrypted_filename"], row["iv"], row["size"], row["expiry"],
             row["max_downloads"], row["has_password"], row["salt"], row["wrapped_key"],
             int(time.time()), row["content_kind"], row["group_id"], row["group_index"],
             row["group_count"], delete_token_hash, row["upload_via"], row["invite_token_id"])
        )
        db.execute("DELETE FROM pending_uploads WHERE upload_id = ?", (upload_id,))
        db.commit()
    except sqlite3.IntegrityError:
        try:
            os.remove(final_path)
        except OSError:
            pass
        return jsonify({"error": "group_id/group_index already in use"}), 409
    except Exception:
        try:
            os.remove(final_path)
        except OSError:
            pass
        return jsonify({"error": "database failed"}), 500

    record_upload()
    return jsonify({"id": file_id, "delete_token": delete_token})


@bp.route("/api/upload/status/<upload_id>")
def api_upload_status(upload_id):
    if not valid_upload_id(upload_id):
        return jsonify({"error": "invalid upload_id"}), 400
    ip = request.remote_addr or "unknown"
    if not rate_limit_mem("status:" + ip, config.DOWNLOAD_RATE_LIMIT, config.RATE_WINDOW):
        return jsonify({"error": "rate limit exceeded"}), 429
    db = get_db()
    row = db.execute(
        "SELECT next_chunk_index, bytes_received FROM pending_uploads WHERE upload_id = ?", (upload_id,)
    ).fetchone()
    if not row:
        return jsonify({"error": "unknown or expired upload"}), 404
    return jsonify({"next_chunk_index": row["next_chunk_index"], "bytes_received": row["bytes_received"]})


@bp.route("/api/file/<file_id>", methods=["DELETE"])
def api_delete_file(file_id):
    if not valid_id(file_id):
        return jsonify({"error": "not found"}), 404

    ip = request.remote_addr or "unknown"
    if not rate_limit_mem("delete:" + ip, config.DOWNLOAD_RATE_LIMIT, config.RATE_WINDOW):
        return jsonify({"error": "rate limit exceeded"}), 429

    provided = request.headers.get("X-Delete-Token") or request.form.get("delete_token", "")
    if not provided:
        return jsonify({"error": "delete token required"}), 400

    db = get_db()
    row = db.execute("SELECT delete_token_hash FROM files WHERE id = ?", (file_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    if not row["delete_token_hash"] or not safe_compare(hash_token(provided), row["delete_token_hash"]):
        return jsonify({"error": "invalid delete token"}), 403

    remove_blob(file_id)
    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    return jsonify({"status": "deleted"})


def _check_file_availability(row, db):
    """Returns None if the file row is currently downloadable, else (error_str, status)."""
    if row["expiry"] < int(time.time()):
        remove_blob(row["id"])
        db.execute("DELETE FROM files WHERE id = ?", (row["id"],))
        db.commit()
        return ("expired", 410)
    if row["suspended"]:
        return ("suspended", 451)
    return None


def _file_meta_dict(row):
    """Public metadata for one file row."""
    meta = {
        "id": row["id"],
        "iv": base64.b64encode(row["iv"]).decode(),
        "encrypted_filename": base64.b64encode(row["encrypted_filename"]).decode(),
        "size": row["size"],
        "expiry": row["expiry"],
        "has_password": bool(row["has_password"]),
        "salt": base64.b64encode(row["salt"]).decode() if row["salt"] else None,
        "wrapped_key": base64.b64encode(row["wrapped_key"]).decode() if row["wrapped_key"] else None,
        "max_downloads": row["max_downloads"],
        "created": row["created"],
        "content_kind": row["content_kind"],
        "group_id": row["group_id"],
        "group_index": row["group_index"],
        "group_count": row["group_count"],
    }
    if config.EXPOSE_DOWNLOAD_COUNT:
        meta["downloads"] = row["downloads"]
    return meta


@bp.route("/api/meta/<file_id>")
def api_meta(file_id):
    if not valid_id(file_id):
        return jsonify({"error": "not found"}), 404

    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    if not row:
        return jsonify({"error": "not found"}), 410

    unavailable = _check_file_availability(row, db)
    if unavailable:
        return jsonify({"error": unavailable[0]}), unavailable[1]

    return jsonify(_file_meta_dict(row))


@bp.route("/api/group/<group_id>")
def api_group(group_id):
    if not valid_upload_id(group_id):
        return jsonify({"error": "not found"}), 404

    ip = request.remote_addr or "unknown"
    if not rate_limit_mem("download:" + ip, config.DOWNLOAD_RATE_LIMIT, config.RATE_WINDOW):
        return jsonify({"error": "rate limit exceeded"}), 429

    db = get_db()
    rows = db.execute(
        "SELECT * FROM files WHERE group_id = ? ORDER BY group_index", (group_id,)
    ).fetchall()

    if not rows:
        return jsonify({"error": "not found"}), 404

    files = []
    for row in rows:
        if _check_file_availability(row, db):
            continue
        files.append(_file_meta_dict(row))

    if not files:
        return jsonify({"error": "expired"}), 410

    return jsonify({"group_id": group_id, "files": files})


@bp.route("/api/file/<file_id>")
def api_file(file_id):
    if not valid_id(file_id):
        return jsonify({"error": "not found"}), 404

    ip = request.remote_addr or "unknown"
    if not rate_limit_mem("download:" + ip, config.DOWNLOAD_RATE_LIMIT, config.RATE_WINDOW):
        return jsonify({"error": "rate limit exceeded"}), 429

    db = get_db()
    s_path = storage_path(file_id)
    delete_after = False

    if request.method == "HEAD":
        # HEAD must be side-effect free (no counter, no deletion). Otherwise any
        # link checker or `wget --spider` could burn a burn-after-reading file,
        # and the blob would be orphaned since the stream generator never runs.
        row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if not row or row["expiry"] < int(time.time()):
            return jsonify({"error": "not found"}), 410
        if row["suspended"]:
            return jsonify({"error": "suspended"}), 451
        if row["max_downloads"] > 0 and row["downloads"] >= row["max_downloads"]:
            return jsonify({"error": "expired"}), 410
        if not safe_storage_path(s_path) or not s_path.exists():
            return jsonify({"error": "not found"}), 410
    else:
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

            if not safe_storage_path(s_path) or not s_path.exists():
                # Row without a blob — count nothing, and reap the orphaned row.
                db.execute("DELETE FROM files WHERE id = ?", (file_id,))
                db.execute("COMMIT")
                return jsonify({"error": "not found"}), 410

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

        record_download()

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

    response = Response(generate(), mimetype="application/octet-stream")
    response.headers["Content-Disposition"] = 'attachment; filename="' + file_id + '"'
    response.headers["Content-Length"] = str(file_size)
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/api/report", methods=["POST"])
def api_report():
    # Require a custom header so cross-origin "simple request" form POSTs (CSRF)
    # can't suspend files — browsers won't send this header without a CORS
    # preflight, and this app doesn't enable CORS.
    if request.headers.get("X-Requested-With") != "XMLHttpRequest":
        return jsonify({"error": "forbidden"}), 403

    ip = request.remote_addr or "unknown"
    if not rate_limit_mem("report:" + ip, config.REPORT_RATE_LIMIT, config.RATE_WINDOW):
        return jsonify({"error": "rate limit exceeded"}), 429

    file_id = request.form.get("file_id", "")
    reason = (request.form.get("reason") or "").strip()[:2000]

    if not valid_id(file_id):
        return jsonify({"error": "invalid file id"}), 400

    db = get_db()
    row = db.execute("SELECT id FROM files WHERE id = ?", (file_id,)).fetchone()

    # The reporter's IP is never stored (privacy-by-default); the operator can still see the
    # report text and act on it. REPORT_ACTION controls whether a report auto-pauses the file.
    db.execute(
        "INSERT INTO reports (file_id, reason, existed, created) VALUES (?, ?, ?, ?)",
        (file_id, reason, 1 if row else 0, int(time.time())),
    )
    if row and config.REPORT_ACTION == "suspend":
        db.execute("UPDATE files SET suspended = 1 WHERE id = ?", (file_id,))
    db.commit()

    return jsonify({"status": "reported"})
