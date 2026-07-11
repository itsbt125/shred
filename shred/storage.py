import secrets
import string
from pathlib import Path

from shred import config


def generate_id():
    chars = string.ascii_lowercase + string.digits
    parts = ["".join(secrets.choice(chars) for _ in range(4)) for _ in range(3)]
    return "-".join(parts)


def storage_path(file_id):
    clean = file_id.replace("-", "")
    return config.UPLOAD_DIR / clean[:2] / clean[2:4] / (file_id + ".enc")


# Partial uploads live under UPLOAD_DIR (not TMPDIR) specifically so the
# finish step can os.replace() them straight into final storage — an
# atomic, same-filesystem rename regardless of file size, instead of a
# cross-device copy.
def partial_storage_path(upload_id):
    return config.UPLOAD_DIR / "partial" / (upload_id + ".part")


def safe_partial_path(path):
    try:
        Path(path).resolve().relative_to((config.UPLOAD_DIR / "partial").resolve())
        return True
    except ValueError:
        return False


def remove_partial(upload_id):
    try:
        partial_storage_path(upload_id).unlink()
    except OSError:
        pass


def remove_blob(file_id):
    s_path = storage_path(file_id)
    try:
        s_path.unlink()
    except OSError:
        pass
    try:
        s_path.parent.rmdir()
        s_path.parent.parent.rmdir()
    except OSError:
        pass


def valid_id(file_id):
    return bool(config.ID_PATTERN.match(file_id))


def valid_upload_id(upload_id):
    return bool(config.UPLOAD_ID_PATTERN.match(upload_id))


def safe_storage_path(path):
    try:
        Path(path).resolve().relative_to(config.UPLOAD_DIR.resolve())
        return True
    except ValueError:
        return False
