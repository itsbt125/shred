import ipaddress
import json
import os
import re
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


_storage = os.environ.get("STORAGE_DIR", "data")
DATA_DIR = Path(_storage) if os.path.isabs(_storage) else PROJECT_ROOT / _storage
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "shred.db"

MAX_FILE_SIZE = _env_int("MAX_SIZE_BYTES", 2 * 1024**3)
MAX_CIPHERTEXT_SIZE = MAX_FILE_SIZE + 1024**2
MAX_PASTE_SIZE = _env_int("MAX_PASTE_SIZE", 5 * 1024**2)

# Client encrypts in fixed-size chunks (AES-GCM), appending one auth tag per chunk.
# These MUST match CHUNK_SIZE and TAG_LENGTH in static/crypto.js so the server can
# derive the expected ciphertext length from a declared plaintext size.
CHUNK_SIZE = 1024**2
GCM_TAG_SIZE = 16

# Per-request body cap enforced by Flask/Werkzeug (MAX_CONTENT_LENGTH), distinct from
# MAX_CIPHERTEXT_SIZE which caps cumulative bytes across a whole chunked upload session.
MAX_UPLOAD_CHUNK_BYTES = _env_int("MAX_UPLOAD_CHUNK_BYTES", 2 * 1024**2)
CLEANUP_INTERVAL = _env_int("CLEANUP_INTERVAL", 300)
ID_PATTERN = re.compile(r'^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$')
UPLOAD_ID_PATTERN = re.compile(r'^[A-Za-z0-9_-]{16,64}$')
UPLOAD_RATE_LIMIT = _env_int("UPLOAD_RATE_LIMIT", 10)
DOWNLOAD_RATE_LIMIT = _env_int("DOWNLOAD_RATE_LIMIT", 30)
REPORT_RATE_LIMIT = _env_int("REPORT_RATE_LIMIT", 5)
RATE_WINDOW = _env_int("RATE_WINDOW", 60)

# Per-upload_id chunk throttling (DB-backed, IP-less — shared across gunicorn workers).
# Bounds total chunks per upload session over time; the per-IP concurrency cap below
# is the complementary in-memory control that stops one client from hogging workers.
CHUNK_RATE_LIMIT = _env_int("CHUNK_RATE_LIMIT", 1000)
CHUNK_RATE_WINDOW = _env_int("CHUNK_RATE_WINDOW", 60)

# Max simultaneous in-flight /api/upload/chunk requests per IP (in-memory, per worker).
MAX_CONCURRENT_CHUNKS_PER_IP = _env_int("MAX_CONCURRENT_CHUNKS_PER_IP", 8)

# Global ceiling on in-progress (pending) uploads; 0 = unlimited.
MAX_PENDING_UPLOADS = _env_int("MAX_PENDING_UPLOADS", 0)

MIN_FREE_DISK_BYTES = _env_int("MIN_FREE_DISK_BYTES", 1024**3)

PENDING_UPLOAD_TTL = _env_int("PENDING_UPLOAD_TTL", 3600)

# 0 = keep forever.
REPORTS_RETENTION_SECONDS = _env_int("REPORTS_RETENTION_SECONDS", 90 * 86400)

TRUSTED_PROXY_COUNT = _env_int("TRUSTED_PROXY_COUNT", 0)

ABUSE_CONTACT = os.environ.get("ABUSE_CONTACT", "abuse@example.com")

UPLOAD_TOKEN = os.environ.get("UPLOAD_TOKEN", "").strip()

MAX_EXPIRY_SECONDS = _env_int("MAX_EXPIRY_SECONDS", 30 * 86400)
MAX_DOWNLOADS_CAP = _env_int("MAX_DOWNLOADS_CAP", 1000)
ADMIN_RATE_LIMIT = _env_int("ADMIN_RATE_LIMIT", 30)

_DEFAULT_EXPIRY_OPTIONS = [
    {"label": "5 minutes", "seconds": 300},
    {"label": "15 minutes", "seconds": 900},
    {"label": "30 minutes", "seconds": 1800},
    {"label": "1 hour", "seconds": 3600},
    {"label": "1 day", "seconds": 86400, "default": True},
    {"label": "1 week", "seconds": 604800},
    {"label": "burn after reading", "seconds": 0},
]
def _validate_expiry_options(raw):
    """Drops malformed entries (and options beyond MAX_EXPIRY_SECONDS, which the
    server would reject at upload time anyway) so a bad env value can't 500 the
    index page. Returns None if nothing usable remains."""
    if not isinstance(raw, list):
        return None
    out = []
    for opt in raw:
        if not isinstance(opt, dict):
            continue
        try:
            label = str(opt["label"])
            seconds = int(opt["seconds"])
        except (KeyError, TypeError, ValueError):
            continue
        if not label or seconds < 0 or seconds > MAX_EXPIRY_SECONDS:
            continue
        entry = {"label": label, "seconds": seconds}
        if opt.get("default"):
            entry["default"] = True
        out.append(entry)
    return out or None


try:
    EXPIRY_OPTIONS = _validate_expiry_options(json.loads(os.environ.get("EXPIRY_OPTIONS", "null")))
    if EXPIRY_OPTIONS is None:
        EXPIRY_OPTIONS = _DEFAULT_EXPIRY_OPTIONS
except (json.JSONDecodeError, TypeError):
    EXPIRY_OPTIONS = _DEFAULT_EXPIRY_OPTIONS


def _parse_allowlist(raw):
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            pass
    return nets


UPLOAD_IP_ALLOWLIST = _parse_allowlist(os.environ.get("UPLOAD_IP_ALLOWLIST", ""))

UPLOAD_TOKEN_ROTATION = _env_int("UPLOAD_TOKEN_ROTATION", 0)

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "").strip()

EXPOSE_DOWNLOAD_COUNT = os.environ.get("EXPOSE_DOWNLOAD_COUNT", "0").strip() == "1"

# Operator-configurable report behavior. "suspend" (default) pauses the reported file
# immediately, the same as before; "off" records the report for the operator but does
# not auto-pause the file. The server never stores the reporter's IP either way.
REPORT_ACTION = os.environ.get("REPORT_ACTION", "suspend").strip().lower()
if REPORT_ACTION not in ("suspend", "off"):
    REPORT_ACTION = "suspend"

# Privacy-by-default: when on, the admin access log is kept only in memory (never
# persisted) and no request IPs are written to disk anywhere. Rate limiting still works
# because IPs are held in memory temporarily. Recommended for operators who want a
# minimal disk footprint; someone who needs the persisted admin log just won't enable it.
NO_LOGS = os.environ.get("NO_LOGS", "0").strip() == "1"


def token_gating_enabled():
    return bool(UPLOAD_TOKEN) or UPLOAD_TOKEN_ROTATION > 0


def upload_gating_enabled():
    return token_gating_enabled() or bool(UPLOAD_IP_ALLOWLIST)


def ip_allowed(ip):
    if not UPLOAD_IP_ALLOWLIST:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in UPLOAD_IP_ALLOWLIST)


def format_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{int(n)} {unit}" if n == int(n) else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def client_config():
    opts = []
    for opt in EXPIRY_OPTIONS:
        entry = {"label": opt["label"], "seconds": opt["seconds"]}
        if opt.get("default"):
            entry["default"] = True
        opts.append(entry)

    return {
        "max_file_size_bytes": MAX_FILE_SIZE,
        "max_paste_size_bytes": MAX_PASTE_SIZE,
        "max_file_size_display": format_bytes(MAX_FILE_SIZE),
        "max_paste_size_display": format_bytes(MAX_PASTE_SIZE),
        "max_expiry_seconds": MAX_EXPIRY_SECONDS,
        "max_downloads_cap": MAX_DOWNLOADS_CAP,
        "expiry_options": opts,
        "upload_rate_per_minute": UPLOAD_RATE_LIMIT,
        "download_rate_per_minute": DOWNLOAD_RATE_LIMIT,
        "expose_download_count": EXPOSE_DOWNLOAD_COUNT,
        "report_action": REPORT_ACTION,
        "no_logs": NO_LOGS,
    }
