"""Test environment: must set env vars BEFORE importing shred (config is read at
import time), and make the project importable even without an editable install."""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_TMP = tempfile.mkdtemp(prefix="shred-test-")
os.environ["STORAGE_DIR"] = _TMP
os.environ["ADMIN_TOKEN"] = "test-admin-token-123"
os.environ["UPLOAD_TOKEN_ROTATION"] = "0"
os.environ["NO_LOGS"] = "1"  # keep the admin auth log in memory during tests

import shutil
import sqlite3

import pytest

from shred import app as flask_app
from shred import config
from shred import security
from shred.routes import files as files_module

ADMIN_HEADERS = {"X-Admin-Token": "test-admin-token-123"}

_TABLES = (
    "files", "reports", "tokens", "kv", "rate_limit_hits",
    "pending_uploads", "invite_tokens", "admin_auth_log",
)


@pytest.fixture(autouse=True)
def clean_state():
    """Fresh DB rows, blobs, and in-memory rate-limit state for every test."""
    yield
    db = sqlite3.connect(str(config.DB_PATH))
    for table in _TABLES:
        db.execute(f"DELETE FROM {table}")
    db.commit()
    db.close()
    security._memory_hits.clear()
    files_module._chunk_ip_count.clear()
    shutil.rmtree(config.UPLOAD_DIR, ignore_errors=True)
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@pytest.fixture()
def client():
    with flask_app.test_client() as c:
        yield c
