"""End-to-end API tests for shred, simulating the client crypto wire format:
plaintext size + one 16-byte GCM tag per 1 MiB chunk (min one chunk)."""
import base64
import io
import math
import os
import sqlite3
import stat
import time

import pytest

from shred import config
from shred.cleanup import run_cleanup_once
from shred.storage import storage_path
from tests.conftest import ADMIN_HEADERS

CHUNK = 1024**2
TAG = 16


def make_ciphertext(size):
    n = math.ceil(size / CHUNK) if size > 0 else 1
    return os.urandom(size + n * TAG)


def valid_meta(size=100, **over):
    meta = {
        "iv": base64.b64encode(os.urandom(12)).decode(),
        "encrypted_filename": base64.b64encode(os.urandom(32)).decode(),
        "size": str(size),
        "expiry": str(int(time.time()) + 3600),
    }
    meta.update({k: str(v) for k, v in over.items()})
    return meta


def do_upload(client, size=100, token=None, **meta_over):
    """Full init -> chunks -> finish. Returns (response_json, ciphertext)."""
    ct = make_ciphertext(size)
    headers = {"X-Upload-Token": token} if token else {}
    r = client.post("/api/upload/init", data=valid_meta(size, **meta_over), headers=headers)
    assert r.status_code == 200, r.get_json()
    uid = r.get_json()["upload_id"]
    step = CHUNK + TAG
    for i in range(max(1, math.ceil(len(ct) / step))):
        piece = ct[i * step:(i + 1) * step]
        r = client.post(
            "/api/upload/chunk",
            data={"upload_id": uid, "chunk_index": str(i), "chunk": (io.BytesIO(piece), "c.enc")},
            content_type="multipart/form-data",
        )
        assert r.status_code == 200, r.get_json()
    r = client.post("/api/upload/finish", data={"upload_id": uid})
    assert r.status_code == 200, r.get_json()
    return r.get_json(), ct


# --- core upload/download flows ------------------------------------------------

def test_upload_download_roundtrip(client):
    info, ct = do_upload(client, 1500)
    fid = info["id"]
    m = client.get(f"/api/meta/{fid}")
    assert m.status_code == 200
    assert m.get_json()["size"] == 1500
    d = client.get(f"/api/file/{fid}")
    assert d.status_code == 200
    assert d.data == ct


def test_upload_multichunk(client):
    info, ct = do_upload(client, int(2.5 * CHUNK))
    d = client.get(f"/api/file/{info['id']}")
    assert d.status_code == 200
    assert d.data == ct


def test_paste_flow(client):
    info, _ = do_upload(client, 200, content_kind="paste")
    m = client.get(f"/api/meta/{info['id']}")
    assert m.status_code == 200
    assert m.get_json()["content_kind"] == "paste"


def test_size_mismatch_rejected(client):
    r = client.post("/api/upload/init", data=valid_meta(1000))
    uid = r.get_json()["upload_id"]
    r = client.post(
        "/api/upload/chunk",
        data={"upload_id": uid, "chunk_index": "0", "chunk": (io.BytesIO(os.urandom(500)), "c")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 200
    r = client.post("/api/upload/finish", data={"upload_id": uid})
    assert r.status_code == 400


def test_out_of_order_chunk_rejected(client):
    r = client.post("/api/upload/init", data=valid_meta(100))
    uid = r.get_json()["upload_id"]
    r = client.post(
        "/api/upload/chunk",
        data={"upload_id": uid, "chunk_index": "5", "chunk": (io.BytesIO(os.urandom(16)), "c")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 409


def test_chunk_beyond_declared_size_rejected(client):
    """Declared 100 bytes -> expected ciphertext is 116; a 200-byte chunk must fail."""
    r = client.post("/api/upload/init", data=valid_meta(100))
    uid = r.get_json()["upload_id"]
    r = client.post(
        "/api/upload/chunk",
        data={"upload_id": uid, "chunk_index": "0", "chunk": (io.BytesIO(os.urandom(200)), "c")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 413
    # ...but the correct 116 bytes still lands.
    r = client.post(
        "/api/upload/chunk",
        data={"upload_id": uid, "chunk_index": "0", "chunk": (io.BytesIO(os.urandom(116)), "c")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 200


def test_burn_after_reading(client):
    info, _ = do_upload(client, 100, max_downloads=1)
    fid = info["id"]
    assert client.get(f"/api/file/{fid}").status_code == 200
    assert client.get(f"/api/file/{fid}").status_code == 410


def test_head_request_has_no_side_effects(client):
    """Regression: HEAD used to run the full download transaction, burning
    burn-after-reading files and orphaning the blob."""
    info, _ = do_upload(client, 100, max_downloads=1)
    fid = info["id"]
    assert client.head(f"/api/file/{fid}").status_code == 200
    # The single download slot must still be there after the HEAD.
    assert client.get(f"/api/file/{fid}").status_code == 200
    assert client.get(f"/api/file/{fid}").status_code == 410
    assert client.head(f"/api/file/{fid}").status_code == 410


def test_delete_token_flow(client):
    info, _ = do_upload(client, 64)
    fid, tok = info["id"], info["delete_token"]
    assert client.delete(f"/api/file/{fid}", headers={"X-Delete-Token": "wrong"}).status_code == 403
    assert client.delete(f"/api/file/{fid}", headers={"X-Delete-Token": tok}).status_code == 200
    assert client.get(f"/api/meta/{fid}").status_code == 410


def test_invalid_ids_rejected(client):
    assert client.get("/api/meta/not-a-valid-id").status_code == 404
    assert client.get("/api/file/aaaa-bbbb-cccc/../../../etc/passwd").status_code == 404
    assert client.get("/f/!!bad!!").status_code == 404


def test_expiry_validation(client):
    assert client.post("/api/upload/init", data=valid_meta(100, expiry=int(time.time()) - 5)).status_code == 400
    far_future = int(time.time()) + config.MAX_EXPIRY_SECONDS + 100
    assert client.post("/api/upload/init", data=valid_meta(100, expiry=far_future)).status_code == 400


# --- reporting -----------------------------------------------------------------

def test_report_requires_custom_header(client):
    """CSRF regression: cross-origin simple form POSTs must not suspend files."""
    info, _ = do_upload(client, 100)
    fid = info["id"]
    r = client.post("/api/report", data={"file_id": fid, "reason": "drive-by"})
    assert r.status_code == 403
    assert client.get(f"/api/meta/{fid}").status_code == 200  # not suspended

    r = client.post(
        "/api/report",
        data={"file_id": fid, "reason": "real report"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert r.status_code == 200
    assert client.get(f"/api/meta/{fid}").status_code == 451


def test_admin_reports_endpoint(client):
    """Regression: this endpoint 500ed (selected a non-existent ip column)."""
    info, _ = do_upload(client, 100)
    fid = info["id"]
    client.post(
        "/api/report",
        data={"file_id": fid, "reason": "test reason"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    r = client.get("/api/admin/reports", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    reports = r.get_json()["reports"]
    assert len(reports) == 1
    assert reports[0]["file_id"] == fid
    assert reports[0]["reason"] == "test reason"
    assert "ip" not in reports[0]  # reporter IPs are never stored


# --- admin / gating ------------------------------------------------------------

def test_admin_requires_token(client):
    assert client.get("/api/admin/overview").status_code == 401
    assert client.get("/api/admin/overview", headers=ADMIN_HEADERS).status_code == 200


def test_invite_gating(client):
    r = client.post("/api/admin/invites", headers=ADMIN_HEADERS, data={"name": "bob"})
    assert r.status_code == 200
    token = r.get_json()["token"]

    # An existing invite turns gating on for the whole deployment.
    assert client.post("/api/upload/init", data=valid_meta(64)).status_code == 403
    assert client.post("/api/upload/init", data=valid_meta(64), headers={"X-Upload-Token": token}).status_code == 200

    invites = client.get("/api/admin/invites", headers=ADMIN_HEADERS).get_json()["invites"]
    r = client.post(f"/api/admin/invites/{invites[0]['id']}/revoke", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    # Revoking the last invite must not silently re-open uploads.
    assert client.post("/api/upload/init", data=valid_meta(64)).status_code == 403


def test_admin_suspend_restore(client):
    info, _ = do_upload(client, 100)
    fid = info["id"]
    assert client.post(f"/api/admin/files/{fid}/suspend", headers=ADMIN_HEADERS).status_code == 200
    assert client.get(f"/api/meta/{fid}").status_code == 451
    assert client.post(f"/api/admin/files/{fid}/restore", headers=ADMIN_HEADERS).status_code == 200
    assert client.get(f"/api/meta/{fid}").status_code == 200


# --- groups --------------------------------------------------------------------

def test_group_flow(client):
    gid = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    m1, _ = do_upload(client, 200, group_id=gid, group_index=0, group_count=2)
    m2, _ = do_upload(client, 300, group_id=gid, group_index=1, group_count=2)
    g = client.get(f"/api/group/{gid}")
    assert g.status_code == 200
    files = g.get_json()["files"]
    assert [f["id"] for f in files] == [m1["id"], m2["id"]]


def test_group_duplicate_index_rejected(client):
    gid = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    do_upload(client, 200, group_id=gid, group_index=0, group_count=2)
    r = client.post("/api/upload/init", data=valid_meta(200, group_id=gid, group_index=0, group_count=2))
    uid = r.get_json()["upload_id"]
    ct = make_ciphertext(200)
    client.post(
        "/api/upload/chunk",
        data={"upload_id": uid, "chunk_index": "0", "chunk": (io.BytesIO(ct), "c")},
        content_type="multipart/form-data",
    )
    r = client.post("/api/upload/finish", data={"upload_id": uid})
    assert r.status_code == 409


# --- headers / status ----------------------------------------------------------

def test_security_headers(client):
    h = client.get("/")
    csp = h.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "base-uri 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'self'" in csp
    assert h.headers["X-Content-Type-Options"] == "nosniff"
    assert h.headers["X-Frame-Options"] == "DENY"
    assert h.headers["Referrer-Policy"] == "no-referrer"
    api = client.get("/api/config")
    assert "no-store" in api.headers["Cache-Control"]


def test_status_ages_not_swapped(client):
    """Regression: oldest_age_seconds/newest_age_seconds were inverted."""
    info, _ = do_upload(client, 100)
    # Backdate the file so the ages differ measurably.
    db = sqlite3.connect(str(config.DB_PATH))
    db.execute("UPDATE files SET created = ? WHERE id = ?", (int(time.time()) - 1000, info["id"]))
    db.commit()
    db.close()
    s = client.get("/api/status").get_json()
    assert s["oldest_age_seconds"] >= 1000
    assert s["newest_age_seconds"] <= s["oldest_age_seconds"]


# --- rate limiting ---------------------------------------------------------------

def test_upload_rate_limit(client, monkeypatch):
    monkeypatch.setattr(config, "UPLOAD_RATE_LIMIT", 3)
    codes = [client.post("/api/upload/init", data=valid_meta(10)).status_code for _ in range(4)]
    assert codes[:3] == [200, 200, 200]
    assert codes[3] == 429


def test_upload_status_rate_limit(client, monkeypatch):
    monkeypatch.setattr(config, "DOWNLOAD_RATE_LIMIT", 3)
    codes = [client.get("/api/upload/status/" + "a" * 16).status_code for _ in range(4)]
    assert codes[:3] == [404, 404, 404]
    assert codes[3] == 429


# --- filesystem hygiene ----------------------------------------------------------

def test_db_and_dir_permissions():
    """The DB holds live tokens; it and the data dir must be private."""
    assert stat.S_IMODE(os.stat(config.DB_PATH).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(config.DATA_DIR).st_mode) == 0o700


def test_orphan_blob_sweep(client):
    """Blobs without a DB row are reaped (after a grace period); live blobs stay."""
    info, ct = do_upload(client, 100)
    live_path = storage_path(info["id"])

    orphan = storage_path("zzzz-zzzz-zzzz")
    orphan.parent.mkdir(parents=True, exist_ok=True)
    orphan.write_bytes(b"stale ciphertext")
    old = time.time() - 3600
    os.utime(orphan, (old, old))

    fresh_orphan = storage_path("yyyy-yyyy-yyyy")
    fresh_orphan.parent.mkdir(parents=True, exist_ok=True)
    fresh_orphan.write_bytes(b"in-flight upload")

    run_cleanup_once()

    assert live_path.exists()          # live blob untouched
    assert not orphan.exists()         # old orphan reaped
    assert fresh_orphan.exists()       # within grace period — could be mid-finish


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
