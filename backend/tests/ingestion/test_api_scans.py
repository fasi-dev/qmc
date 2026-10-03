import json
import os
import uuid

import pytest

from tests.conftest import make_tar, make_zip, tar_file

PEM = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLUvVhZ1Rr1h4kqwqUj1HloAoGCCqGSM49\n-----END EC PRIVATE KEY-----\n"
JWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX2hlcmU"
SECRETS = ["MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLUvVhZ1Rr1h4kqwqUj1HloAoGCCqGSM49", JWT, "AKIAABCDEFGHIJKLMNOP", "hunter2hunter2"]


def secret_repo() -> bytes:
    return make_zip({
        "repo/src/auth.py": f'KEY = """{PEM}"""\nTOKEN = "{JWT}"\naws = "AKIAABCDEFGHIJKLMNOP"\npassword = "hunter2hunter2"\n'
                            "k = ec.generate_private_key(ec.SECP256R1())\n",
        "repo/service.yaml": "service: payment-api\nowner: t\ndata_classification: highly-sensitive\n"
                             "business_criticality: critical\ninternet_exposed: true\ndata_lifetime_years: 10\n",
    })


def test_upload_success_shape(client):
    r = client.post("/api/scans?filename=repo.zip", content=secret_repo())
    assert r.status_code == 201
    body = r.json()
    uuid.UUID(body["scan_id"], version=4)
    assert body["status"] == "ingested" and body["archive_type"] == "zip"
    assert body["stats"]["file_count"] == 2 and body["stats"]["redaction_count"] >= 4
    assert "files" not in body and body["services"][0]["service"] == "payment-api"
    assert "never executed" in body["notice"]


def test_no_secret_persisted_anywhere_on_disk_or_in_responses(client, settings):
    r = client.post("/api/scans", content=secret_repo())
    scan_id = r.json()["scan_id"]
    blobs = [r.text, client.get(f"/api/scans/{scan_id}?include_files=true").text]
    for p in settings.data_dir.rglob("*"):
        if p.is_file():
            blobs.append(p.read_bytes().decode("utf-8", "replace"))
    joined = "\n".join(blobs)
    for s in SECRETS:
        assert s not in joined, f"secret leaked: {s[:12]}..."
    assert "***REDACTED***" in joined


def test_redaction_preserves_evidence_lines_and_records_locations(client, settings):
    body = client.post("/api/scans", content=secret_repo()).json()
    src = (settings.scans_dir / body["scan_id"] / "tree" / "src" / "auth.py").read_text()
    lines = src.split("\n")
    assert "ec.generate_private_key(ec.SECP256R1())" in lines[-2]            # non-secret evidence intact, same line no.
    kinds = {(x["file"], x["kind"]) for x in body["redactions"]}
    assert ("src/auth.py", "pem_private_key") in kinds and ("src/auth.py", "jwt") in kinds
    assert all(set(x) == {"file", "line_start", "line_end", "kind", "marker"} for x in body["redactions"])  # no value field


def test_raw_upload_is_deleted_and_workspace_is_uuid_dir(client, settings):
    sid = client.post("/api/scans", content=secret_repo()).json()["scan_id"]
    ws = settings.scans_dir / sid
    assert sorted(p.name for p in ws.iterdir()) == ["manifest.json", "tree"]
    if os.name == "posix":
        assert oct(ws.stat().st_mode & 0o777) == "0o700"


def test_get_manifest_and_files_flag(client):
    sid = client.post("/api/scans", content=secret_repo()).json()["scan_id"]
    g = client.get(f"/api/scans/{sid}")
    assert g.status_code == 200 and "files" not in g.json()
    files = client.get(f"/api/scans/{sid}?include_files=true").json()["files"]
    assert {f["path"] for f in files} == {"src/auth.py", "service.yaml"} and all(len(f["sha256"]) == 64 for f in files)


def test_purge_tree_keeps_manifest_then_delete(client, settings):
    sid = client.post("/api/scans", content=secret_repo()).json()["scan_id"]
    assert client.delete(f"/api/scans/{sid}/tree").json()["tree_deleted"] is True
    assert not (settings.scans_dir / sid / "tree").exists()
    assert client.get(f"/api/scans/{sid}").status_code == 200
    assert client.delete(f"/api/scans/{sid}").status_code == 200
    assert client.get(f"/api/scans/{sid}").status_code == 404


@pytest.mark.parametrize("bad_id", ["../../etc/passwd", "..%2F..%2Fetc", "not-a-uuid", "12345", "%2e%2e"])
def test_scan_id_path_traversal_blocked(client, bad_id):
    for method in (client.get, client.delete):
        assert method(f"/api/scans/{bad_id}").status_code == 404
    assert client.delete(f"/api/scans/{bad_id}/tree").status_code == 404


def test_unknown_valid_uuid_404(client):
    assert client.get(f"/api/scans/{uuid.uuid4()}").status_code == 404


def test_content_length_over_limit_413_before_reading(client, settings):
    r = client.post("/api/scans", content=b"PK\x03\x04" + b"0" * (settings.max_archive_bytes + 1))
    assert r.status_code == 413 and r.json()["error"]["code"] == "archive_too_large"


def test_chunked_upload_without_content_length_still_capped(client, settings):
    def gen():
        yield b"PK\x03\x04"
        for _ in range(settings.max_archive_bytes // 65536 + 2):
            yield b"0" * 65536
    r = client.post("/api/scans", content=gen())
    assert r.status_code == 413
    assert not settings.scans_dir.exists() or list(settings.scans_dir.iterdir()) == []


def test_error_statuses_and_envelope(client):
    cases = [(b"", 400, "empty_archive"), (b"hello world", 415, "unsupported_archive_type"),
             (make_zip({"../x": "1"}), 422, "unsafe_path"),
             (make_tar([tar_file("a", b"1")], mode="w:gz")[:30], 400, "malformed_archive")]
    for data, status, code in cases:
        r = client.post("/api/scans", content=data)
        assert (r.status_code, r.json()["error"]["code"]) == (status, code), code
        assert set(r.json()) == {"error"}


def test_hostile_filename_is_sanitized_in_manifest(client):
    r = client.post("/api/scans", params={"filename": "../../etc/<script>x.zip"}, content=make_zip({"a.py": "1"}))
    assert r.json()["original_filename"] == "x.zip" or "/" not in r.json()["original_filename"]
    assert "<" not in r.json()["original_filename"]


def test_unexpected_exception_is_contained(client, settings, monkeypatch):
    import app.routes_scans as rs
    monkeypatch.setattr(rs, "ingest_archive", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom /secret/path")))
    r = client.post("/api/scans", content=make_zip({"a.py": "1"}))
    assert r.status_code == 500 and r.json()["error"]["code"] == "internal_error" and "boom" not in r.text
    assert not settings.scans_dir.exists() or list(settings.scans_dir.iterdir()) == []


def test_concurrent_scans_get_isolated_workspaces(client, settings):
    ids = {client.post("/api/scans", content=make_zip({"a.py": str(i)})).json()["scan_id"] for i in range(5)}
    assert len(ids) == 5 and len(list(settings.scans_dir.iterdir())) == 5
