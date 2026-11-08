"""Access control, rate limiting, capacity and the atomic analyze claim, through the real API."""
import dataclasses
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app import analysis
from app.config import get_settings
from app.db import FindingRow, ScanRow, open_session
from app.main import app
from tests.conftest import ADMIN

SCAN_PATHS = ["", "/summary", "/findings", "/findings.csv", "/migration", "/report.md", "/findings/CRYPTO-001"]


@pytest.fixture
def demo_raw(raw_client):
    r = raw_client.post("/api/demo/acme")
    assert r.status_code == 201
    body = r.json()
    return body["scan"]["id"], body["access_token"]


@pytest.mark.parametrize("path", SCAN_PATHS)
def test_scan_endpoints_require_the_scan_token(raw_client, demo_raw, path):
    sid, token = demo_raw
    assert raw_client.get(f"/api/scans/{sid}{path}").status_code == 404                       # no token
    assert raw_client.get(f"/api/scans/{sid}{path}", headers={"X-QMC-Scan-Token": "nope"}).status_code == 404
    assert raw_client.get(f"/api/scans/{sid}{path}", headers={"X-QMC-Scan-Token": token}).status_code == 200
    assert raw_client.get(f"/api/scans/{sid}{path}", headers=ADMIN).status_code == 200        # operator


def test_wrong_token_looks_exactly_like_an_unknown_scan(raw_client, demo_raw):
    sid, _ = demo_raw
    a = raw_client.get(f"/api/scans/{sid}/summary", headers={"X-QMC-Scan-Token": "x"})
    b = raw_client.get("/api/scans/00000000-0000-4000-8000-000000000000/summary")
    assert a.status_code == b.status_code == 404 and a.json() == b.json()


def test_mutations_require_the_token(raw_client, demo_raw):
    sid, token = demo_raw
    assert raw_client.post(f"/api/scans/{sid}/findings/CRYPTO-001/suppress", json={"reason": "x"}).status_code == 404
    assert raw_client.delete(f"/api/scans/{sid}").status_code == 404
    assert raw_client.delete(f"/api/scans/{sid}", headers={"X-QMC-Scan-Token": token}).status_code == 200


def test_tokens_are_per_scan(raw_client, demo_raw):
    sid, _ = demo_raw
    other_token = raw_client.post("/api/demo/acme").json()["access_token"]
    assert raw_client.get(f"/api/scans/{sid}/summary", headers={"X-QMC-Scan-Token": other_token}).status_code == 404


def test_token_is_never_stored_in_plaintext(raw_client, demo_raw, settings):
    _, token = demo_raw
    for p in settings.data_dir.rglob("*"):
        if p.is_file():
            assert token.encode() not in p.read_bytes(), p


def test_scan_list_is_operator_only(raw_client, demo_raw):
    assert raw_client.get("/api/scans").status_code == 403
    assert raw_client.get("/api/scans", headers={"X-QMC-Admin-Token": "wrong"}).status_code == 403
    assert len(raw_client.get("/api/scans", headers=ADMIN).json()) == 1


def test_scan_list_disabled_when_no_admin_token(settings, raw_client):
    app.dependency_overrides[get_settings] = lambda: dataclasses.replace(settings, admin_token="")
    assert raw_client.get("/api/scans", headers={"X-QMC-Admin-Token": ""}).status_code == 403


def test_upload_returns_token_once_and_manifest_has_none(raw_client, settings):
    from tests.test_scanner_integration import acme_zip
    body = raw_client.post("/api/scans?filename=a.zip", content=acme_zip()).json()
    token = body["access_token"]
    again = raw_client.get(f"/api/scans/{body['scan_id']}", headers={"X-QMC-Scan-Token": token}).json()
    assert "access_token" not in again and "token_hash" not in again


def test_rate_limit_on_scan_creation(settings, raw_client):
    app.dependency_overrides[get_settings] = lambda: dataclasses.replace(settings, scans_per_window=2, rate_window_seconds=777)
    codes = [raw_client.post("/api/demo/acme").status_code for _ in range(3)]
    assert codes == [201, 201, 429]
    assert raw_client.post("/api/demo/acme").json()["error"]["code"] == "rate_limited"


def test_capacity_cap(settings, raw_client):
    app.dependency_overrides[get_settings] = lambda: dataclasses.replace(settings, max_scans=1)
    assert raw_client.post("/api/demo/acme").status_code == 201
    r = raw_client.post("/api/demo/acme")
    assert r.status_code == 503 and r.json()["error"]["code"] == "capacity_reached"


def test_retention_removes_old_scans_and_workspaces(raw_client, demo_raw, settings):
    sid, token = demo_raw
    db = open_session(settings)
    try:
        assert analysis.purge_expired(db, settings, datetime.now(timezone.utc) + timedelta(hours=1), force=True) == 0
        assert analysis.purge_expired(db, settings, datetime.now(timezone.utc) + timedelta(hours=25), force=True) == 1
        assert db.get(ScanRow, sid) is None and not (settings.scans_dir / sid).exists()
    finally:
        db.close()
    assert raw_client.get(f"/api/scans/{sid}/summary", headers={"X-QMC-Scan-Token": token}).status_code == 404


def test_concurrent_analyze_inserts_findings_once(client, settings):
    from tests.test_scanner_integration import acme_zip
    sid = client.post("/api/scans?filename=a.zip", content=acme_zip()).json()["scan_id"]
    codes: list[int] = []

    def go():
        codes.append(client.post(f"/api/scans/{sid}/analyze").status_code)
    threads = [threading.Thread(target=go) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert codes.count(200) == 1 and all(c in (200, 409, 503) for c in codes)
    db = open_session(settings)
    try:
        fids = [r.fid for r in db.query(FindingRow).filter(FindingRow.scan_id == sid)]
        assert len(fids) == len(set(fids)) > 0
    finally:
        db.close()


def test_failed_analysis_releases_the_claim(client, settings, monkeypatch):
    from tests.test_scanner_integration import acme_zip
    sid = client.post("/api/scans?filename=a.zip", content=acme_zip()).json()["scan_id"]

    def boom(*a, **k):
        raise RuntimeError("scanner crashed")
    monkeypatch.setattr(analysis, "scan_tree", boom)
    with pytest.raises(RuntimeError):
        client.post(f"/api/scans/{sid}/analyze")
    db = open_session(settings)
    try:
        assert db.get(ScanRow, sid).status == "ingested"
    finally:
        db.close()
    monkeypatch.undo()
    assert client.post(f"/api/scans/{sid}/analyze").status_code == 200
