"""Readiness + simulator API: access control, validation, integration with summary and report."""
import pytest


@pytest.fixture
def demo(client):
    body = client.post("/api/demo/acme").json()
    return body["scan"]["id"], body["access_token"]


@pytest.mark.parametrize("path", ["readiness", "simulate?node=algorithm:ECDH"])
def test_require_scan_token(raw_client, demo, path):
    sid, token = demo
    assert raw_client.get(f"/api/scans/{sid}/{path}").status_code == 404
    assert raw_client.get(f"/api/scans/{sid}/{path}", headers={"X-QMC-Scan-Token": "nope"}).status_code == 404
    assert raw_client.get(f"/api/scans/{sid}/{path}", headers={"X-QMC-Scan-Token": token}).status_code == 200


def test_readiness_endpoint(client, demo):
    sid, _ = demo
    a = client.get(f"/api/scans/{sid}/readiness").json()
    assert a["level"]["id"] == "not_ready_blockers" and a["blockers"] and a["recommendations"]
    assert all(e["file"] and e["line"] for b in a["blockers"] for e in b["evidence"])


def test_simulate_endpoint_and_validation(client, demo):
    sid, _ = demo
    base = f"/api/scans/{sid}/simulate"
    s = client.get(base, params={"node": "algorithm:ECDSA", "target": "ML-DSA-87"}).json()
    assert s["tracks"][0]["target"]["id"] == "ML-DSA-87"
    assert client.get(base, params={"node": "algorithm:ECDSA", "target": "ML-KEM-768"}).json()["error"]["code"] == "invalid_target"
    assert client.get(base, params={"node": "algorithm:NOPE"}).status_code == 404
    assert client.get(base, params={"node": "service:payment-api"}).status_code == 422
    assert client.get(base, params={"node": "algorithm:ECDSA", "target": "../../etc"}).status_code == 422
    assert client.get(base).status_code == 422


def test_not_analyzed_scan(client):
    from tests.test_scanner_integration import acme_zip
    sid = client.post("/api/scans?filename=a.zip", content=acme_zip()).json()["scan_id"]
    assert client.get(f"/api/scans/{sid}/readiness").status_code == 409
    assert client.get(f"/api/scans/{sid}/simulate", params={"node": "algorithm:ECDH"}).status_code == 409
    assert client.get(f"/api/scans/{sid}/summary").json()["readiness"] == {"available": False}


def test_summary_and_report_include_readiness(client, demo):
    sid, _ = demo
    r = client.get(f"/api/scans/{sid}/summary").json()["readiness"]
    assert r == {"available": True, "level": "not_ready_blockers", "label": "Not ready: critical blockers", "blockers": 3,
                 "top_recommendation": "Protect long-lived data first: hybrid key establishment"}
    md = client.get(f"/api/scans/{sid}/report.md").text
    assert "## 9. PQC readiness assessment" in md and "### Critical blockers" in md and "FIPS 203" in md
    assert "quantum-safe" not in md.replace("never certifies an application as quantum-safe", "")


def test_suppression_changes_readiness(client, demo):
    sid, _ = demo
    before = client.get(f"/api/scans/{sid}/readiness").json()["counts"]["key_establishment"]
    fid = next(f["id"] for f in client.get(f"/api/scans/{sid}/findings").json()["findings"] if f["file"] == "src/payments/keys.py")
    client.post(f"/api/scans/{sid}/findings/{fid}/suppress", json={"reason": "test"})
    assert client.get(f"/api/scans/{sid}/readiness").json()["counts"]["key_establishment"] == before - 1
