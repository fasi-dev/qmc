"""Dependency graph API: access control, validation, caching/suppression, legacy scans, report + summary integration."""
import sqlite3

import pytest
from sqlalchemy import create_engine, inspect

from app.db import ScanRow, open_session, upgrade_schema


@pytest.fixture
def demo(client):
    body = client.post("/api/demo/acme").json()
    return body["scan"]["id"], body["access_token"]


def test_graph_requires_the_scan_token(raw_client, demo):
    sid, token = demo
    for path in ("graph", "graph/blast-radius?node=algorithm:ECDSA"):
        assert raw_client.get(f"/api/scans/{sid}/{path}").status_code == 404
        assert raw_client.get(f"/api/scans/{sid}/{path}", headers={"X-QMC-Scan-Token": "wrong"}).status_code == 404
        assert raw_client.get(f"/api/scans/{sid}/{path}", headers={"X-QMC-Scan-Token": token}).status_code == 200


def test_graph_shape_and_no_internal_paths(client, demo, settings):
    sid, _ = demo
    d = client.get(f"/api/scans/{sid}/graph").json()
    assert d["version"] == 1 and d["stats"]["imports_available"] is True
    ids = {n["id"] for n in d["nodes"]}
    assert {"algorithm:ECDH", "file:src/api/routes.py", "library:cryptography"} <= ids
    assert all(e["source"] in ids and e["target"] in ids for e in d["edges"])
    blob = str(d)
    assert str(settings.data_dir) not in blob and "/tmp" not in blob and "upload.bin" not in blob


def test_graph_is_deterministic_across_scans(client):
    a = client.post("/api/demo/acme").json()["scan"]["id"]
    b = client.post("/api/demo/acme").json()["scan"]["id"]
    assert client.get(f"/api/scans/{a}/graph").json() == client.get(f"/api/scans/{b}/graph").json()


def test_blast_radius_endpoint(client, demo):
    sid, _ = demo
    br = client.get(f"/api/scans/{sid}/graph/blast-radius", params={"node": "algorithm:ECDSA"}).json()
    ind = {x["file"]: x for x in br["indirect"]}
    assert ind["src/api/app.py"]["depth"] == 2 and ind["src/api/app.py"]["confidence"] == "confirmed"
    assert br["summary"]["direct_files"] >= 2 and br["meaning"]["indirect"]


@pytest.mark.parametrize("node,code", [
    (None, 422), ("", 422), ("algorithm:", 422), ("nonsense", 422), ("bogus:RSA", 422), ("file:\x00x", 422),
    ("x" * 700, 422), ("algorithm:NOPE", 404), ("service:payment-api", 422)])
def test_blast_radius_validation(client, demo, node, code):
    sid, _ = demo
    params = {} if node is None else {"node": node}
    assert client.get(f"/api/scans/{sid}/graph/blast-radius", params=params).status_code == code


def test_graph_requires_analysis(client):
    from tests.test_scanner_integration import acme_zip
    sid = client.post("/api/scans?filename=a.zip", content=acme_zip()).json()["scan_id"]
    r = client.get(f"/api/scans/{sid}/graph")
    assert r.status_code == 409 and r.json()["error"]["code"] == "not_analyzed"
    assert client.get(f"/api/scans/{sid}/summary").json()["dependency_graph"] == {"available": False}


def test_suppression_invalidates_the_cached_graph(client, demo):
    sid, _ = demo
    before = client.get(f"/api/scans/{sid}/graph").json()
    fid = next(n["fid"] for n in before["nodes"] if n["type"] == "finding" and n["file"] == "src/payments/keys.py")
    client.post(f"/api/scans/{sid}/findings/{fid}/suppress", json={"reason": "test"})
    after = client.get(f"/api/scans/{sid}/graph").json()
    assert f"finding:{fid}" not in {n["id"] for n in after["nodes"]}
    assert any("false positive" in x for x in after["limitations"])
    client.delete(f"/api/scans/{sid}/findings/{fid}/suppress")
    assert client.get(f"/api/scans/{sid}/graph").json() == before


def test_legacy_scan_without_graph_data_still_works(client, demo, settings):
    sid, _ = demo
    db = open_session(settings)
    try:
        row = db.get(ScanRow, sid)
        row.graph = None
        row.analysis = {**row.analysis, "analyzed_at": "legacy"}       # new cache key, as a real old row would have
        db.commit()
    finally:
        db.close()
    d = client.get(f"/api/scans/{sid}/graph").json()
    assert d["stats"]["imports_available"] is False and "Re-scan" in d["limitations"][0]
    br = client.get(f"/api/scans/{sid}/graph/blast-radius", params={"node": "algorithm:ECDH"}).json()
    assert br["indirect"] == [] and br["direct"]


def test_summary_and_report_include_the_graph(client, demo):
    sid, _ = demo
    s = client.get(f"/api/scans/{sid}/summary").json()["dependency_graph"]
    assert s["available"] and s["imports_available"] and s["dependent_files"] == 3
    md = client.get(f"/api/scans/{sid}/report.md").text
    assert "## 8. Cryptographic dependency blast radius" in md and "| ECDSA |" in md
    assert "`src/api/app.py` (depth 2, confirmed" in md
    for h in ("## 6. Limitations", "## 7. Scan metadata"):              # existing sections unchanged
        assert h in md


def test_schema_upgrade_adds_graph_column_without_touching_data(tmp_path):
    path = tmp_path / "old.db"
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE scans (id VARCHAR(36) PRIMARY KEY, created_at VARCHAR(40), status VARCHAR(16), original_filename VARCHAR(120),
                            repo_name VARCHAR(120), manifest JSON, analysis JSON, token_hash VARCHAR(64));
        CREATE TABLE findings (pk INTEGER PRIMARY KEY AUTOINCREMENT, scan_id VARCHAR(36), fid VARCHAR(16));
        INSERT INTO scans VALUES ('a', '2026-11-01T00:00:00+00:00', 'analyzed', 'x.zip', 'x', '{}', '{}', 'h');""")
    c.commit()
    c.close()
    engine = create_engine(f"sqlite:///{path}")
    upgrade_schema(engine)
    upgrade_schema(engine)                                              # idempotent
    assert "graph" in {col["name"] for col in inspect(engine).get_columns("scans")}
    with engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT id, token_hash, graph FROM scans").all() == [("a", "h", None)]
