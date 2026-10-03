import re


def test_report_has_all_required_sections_and_honest_limitations(client):
    sid = client.post("/api/demo/acme").json()["scan"]["id"]
    r = client.get(f"/api/scans/{sid}/report.md")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"] and r.headers["content-type"].startswith("text/markdown")
    md = r.text
    for h in ("## 1. Executive summary", "## 2. Services", "## 3. Cryptographic inventory", "## 4. Findings with evidence", "## 5. Migration roadmap", "## 6. Limitations", "## 7. Scan metadata"):
        assert h in md, h
    assert "Not a certification" in md and "not an official NIST score" in md and "not CVSS" in md.replace("**not** CVSS", "not CVSS")
    assert "elevated harvest-now-decrypt-later" in md and "ML-KEM (FIPS 203)" in md and "Crypto-agility" in md
    assert "X25519PrivateKey.generate()" in md and "| Quantum exposure (QE) | 4 | 2 |" in md
    assert sid in md and "PY-CRYPTOGRAPHY-ECDH-001" in md                  # rule versions + scan id (reproducibility)
    for banned in ("100% quantum safe", "unbreakable", "is currently broken", "guarantee"):
        assert banned not in md.lower()
    assert "PRIVATE KEY" not in md


def test_report_includes_suppressions_and_requires_analysis(client):
    sid = client.post("/api/demo/acme").json()["scan"]["id"]
    fid = client.get(f"/api/scans/{sid}/findings").json()["findings"][0]["id"]
    client.post(f"/api/scans/{sid}/findings/{fid}/suppress", json={"reason": "reviewed: dead code"})
    assert "Suppressed findings" in client.get(f"/api/scans/{sid}/report.md").text and "reviewed: dead code" in client.get(f"/api/scans/{sid}/report.md").text
    from tests.test_scanner_integration import acme_zip
    up = client.post("/api/scans?filename=a.zip", content=acme_zip()).json()["scan_id"]
    assert client.get(f"/api/scans/{up}/report.md").status_code == 409
