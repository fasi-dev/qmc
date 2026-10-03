"""End-to-end demo flow on REAL scanner output: upload/demo -> ingest -> scan -> QMP risk -> inventory -> detail."""
import json
import uuid

import pytest

from app import analysis


@pytest.fixture
def demo(client, settings):
    r = client.post("/api/demo/acme")
    assert r.status_code == 201, r.text
    return r.json()


def sid(demo):
    return demo["scan"]["id"]


def test_demo_flow_summary(client, demo):
    t = demo["totals"]
    assert demo["scan"]["status"] == "analyzed" and demo["scan"]["repo_name"] == "acme-payments"
    assert t["crypto_findings"] >= 18 and t["quantum_vulnerable"] >= 8 and t["already_pqc"] == 1
    assert t["critical"] >= 4 and t["hndl_elevated"] >= 2 and t["services"] == 3
    assert t["comment_or_doc_mentions"] == 3          # README trap + 2 code comments, kept visible as a count
    assert "not a security certification" in demo["qmp_label"].lower() or "not a security certification" in demo["qmp_label"]
    assert "Not a certification" in demo["limitations"]
    assert sum(demo["by_band"].values()) == t["crypto_findings"]
    assert demo["by_primitive"]["public-key"] >= 8 and demo["by_primitive"]["pqc-kem"] == 1


def test_top_finding_is_ecdh_critical_with_elevated_hndl(client, demo):
    top = demo["top_findings"][0]
    assert (top["algorithm"], top["band"], top["qmp"], top["hndl"], top["hndl_severity"], top["service"]) == ("ECDH", "Critical", 20, True, "elevated", "payment-api")
    assert top["operation"] in ("key_agreement", "key_generation") and top["confidence_level"] == "high"


def test_dev_script_rsa_is_review_far_below_payment_api(client, demo):
    rows = client.get(f"/api/scans/{sid(demo)}/findings", params={"include_tests": True}).json()["findings"]
    dev = [r for r in rows if r["file"] == "scripts/gen_test_keys.py"][0]
    assert (dev["service"], dev["band"], dev["qmp"], dev["test_path"]) == ("dev-scripts", "Review", 9, True)
    pay = [r for r in rows if r["file"] == "src/auth.py" and r["algorithm"] == "RSA" and r["operation"] == "key_generation"][0]
    assert pay["band"] == "Critical" and pay["qmp"] - dev["qmp"] >= 10      # the 06 Example B/C contrast with REAL data
    default = client.get(f"/api/scans/{sid(demo)}/findings").json()["findings"]
    assert "scripts/gen_test_keys.py" not in {r["file"] for r in default}   # test paths hidden by default, not deleted


def test_informational_guard_and_hygiene_bands(client, demo):
    rows = {(r["file"], r["algorithm"], r["operation"]): r for r in client.get(f"/api/scans/{sid(demo)}/findings").json()["findings"]}
    assert rows[("src/payments/settle.py", "AES", "encryption")]["band"] == "Informational"
    assert rows[("src/payments/settle.py", "HMAC", "mac_generation")]["band"] == "Informational"
    sha1 = rows[("src/legacy/old_hash.py", "SHA-1", "hashing")]
    assert (sha1["band"], sha1["service"], sha1["quantum_vulnerable"]) == ("Review", "settlement-worker", False) and "classical hygiene" in sha1["badges"]
    assert rows[("pqc-lab/kem_demo.py", "ML-KEM", "key_generation")]["already_pqc"] is True
    tls = rows[("deploy/nginx/tls.conf", "TLS", "config")]
    assert tls["band"] in ("Review", "Informational") and tls["quantum_vulnerable"] is False


def test_nginx_ecdhe_is_quantum_vulnerable_review_with_hndl(client, demo):
    ecdhe = [r for r in client.get(f"/api/scans/{sid(demo)}/findings").json()["findings"]
             if r["rule_id"] == "CFG-NGINX-CIPHER-001"][0]
    assert (ecdhe["quantum_vulnerable"], ecdhe["band"], ecdhe["hndl"], ecdhe["confidence_level"]) == (True, "Review", True, "medium")


def test_finding_detail_has_evidence_snippet_and_factor_breakdown(client, demo):
    top = demo["top_findings"][0]
    d = client.get(f"/api/scans/{sid(demo)}/findings/{top['id']}").json()
    f, r, sn = d["finding"], d["risk"], d["snippet"]
    assert f["evidence"] and f["file"] == top["file"] and f["rule_id"] and f["rule_version"] and f["line_start"] == top["line_start"]
    assert set(r["factors"]) == {"QE", "DS", "IE", "BC", "MC"} and all(r["factors"][k]["why"] for k in r["factors"])
    assert r["factors"]["DS"]["source"] == "service.yaml" and r["hndl"]["flag"] and "harvest-now-decrypt-later" in r["hndl"]["text"]
    assert sn["lines"] and sn["highlight_start"] <= f["line_start"] and f["evidence"].split("(")[0].strip()[-8:] in "\n".join(sn["lines"])
    assert "not a security certification" in d["qmp_label"].lower() or "not a security certification" in d["qmp_label"]


def test_snippets_never_contain_secrets_and_tree_is_purged(client, demo, settings):
    scan_id = sid(demo)
    ws = settings.scans_dir / scan_id
    assert not (ws / "tree").exists() and (ws / "manifest.json").exists()      # 04 section 5: extracted source deleted after analysis
    blob = json.dumps(client.get(f"/api/scans/{scan_id}/findings", params={"include_comments": True, "include_tests": True}).json())
    assert "PRIVATE KEY" not in blob


def test_filters_search_and_facets(client, demo):
    base = f"/api/scans/{sid(demo)}/findings"
    allv = client.get(base).json()
    assert allv["count"] < allv["total_all"] and {"ECDH", "RSA", "SHA-1"} <= set(allv["facets"]["algorithm"])
    vul = client.get(base, params={"vulnerable": True}).json()["findings"]
    assert vul and all(r["quantum_vulnerable"] for r in vul)
    crit = client.get(base, params={"band": "Critical"}).json()["findings"]
    assert crit and all(r["band"] == "Critical" for r in crit)
    assert {r["service"] for r in client.get(base, params={"service": "settlement-worker"}).json()["findings"]} == {"settlement-worker"}
    assert [r["algorithm"] for r in client.get(base, params={"pqc": True}).json()["findings"]] == ["ML-KEM"]
    assert all(r["primitive"] == "public-key" for r in client.get(base, params={"primitive": "public-key"}).json()["findings"])
    assert all(r["file"].endswith(".java") for r in client.get(base, params={"language": "java"}).json()["findings"])
    assert {r["file"] for r in client.get(base, params={"language": "config"}).json()["findings"]} >= {"deploy/nginx/tls.conf", "certs/api.acme-payments.example.crt"}
    assert client.get(base, params={"q": "x25519"}).json()["count"] == 1
    assert client.get(base, params={"q": "zzzz-nothing"}).json()["count"] == 0
    withc = client.get(base, params={"include_comments": True}).json()
    assert withc["count"] == allv["count"] + 3


def test_findings_are_ranked_critical_first(client, demo):
    rows = client.get(f"/api/scans/{sid(demo)}/findings").json()["findings"]
    ranks = [r["rank"] for r in rows]
    assert ranks == sorted(ranks)
    scored = [r["qmp"] for r in rows if r["qmp"] is not None]
    assert scored[0] == max(scored)


def test_suppression_excludes_from_views_and_counts_but_keeps_record(client, demo):
    scan_id = sid(demo)
    top = demo["top_findings"][0]["id"]
    r = client.post(f"/api/scans/{scan_id}/findings/{top}/suppress", json={"reason": "demo: confirmed unused", "author": "alice"})
    assert r.status_code == 200 and r.json()["suppressed"] and r.json()["suppression"]["author"] == "alice"
    s2 = client.get(f"/api/scans/{scan_id}/summary").json()
    assert s2["totals"]["suppressed"] == 1 and s2["totals"]["crypto_findings"] == demo["totals"]["crypto_findings"] - 1
    assert top not in {x["id"] for x in client.get(f"/api/scans/{scan_id}/findings").json()["findings"]}
    assert top in {x["id"] for x in client.get(f"/api/scans/{scan_id}/findings", params={"include_suppressed": True}).json()["findings"]}
    assert client.post(f"/api/scans/{scan_id}/findings/{top}/suppress", json={"reason": "  "}).status_code == 422
    assert client.delete(f"/api/scans/{scan_id}/findings/{top}/suppress").json()["suppressed"] is False
    assert client.get(f"/api/scans/{scan_id}/summary").json()["totals"]["suppressed"] == 0


def test_dashboard_services_and_migration_status(client, demo):
    svc = {s["service"]: s for s in demo["services"]}
    assert set(svc) == {"payment-api", "settlement-worker", "dev-scripts"}
    assert svc["payment-api"]["critical"] >= 4 and svc["payment-api"]["data_classification"] == "highly-sensitive" and svc["payment-api"]["internet_exposed"] is True
    assert svc["payment-api"]["migration_status"].startswith("in progress")       # ML-KEM lab code present
    assert svc["settlement-worker"]["quantum_vulnerable"] == 0 and "no quantum" in svc["settlement-worker"]["migration_status"]
    assert svc["dev-scripts"]["quantum_vulnerable"] == 1 and svc["dev-scripts"]["migration_status"] == "not started"


def test_csv_export_is_safe_and_filtered(client, demo):
    r = client.get(f"/api/scans/{sid(demo)}/findings.csv", params={"band": "Critical"})
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("id,algorithm") and len(lines) > 1 and all("Critical" in l for l in lines[1:])


def test_upload_then_analyze_flow_and_idempotency_guard(client, settings):
    from tests.test_scanner_integration import acme_zip
    r = client.post("/api/scans?filename=acme.zip", content=acme_zip())
    scan_id = r.json()["scan_id"]
    assert client.get("/api/scans").json()[0]["status"] == "ingested"
    s = client.post(f"/api/scans/{scan_id}/analyze")
    assert s.status_code == 200 and s.json()["scan"]["status"] == "analyzed"
    assert client.post(f"/api/scans/{scan_id}/analyze").status_code == 409
    assert client.get("/api/scans").json()[0]["status"] == "analyzed"
    assert client.delete(f"/api/scans/{scan_id}").status_code == 200
    assert client.get(f"/api/scans/{scan_id}/summary").status_code == 404 and client.get("/api/scans").json() == []


def test_analysis_is_deterministic_across_runs(client):
    a = client.post("/api/demo/acme").json()
    b = client.post("/api/demo/acme").json()
    strip = lambda x: [{k: v for k, v in f.items()} for f in x["top_findings"]]
    assert strip(a) == strip(b) and a["totals"] == b["totals"] and a["by_band"] == b["by_band"]
    fa = client.get(f"/api/scans/{a['scan']['id']}/findings", params={"include_comments": True, "include_tests": True}).json()["findings"]
    fb = client.get(f"/api/scans/{b['scan']['id']}/findings", params={"include_comments": True, "include_tests": True}).json()["findings"]
    assert fa == fb


@pytest.mark.parametrize("path", ["summary", "findings", "findings/CRYPTO-001", "findings.csv"])
def test_unknown_and_malformed_ids_404(client, path):
    assert client.get(f"/api/scans/not-a-uuid/{path}").status_code == 404
    assert client.get(f"/api/scans/{uuid.uuid4()}/{path}").status_code == 404


def test_unknown_finding_404(client, demo):
    assert client.get(f"/api/scans/{sid(demo)}/findings/CRYPTO-999").status_code == 404
