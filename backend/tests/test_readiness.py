"""PQC Readiness Assessment rules on REAL scanner output (pure; no FastAPI)."""
import json

import pytest

from app.readiness import LEVEL_RULES, REFERENCES, assess
from tests.pipeline import ACME, run, tree

PYC = "cryptography.hazmat.primitives"
SENSITIVE = ("service: api\nowner: t\ndata_classification: highly-sensitive\nbusiness_criticality: critical\n"
             "internet_exposed: true\ndata_lifetime_years: 10\n")


def assess_dir(root, repo="repo"):
    recs, g, svc, an, _ = run(root, repo)
    return assess(recs, g, analysis=an, services=svc)


@pytest.fixture(scope="module")
def acme():
    return assess_dir(ACME, "acme-payments")


def cat(a, cid):
    return next(c for c in a["categories"] if c["id"] == cid)


# ---------------------------------------------------------------- the demo repository
def test_acme_level_and_blockers_are_evidence_backed(acme):
    assert acme["level"]["id"] == "not_ready_blockers"
    ids = {b["id"] for b in acme["blockers"]}
    assert {"hndl_key_establishment", "deprecated_protocols", "weak_suites"} <= ids
    for b in acme["blockers"]:
        assert b["evidence"] and all(e["file"] and e["line"] >= 1 and e["text"] and e["fid"].startswith("CRYPTO-") for e in b["evidence"])
        assert all(r in REFERENCES for r in b["references"])
    hndl = next(b for b in acme["blockers"] if b["id"] == "hndl_key_establishment")
    assert hndl["services"] == ["payment-api"]


def test_acme_categories(acme):
    assert cat(acme, "key_establishment")["status"] == "blocker"
    assert cat(acme, "signatures")["status"] == "action" and cat(acme, "signatures")["count"] >= 2
    assert cat(acme, "undetermined")["status"] == "review"                    # bare RSA key generation in a dev script
    assert cat(acme, "hashes")["status"] == "action"                          # SHA-1 in legacy/old_hash.py
    pqc = cat(acme, "pqc_adoption")
    assert pqc["status"] == "partial" and pqc["evidence"][0]["file"] == "pqc-lab/kem_demo.py"   # lab code is not production
    assert cat(acme, "legacy_symmetric")["status"] == "not_detected"


def test_counts_match_category_evidence(acme):
    c = acme["counts"]
    assert c["key_establishment"] == cat(acme, "key_establishment")["count"]
    assert c["signatures"] == cat(acme, "signatures")["count"]
    assert c["quantum_vulnerable"] == c["key_establishment"] + c["signatures"] + c["certificates"] + c["undetermined"]


def test_recommendations_are_ordered_and_link_to_the_simulator(acme):
    prios = [r["priority"] for r in acme["recommendations"]]
    assert prios == sorted(prios) and prios[0] == 1
    first = acme["recommendations"][0]
    assert "hybrid" in first["title"].lower() and first["simulate"] == "algorithm:ECDH" and first["evidence"]
    assert any(r["title"].startswith("Verify library versions") and "cryptography" in r["libraries"] for r in acme["recommendations"])


def test_no_percentages_and_honest_statement(acme):
    blob = json.dumps(acme)
    assert "%" not in blob and "quantum-safe" not in acme["level"]["label"].lower()
    assert "never certifies" in acme["statement"]
    assert acme["not_analyzed"] and any("versions" in x for x in acme["not_analyzed"])
    assert [r["id"] for r in acme["level_rules"]] == [r[0] for r in LEVEL_RULES]


def test_libraries_report_known_support_without_versions(acme):
    libs = {l["library"]: l for l in acme["libraries"]}
    assert libs["cryptography"]["status"] == "known" and "ML-KEM" in libs["cryptography"]["pqc_support"]
    assert all("not determined" in l["note"] for l in acme["libraries"])
    assert libs["java.security"]["references"] == ["JEP496", "JEP497"]


# ---------------------------------------------------------------- rule-by-rule
def test_no_vulnerable_usage_is_not_called_quantum_safe(tmp_path):
    a = assess_dir(tree(tmp_path, {"a.py": "import hashlib\nhashlib.sha256(b'')\n"}))
    assert a["level"]["id"] == "no_vulnerable_usage_detected"
    assert "NOT a statement" in a["level"]["rule"] and a["blockers"] == []


def test_empty_repository(tmp_path):
    a = assess_dir(tree(tmp_path, {"README.md": "nothing\n"}))
    assert a["level"]["id"] == "no_vulnerable_usage_detected" and a["counts"]["findings"] == 0
    assert all(c["status"] in ("not_detected", "info") for c in a["categories"])


def test_vulnerable_without_metadata_is_not_ready_but_no_hndl_blocker(tmp_path):
    a = assess_dir(tree(tmp_path, {"k.py": f"from {PYC}.asymmetric import ec\nz = key.exchange(ec.ECDH(), peer)\n"}))
    assert a["level"]["id"] == "not_ready" and a["blockers"] == []
    assert any("service.yaml" in l for l in a["limitations"])                 # says why HNDL could not be raised


def test_hndl_blocker_needs_sensitive_exposed_long_lived_service(tmp_path):
    a = assess_dir(tree(tmp_path, {"service.yaml": SENSITIVE,
                                   "k.py": f"from {PYC}.asymmetric import ec\nz = key.exchange(ec.ECDH(), peer)\n"}))
    assert a["level"]["id"] == "not_ready_blockers" and a["blockers"][0]["id"] == "hndl_key_establishment"


def test_pqc_in_production_path_means_in_transition(tmp_path):
    a = assess_dir(tree(tmp_path, {
        "svc/sign.py": f"from {PYC}.asymmetric import ec\ns = key.sign(d, ec.ECDSA(None))\n",
        "svc/kem.py": "import oqs\nk = oqs.KeyEncapsulation('ML-KEM-768')\n"}))
    assert a["level"]["id"] == "in_transition" and cat(a, "pqc_adoption")["status"] == "positive"


def test_legacy_cipher_is_a_blocker(tmp_path):
    a = assess_dir(tree(tmp_path, {"c.py": "from Crypto.Cipher import DES3\nc = DES3.new(k, DES3.MODE_CBC, iv)\n"}))
    assert a["level"]["id"] == "not_ready_blockers" and a["blockers"][0]["id"] == "legacy_ciphers"
    assert a["recommendations"][0]["title"] == "Remove disallowed classical cryptography"


def test_aes128_is_review_not_blocker(tmp_path):
    a = assess_dir(tree(tmp_path, {"c.py": f"from {PYC}.ciphers import algorithms\na = algorithms.AES128(k)\n"}))
    assert cat(a, "symmetric_strength")["status"] == "review" and a["blockers"] == []


def test_agility_hubs_come_from_the_graph(tmp_path):
    a = assess_dir(tree(tmp_path, {
        "core/sig.py": f"from {PYC}.asymmetric import ec\ns = key.sign(d, ec.ECDSA(None))\n", "core/__init__.py": "",
        "api/a.py": "from core import sig\n", "api/b.py": "from core.sig import s\n"}))
    ag = cat(a, "agility")
    assert ag["hubs"] == [{"file": "core/sig.py", "imported_by": ["api/a.py", "api/b.py"]}]
    assert any(r["title"].startswith("Centralize") for r in a["recommendations"])


def test_partial_scan_and_skipped_files_are_limitations(tmp_path):
    recs, g, svc, an, _ = run(tree(tmp_path, {"bad.py": "print 'py2'\n", "a.py": "import hashlib\n"}))
    a = assess(recs, g, analysis={**an, "scan_status": "partial"}, services=svc)
    assert any("time limit" in l for l in a["limitations"]) and any("skipped" in l for l in a["limitations"])
    assert a["analyzed"]["skipped_by_reason"] == {"parse_error": 1}


def test_deterministic(acme):
    again = assess_dir(ACME, "acme-payments")
    assert json.dumps(again) == json.dumps(acme)
