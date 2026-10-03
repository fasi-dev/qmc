"""07_MIGRATION_RULES.md: role-aware, deterministic, honest."""
import pytest

from app.migration import plan_for
from app.risk import score
from tests.test_risk import DEV, PAYMENT, F


def plan(**kw):
    f = F(**kw)
    return plan_for(f, score(f, PAYMENT))


@pytest.mark.parametrize("alg,op,ctx,rule,needle", [
    ("ECDH", "key_agreement", "key-establishment", "R-03", "ML-KEM"), ("DH", "key_agreement", "key-establishment", "R-02", "ML-KEM"),
    ("RSA", "encryption", "unknown", "R-01", "ML-KEM"), ("RSA", "signature", "authentication", "R-04", "ML-DSA"),
    ("ECDSA", "signature", "authentication", "R-05", "SLH-DSA"), ("EdDSA", "signature", "unknown", "R-06", "FIPS 204"),
    ("DSA", "signature", "unknown", "R-07", "FIPS 205")])
def test_role_aware_mapping(alg, op, ctx, rule, needle):
    p = plan(algorithm=alg, operation=op, context=ctx)
    assert p["rule_id"] == rule and needle in p["direction"] and p["human_review"] is True and p["steps"] and p["caveats"]


def test_rsa_is_never_blindly_ml_kem():
    sig = plan(algorithm="RSA", operation="signature", context="unknown")
    assert "ML-KEM" not in sig["direction"] and sig["rule_id"] == "R-04"
    kem = plan(algorithm="RSA", operation="encryption", context="unknown")
    assert "ML-DSA" not in kem["direction"] and kem["rule_id"] == "R-01"


def test_undetermined_role_goes_to_manual_review_not_a_guess():
    p = plan(algorithm="RSA", operation="key_generation", context="unknown")
    assert p["rule_id"] == "R-12" and "Manual review" in p["direction"] and p["standard"] is None
    assert "cannot be determined statically" in p["note"] and p["human_review"]
    q = plan(algorithm="EC", operation="key_generation", context="unknown", confidence_level="medium")
    assert q["rule_id"] == "R-12"


def test_key_establishment_plan_carries_the_required_caveats():
    p = plan()
    assert any("KEM -> KDF -> symmetric" in c for c in p["caveats"]) and "hybrid" in p["interoperability"].lower()
    assert "X25519+ML-KEM-768" in p["interoperability"] and "peer coordination" in p["human_review_note"]
    assert p["steps"][1].startswith("Add ML-KEM alongside")


def test_signature_plan_requires_verifiers_first():
    p = plan(algorithm="ECDSA", operation="signature", context="authentication")
    assert any("ALL verifiers" in c for c in p["caveats"]) and p["steps"][1].startswith("Add PQC verification support everywhere first")
    assert "Dual-sign" in p["interoperability"]


@pytest.mark.parametrize("kw,rule", [
    (dict(algorithm="AES", primitive="symmetric", operation="encryption", quantum_vulnerable=False), "R-08"),
    (dict(algorithm="SHA-1", primitive="hash", operation="hashing", quantum_vulnerable=False), "R-09"),
    (dict(algorithm="SHA-256", primitive="hash", operation="hashing", quantum_vulnerable=False), "R-10"),
    (dict(algorithm="HMAC", primitive="mac", operation="mac_generation", quantum_vulnerable=False), "R-11")])
def test_aes_hash_mac_never_mapped_to_pqc(kw, rule):
    p = plan(**kw)
    assert p["rule_id"] == rule and p["no_pqc_mapping"] is True and p["standard"] is None
    assert not any(x in p["direction"] for x in ("ML-KEM", "ML-DSA", "SLH-DSA"))
    assert p["human_review"] is False


def test_sha1_is_classical_hygiene_not_quantum():
    p = plan(algorithm="SHA-1", primitive="hash", operation="hashing", quantum_vulnerable=False)
    assert "classical" in p["why"].lower() and "SHA-256" in p["steps"][0]


def test_protocol_and_pqc_and_comment_findings():
    t = plan(algorithm="TLS", primitive="protocol", operation="config", rule_id="CFG-NGINX-TLS-001", quantum_vulnerable=False)
    assert t["no_pqc_mapping"] and "classical hygiene" in t["direction"]
    pq = plan(algorithm="ML-KEM", primitive="pqc-kem", operation="key_generation", already_pqc=True, quantum_vulnerable=False)
    assert pq["direction"] == "No migration needed" and pq["human_review"] is False
    c = F(); c["metadata"] = {**c["metadata"], "comment_only": True}
    assert plan_for(c, None) is None


def test_every_plan_has_agility_and_honesty_notes_and_no_certification_claims():
    p = plan()
    assert len(p["crypto_agility"]) == 6 and any("not certifications" in h for h in p["honesty"])
    blob = str(p).lower()
    assert "100% quantum safe" not in blob and "unbreakable" not in blob and "currently broken" not in blob


def test_planner_endpoint_on_real_demo_data(client):
    sid = client.post("/api/demo/acme").json()["scan"]["id"]
    d = client.get(f"/api/scans/{sid}/migration").json()
    rows = {(r["file"], r["algorithm"], r["operation"]): r for r in d["rows"]}
    ecdh = rows[("src/payments/keys.py", "ECDH", "key_generation")]
    assert (ecdh["rule_id"], ecdh["standard"], ecdh["service"], ecdh["human_review"]) == ("R-03", "ML-KEM (FIPS 203)", "payment-api", True)
    assert rows[("src/auth.py", "ECDSA", "signature")]["rule_id"] == "R-05"
    assert rows[("src/payments/settle.py", "AES", "encryption")]["no_pqc_mapping"] is True
    assert rows[("src/legacy/old_hash.py", "SHA-1", "hashing")]["rule_id"] == "R-09"
    assert rows[("src/auth.py", "RSA", "key_generation")]["rule_id"] in ("R-04", "R-12")
    assert all("ML-KEM" not in r["direction"] for r in d["rows"] if r["algorithm"] in ("AES", "SHA-1", "SHA-256", "HMAC"))
    assert [r["rank"] for r in d["rows"]] == sorted(r["rank"] for r in d["rows"])
    det = client.get(f"/api/scans/{sid}/findings/{ecdh['id']}").json()
    assert det["migration"]["rule_id"] == "R-03" and det["migration"]["steps"]
