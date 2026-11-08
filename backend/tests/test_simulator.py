"""Migration Impact Simulator on REAL scanner output (pure; no FastAPI)."""
import json

import pytest

from app.graph import NodeNotFound, NotSelectable
from app.simulator import TARGETS, TRACKS, InvalidTarget, simulate
from tests.pipeline import ACME, run, tree

PYC = "cryptography.hazmat.primitives"


@pytest.fixture(scope="module")
def acme():
    recs, g, *_ = run(ACME, "acme-payments")
    return g, recs


def track(sim, tid):
    return next(t for t in sim["tracks"] if t["id"] == tid)


def test_ecdh_to_hybrid_mlkem(acme):
    g, recs = acme
    s = simulate(g, recs, "algorithm:ECDH")
    (t,) = s["tracks"]
    assert t["id"] == "kem" and t["target"]["id"] == "X25519MLKEM768"                  # default: hybrid during transition
    assert [o["id"] for o in t["target_options"]] == TRACKS["kem"]["targets"]
    assert set(t["affected"]["direct_files"]) == {"deploy/nginx/tls.conf", "src/java/TokenSigner.java", "src/payments/keys.py"}
    assert t["affected"]["indirect_files"] == []
    ops = {c["operation"] for c in t["integration_changes"]}
    assert "key_agreement" in ops and all(c["call_sites"] for c in t["integration_changes"])
    assert any("KEM ciphertext" in c["change"] for c in t["integration_changes"])
    assert [r["rule_id"] for r in t["rules"]] == ["R-03"]
    assert any("X25519MLKEM768" in c for c in t["compatibility"])                      # TLS context caveat from nginx evidence


def test_ecdsa_to_mldsa_with_transitive_dependents(acme):
    g, recs = acme
    t = track(simulate(g, recs, "algorithm:ECDSA"), "sig")
    assert t["target"]["id"] == "ML-DSA-65" and t["target"]["sizes"] == {"public key": 1952, "signature": 3309}
    ind = {x["file"]: x for x in t["affected"]["indirect_files"]}
    assert ind["src/api/app.py"]["depth"] == 2 and ind["src/api/app.py"]["confidence"] == "confirmed"
    assert t["current"]["sizes"]["ECDSA"]["signature (P-256, raw r||s)"] == "64"
    assert any("verifiers" in c.lower() for c in t["compatibility"])


def test_target_override_and_validation(acme):
    g, recs = acme
    assert track(simulate(g, recs, "algorithm:ECDSA", "SLH-DSA-SHA2-128s"), "sig")["target"]["sizes"]["signature"] == 7856
    for bad in ("ML-KEM-768", "RSA-4096", "", "x" * 50):
        with pytest.raises(InvalidTarget):
            simulate(g, recs, "algorithm:ECDSA", bad)
    with pytest.raises(NodeNotFound):
        simulate(g, recs, "algorithm:NOPE")
    with pytest.raises(NotSelectable):
        simulate(g, recs, "service:payment-api")


def test_library_selection_splits_into_tracks_with_their_own_impact(acme):
    g, recs = acme
    s = simulate(g, recs, "library:cryptography")
    ids = [t["id"] for t in s["tracks"]]
    assert ids == ["kem", "sig", "unclear"]                                            # fixed track order
    assert track(s, "kem")["affected"]["indirect_files"] == []                         # keys.py has no importers
    assert {x["file"] for x in track(s, "sig")["affected"]["indirect_files"]} == {"src/api/routes.py", "src/api/app.py"}
    unclear = track(s, "unclear")
    assert unclear["target"] is None and "undetermined" in unclear["limitations"][0]
    assert {x["algorithm"] for x in s["no_migration_needed"]} == {"SHA-256", "AES"}   # never invented as migrations


def test_architecture_views_are_evidence_only(acme):
    g, recs = acme
    t = track(simulate(g, recs, "algorithm:ECDSA"), "sig")
    cur, prop = t["architecture"]["current"], t["architecture"]["proposed"]
    ids = {n["id"] for n in cur["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in cur["edges"])
    proposed = [n for n in prop["nodes"] if n.get("proposed")]
    assert [n["label"] for n in proposed] == ["ML-DSA-65 (proposed)"]
    assert all(e["confidence"] == "inferred" for e in prop["edges"] if e["target"] == proposed[0]["id"])
    assert {e["id"] for e in cur["edges"] if e["type"] == "IMPORTS"} == {e["id"] for e in prop["edges"] if e["type"] == "IMPORTS"}


def test_classical_tracks(tmp_path):
    recs, g, *_ = run(tree(tmp_path, {
        "a.py": "import hashlib\nhashlib.md5(b'x')\nfrom Crypto.Cipher import DES3\nc = DES3.new(k, DES3.MODE_CBC, iv)\n"
                f"from {PYC}.ciphers import algorithms\nx = algorithms.AES128(k)\n"}))
    s = simulate(g, recs, "file:a.py")
    assert [t["id"] for t in s["tracks"]] == ["hash", "legacy", "aes128"]
    assert track(s, "legacy")["target"]["id"] == "AES-256-GCM" and track(s, "hash")["target"]["id"] == "SHA-256"
    assert all(not any(k in json.dumps(t["target"]) for k in ("ML-KEM", "ML-DSA")) for t in s["tracks"])


def test_rsa_encryption_becomes_kem_dataflow(tmp_path):
    recs, g, *_ = run(tree(tmp_path, {"svc/keys.py": f"from {PYC}.asymmetric import padding\n"
                                                    "ct = pub.encrypt(m, padding.OAEP(mgf=None, algorithm=None, label=None))\n"}))
    t = track(simulate(g, recs, "algorithm:RSA"), "kem")
    (c,) = [c for c in t["integration_changes"] if c["operation"] == "encryption"]
    assert "KEM encapsulate -> KDF -> AEAD" in c["change"] and c["call_sites"][0]["line"] == 2


def test_already_pqc_and_unknown_library_versions(tmp_path):
    recs, g, *_ = run(tree(tmp_path, {"k.py": "import oqs\nk = oqs.KeyEncapsulation('ML-KEM-768')\n"}))
    s = simulate(g, recs, "file:k.py")
    assert s["tracks"] == [] and s["no_migration_needed"][0]["reason"] == "already post-quantum"


def test_statement_and_no_estimates(acme):
    g, recs = acme
    s = simulate(g, recs, "library:cryptography")
    assert "does not change code" in s["statement"] and "does not confirm compatibility" in s["statement"]
    blob = json.dumps(s).lower()
    for banned in ("hours", "days", "percent", "% ", "effort estimate", "guaranteed", "fully compatible"):
        assert banned not in blob, banned
    assert all(t["id"] in TARGETS for t in [{"id": x["target"]["id"]} for x in s["tracks"] if x["target"]])


def test_deterministic(acme):
    g, recs = acme
    assert json.dumps(simulate(g, recs, "library:cryptography")) == json.dumps(simulate(g, recs, "library:cryptography"))
