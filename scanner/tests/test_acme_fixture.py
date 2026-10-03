"""09_SAMPLE_REPOSITORY_SPEC.md section 4: can the scanner represent the seeded Acme Payments findings?

Rows 6 (nginx TLS) and 11 (expired cert) need config/cert rules, which are NOT part of this scanner step
(README build order step 4). They are asserted as 'deferred' so the gap is explicit, not silent.
"""
import json
from pathlib import Path

import pytest

from qmc_scanner import scan_tree

FIXTURE = Path(__file__).parents[2] / "sample-repos" / "acme-payments"
SERVICES = [{"service": "payment-api", "root": ""}]


@pytest.fixture(scope="module")
def res():
    return scan_tree(FIXTURE, scan_id="22222222-2222-4222-8222-222222222222", services=SERVICES, repo_name="acme-payments")


def pick(res, file, algorithm, operation=None, comment_only=False):
    out = [f for f in res.findings if f["file"] == file and f["algorithm"] == algorithm
           and (operation is None or f["operation"] == operation) and f["metadata"]["comment_only"] == comment_only]
    assert out, f"no finding {file} {algorithm} {operation}"
    return out[0]


def test_scan_complete_and_fast(res):
    assert res.status == "complete" and res.files_skipped == [] and res.files_scanned == {"doc": 2, "java": 1, "pem": 1, "python": 6, "text": 1, "yaml": 4}


def test_row1_ecdh_key_establishment(res):
    f = pick(res, "src/payments/keys.py", "ECDH")
    assert (f["confidence_level"], f["context"], f["quantum_vulnerable"], f["service"]) == ("high", "key-establishment", True, "payment-api")
    assert "X25519PrivateKey.generate()" in f["evidence"] and f["line_start"] == 6


def test_row2_rsa_2048_keygen_in_auth(res):
    f = pick(res, "src/auth.py", "RSA", "key_generation")
    assert (f["confidence_level"], f["metadata"]["key_size"], f["context"], f["quantum_vulnerable"]) == ("high", 2048, "authentication", True)


def test_row3_ecdsa_p256_jwt_signing(res):
    f = pick(res, "src/auth.py", "ECDSA", "signature")
    assert (f["confidence_level"], f["context"], f["quantum_vulnerable"]) == ("high", "authentication", True)
    assert f["evidence"] == "ec.ECDSA(hashes.SHA256())"
    k = pick(res, "src/auth.py", "ECDSA", "key_generation")        # EC keygen resolved from same-file ECDSA use
    assert k["confidence_level"] == "medium" and "ec.generate_private_key(ec.SECP256R1())" in k["evidence"]


def test_rows4_5_java_ecdsa_and_ecdh(res):
    s = pick(res, "src/java/TokenSigner.java", "ECDSA", "signature")
    k = pick(res, "src/java/TokenSigner.java", "ECDH", "key_agreement")
    assert s["evidence"] == 'Signature.getInstance("SHA256withECDSA")' and k["evidence"] == 'KeyAgreement.getInstance("ECDH")'
    assert (s["confidence_level"], k["confidence_level"]) == ("high", "high") and s["context"] == "authentication"


def test_java_string_literal_trap_not_a_finding(res):
    """TokenSigner.java logs a string containing KeyAgreement.getInstance("DH"): must NOT become a DH finding."""
    assert not [f for f in res.findings if f["algorithm"] == "DH"]


def test_row7_sha1_is_high_by_05_rule_but_not_quantum_vulnerable(res):
    f = pick(res, "src/legacy/old_hash.py", "SHA-1", "hashing")
    assert f["confidence_level"] == "high" and f["quantum_vulnerable"] is False   # 09 says Medium: see DECISIONS #22


def test_rows8_9_aes_and_hmac_informational_not_vulnerable(res):
    aes = pick(res, "src/payments/settle.py", "AES", "key_generation")
    assert aes["metadata"]["key_size"] == 256 and aes["quantum_vulnerable"] is False and aes["context"] == "data-protection"
    assert pick(res, "src/payments/settle.py", "AES", "encryption")["quantum_vulnerable"] is False
    h = pick(res, "src/payments/settle.py", "HMAC")
    assert (h["confidence_level"], h["quantum_vulnerable"], h["primitive"]) == ("high", False, "mac")


def test_row10_dev_script_rsa_flagged_test_path(res):
    f = pick(res, "scripts/gen_test_keys.py", "RSA", "key_generation")
    assert f["metadata"]["test_path"] is True and f["confidence_level"] == "high" and f["quantum_vulnerable"] is True


def test_row12_ml_kem_is_already_pqc_and_excluded_from_vulnerable(res):
    f = pick(res, "pqc-lab/kem_demo.py", "ML-KEM")
    assert (f["already_pqc"], f["quantum_vulnerable"], f["primitive"], f["confidence_level"]) == (True, False, "pqc-kem", "high")
    assert 'oqs.KeyEncapsulation("ML-KEM-768")' in f["evidence"]


def test_readme_comment_trap_is_low(res):
    f = pick(res, "README.md", "RSA", comment_only=True)
    assert (f["confidence_level"], f["quantum_vulnerable"], f["line_start"]) == ("low", False, 5)


def test_quantum_vulnerable_set_is_exactly_the_code_rows(res):
    vuln = sorted((f["file"], f["algorithm"], f["operation"]) for f in res.findings if f["quantum_vulnerable"])
    assert vuln == sorted([
        ("scripts/gen_test_keys.py", "RSA", "key_generation"),
        ("src/auth.py", "ECDSA", "key_generation"), ("src/auth.py", "ECDSA", "signature"), ("src/auth.py", "RSA", "key_generation"),
        ("src/java/TokenSigner.java", "ECDH", "key_agreement"), ("src/java/TokenSigner.java", "ECDSA", "signature"),
        ("src/payments/keys.py", "ECDH", "key_generation"),
        ("certs/api.acme-payments.example.crt", "RSA", "verification"),
        ("deploy/nginx/tls.conf", "ECDH", "key_agreement"), ("deploy/nginx/tls.conf", "RSA", "signature")])


def test_row6_nginx_tls_deprecated_protocols_and_weak_ciphers(res):
    proto = pick(res, "deploy/nginx/tls.conf", "TLS", "config")
    assert proto["rule_id"] in {"CFG-NGINX-TLS-001", "CFG-NGINX-CIPHER-004"} and proto["confidence_level"] == "medium"
    rules = {f["rule_id"] for f in res.findings if f["file"] == "deploy/nginx/tls.conf"}
    assert {"CFG-NGINX-TLS-001", "CFG-NGINX-CIPHER-004", "CFG-NGINX-CIPHER-001", "CFG-NGINX-CIPHER-003", "CFG-NGINX-TLS-002"} <= rules
    assert not pick(res, "deploy/nginx/tls.conf", "TLS", "config")["quantum_vulnerable"]      # TLS 1.0 / weak ciphers = classical hygiene
    assert pick(res, "deploy/nginx/tls.conf", "ECDH", "key_agreement")["quantum_vulnerable"]  # ECDHE key exchange = quantum-vulnerable


def test_row11_expired_self_signed_certificate(res):
    f = pick(res, "certs/api.acme-payments.example.crt", "RSA", "verification")
    assert (f["confidence_level"], f["quantum_vulnerable"], f["metadata"]["key_size"]) == ("medium", True, 2048)
    assert "self-signed" in f["evidence"] and "; expired)" in f["evidence"] and "notAfter=2021-03-01" in f["evidence"]


def test_docker_compose_has_no_crypto_findings(res):
    assert not [f for f in res.findings if f["file"] == "deploy/docker-compose.yml"]


def test_every_finding_has_file_line_evidence(res):
    for f in res.findings:
        assert f["file"] and f["line_start"] >= 1 and f["evidence"] and f["rule_id"] and f["rule_version"]


def test_comment_in_java_is_low(res):
    f = pick(res, "src/java/TokenSigner.java", "ECDSA", comment_only=True)
    assert f["confidence_level"] == "low" and f["quantum_vulnerable"] is False


def test_golden_summary_is_stable(res):
    """Frozen (rule_id, file, line, algorithm, operation, level) list for the fixture: any rule change shows up here."""
    got = [(f["rule_id"], f["file"], f["line_start"], f["algorithm"], f["operation"], f["confidence_level"]) for f in res.findings]
    assert got == [
        ("GEN-COMMENT-001", "README.md", 5, "RSA", "unspecified", "low"),
        ("CFG-X509-001", "certs/api.acme-payments.example.crt", 1, "RSA", "verification", "medium"),
        ("CFG-NGINX-TLS-002", "deploy/nginx/tls.conf", 6, "TLS", "termination", "medium"),
        ("CFG-NGINX-TLS-001", "deploy/nginx/tls.conf", 10, "TLS", "config", "medium"),
        ("CFG-NGINX-CIPHER-001", "deploy/nginx/tls.conf", 11, "ECDH", "key_agreement", "medium"),
        ("CFG-NGINX-CIPHER-003", "deploy/nginx/tls.conf", 11, "RSA", "signature", "medium"),
        ("CFG-NGINX-CIPHER-004", "deploy/nginx/tls.conf", 11, "TLS", "config", "medium"),
        ("PY-OQS-KEM-001", "pqc-lab/kem_demo.py", 4, "ML-KEM", "key_generation", "high"),
        ("PY-CRYPTOGRAPHY-RSA-001", "scripts/gen_test_keys.py", 4, "RSA", "key_generation", "high"),
        ("GEN-COMMENT-001", "src/auth.py", 7, "RSA", "unspecified", "low"),
        ("PY-CRYPTOGRAPHY-RSA-001", "src/auth.py", 8, "RSA", "key_generation", "high"),
        ("PY-CRYPTOGRAPHY-EC-001", "src/auth.py", 13, "ECDSA", "key_generation", "medium"),
        ("PY-CRYPTOGRAPHY-ECDSA-001", "src/auth.py", 14, "ECDSA", "signature", "high"),
        ("PY-CRYPTOGRAPHY-HASH-001", "src/auth.py", 14, "SHA-256", "hashing", "high"),
        ("GEN-COMMENT-001", "src/java/TokenSigner.java", 11, "ECDSA", "unspecified", "low"),
        ("JAVA-JCA-SIG-001", "src/java/TokenSigner.java", 13, "ECDSA", "signature", "high"),
        ("JAVA-JCA-KA-001", "src/java/TokenSigner.java", 20, "ECDH", "key_agreement", "high"),
        ("PY-HASHLIB-001", "src/legacy/old_hash.py", 6, "SHA-1", "hashing", "high"),
        ("PY-CRYPTOGRAPHY-ECDH-001", "src/payments/keys.py", 6, "ECDH", "key_generation", "high"),
        ("PY-CRYPTOGRAPHY-AES-002", "src/payments/settle.py", 9, "AES", "key_generation", "high"),
        ("PY-CRYPTOGRAPHY-AES-001", "src/payments/settle.py", 13, "AES", "encryption", "high"),
        ("PY-HMAC-001", "src/payments/settle.py", 17, "HMAC", "mac_generation", "high")]
