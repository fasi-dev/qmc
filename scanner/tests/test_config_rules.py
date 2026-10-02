"""Phase 3.5: YAML/JSON, nginx/SSH/Docker/CI line directives, X.509 PEM. Positive cases live in corpus.CFG."""
import json
import time
from datetime import datetime, timezone

import pytest

from qmc_scanner import scan_tree, validate_finding
from tests.conftest import code_findings, make_cert, write_tree

AS_OF = datetime(2026, 10, 2, tzinfo=timezone.utc)

NEG = {
    # --- nginx / TLS
    "nginx_modern_protocols": ("a.conf", "ssl_protocols TLSv1.2 TLSv1.3;\n"),
    "nginx_disabled_ciphers_are_not_enabled": ("a.conf", "ssl_ciphers HIGH:!aNULL:!MD5:!RC4:!3DES:!EXPORT;\n"),
    "nginx_negated_ecdhe_not_enabled": ("a.conf", "ssl_ciphers !ECDHE-RSA-AES128-GCM-SHA256:HIGH;\n"),
    "nginx_tls13_suites_name_no_kx": ("a.conf", "ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256';\n"),
    "nginx_commented_out": ("a.conf", "# ssl_protocols TLSv1 TLSv1.1;\n#ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\n"),
    "nginx_key_directive_is_not_termination": ("a.conf", "ssl_certificate_key /etc/x.key;\n"),
    "nginx_directive_in_non_conf_file": ("notes.txt", "ssl_protocols TLSv1 TLSv1.1;\nssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\n"),
    "nginx_unrelated_directives": ("a.conf", "proxy_pass http://payment-api:8080;\nlisten 443 ssl;\nssl_prefer_server_ciphers on;\n"),
    # --- ssh
    "ssh_commented_default": ("sshd_config", "#KexAlgorithms curve25519-sha256\n#HostKeyAlgorithms ssh-rsa\n"),
    "ssh_removal_prefix_means_disabled": ("sshd_config", "KexAlgorithms -diffie-hellman-group1-sha1,-ecdh-sha2-nistp256\n"),
    "ssh_directive_in_other_file": ("config.txt", "KexAlgorithms curve25519-sha256\n"),
    # --- yaml / json
    "yaml_non_algorithms": ("c.yaml", "algorithm: none\nhash_algorithm: sha512crypt\npassword_algorithm: bcrypt\njwt_algorithm: \"{{ jwt_alg }}\"\n"),
    "yaml_app_version_is_not_tls": ("c.yaml", "version: 1.0\napi_version: \"1.1\"\nmin_version: 1.0\nprotocols: [grpc, http]\n"),
    "yaml_modern_tls": ("c.yaml", "tls_min_version: \"1.2\"\nssl_protocols: [TLSv1.2, TLSv1.3]\n"),
    "yaml_algorithm_names_in_non_alg_keys": ("c.yaml", "description: uses RSA and ES256\nname: ECDSA\n"),
    "yaml_commented": ("c.yaml", "# algorithm: ES256\n# tls_min_version: TLSv1\n"),
    "json_non_algorithm_keys": ("c.json", '{"description": "RS256", "version": "1.0"}\n'),
    "service_yaml_metadata": ("service.yaml", "service: payment-api\nowner: t\ndata_classification: highly-sensitive\nbusiness_criticality: critical\ninternet_exposed: true\ndata_lifetime_years: 10\n"),
    # --- docker / CI
    "docker_unrelated": ("Dockerfile", "FROM python:3.12\nCOPY src/ /app/\nCOPY --from=builder /app/dist /app\nRUN echo server.crt\n"),
    "docker_commented": ("Dockerfile", "# COPY a.crt /etc/ssl/\n# FROM nginx\n"),
    "docker_image_name_only_contains_nginx": ("Dockerfile", "FROM mynginxfork:1\n"),
    "ci_same_text_in_non_ci_yaml": ("docs/example.yml", "steps:\n  - run: cp certs/ca.crt /usr/local/share/ca-certificates/\n"),
    "ci_copy_non_cert": (".github/workflows/ci.yml", "jobs:\n  b:\n    steps:\n      - run: cp README.md docs/\n"),
}


@pytest.mark.parametrize("name", list(NEG))
def test_config_false_positive_defenses(scan, name):
    fname, src = NEG[name]
    res = scan({fname: src})
    assert code_findings(res) == [], [(f["rule_id"], f["evidence"]) for f in code_findings(res)]
    assert all(f["confidence_level"] == "low" for f in res.findings)


def test_ssh_plus_prefix_still_enables_algorithm(scan):
    f = code_findings(scan({"sshd_config": "KexAlgorithms +ecdh-sha2-nistp256\n"}))
    assert [(x["algorithm"], x["rule_id"]) for x in f] == [("ECDH", "CFG-SSH-001")]


def test_ssh_config_d_dropin_applies(scan):
    f = code_findings(scan({"etc/ssh/sshd_config.d/10-crypto.conf": "HostKeyAlgorithms ssh-rsa\n"}))
    assert [x["algorithm"] for x in f] == ["RSA"]


# ---------------------------------------------------------------- classification / confidence / quantum distinction
def test_config_confidence_levels_follow_spec(scan):
    res = scan({"a.conf": "ssl_protocols TLSv1;\nssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\nssl_certificate /x.crt;\n",
                "c.yaml": "algorithm: ES256\n", "Dockerfile": "FROM nginx\n"})
    by_rule = {f["rule_id"]: (f["confidence"], f["confidence_level"]) for f in res.findings}
    assert by_rule["CFG-NGINX-TLS-001"] == (0.85, "medium")          # config directive => Medium (05 section 5)
    assert by_rule["CFG-NGINX-CIPHER-001"] == (0.75, "medium")
    assert by_rule["CFG-STRUCT-ALG-001"] == (0.80, "medium")          # 05 example: algorithm: "ES256" in YAML => Medium
    assert by_rule["CFG-DOCKER-002"] == (0.55, "medium")              # image only hints at TLS
    assert all(f["confidence_level"] != "high" for f in res.findings)


def test_classical_hygiene_vs_quantum_vulnerable_distinction(scan):
    res = scan({"a.conf": "ssl_protocols TLSv1 TLSv1.1;\nssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA;\nssl_certificate /x.crt;\n",
                "certs/a.crt": make_cert(), "certs/b.crt": make_cert(sign_hash="sha1")}, as_of=AS_OF)
    vuln = {(f["rule_id"], f["algorithm"]): f["quantum_vulnerable"] for f in res.findings}
    # deprecated protocol, weak cipher, termination, SHA-1 signature: classical hygiene => NOT quantum-vulnerable
    assert vuln[("CFG-NGINX-TLS-001", "TLS")] is False and vuln[("CFG-NGINX-CIPHER-004", "TLS")] is False
    assert vuln[("CFG-NGINX-TLS-002", "TLS")] is False and vuln[("CFG-X509-002", "SHA-1")] is False
    # key exchange / authentication algorithms and certificate public keys: quantum-vulnerable public-key crypto
    assert vuln[("CFG-NGINX-CIPHER-001", "ECDH")] is True and vuln[("CFG-NGINX-CIPHER-003", "RSA")] is True and vuln[("CFG-X509-001", "RSA")] is True
    assert all(f["primitive"] == "protocol" and f["already_pqc"] is False for f in res.findings if f["algorithm"] == "TLS")


def test_pqc_algorithm_string_in_config_is_already_pqc(scan):
    f = code_findings(scan({"c.yaml": "kem_algorithm: ML-KEM-768\n"}))[0]
    assert (f["already_pqc"], f["quantum_vulnerable"], f["primitive"]) == (True, False, "pqc-kem")


def test_context_inferred_from_yaml_key_path(scan):
    f = code_findings(scan({"config/app.yaml": "auth:\n  jwt:\n    algorithm: ES256\n"}))[0]
    assert f["context"] == "authentication" and f["line_start"] == 3 and f["evidence"] == "algorithm: ES256"


def test_json_evidence_line_and_tab_indentation(scan):
    src = '{\n\t"auth": {\n\t\t"algorithm": "RS256"\n\t}\n}\n'
    f = code_findings(scan({"c.json": src}))[0]
    assert (f["algorithm"], f["line_start"], f["evidence"]) == ("RSA", 3, '"algorithm": "RS256"')


def test_minified_json_uses_key_value_evidence(scan):
    big = json.dumps({"pad": "x" * 400, "auth": {"algorithm": "ES256"}})
    f = code_findings(scan({"c.json": big}))[0]
    assert f["evidence"] == "algorithm: ES256" and len(f["evidence"]) <= 300


def test_yaml_multi_document_and_sequences(scan):
    src = "---\nalgorithms:\n  - ES256\n  - RS256\n---\ntls_min_version: TLSv1\n"
    f = code_findings(scan({"c.yaml": src}))
    assert sorted((x["rule_id"], x["algorithm"], x["line_start"]) for x in f) == [
        ("CFG-STRUCT-ALG-001", "ECDSA", 3), ("CFG-STRUCT-ALG-001", "RSA", 4), ("CFG-STRUCT-TLS-001", "TLS", 6)]


# ---------------------------------------------------------------- YAML/JSON robustness
def test_yaml_alias_bomb_is_bounded(scan):
    lines = ['a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]']
    prev = "a"
    for n in "bcdefghijk":
        lines.append(f"{n}: &{n} [" + ",".join([f"*{prev}"] * 9) + "]")
        prev = n
    t = time.time()
    res = scan({"bomb.yaml": "\n".join(lines) + "\nalgorithm: ES256\n"})
    assert time.time() - t < 5 and res.status == "complete"
    assert [f["algorithm"] for f in code_findings(res)] == ["ECDSA"]


def test_python_object_yaml_tag_is_never_constructed(tmp_path):
    marker = tmp_path / "PWNED"
    root = write_tree(tmp_path / "t", {"evil.yaml": f"x: !!python/object/apply:os.system ['touch {marker}']\nalgorithm: ES256\n"})
    res = scan_tree(root)
    assert not marker.exists() and [f["algorithm"] for f in code_findings(res)] == ["ECDSA"]


def test_invalid_yaml_and_json_reported_not_crashing(scan):
    res = scan({"bad.yaml": "a: [unclosed\n", "bad.json": '{"algorithm": "ES256",}\n', "ok.yaml": "algorithm: ES256\n"})
    assert {(s["file"], s["reason"]) for s in res.files_skipped} == {("bad.yaml", "parse_error"), ("bad.json", "parse_error")}
    assert [f["file"] for f in code_findings(res)] == ["ok.yaml"]


def test_oversized_structured_file_skipped(scan):
    res = scan({"huge.yaml": "algorithm: ES256\n" + "# pad\n" * 200_000})
    assert res.files_skipped == [{"file": "huge.yaml", "reason": "too_large"}] and res.findings == []


def test_deeply_nested_yaml_is_bounded(scan):
    t = time.time()
    res = scan({"deep.yaml": "".join("  " * i + f"k{i}:\n" for i in range(300)) + "  " * 300 + "algorithm: ES256\n"})
    assert time.time() - t < 5 and res.status == "complete"


# ---------------------------------------------------------------- directives: robustness
@pytest.mark.parametrize("name,fname,src", [
    ("long config line", "a.conf", "ssl_ciphers " + "ECDHE-RSA-AES128-GCM-SHA256:" * 600 + ";\n"),
    ("many directives", "a.conf", "ssl_protocols TLSv1;\n" * 50000),
    ("dockerfile flood", "Dockerfile", "COPY " + "a.crt " * 50000 + "/x\n"),
    ("ssh flood", "sshd_config", "KexAlgorithms " + ",".join(["ecdh-sha2-nistp256"] * 30000) + "\n"),
])
def test_directive_inputs_finish_quickly(scan, name, fname, src):
    t = time.time()
    res = scan({fname: src})
    assert time.time() - t < 10 and res.status == "complete"


def test_very_long_lines_are_ignored_not_scanned(scan):
    res = scan({"a.conf": "ssl_protocols TLSv1;" + " " * 20000 + "\n"})
    assert res.findings == []


def test_comment_mention_in_config_is_low(scan):
    res = scan({"a.conf": "# TODO: drop RSA ciphers\nssl_protocols TLSv1.2;\n", "c.yaml": "# migrate away from ECDSA\nk: v\n"})
    assert sorted((f["file"], f["algorithm"], f["confidence_level"]) for f in res.findings) == [("a.conf", "RSA", "low"), ("c.yaml", "ECDSA", "low")]
    assert all(f["metadata"]["comment_only"] and not f["quantum_vulnerable"] for f in res.findings)


def test_evidence_guard_redacts_secrets_in_config_lines(scan):
    tok = "ghp_" + "a" * 36
    f = code_findings(scan({"c.yaml": f"signing_algorithm: ES256  # {tok}\nauth:\n  algorithm: ES256\n"}))
    assert f and all(tok not in x["evidence"] for x in f)
    f2 = code_findings(scan({"c.json": json.dumps({"algorithm": "ES256", "token": "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"}) + "\n"}))
    assert f2 and "eyJhbGci" not in f2[0]["evidence"]


# ---------------------------------------------------------------- X.509 certificates
def cert_findings(res):
    return [f for f in res.findings if f["rule_id"].startswith("CFG-X509")]


def test_expired_self_signed_rsa_certificate(scan):
    res = scan({"certs/a.crt": make_cert()}, as_of=AS_OF)
    (f,) = cert_findings(res)
    assert (f["rule_id"], f["algorithm"], f["primitive"], f["operation"], f["confidence"], f["confidence_level"]) == (
        "CFG-X509-001", "RSA", "public-key", "verification", 0.75, "medium")
    assert f["quantum_vulnerable"] is True and f["metadata"]["key_size"] == 2048 and f["metadata"]["comment_only"] is False
    for part in ("self-signed", "key=RSA-2048", "signature=sha256WithRSAEncryption", "notAfter=2021-03-01", "expired",
                 "subject=CN=api.acme-payments.example", "-----BEGIN CERTIFICATE-----"):
        assert part in f["evidence"], part
    assert "not expired" not in f["evidence"] and (f["line_start"], f["line_end"]) == (1, 20)
    validate_finding(f)


def test_expiry_is_evaluated_against_explicit_as_of(scan):
    pem = make_cert()
    before = cert_findings(scan({"a.crt": pem}, as_of=datetime(2020, 6, 1, tzinfo=timezone.utc)))[0]
    after = cert_findings(scan({"a.crt": pem}, as_of=datetime(2022, 1, 1, tzinfo=timezone.utc)))[0]
    assert "not expired" in before["evidence"] and "; expired)" in after["evidence"]
    assert (before["confidence"], before["algorithm"]) == (after["confidence"], after["algorithm"])
    assert scan({"a.crt": pem}, as_of=AS_OF).as_of == "2026-10-02"
    naive = scan({"a.crt": pem}, as_of=datetime(2026, 10, 2))      # naive datetimes are treated as UTC
    assert naive.as_of == "2026-10-02"


@pytest.mark.parametrize("kind,alg,size,desc", [("ec", "ECDSA", 256, "EC-secp256r1"), ("ed25519", "EdDSA", None, "Ed25519"), ("rsa", "RSA", 3072, "RSA-3072")])
def test_certificate_public_key_algorithms(scan, kind, alg, size, desc):
    (f,) = cert_findings(scan({"a.pem": make_cert(kind, bits=3072)}, as_of=AS_OF))
    assert (f["algorithm"], f["metadata"]["key_size"], f["quantum_vulnerable"]) == (alg, size, True) and f"key={desc}" in f["evidence"]


def test_ca_signed_certificate_not_marked_self_signed(scan):
    (f,) = cert_findings(scan({"a.crt": make_cert(self_signed=False)}, as_of=AS_OF))
    assert "issuer=CN=Example Test CA" in f["evidence"] and "self-signed" not in f["evidence"]


def test_sha1_signed_certificate_adds_hash_hygiene_finding(scan):
    res = scan({"a.crt": make_cert(sign_hash="sha1")}, as_of=AS_OF)
    got = sorted((f["rule_id"], f["algorithm"], f["primitive"], f["quantum_vulnerable"]) for f in cert_findings(res))
    assert got == [("CFG-X509-001", "RSA", "public-key", True), ("CFG-X509-002", "SHA-1", "hash", False)]
    assert "signature=sha1WithRSAEncryption" in cert_findings(res)[0]["evidence"]
    assert not [f for f in cert_findings(scan({"a.crt": make_cert()}, as_of=AS_OF)) if f["rule_id"] == "CFG-X509-002"]   # sha256: no SHA-1 finding


def test_certificate_chain_gives_one_finding_per_cert(scan):
    res = scan({"chain.pem": make_cert() + make_cert("ec", self_signed=False)}, as_of=AS_OF)
    fs = cert_findings(res)
    assert [(f["algorithm"], f["line_start"]) for f in fs] == [("RSA", 1), ("ECDSA", 21)]


def test_private_key_blocks_and_non_certificates_are_ignored(scan):
    pem = "-----BEGIN PRIVATE KEY-----\n***REDACTED***\n-----END PRIVATE KEY-----\n-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"
    assert scan({"k.pem": pem}, as_of=AS_OF).findings == []


def test_garbage_certificate_block_reported_without_crash(scan):
    junk = "-----BEGIN CERTIFICATE-----\nnot base64 !!!\n-----END CERTIFICATE-----\n"
    res = scan({"a.crt": make_cert() + junk, "b.crt": junk}, as_of=AS_OF)
    assert len(cert_findings(res)) == 1
    assert {(s["file"], s["reason"]) for s in res.files_skipped} == {("a.crt", "cert_parse_error"), ("b.crt", "cert_parse_error")}
    res = scan({"c.crt": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}, as_of=AS_OF)   # valid base64, not DER
    assert res.findings == [] and res.files_skipped[0]["reason"] == "cert_parse_error"


def test_pem_in_source_files_is_not_parsed_as_certificate(scan):
    res = scan({"t.py": 'CERT = """' + make_cert() + '"""\n'}, as_of=AS_OF)
    assert cert_findings(res) == []


def test_hostile_certificate_subject_is_bounded_and_redacted(scan):
    tok = "ghp_" + "b" * 36
    (f,) = cert_findings(scan({"a.crt": make_cert(cn=("x" * 300) + tok)}, as_of=AS_OF))
    assert len(f["evidence"]) <= 300 and tok not in f["evidence"]


def test_certificate_flow_through_phase2_redaction_keeps_certificate_intact(scan):
    """Public certificates are never redacted (they are public); only private-key bodies are."""
    from qmc_scanner.redaction import redact_text
    pem = make_cert()
    assert redact_text(pem, "a.crt") == (pem, [])


# ---------------------------------------------------------------- determinism for config kinds
def test_config_scan_is_deterministic_with_fixed_as_of(tmp_path):
    files = {"a.conf": "ssl_protocols TLSv1;\nssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA;\n", "c.yaml": "algorithm: ES256\n",
             "Dockerfile": "FROM nginx\nCOPY a.crt /x\n", "certs/a.crt": make_cert(), "sshd_config": "KexAlgorithms curve25519-sha256\n",
             ".github/workflows/ci.yml": "steps:\n  - run: cp a.crt /x\n"}
    t1, t2 = write_tree(tmp_path / "one", dict(files)), write_tree(tmp_path / "two", dict(reversed(list(files.items()))))
    a = json.dumps(scan_tree(t1, scan_id="x", as_of=AS_OF).to_dict())
    b = json.dumps(scan_tree(t2, scan_id="x", as_of=AS_OF).to_dict())
    assert a == b and json.loads(a)["findings"]


def test_all_config_findings_validate_against_schema(scan):
    from tests import corpus
    for cid, fname, src, _ in corpus.CFG:
        for f in scan({fname: src}).findings:
            validate_finding(f)
            assert f["evidence"] and f["file"] == fname and f["rule_version"] == "1.0.0"
