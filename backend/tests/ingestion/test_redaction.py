import time

from app.ingestion.redaction import MARKER, redact_text

PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"


def test_pem_private_key_redacted_line_count_preserved():
    src = f"a = 1\n-----BEGIN RSA PRIVATE KEY-----\n{PEM_BODY}\n{PEM_BODY}\n-----END RSA PRIVATE KEY-----\nb = 2\n"
    out, reds = redact_text(src, "k.pem")
    assert PEM_BODY not in out
    assert out.count("\n") == src.count("\n")                 # line numbers stay valid
    assert "-----BEGIN RSA PRIVATE KEY-----" in out            # header kept (key type is useful evidence)
    assert "a = 1" in out and "b = 2" in out
    assert [(r.line_start, r.line_end, r.kind) for r in reds] == [(2, 5, "pem_private_key")]


def test_pem_in_single_line_string_literal():
    src = f'KEY = "-----BEGIN PRIVATE KEY-----\\n{PEM_BODY}\\n-----END PRIVATE KEY-----"\n'
    out, reds = redact_text(src, "x.py")
    assert PEM_BODY not in out and MARKER in out and reds[0].kind == "pem_private_key"


def test_pem_body_on_header_line_and_end_line():
    src = f'k = ("-----BEGIN PRIVATE KEY-----{PEM_BODY}"\n"{PEM_BODY}-----END PRIVATE KEY-----")\n'
    out, _ = redact_text(src, "x.py")
    assert PEM_BODY not in out


def test_unterminated_key_redacted_to_eof():
    src = f"-----BEGIN EC PRIVATE KEY-----\n{PEM_BODY}\nmore\n"
    out, reds = redact_text(src, "x")
    assert PEM_BODY not in out and "more" not in out
    assert reds[0].line_end == 4 or reds[0].line_end == 3


def test_public_cert_not_redacted():
    src = f"-----BEGIN CERTIFICATE-----\n{PEM_BODY}\n-----END CERTIFICATE-----\n"
    out, reds = redact_text(src, "c.crt")
    assert out == src and reds == []


def test_jwt_and_cloud_keys_redacted():
    jwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc_DEF-123"
    src = (f'tok = "{jwt}"\naws = "AKIAABCDEFGHIJKLMNOP"\n'
           f'gh = "ghp_{"a" * 36}"\nstripe = "sk_test_{"b" * 24}"\n')
    out, reds = redact_text(src, "x.py")
    assert jwt not in out and "AKIAABCDEFGHIJKLMNOP" not in out and "ghp_" not in out and "sk_test_" not in out
    assert {r.kind for r in reds} >= {"jwt", "aws_access_key_id", "github_token", "stripe_key"}
    assert out.count("\n") == src.count("\n")


def test_credential_assignment_quoted_and_yaml():
    out, _ = redact_text('password = "hunter2hunter2"\napi_key: "abcd1234efgh"\n', "x.py")
    assert "hunter2" not in out and "abcd1234" not in out
    out, _ = redact_text("db_password: s3cretValue99\ntoken: ${TOKEN}\n", "app.yaml")
    assert "s3cretValue99" not in out and "${TOKEN}" in out   # placeholders untouched


def test_unquoted_yaml_rule_not_applied_to_python():
    src = "def f(secret: SomeLongTypeName): ...\n"
    out, reds = redact_text(src, "x.py")
    assert out == src and reds == []


def test_crypto_evidence_is_not_mangled():
    src = ("key = ec.generate_private_key(ec.SECP256R1())\n"
           'algorithm: "ES256"\nssl_protocols TLSv1 TLSv1.1;\n# TODO: consider RSA\n')
    out, reds = redact_text(src, "x.yaml")
    assert out == src and reds == []


def test_pathological_many_begin_lines_is_fast():
    src = "-----BEGIN PRIVATE KEY-----\n" * 150_000
    t = time.time()
    out, _ = redact_text(src, "x")
    assert time.time() - t < 5
    assert out.count("\n") == src.count("\n")


def test_pathological_single_long_line_is_fast():
    src = "-----BEGIN PRIVATE KEY----- " * 100_000 + "\n"
    t = time.time()
    redact_text(src, "x")
    assert time.time() - t < 5
