"""Context inference regressions: whole-token matching, not substrings (context drives the RSA role and the QMP score)."""
import pytest

from qmc_scanner.context import infer_context, tokens

RSA_KEYGEN = ("RSA", "public-key", "key_generation")


@pytest.mark.parametrize("path,scope,expected", [
    # previously mis-classified by substring matching
    ("processor/compressor.py", ("handle",), "unknown"),          # 'sso' inside 'processor'/'compressor'
    ("src/author.py", ("author_list",), "unknown"),              # 'auth' inside 'author'
    ("src/tokenizer.py", (), "unknown"),                         # 'token' inside 'tokenizer'
    ("src/lesson_plan.py", (), "unknown"),                       # 'sso' inside 'lesson'
    ("src/artifactory_client.py", (), "unknown"),                # 'artifact' inside 'artifactory'
    # true positives still detected
    ("src/auth.py", (), "authentication"),
    ("src/java/TokenSigner.java", ("TokenSigner",), "authentication"),
    ("svc/jwt_utils.py", (), "authentication"),
    ("svc/x.py", ("authenticateUser",), "authentication"),
    ("svc/oauth2/client.py", (), "authentication"),
    ("deploy/nginx/tls.conf", (), "tls-termination"),
    ("build/codesign.py", (), "code-signing"),
    ("build/x.py", ("sign_release",), "code-signing"),
    ("build/x.py", ("code_signing_key",), "code-signing"),
    ("src/payments/settle.py", (), "data-protection"),
    ("src/settlement/worker.py", (), "data-protection"),
    ("src/x.py", ("encrypt_at_rest",), "data-protection"),
    ("src/x.py", ("encryptPayload",), "data-protection"),
    ("hooks/webhook_verify.py", (), "integrity"),
])
def test_context_uses_whole_tokens(path, scope, expected):
    assert infer_context(path, scope, *RSA_KEYGEN) == expected


def test_tokens_split_camel_snake_and_paths():
    assert tokens("src/JWTUtils/http_client.py", ("TokenSigner",)) == ["src", "jwt", "utils", "http", "client", "py", "token", "signer"]


def test_algorithm_and_primitive_rules_take_precedence():
    assert infer_context("src/auth.py", (), "ECDH", "public-key", "key_agreement") == "key-establishment"
    assert infer_context("src/auth.py", (), "TLS", "protocol", "config") == "tls-termination"
    assert infer_context("src/util.py", (), "SHA-256", "hash", "hashing") == "integrity"
    assert infer_context("src/util.py", (), "RSA", "public-key", "encryption") == "key-establishment"
