import json
from pathlib import Path

import pytest

from qmc_scanner import scan_tree


def write_tree(root: Path, files: dict[str, str | bytes]) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return root


@pytest.fixture
def scan(tmp_path):
    counter = iter(range(10_000))

    def _scan(files: dict[str, str | bytes], **kw):
        root = write_tree(tmp_path / f"t{next(counter)}", files)
        return scan_tree(root, scan_id="11111111-1111-4111-8111-111111111111", **kw)
    return _scan


def sig(f: dict) -> tuple:
    """(rule_id, algorithm, operation, key_size) for executable (non-comment) findings."""
    return (f["rule_id"], f["algorithm"], f["operation"], f["metadata"]["key_size"])


def code_findings(res) -> list[dict]:
    return [f for f in res.findings if not f["metadata"]["comment_only"]]


# ---- certificate builder (tests generate throwaway keys; nothing is shipped) ----
def make_cert(kind="rsa", *, self_signed=True, sign_hash="sha256", not_before=(2020, 3, 1), not_after=(2021, 3, 1),
              cn="api.acme-payments.example", bits=2048) -> str:
    import datetime as dt
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    key = {"rsa": lambda: rsa.generate_private_key(65537, bits), "ec": lambda: ec.generate_private_key(ec.SECP256R1()),
           "ed25519": lambda: ed25519.Ed25519PrivateKey.generate()}[kind]()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = subject if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example Test CA")])
    alg = None if kind == "ed25519" else hashes.SHA256()   # the library refuses SHA-1 signing (good); see patch below
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
            .serial_number(1234).not_valid_before(dt.datetime(*not_before)).not_valid_after(dt.datetime(*not_after))
            .sign(key, alg))
    if sign_hash == "sha1":
        # Test-only: relabel sha256WithRSAEncryption (…01010B) as sha1WithRSAEncryption (…010105) in the DER. The signature
        # is then invalid, which is irrelevant: the scanner only PARSES certificates, it never verifies them.
        der = cert.public_bytes(serialization.Encoding.DER)
        oid256, oid1 = bytes.fromhex("2A864886F70D01010B"), bytes.fromhex("2A864886F70D010105")
        assert der.count(oid256) == 2
        return serialization.Encoding.PEM and _pem(x509.load_der_x509_certificate(der.replace(oid256, oid1)))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _pem(cert) -> str:
    from cryptography.hazmat.primitives import serialization
    return cert.public_bytes(serialization.Encoding.PEM).decode()
