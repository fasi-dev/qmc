"""Deterministic `context` inference (05 section 4): from algorithm/operation, then enclosing
function/class names and path components. Falls back to 'unknown'. No AI, no dataflow."""
from __future__ import annotations

import re

_KEYWORDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("tls-termination", re.compile(r"tls|ssl|https")),
    ("code-signing", re.compile(r"code[_-]?sign|sign[_-]?(?:release|artifact|package|firmware)|firmware|artifact")),
    ("authentication", re.compile(r"auth|login|logon|jwt|token|session|credential|oauth|sso")),
    ("integrity", re.compile(r"webhook|checksum|digest|integrity|fingerprint")),
    ("data-protection", re.compile(r"encrypt|decrypt|at[_-]?rest|vault|storage|settle|ledger")),
)


def infer_context(path: str, scope: tuple[str, ...], algorithm: str, primitive: str, operation: str) -> str:
    if primitive == "pqc-kem" or operation in ("key_agreement", "encapsulation", "decapsulation") \
            or algorithm in ("ECDH", "DH", "DH/ECDH"):
        return "key-establishment"
    text = " ".join([*path.lower().replace("/", " ").split(), *[s.lower() for s in scope]])
    for ctx, pat in _KEYWORDS:
        if pat.search(text):
            return ctx
    if primitive in ("hash", "mac"):
        return "integrity"
    if primitive == "symmetric":
        return "data-protection"
    if primitive == "public-key" and operation in ("encryption", "decryption"):
        return "key-establishment"   # RSA encryption/key transport (02 section 9)
    return "unknown"
