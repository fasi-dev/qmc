"""Deterministic `context` inference (05 section 4): from algorithm/operation, then enclosing
function/class names and path components. Falls back to 'unknown'. No AI, no dataflow.

Matching is done on whole identifier *tokens* (paths and scope names are split on separators and
camelCase boundaries), not on raw substrings. Substring matching produced wrong contexts such as
`processor.py` -> authentication (it contains "sso") or `author_list()` -> authentication ("auth"),
and context feeds the RSA role and therefore the QMP score.
"""
from __future__ import annotations

import re

_SPLIT = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")

# Per context: exact tokens, and token prefixes (stems). Checked in this order; first hit wins.
_EXACT: dict[str, frozenset[str]] = {
    "tls-termination": frozenset({"tls", "ssl", "https", "mtls"}),
    "code-signing": frozenset({"firmware", "artifact", "artifacts"}),
    "authentication": frozenset({"auth", "authn", "login", "logon", "signin", "jwt", "jwts", "jws", "token", "tokens",
                                 "session", "sessions", "credential", "credentials", "oauth", "oidc", "sso", "saml"}),
    "integrity": frozenset({"webhook", "webhooks", "checksum", "checksums", "digest", "digests", "integrity",
                            "fingerprint", "fingerprints"}),
    "data-protection": frozenset({"vault", "storage", "ledger", "ledgers"}),
}
_PREFIX: dict[str, tuple[str, ...]] = {
    "code-signing": ("codesign",),
    "authentication": ("authent",),            # authenticate, authentication, authenticator
    "data-protection": ("encrypt", "decrypt", "settle"),   # settle, settlement(s), settling
}
_SIGN_TARGETS = frozenset({"release", "releases", "artifact", "artifacts", "package", "packages", "firmware"})
_ORDER = ("tls-termination", "code-signing", "authentication", "integrity", "data-protection")


def tokens(path: str, scope: tuple[str, ...]) -> list[str]:
    """Identifier tokens of the path components and enclosing scopes, lower-cased, in order."""
    out: list[str] = []
    for part in [*path.split("/"), *scope]:
        out += [t.lower() for t in _SPLIT.findall(part)]
    return out


def _pair_context(toks: list[str]) -> str | None:
    for a, b in zip(toks, toks[1:]):
        if a == "code" and b.startswith("sign"):
            return "code-signing"
        if a.startswith("sign") and b in _SIGN_TARGETS:
            return "code-signing"
    return None


def _keyword_context(toks: list[str]) -> str | None:
    pair = _pair_context(toks)
    has_at_rest = any(a == "at" and b == "rest" for a, b in zip(toks, toks[1:])) or "atrest" in toks
    for ctx in _ORDER:
        if ctx == "code-signing" and pair:
            return pair
        if ctx == "data-protection" and has_at_rest:
            return ctx
        exact, prefixes = _EXACT.get(ctx, frozenset()), _PREFIX.get(ctx, ())
        if any(t in exact or t.startswith(prefixes) for t in toks):
            return ctx
    return None


def infer_context(path: str, scope: tuple[str, ...], algorithm: str, primitive: str, operation: str) -> str:
    if primitive == "pqc-kem" or operation in ("key_agreement", "encapsulation", "decapsulation") \
            or algorithm in ("ECDH", "DH", "DH/ECDH"):
        return "key-establishment"
    if primitive == "protocol":
        return "tls-termination"
    ctx = _keyword_context(tokens(path, scope))
    if ctx:
        return ctx
    if primitive in ("hash", "mac"):
        return "integrity"
    if primitive == "symmetric":
        return "data-protection"
    if primitive == "public-key" and operation in ("encryption", "decryption"):
        return "key-establishment"   # RSA encryption/key transport (02 section 9)
    return "unknown"
