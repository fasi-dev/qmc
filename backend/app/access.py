"""Per-scan access tokens (no user accounts).

Each scan gets a random bearer token when it is created. The token is returned ONCE in the creation response and
only its SHA-256 hash is stored, so a leaked database or manifest does not grant access. Every scan-specific
endpoint requires the token in the `X-QMC-Scan-Token` header. An optional operator token (`QMC_ADMIN_TOKEN`,
header `X-QMC-Admin-Token`) can list and open all scans.

A wrong or missing token returns the same 404 as an unknown scan, so scan ids cannot be probed.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

SCAN_TOKEN_HEADER = "X-QMC-Scan-Token"
ADMIN_TOKEN_HEADER = "X-QMC-Admin-Token"
TOKEN_BYTES = 32


def new_token() -> tuple[str, str]:
    """(token, sha256-hex hash). The token has 256 bits of entropy."""
    token = secrets.token_urlsafe(TOKEN_BYTES)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_admin(presented: str | None, admin_token: str) -> bool:
    """True only if an admin token is configured AND the presented one matches (constant-time)."""
    if not admin_token or not presented:
        return False
    return hmac.compare_digest(presented.encode("utf-8"), admin_token.encode("utf-8"))


def can_access(stored_hash: str | None, presented: str | None, *, admin: bool = False) -> bool:
    """Scan rows without a stored hash (created before access control existed) are reachable by the admin only."""
    if admin:
        return True
    if not stored_hash or not presented:
        return False
    return hmac.compare_digest(hash_token(presented), stored_hash)
