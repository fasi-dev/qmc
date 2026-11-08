"""FastAPI dependencies shared by the routers: scan access control and creation rate limiting."""
from __future__ import annotations

from fastapi import Depends, Header, Request

from . import analysis
from .access import is_admin
from .config import Settings, get_settings
from .db import open_session
from .ingestion import IngestionError
from .ingestion.pipeline import parse_scan_id
from .limits import client_key, limiter_for


def scan_access(scan_id: str,
                x_qmc_scan_token: str | None = Header(default=None),
                x_qmc_admin_token: str | None = Header(default=None),
                s: Settings = Depends(get_settings)) -> str:
    """Validated scan id the caller may access (X-QMC-Scan-Token, or the operator's X-QMC-Admin-Token)."""
    sid = parse_scan_id(scan_id)
    db = open_session(s)
    try:
        analysis.authorize(db, sid, x_qmc_scan_token, is_admin(x_qmc_admin_token, s.admin_token))
    finally:
        db.close()
    return sid


def require_admin(x_qmc_admin_token: str | None = Header(default=None), s: Settings = Depends(get_settings)) -> None:
    if not is_admin(x_qmc_admin_token, s.admin_token):
        raise IngestionError("admin_required", "Listing scans requires the operator token (QMC_ADMIN_TOKEN).", 403)


def creation_allowed(request: Request, s: Settings = Depends(get_settings)) -> None:
    """Rate limit for endpoints that create scans (uploads and the demo)."""
    key = client_key(request.headers, request.client.host if request.client else None, s.trust_proxy)
    limiter = limiter_for(s.scans_per_window, s.rate_window_seconds)
    if not limiter.hit(key):
        raise IngestionError("rate_limited", f"Too many new scans from this address. Retry in about "
                                             f"{limiter.retry_after(key)} seconds.", 429)
