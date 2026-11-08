"""Analysis API: run scan+risk, dashboard summary, findings inventory, finding detail, suppression, demo repo.

Every /scans/{id}/... route depends on `scan_access` (per-scan token or operator token; see app/access.py).
"""
from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from . import analysis
from .access import new_token
from .config import Settings, get_settings
from .db import ScanRow, open_session
from .deps import creation_allowed, require_admin, scan_access
from .ingestion import IngestionError, ingest_archive
from .ingestion.pipeline import create_workspace
from .limits import gate_for
from .routes_scans import TOKEN_NOTICE

router = APIRouter(prefix="/api", tags=["analysis"])


class SuppressBody(BaseModel):
    reason: str = Field(max_length=2000)
    author: str | None = Field(default=None, max_length=200)


@router.post("/scans/{scan_id}/analyze")
def analyze(sid: str = Depends(scan_access), s: Settings = Depends(get_settings)) -> dict:
    with gate_for(s.max_concurrent_analyses).slot():
        db = open_session(s)
        try:
            return analysis.analyze_scan(db, sid, s)
        finally:
            db.close()


@router.post("/demo/acme", status_code=201, dependencies=[Depends(creation_allowed)])
async def load_demo(s: Settings = Depends(get_settings)) -> dict:
    """One click: bundled Acme Payments repo -> real ingestion -> real scan -> risk scoring."""
    db = open_session(s)
    try:
        await run_in_threadpool(analysis.ensure_capacity, db, s)
    finally:
        db.close()
    scan_id = str(uuid.uuid4())
    ws = s.scans_dir / scan_id
    create_workspace(ws)
    up = ws / "upload.bin"
    try:
        up.write_bytes(analysis.sample_zip_bytes())
        manifest = await run_in_threadpool(ingest_archive, up, ws, scan_id, "acme-payments.zip", s)
    except Exception:
        shutil.rmtree(ws, ignore_errors=True)
        raise
    finally:
        Path(up).unlink(missing_ok=True)
    token, token_hash = new_token()
    db = open_session(s)
    try:
        analysis.register_scan(db, manifest, token_hash)
        with gate_for(s.max_concurrent_analyses).slot():
            summary = await run_in_threadpool(analysis.analyze_scan, db, scan_id, s)
        return {**summary, "access_token": token, "access_token_notice": TOKEN_NOTICE}
    finally:
        db.close()


@router.get("/scans", dependencies=[Depends(require_admin)])
def list_scans(s: Settings = Depends(get_settings)) -> list[dict]:
    """Operator-only (X-QMC-Admin-Token). Public listing would disclose every visitor's scan ids."""
    db = open_session(s)
    try:
        rows = db.scalars(select(ScanRow).order_by(ScanRow.created_at.desc())).all()
        return [{"id": r.id, "created_at": r.created_at, "filename": r.original_filename, "repo_name": r.repo_name, "status": r.status} for r in rows]
    finally:
        db.close()


@router.get("/scans/{scan_id}/summary")
def summary(sid: str = Depends(scan_access), s: Settings = Depends(get_settings)) -> dict:
    db = open_session(s)
    try:
        return analysis.summarize(db, sid)
    finally:
        db.close()


def _filters(q, algorithm, primitive, service, band, confidence, vulnerable, pqc, include_comments, include_tests, include_suppressed, language):
    return dict(q=q, algorithm=algorithm, primitive=primitive, service=service, band=band, confidence=confidence, vulnerable=vulnerable,
                pqc=pqc, include_comments=include_comments, include_tests=include_tests, include_suppressed=include_suppressed, language=language)


@router.get("/scans/{scan_id}/findings")
def findings(sid: str = Depends(scan_access), q: str | None = None, algorithm: str | None = None, primitive: str | None = None,
             service: str | None = None, band: str | None = None, confidence: str | None = None, vulnerable: bool | None = None,
             pqc: bool | None = None, include_comments: bool = False, include_tests: bool = False, include_suppressed: bool = False,
             language: str | None = None, s: Settings = Depends(get_settings)) -> dict:
    db = open_session(s)
    try:
        f = _filters(q, algorithm, primitive, service, band, confidence, vulnerable, pqc, include_comments, include_tests, include_suppressed, language)
        rows = analysis.list_findings(db, sid, **f)
        everything = analysis.list_findings(db, sid, include_comments=True, include_tests=True, include_suppressed=True)
        facets = {k: sorted({r[k] for r in everything if r[k]}) for k in ("algorithm", "primitive", "service", "band", "confidence_level")}
        return {"findings": rows, "count": len(rows), "total_all": len(everything), "facets": facets}
    finally:
        db.close()


@router.get("/scans/{scan_id}/migration")
def migration(sid: str = Depends(scan_access), s: Settings = Depends(get_settings)) -> dict:
    db = open_session(s)
    try:
        return analysis.migration_plan(db, sid)
    finally:
        db.close()


@router.get("/scans/{scan_id}/report.md")
def report(sid: str = Depends(scan_access), s: Settings = Depends(get_settings)) -> Response:
    from .report import build_report
    db = open_session(s)
    try:
        md = build_report(db, sid)
    finally:
        db.close()
    return Response(md, media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="qmc-report-{sid[:8]}.md"'})


@router.get("/scans/{scan_id}/findings.csv", response_class=PlainTextResponse)
def findings_csv(sid: str = Depends(scan_access), q: str | None = None, algorithm: str | None = None, primitive: str | None = None,
                 service: str | None = None, band: str | None = None, confidence: str | None = None, vulnerable: bool | None = None,
                 pqc: bool | None = None, include_comments: bool = False, include_tests: bool = False, include_suppressed: bool = False,
                 language: str | None = None, s: Settings = Depends(get_settings)) -> Response:
    db = open_session(s)
    try:
        f = _filters(q, algorithm, primitive, service, band, confidence, vulnerable, pqc, include_comments, include_tests, include_suppressed, language)
        csv_text = analysis.export_csv(analysis.list_findings(db, sid, **f))
    finally:
        db.close()
    return Response(csv_text, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="qmc-findings-{sid[:8]}.csv"'})


@router.get("/scans/{scan_id}/findings/{fid}")
def finding(fid: str, sid: str = Depends(scan_access), s: Settings = Depends(get_settings)) -> dict:
    db = open_session(s)
    try:
        return analysis.get_finding(db, sid, fid)
    finally:
        db.close()


@router.post("/scans/{scan_id}/findings/{fid}/suppress")
def suppress(fid: str, body: SuppressBody, sid: str = Depends(scan_access), s: Settings = Depends(get_settings)) -> dict:
    if not body.reason.strip():
        raise IngestionError("reason_required", "A reason is required to mark a finding as a false positive.", 422)
    db = open_session(s)
    try:
        return analysis.set_suppression(db, sid, fid, body.reason.strip(), body.author)
    finally:
        db.close()


@router.delete("/scans/{scan_id}/findings/{fid}/suppress")
def unsuppress(fid: str, sid: str = Depends(scan_access), s: Settings = Depends(get_settings)) -> dict:
    db = open_session(s)
    try:
        return analysis.set_suppression(db, sid, fid, None, None)
    finally:
        db.close()
