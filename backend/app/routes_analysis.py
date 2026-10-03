"""Analysis API: run scan+risk, dashboard summary, findings inventory, finding detail, suppression, demo repo."""
from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from . import analysis
from .config import Settings, get_settings
from .db import ScanRow, open_session
from .ingestion import IngestionError, ingest_archive
from .ingestion.pipeline import parse_scan_id

router = APIRouter(prefix="/api", tags=["analysis"])


class SuppressBody(BaseModel):
    reason: str
    author: str | None = None


def _sid(scan_id: str) -> str:
    return parse_scan_id(scan_id)


@router.post("/scans/{scan_id}/analyze")
def analyze(scan_id: str, s: Settings = Depends(get_settings)) -> dict:
    db = open_session(s)
    try:
        return analysis.analyze_scan(db, _sid(scan_id), s)
    finally:
        db.close()


@router.post("/demo/acme", status_code=201)
async def load_demo(s: Settings = Depends(get_settings)) -> dict:
    """One click: bundled Acme Payments repo -> real ingestion -> real scan -> risk scoring."""
    scan_id = str(uuid.uuid4())
    ws = s.scans_dir / scan_id
    ws.mkdir(mode=0o700, parents=True)
    up = ws / "upload.bin"
    try:
        up.write_bytes(analysis.sample_zip_bytes())
        manifest = await run_in_threadpool(ingest_archive, up, ws, scan_id, "acme-payments.zip", s)
    except Exception:
        import shutil
        shutil.rmtree(ws, ignore_errors=True)
        raise
    finally:
        Path(up).unlink(missing_ok=True)
    db = open_session(s)
    try:
        analysis.register_scan(db, manifest)
        return await run_in_threadpool(analysis.analyze_scan, db, scan_id, s)
    finally:
        db.close()


@router.get("/scans")
def list_scans(s: Settings = Depends(get_settings)) -> list[dict]:
    db = open_session(s)
    try:
        from sqlalchemy import select
        rows = db.scalars(select(ScanRow).order_by(ScanRow.created_at.desc())).all()
        return [{"id": r.id, "created_at": r.created_at, "filename": r.original_filename, "repo_name": r.repo_name, "status": r.status} for r in rows]
    finally:
        db.close()


@router.get("/scans/{scan_id}/summary")
def summary(scan_id: str, s: Settings = Depends(get_settings)) -> dict:
    db = open_session(s)
    try:
        return analysis.summarize(db, _sid(scan_id))
    finally:
        db.close()


def _filters(q, algorithm, primitive, service, band, confidence, vulnerable, pqc, include_comments, include_tests, include_suppressed, language):
    return dict(q=q, algorithm=algorithm, primitive=primitive, service=service, band=band, confidence=confidence, vulnerable=vulnerable,
                pqc=pqc, include_comments=include_comments, include_tests=include_tests, include_suppressed=include_suppressed, language=language)


@router.get("/scans/{scan_id}/findings")
def findings(scan_id: str, q: str | None = None, algorithm: str | None = None, primitive: str | None = None, service: str | None = None,
             band: str | None = None, confidence: str | None = None, vulnerable: bool | None = None, pqc: bool | None = None,
             include_comments: bool = False, include_tests: bool = False, include_suppressed: bool = False, language: str | None = None,
             s: Settings = Depends(get_settings)) -> dict:
    db = open_session(s)
    try:
        sid = _sid(scan_id)
        f = _filters(q, algorithm, primitive, service, band, confidence, vulnerable, pqc, include_comments, include_tests, include_suppressed, language)
        rows = analysis.list_findings(db, sid, **f)
        everything = analysis.list_findings(db, sid, include_comments=True, include_tests=True, include_suppressed=True)
        facets = {k: sorted({r[k] for r in everything if r[k]}) for k in ("algorithm", "primitive", "service", "band", "confidence_level")}
        return {"findings": rows, "count": len(rows), "total_all": len(everything), "facets": facets}
    finally:
        db.close()


@router.get("/scans/{scan_id}/migration")
def migration(scan_id: str, s: Settings = Depends(get_settings)) -> dict:
    db = open_session(s)
    try:
        return analysis.migration_plan(db, _sid(scan_id))
    finally:
        db.close()


@router.get("/scans/{scan_id}/report.md")
def report(scan_id: str, s: Settings = Depends(get_settings)) -> Response:
    from .report import build_report
    db = open_session(s)
    try:
        md = build_report(db, _sid(scan_id))
    finally:
        db.close()
    return Response(md, media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="qmc-report-{scan_id[:8]}.md"'})


@router.get("/scans/{scan_id}/findings.csv", response_class=PlainTextResponse)
def findings_csv(scan_id: str, q: str | None = None, algorithm: str | None = None, primitive: str | None = None, service: str | None = None,
                 band: str | None = None, confidence: str | None = None, vulnerable: bool | None = None, pqc: bool | None = None,
                 include_comments: bool = False, include_tests: bool = False, include_suppressed: bool = False, language: str | None = None,
                 s: Settings = Depends(get_settings)) -> str:
    db = open_session(s)
    try:
        f = _filters(q, algorithm, primitive, service, band, confidence, vulnerable, pqc, include_comments, include_tests, include_suppressed, language)
        return analysis.export_csv(analysis.list_findings(db, _sid(scan_id), **f))
    finally:
        db.close()


@router.get("/scans/{scan_id}/findings/{fid}")
def finding(scan_id: str, fid: str, s: Settings = Depends(get_settings)) -> dict:
    db = open_session(s)
    try:
        return analysis.get_finding(db, _sid(scan_id), fid)
    finally:
        db.close()


@router.post("/scans/{scan_id}/findings/{fid}/suppress")
def suppress(scan_id: str, fid: str, body: SuppressBody, s: Settings = Depends(get_settings)) -> dict:
    if not body.reason.strip():
        raise IngestionError("reason_required", "A reason is required to mark a finding as a false positive.", 422)
    db = open_session(s)
    try:
        return analysis.set_suppression(db, _sid(scan_id), fid, body.reason.strip(), body.author)
    finally:
        db.close()


@router.delete("/scans/{scan_id}/findings/{fid}/suppress")
def unsuppress(scan_id: str, fid: str, s: Settings = Depends(get_settings)) -> dict:
    db = open_session(s)
    try:
        return analysis.set_suppression(db, _sid(scan_id), fid, None, None)
    finally:
        db.close()
