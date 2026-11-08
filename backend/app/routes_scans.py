"""Scan upload / retrieval endpoints.

Upload is a raw-body POST (not multipart) so the size cap is enforced while streaming to disk,
before anything is parsed:  POST /api/scans?filename=repo.zip   (body = archive bytes)

The 201 response carries `access_token` exactly once; every other /api/scans/{id}... call needs it in the
X-QMC-Scan-Token header (see app/access.py).
"""
from __future__ import annotations

import logging
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request
from starlette.concurrency import run_in_threadpool

from . import analysis
from .access import new_token
from .config import Settings, get_settings
from .db import open_session
from .deps import creation_allowed, scan_access
from .ingestion import IngestionError, delete_scan, ingest_archive, load_manifest, purge_tree
from .ingestion.pipeline import create_workspace

log = logging.getLogger("qmc.ingestion")
router = APIRouter(prefix="/api/scans", tags=["scans"])

TOKEN_NOTICE = ("Keep access_token: it is shown only once and is required (header X-QMC-Scan-Token) to read, "
                "analyze or delete this scan. Scans are deleted automatically after the retention period.")


def _summary(manifest: dict, include_files: bool = False) -> dict:
    out = dict(manifest)
    if not include_files:
        out.pop("files", None)
    return out


@router.post("", status_code=201, dependencies=[Depends(creation_allowed)])
async def create_scan(request: Request, filename: str = Query("upload", max_length=255),
                      s: Settings = Depends(get_settings)) -> dict:
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > s.max_archive_bytes:
        raise IngestionError("archive_too_large", f"Archive exceeds {s.max_archive_bytes} bytes.", 413)
    db = open_session(s)
    try:
        await run_in_threadpool(analysis.ensure_capacity, db, s)
    finally:
        db.close()

    scan_id = str(uuid.uuid4())
    ws = s.scans_dir / scan_id
    upload = ws / "upload.bin"
    try:
        create_workspace(ws)
        size = 0
        with open(upload, "wb") as f:
            async for chunk in request.stream():
                size += len(chunk)
                if size > s.max_archive_bytes:  # enforced while streaming (chunked uploads have no Content-Length)
                    raise IngestionError("archive_too_large", f"Archive exceeds {s.max_archive_bytes} bytes.", 413)
                f.write(chunk)
        if size == 0:
            raise IngestionError("empty_archive", "The upload was empty.", 400)
        manifest = await run_in_threadpool(ingest_archive, upload, ws, scan_id, filename, s)
        token, token_hash = new_token()
        db = open_session(s)
        try:
            analysis.register_scan(db, manifest, token_hash)
        finally:
            db.close()
        return {**_summary(manifest), "access_token": token, "access_token_notice": TOKEN_NOTICE}
    except IngestionError:
        shutil.rmtree(ws, ignore_errors=True)
        raise
    except Exception:
        log.exception("unexpected ingestion failure")
        shutil.rmtree(ws, ignore_errors=True)
        raise IngestionError("internal_error", "Ingestion failed unexpectedly.", 500)
    finally:
        Path(upload).unlink(missing_ok=True)  # the raw upload is never kept


@router.get("/{scan_id}")
def get_scan(sid: str = Depends(scan_access), include_files: bool = False, s: Settings = Depends(get_settings)) -> dict:
    return _summary(load_manifest(sid, s), include_files)


@router.delete("/{scan_id}/tree")
def purge_scan_tree(sid: str = Depends(scan_access), s: Settings = Depends(get_settings)) -> dict:
    """Delete the extracted source tree, keep the manifest (what happens after analysis)."""
    return {"scan_id": sid, "tree_deleted": purge_tree(sid, s)}


@router.delete("/{scan_id}")
def delete_scan_route(sid: str = Depends(scan_access), s: Settings = Depends(get_settings)) -> dict:
    db = open_session(s)
    try:
        analysis.delete_rows(db, sid)
    finally:
        db.close()
    try:
        delete_scan(sid, s)
    except IngestionError:
        pass  # rows are gone; a workspace that was already removed is not an error
    return {"scan_id": sid, "deleted": True}
