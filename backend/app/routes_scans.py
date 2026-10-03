"""Scan upload / retrieval endpoints.

Upload is a raw-body POST (not multipart) so the size cap is enforced while streaming to disk,
before anything is parsed:  POST /api/scans?filename=repo.zip   (body = archive bytes)
"""
from __future__ import annotations

import logging
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request
from starlette.concurrency import run_in_threadpool

from . import analysis
from .config import Settings, get_settings
from .db import open_session
from .ingestion import IngestionError, delete_scan, ingest_archive, load_manifest, purge_tree
from .ingestion.pipeline import workspace_path

log = logging.getLogger("qmc.ingestion")
router = APIRouter(prefix="/api/scans", tags=["scans"])


def _summary(manifest: dict, include_files: bool = False) -> dict:
    out = dict(manifest)
    if not include_files:
        out.pop("files", None)
    return out


@router.post("", status_code=201)
async def create_scan(request: Request, filename: str = Query("upload", max_length=255),
                      s: Settings = Depends(get_settings)) -> dict:
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > s.max_archive_bytes:
        raise IngestionError("archive_too_large", f"Archive exceeds {s.max_archive_bytes} bytes.", 413)

    scan_id = str(uuid.uuid4())
    ws = s.scans_dir / scan_id
    upload = ws / "upload.bin"
    try:
        ws.mkdir(mode=0o700, parents=True)
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
        db = open_session(s)
        try:
            analysis.register_scan(db, manifest)
        finally:
            db.close()
        return _summary(manifest)
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
def get_scan(scan_id: str, include_files: bool = False, s: Settings = Depends(get_settings)) -> dict:
    return _summary(load_manifest(scan_id, s), include_files)


@router.delete("/{scan_id}/tree")
def purge_scan_tree(scan_id: str, s: Settings = Depends(get_settings)) -> dict:
    """Delete the extracted source tree, keep the manifest (what happens after analysis)."""
    return {"scan_id": scan_id, "tree_deleted": purge_tree(scan_id, s)}


@router.delete("/{scan_id}")
def delete_scan_route(scan_id: str, s: Settings = Depends(get_settings)) -> dict:
    delete_scan(scan_id, s)
    db = open_session(s)
    try:
        analysis.delete_rows(db, scan_id)
    finally:
        db.close()
    return {"scan_id": scan_id, "deleted": True}
