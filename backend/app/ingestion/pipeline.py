"""Ingestion orchestration: archive file -> inert, redacted workspace tree + manifest.

Workspace layout (per scan UUID):
    <data_dir>/scans/<uuid>/tree/          extracted, redacted files (deleted after analysis, 04 section 5)
    <data_dir>/scans/<uuid>/manifest.json  inventory of what was ingested (kept; contains no secrets)
"""
from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from qmc_scanner import ENGINE_VERSION

from ..config import Settings
from .archive import detect_archive_type, extract_archive
from .errors import IngestionError
from .metadata import parse_service_metadata

TREE_DIR = "tree"
MANIFEST = "manifest.json"


def create_workspace(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True)
    if os.name == "posix":
        os.chmod(path, 0o700)


def parse_scan_id(value: str) -> str:
    """Validate a scan id (prevents path traversal via the URL). Raises IngestionError(404)."""
    try:
        return str(uuid.UUID(value, version=4))
    except (ValueError, AttributeError, TypeError):
        raise IngestionError("scan_not_found", "Scan not found.", 404)


def workspace_path(scan_id: str, s: Settings) -> Path:
    return s.scans_dir / parse_scan_id(scan_id)


def sanitize_filename(name: str) -> str:
    base = re.split(r"[\\/]", name or "")[-1]
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base)[:100].strip()
    return base or "upload"


def _flatten_single_root(tree: Path) -> str | None:
    """If the archive is wrapped in exactly one top-level directory (e.g. GitHub zips), lift it."""
    entries = os.listdir(tree)
    if len(entries) != 1:
        return None
    top = tree / entries[0]
    if top.is_symlink() or not top.is_dir():
        return None
    tmp = tree.parent / "_flatten_tmp"
    os.rename(top, tmp)
    os.rmdir(tree)
    os.rename(tmp, tree)
    return entries[0]


def ingest_archive(archive_path: Path, workspace: Path, scan_id: str, original_filename: str,
                   s: Settings) -> dict:
    """Validate + extract + redact + describe. Raises IngestionError; caller cleans the workspace."""
    archive_size = archive_path.stat().st_size
    if archive_size > s.max_archive_bytes:
        raise IngestionError("archive_too_large", f"Archive exceeds {s.max_archive_bytes} bytes.", 413)
    kind = detect_archive_type(archive_path)
    tree = workspace / TREE_DIR
    res = extract_archive(archive_path, kind, tree, s)

    stripped = _flatten_single_root(tree)
    if stripped:
        prefix = stripped + "/"

        def fix(p: str) -> str:
            return p[len(prefix):] if p.startswith(prefix) else p
        for r in res.files:
            r.path = fix(r.path)
        for r in res.skipped:
            r.path = fix(r.path)
        for r in res.redactions:
            r.file = fix(r.file)

    services, warnings = parse_service_metadata(tree, [f.path for f in res.files], s)
    manifest = {
        "scan_id": scan_id,
        "status": "ingested",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "engine_version": ENGINE_VERSION,
        "original_filename": sanitize_filename(original_filename),
        "archive_type": kind,
        "archive_bytes": archive_size,
        "stripped_root_dir": stripped,
        "stats": {
            "entry_count": res.entry_count,
            "file_count": len(res.files),
            "total_bytes": res.total_bytes,
            "skipped_count": len(res.skipped),
            "redaction_count": len(res.redactions),
            "service_count": len(services),
        },
        "services": services,
        "skipped": [asdict(x) for x in res.skipped],
        "redactions": [asdict(x) for x in res.redactions],
        "warnings": warnings,
        "files": [asdict(x) for x in res.files],
        "notice": "Uploaded code is never executed. Secrets are redacted in the stored copy; "
                  "redaction is heuristic and not exhaustive.",
    }
    (workspace / MANIFEST).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def load_manifest(scan_id: str, s: Settings) -> dict:
    p = workspace_path(scan_id, s) / MANIFEST
    if not p.is_file():
        raise IngestionError("scan_not_found", "Scan not found.", 404)
    return json.loads(p.read_text(encoding="utf-8"))


def purge_tree(scan_id: str, s: Settings) -> bool:
    """Delete the extracted tree (called after analysis; 04 section 5). Manifest/findings are kept."""
    tree = workspace_path(scan_id, s) / TREE_DIR
    if tree.exists():
        shutil.rmtree(tree)
        return True
    return False


def delete_scan(scan_id: str, s: Settings) -> None:
    ws = workspace_path(scan_id, s)
    if not ws.exists():
        raise IngestionError("scan_not_found", "Scan not found.", 404)
    shutil.rmtree(ws)
