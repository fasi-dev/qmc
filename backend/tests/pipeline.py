"""Shared test helper: run the REAL scanner + QMP + migration on a directory and build graph inputs (no FastAPI/DB)."""
from datetime import datetime, timezone
from pathlib import Path

from qmc_scanner import scan_tree

from app.config import Settings
from app.graph import build_graph, finding_record
from app.ingestion.metadata import parse_service_metadata
from app.migration import plan_for
from app.risk import score

ACME = Path(__file__).resolve().parents[2] / "sample-repos" / "acme-payments"
AS_OF = datetime(2026, 11, 8, tzinfo=timezone.utc)


def run(root: Path, repo: str = "repo", *, with_imports: bool = True):
    files = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
    services, _ = parse_service_metadata(root, files, Settings())
    res = scan_tree(root, services=services, repo_name=repo, as_of=AS_OF)
    meta = {s["service"]: s for s in services}
    recs = []
    for f in res.findings:
        if f["metadata"]["comment_only"]:
            continue
        r = score(f, meta.get(f["service"]))
        recs.append(finding_record(f, r, plan_for(f, r)))
    g = build_graph(recs, res.imports if with_imports else None, services, repo, imports_truncated=res.imports_truncated)
    analysis = {"files_scanned": res.files_scanned, "files_skipped": res.files_skipped, "scan_status": res.status,
                "engine_version": res.engine_version}
    return recs, g, services, analysis, res


def tree(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, src in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    return tmp_path
