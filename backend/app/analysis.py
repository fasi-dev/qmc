"""Analysis pipeline: ingested tree -> deterministic scan -> QMP risk -> persisted findings (+ snippets).

Order matches the demo: ingestion (already done) -> scan -> risk scoring -> persist -> purge extracted tree (04 section 5).
"""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from qmc_scanner import scan_tree
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import Settings
from .db import FindingRow, ScanRow
from .ingestion import IngestionError, load_manifest, purge_tree
from .ingestion.pipeline import TREE_DIR, workspace_path
from .risk import LABEL, priority_key, score

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "sample-repos" / "acme-payments"
SNIPPET_BEFORE, SNIPPET_AFTER, SNIPPET_MAX = 3, 3, 14
LIMITATIONS = ("Static-analysis estimates. Not a certification. Findings are evidence-based and heuristic; low and medium "
               "confidence findings require human review, and static analysis cannot see dynamically loaded or external crypto.")


def repo_name_of(manifest: dict) -> str:
    return manifest.get("stripped_root_dir") or Path(manifest.get("original_filename", "repo")).stem or "repo"


def register_scan(db: Session, manifest: dict) -> ScanRow:
    row = db.get(ScanRow, manifest["scan_id"])
    summary = {k: v for k, v in manifest.items() if k != "files"}
    if row is None:
        row = ScanRow(id=manifest["scan_id"], created_at=manifest["created_at"], status="ingested",
                      original_filename=manifest["original_filename"], repo_name=repo_name_of(manifest), manifest=summary)
        db.add(row)
    db.commit()
    return row


def delete_rows(db: Session, scan_id: str) -> None:
    db.execute(delete(FindingRow).where(FindingRow.scan_id == scan_id))
    row = db.get(ScanRow, scan_id)
    if row:
        db.delete(row)
    db.commit()


def _snippet(lines: list[str], ls: int, le: int) -> dict:
    start = max(1, ls - SNIPPET_BEFORE)
    end = min(len(lines), max(le, ls) + SNIPPET_AFTER, start + SNIPPET_MAX - 1)
    return {"start_line": start, "highlight_start": ls, "highlight_end": le,
            "lines": [l[:240] for l in lines[start - 1:end]]}


def analyze_scan(db: Session, scan_id: str, s: Settings, as_of: datetime | None = None) -> dict:
    row = db.get(ScanRow, scan_id)
    if row is None:
        raise IngestionError("scan_not_found", "Scan not found.", 404)
    if row.status == "analyzed":
        raise IngestionError("already_analyzed", "This scan was already analyzed (the extracted source is deleted after analysis).", 409)
    manifest = load_manifest(scan_id, s)
    tree = workspace_path(scan_id, s) / TREE_DIR
    if not tree.is_dir():
        raise IngestionError("tree_missing", "The extracted source tree is no longer available.", 409)

    res = scan_tree(tree, scan_id=scan_id, services=manifest["services"], repo_name=repo_name_of(manifest), as_of=as_of)
    services = {x["service"]: x for x in manifest["services"] if x.get("service")}
    scored = [(f, score(f, services.get(f["service"]))) for f in res.findings]
    ranked = sorted(scored, key=lambda p: priority_key(*p))
    rank_of = {f["id"]: i for i, (f, _) in enumerate(ranked, 1)}

    cache: dict[str, list[str]] = {}
    for f, r in scored:
        if f["file"] not in cache:
            try:
                cache[f["file"]] = (tree / f["file"]).read_text(encoding="utf-8", errors="replace").split("\n")
            except OSError:
                cache[f["file"]] = []
        md = f["metadata"]
        db.add(FindingRow(
            scan_id=scan_id, fid=f["id"], file=f["file"], algorithm=f["algorithm"], primitive=f["primitive"], operation=f["operation"],
            service=f["service"], confidence_level=f["confidence_level"], quantum_vulnerable=f["quantum_vulnerable"],
            already_pqc=f["already_pqc"], comment_only=md["comment_only"], test_path=md["test_path"],
            band=r["band"] if r else None, qmp=r["qmp"] if r else None, raw=r["raw"] if r else None,
            hndl=bool(r and r["hndl"]["flag"]), rank=rank_of[f["id"]], data=f, risk=r,
            snippet=_snippet(cache[f["file"]], f["line_start"], f["line_end"]) if cache[f["file"]] else None))
    row.status = "analyzed"
    row.analysis = {"engine_version": res.engine_version, "scan_status": res.status, "as_of": res.as_of,
                    "files_scanned": res.files_scanned, "files_skipped": res.files_skipped,
                    "skipped_directories": res.skipped_directories, "rule_hits": res.rule_hits,
                    "rule_versions": res.rule_versions, "analyzed_at": datetime.now(timezone.utc).isoformat()}
    db.commit()
    purge_tree(scan_id, s)          # 04 section 5: keep findings, delete the extracted source
    return summarize(db, scan_id)


def sample_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(SAMPLE_DIR.rglob("*")):
            if p.is_file():
                zf.write(p, "acme-payments/" + p.relative_to(SAMPLE_DIR).as_posix())
    return buf.getvalue()


# ------------------------------------------------------------------ queries
def _rows(db: Session, scan_id: str) -> list[FindingRow]:
    if db.get(ScanRow, scan_id) is None:
        raise IngestionError("scan_not_found", "Scan not found.", 404)
    return list(db.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id).order_by(FindingRow.rank)))


def summarize(db: Session, scan_id: str) -> dict:
    scan = db.get(ScanRow, scan_id)
    if scan is None:
        raise IngestionError("scan_not_found", "Scan not found.", 404)
    rows = _rows(db, scan_id)
    live = [r for r in rows if not r.suppressed]
    code = [r for r in live if not r.comment_only]
    vuln = [r for r in code if r.quantum_vulnerable]
    bands = {b: 0 for b in ("Critical", "High", "Review", "Informational")}
    for r in code:
        if r.band:
            bands[r.band] += 1
    prim: dict[str, int] = {}
    alg: dict[str, int] = {}
    for r in code:
        prim[r.primitive] = prim.get(r.primitive, 0) + 1
        alg[r.algorithm] = alg.get(r.algorithm, 0) + 1
    meta = {x.get("service"): x for x in scan.manifest.get("services", [])}
    svc: dict[str, dict] = {}
    for r in code:
        d = svc.setdefault(r.service, {"service": r.service, "findings": 0, "quantum_vulnerable": 0, "already_pqc": 0,
                                       "critical": 0, "high": 0, "hndl": 0})
        d["findings"] += 1
        d["quantum_vulnerable"] += int(r.quantum_vulnerable)
        d["already_pqc"] += int(r.already_pqc)
        d["critical"] += int(r.band == "Critical")
        d["high"] += int(r.band == "High")
        d["hndl"] += int(r.hndl)
    for name, d in svc.items():
        m = meta.get(name) or {}
        d.update(data_classification=m.get("data_classification"), business_criticality=m.get("business_criticality"),
                 internet_exposed=m.get("internet_exposed"), data_lifetime_years=m.get("data_lifetime_years"),
                 metadata_missing=bool(m.get("missing_fields") or m.get("invalid_fields") or not m))
        d["migration_status"] = ("no quantum-vulnerable crypto found" if d["quantum_vulnerable"] == 0 else
                                 "in progress: PQC already present" if d["already_pqc"] else "not started")
    top = [r for r in live if r.band in ("Critical", "High", "Review") and not r.comment_only][:8]
    return {
        "scan": {"id": scan.id, "created_at": scan.created_at, "filename": scan.original_filename, "repo_name": scan.repo_name,
                 "status": scan.status, "ingestion": {k: scan.manifest.get(k) for k in ("archive_type", "stats", "warnings")},
                 "analysis": scan.analysis},
        "totals": {"crypto_findings": len(code), "quantum_vulnerable": len(vuln), "already_pqc": sum(r.already_pqc for r in code),
                   "high_confidence": sum(r.confidence_level == "high" for r in code),
                   "critical": bands["Critical"], "hndl_elevated": sum(1 for r in code if r.hndl and (r.risk or {}).get("hndl", {}).get("severity") == "elevated"),
                   "services": len(svc), "comment_or_doc_mentions": sum(r.comment_only for r in live),
                   "suppressed": sum(r.suppressed for r in rows), "test_path": sum(r.test_path for r in code)},
        "by_band": bands, "by_primitive": dict(sorted(prim.items())), "by_algorithm": dict(sorted(alg.items(), key=lambda kv: (-kv[1], kv[0]))),
        "services": sorted(svc.values(), key=lambda d: (-d["critical"], -d["quantum_vulnerable"], d["service"])),
        "top_findings": [_card(r) for r in top],
        "qmp_label": LABEL, "limitations": LIMITATIONS,
    }


def _card(r: FindingRow) -> dict:
    d = r.data
    return {"id": r.fid, "file": r.file, "line_start": d["line_start"], "algorithm": r.algorithm, "operation": r.operation,
            "service": r.service, "confidence_level": r.confidence_level, "quantum_vulnerable": r.quantum_vulnerable,
            "already_pqc": r.already_pqc, "band": r.band, "qmp": r.qmp, "hndl": r.hndl,
            "hndl_severity": ((r.risk or {}).get("hndl") or {}).get("severity"), "primitive": r.primitive,
            "context": d["context"], "rule_id": d["rule_id"], "comment_only": r.comment_only, "test_path": r.test_path,
            "suppressed": r.suppressed, "evidence": d["evidence"], "rank": r.rank,
            "badges": (r.risk or {}).get("badges", [])}


def list_findings(db: Session, scan_id: str, *, q: str | None = None, algorithm: str | None = None, primitive: str | None = None,
                  service: str | None = None, band: str | None = None, confidence: str | None = None,
                  vulnerable: bool | None = None, pqc: bool | None = None, include_comments: bool = False,
                  include_tests: bool = False, include_suppressed: bool = False, language: str | None = None) -> list[dict]:
    out = []
    ql = q.lower() if q else None
    ext_lang = {".py": "python", ".java": "java", ".js": "js", ".ts": "js", ".jsx": "js", ".tsx": "js", ".mjs": "js", ".cjs": "js",
                ".yaml": "config", ".yml": "config", ".json": "config", ".conf": "config", ".crt": "config", ".pem": "config"}
    for r in _rows(db, scan_id):
        if r.suppressed and not include_suppressed or r.comment_only and not include_comments or r.test_path and not include_tests:
            continue
        if algorithm and r.algorithm != algorithm or primitive and r.primitive != primitive or service and r.service != service:
            continue
        if band and r.band != band or confidence and r.confidence_level != confidence:
            continue
        if vulnerable is not None and r.quantum_vulnerable != vulnerable or pqc is not None and r.already_pqc != pqc:
            continue
        if language:
            ext = "." + r.file.rsplit(".", 1)[-1].lower() if "." in r.file else ""
            if ext_lang.get(ext, "other") != language and not (language == "config" and r.file.lower().endswith("dockerfile")):
                continue
        if ql and ql not in f"{r.file} {r.algorithm} {r.operation} {r.service} {r.data['evidence']} {r.data['rule_id']}".lower():
            continue
        out.append(_card(r))
    return out


def get_finding(db: Session, scan_id: str, fid: str) -> dict:
    r = db.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id, FindingRow.fid == fid)).first()
    if r is None:
        raise IngestionError("finding_not_found", "Finding not found.", 404)
    return {"finding": r.data, "risk": r.risk, "snippet": r.snippet, "rank": r.rank, "band": r.band, "qmp": r.qmp,
            "suppressed": r.suppressed, "suppression": r.suppression, "qmp_label": LABEL}


def set_suppression(db: Session, scan_id: str, fid: str, reason: str | None, author: str | None) -> dict:
    r = db.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id, FindingRow.fid == fid)).first()
    if r is None:
        raise IngestionError("finding_not_found", "Finding not found.", 404)
    if reason is None:
        r.suppressed, r.suppression = False, None
    else:
        r.suppressed = True
        r.suppression = {"reason": reason[:500], "author": (author or "demo-user")[:80], "at": datetime.now(timezone.utc).isoformat()}
    db.commit()
    return get_finding(db, scan_id, fid)


def export_csv(rows: list[dict]) -> str:
    import csv
    buf = io.StringIO()
    cols = ["id", "algorithm", "primitive", "operation", "service", "file", "line_start", "confidence_level", "band", "qmp",
            "quantum_vulnerable", "already_pqc", "hndl", "rule_id", "evidence"]
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([("'" + str(r[c]) if isinstance(r[c], str) and r[c][:1] in "=+-@" else r[c]) for c in cols])   # CSV-injection safe
    return buf.getvalue()
