"""Command line: python -m qmc_scanner <tree> [--manifest manifest.json] [--scan-id ID] [--summary]"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import scan_tree


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="qmc_scanner", description="Deterministic static crypto discovery.")
    ap.add_argument("tree", help="extracted (redacted) source tree")
    ap.add_argument("--manifest", help="Phase 2 manifest.json (supplies service metadata + repo name)")
    ap.add_argument("--scan-id", default="00000000-0000-4000-8000-000000000000")
    ap.add_argument("--summary", action="store_true", help="print a table instead of JSON")
    a = ap.parse_args(argv)
    root = Path(a.tree)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    services, repo = [], root.resolve().name
    if a.manifest:
        mf = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
        services = mf.get("services", [])
        repo = mf.get("stripped_root_dir") or Path(mf.get("original_filename", repo)).stem
    res = scan_tree(root, scan_id=a.scan_id, services=services, repo_name=repo)
    if a.summary:
        for f in res.findings:
            print(f"{f['id']}  {f['confidence_level']:<6} {f['algorithm']:<10} {f['operation']:<14} "
                  f"{f['file']}:{f['line_start']}  [{f['rule_id']}]")
        print(f"\n{len(res.findings)} findings, status={res.status}, files={res.files_scanned}, "
              f"skipped={len(res.files_skipped)}")
    else:
        print(json.dumps(res.to_dict(), indent=2))
    return 0
