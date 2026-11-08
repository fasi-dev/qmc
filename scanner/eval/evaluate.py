"""Scanner evaluation: precision / recall / F1 against the hand-labelled set in eval/cases.py.

    cd scanner && python -m eval.evaluate            # Markdown report to stdout
    cd scanner && python -m eval.evaluate --json     # machine-readable

Matching: a finding is a true positive when (line_start, algorithm) equals a labelled item of the same case
(multiset match). Comment/doc-only findings are ignored. Numbers describe THIS small set only (see README in eval/);
they are not a general accuracy claim.
"""
from __future__ import annotations

import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

from qmc_scanner import scan_tree

from .cases import CASES


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3)}


def evaluate(cases: list[dict] = CASES) -> dict:
    per_case = []
    with tempfile.TemporaryDirectory() as tmp:
        for i, c in enumerate(cases):
            root = Path(tmp) / f"c{i}"
            p = root / c["file"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(c["src"].encode("utf-8"))
            res = scan_tree(root)
            got = Counter((f["line_start"], f["algorithm"]) for f in res.findings if not f["metadata"]["comment_only"])
            want = Counter(tuple(x) for x in c["expected"])
            tp = sum((got & want).values())
            per_case.append({"id": c["id"], "kind": c["kind"], "tp": tp, "fp": sum((got - want).values()),
                             "fn": sum((want - got).values()), "extra": sorted(got - want), "missed": sorted(want - got)})

    def agg(rows):
        return _prf(sum(r["tp"] for r in rows), sum(r["fp"] for r in rows), sum(r["fn"] for r in rows))
    kinds = sorted({c["kind"] for c in per_case})
    return {"overall": agg(per_case),
            "excluding_limitations": agg([r for r in per_case if r["kind"] != "limitation"]),
            "by_kind": {k: agg([r for r in per_case if r["kind"] == k]) for k in kinds},
            "cases": per_case}


def to_markdown(r: dict) -> str:
    L = ["| Subset | TP | FP | FN | Precision | Recall | F1 |", "|---|---|---|---|---|---|---|"]
    rows = [("overall", r["overall"]), ("excluding known limitations", r["excluding_limitations"])]
    rows += [(f"kind = {k}", v) for k, v in r["by_kind"].items()]
    for name, m in rows:
        L.append(f"| {name} | {m['tp']} | {m['fp']} | {m['fn']} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} |")
    bad = [c for c in r["cases"] if c["fp"] or c["fn"]]
    if bad:
        L += ["", "Cases with errors:", ""]
        L += [f"- `{c['id']}` ({c['kind']}): missed {c['missed'] or '-'}; extra {c['extra'] or '-'}" for c in bad]
    return "\n".join(L)


if __name__ == "__main__":
    out = evaluate()
    print(json.dumps(out, indent=2) if "--json" in sys.argv else to_markdown(out))
