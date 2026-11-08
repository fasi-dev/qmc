"""Dependency graph + blast radius on REAL scanner output (pure functions; no FastAPI needed)."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from qmc_scanner import scan_tree

from app.config import Settings
from app.graph import MAX_DEPTH, NodeNotFound, NotSelectable, blast_radius, build_graph, finding_record
from app.ingestion.metadata import parse_service_metadata
from app.migration import plan_for
from app.risk import score

ACME = Path(__file__).resolve().parents[2] / "sample-repos" / "acme-payments"
AS_OF = datetime(2026, 11, 8, tzinfo=timezone.utc)


def graph_for(root: Path, repo="repo", *, with_imports=True):
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
    return build_graph(recs, res.imports if with_imports else None, services, repo,
                       imports_truncated=res.imports_truncated), res


def tree(tmp_path, files: dict[str, str]) -> Path:
    for rel, src in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    return tmp_path


@pytest.fixture(scope="module")
def acme():
    g, _ = graph_for(ACME, "acme-payments")
    return g


# ---------------------------------------------------------------- construction on the real demo repository
def test_acme_graph_nodes_edges_and_evidence(acme):
    d = acme.to_dict()
    ids = {n["id"] for n in d["nodes"]}
    assert {"algorithm:ECDH", "algorithm:ECDSA", "algorithm:RSA", "library:cryptography", "library:java.security",
            "file:src/auth.py", "file:src/api/routes.py", "file:src/api/app.py", "service:payment-api"} <= ids
    assert "file:README.md" not in ids                          # comment/doc mentions are not executable evidence
    for e in d["edges"]:
        assert e["source"] in ids and e["target"] in ids, e["id"]
        assert e["confidence"] in ("confirmed", "inferred") and e["basis"]
        if e["type"] != "CONTAINS" or e["target"].startswith("finding:"):
            assert e["evidence"] and all(x["file"] and x["line"] >= 1 and x["text"] for x in e["evidence"]), e["id"]
    imp = {(e["source"], e["target"]): e for e in d["edges"] if e["type"] == "IMPORTS" and e["target"].startswith("file:")}
    assert set(imp) == {("file:src/api/routes.py", "file:src/auth.py"), ("file:src/api/routes.py", "file:src/payments/settle.py"),
                        ("file:src/api/app.py", "file:src/api/routes.py"), ("file:src/payments/refunds.py", "file:src/payments/settle.py")}
    assert all(e["confidence"] == "confirmed" for e in imp.values())
    assert imp[("file:src/api/routes.py", "file:src/auth.py")]["evidence"][0]["line"] == 2
    assert d["stats"]["imports_available"] and d["stats"]["dependent_files"] == 3   # routes, app, refunds


def test_no_duplicate_nodes_or_edges_and_deterministic(acme):
    d = acme.to_dict()
    assert len({n["id"] for n in d["nodes"]}) == len(d["nodes"]) and len({e["id"] for e in d["edges"]}) == len(d["edges"])
    again, _ = graph_for(ACME, "acme-payments")
    assert json.dumps(d) == json.dumps(again.to_dict())


def test_library_import_edges_meet_finding_usage_at_the_same_node(acme):
    e = acme.edges
    assert "IMPORTS:file:src/auth.py->library:cryptography" in e
    assert any(k.startswith("USES:finding:") and k.endswith("->library:cryptography") for k in e)


# ---------------------------------------------------------------- blast radius
def test_ecdsa_blast_radius_direct_indirect_and_depth(acme):
    br = blast_radius(acme, "algorithm:ECDSA")
    direct = {x["file"] for x in br["direct"]}
    assert {"src/auth.py", "src/java/TokenSigner.java"} <= direct
    ind = {x["file"]: x for x in br["indirect"]}
    assert ind["src/api/routes.py"]["depth"] == 1 and ind["src/api/routes.py"]["confidence"] == "confirmed"
    assert ind["src/api/app.py"]["depth"] == 2                                    # transitive
    path = ind["src/api/app.py"]["path"]
    assert [p["from"] for p in path] == ["file:src/api/routes.py", "file:src/api/app.py"]
    assert all(p["evidence"] for p in path)                                      # every hop is evidenced
    assert br["summary"]["indirect_files"] == len(br["indirect"]) and br["summary"]["findings"] == len(br["findings"])
    assert sum(br["severity"].values()) == len(br["findings"])
    assert all(r["reasons"] and r["reasons"][0]["evidence"] for r in br["direct"] if r["file"] in ("src/auth.py",))


def test_ecdh_blast_radius_has_no_invented_dependents(acme):
    br = blast_radius(acme, "algorithm:ECDH")
    assert {x["file"] for x in br["direct"]} >= {"src/payments/keys.py"}
    assert "src/api/routes.py" not in {x["file"] for x in br["indirect"]}      # routes does not import keys.py


def test_finding_and_file_selection(acme):
    fid = next(n["id"] for n in acme.nodes.values() if n["type"] == "finding" and n["file"] == "src/payments/settle.py")
    br = blast_radius(acme, fid)
    assert [x["file"] for x in br["direct"]] == ["src/payments/settle.py"] and br["summary"]["findings"] == 1
    assert {x["file"] for x in br["indirect"]} == {"src/api/routes.py", "src/api/app.py", "src/payments/refunds.py"}
    brf = blast_radius(acme, "file:src/payments/settle.py")
    assert {x["file"] for x in brf["indirect"]} == {x["file"] for x in br["indirect"]}


def test_library_selection_includes_importers(acme):
    br = blast_radius(acme, "library:hashlib")
    assert {"src/legacy/old_hash.py", "src/payments/settle.py"} <= {x["file"] for x in br["direct"]}
    assert all(any(r["evidence"] for r in x["reasons"]) for x in br["direct"])


def test_invalid_selection(acme):
    with pytest.raises(NodeNotFound):
        blast_radius(acme, "algorithm:NOPE")
    with pytest.raises(NotSelectable):
        blast_radius(acme, "service:payment-api")


def test_migration_impact_uses_existing_rules_without_estimates(acme):
    br = blast_radius(acme, "algorithm:ECDH")
    assert {r["rule_id"] for r in br["migration"]["by_rule"]} >= {"R-03"}
    assert br["migration"]["files_to_change"] == len(br["direct"])
    blob = json.dumps(br).lower()
    for banned in ("hours", "days", "% ", "percent", "effort estimate"):
        assert banned not in blob, banned


# ---------------------------------------------------------------- edge cases
def test_cyclic_imports_terminate_and_are_reported_once(tmp_path):
    g, _ = graph_for(tree(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/a.py": "import hashlib\nfrom pkg import b\nh = hashlib.sha256(b'x')\n",
        "pkg/b.py": "from pkg import c\n",
        "pkg/c.py": "from pkg import a\n",
    }))
    br = blast_radius(g, "algorithm:SHA-256")
    assert [x["file"] for x in br["direct"]] == ["pkg/a.py"]
    assert [(x["file"], x["depth"]) for x in br["indirect"]] == [("pkg/c.py", 1), ("pkg/b.py", 2)]


def test_ambiguous_imports_are_inferred_not_confirmed(tmp_path):
    g, _ = graph_for(tree(tmp_path, {
        "a/utils.py": "import hashlib\nhashlib.sha1(b'x')\n",
        "b/utils.py": "x = 1\n",
        "tools/run.py": "import utils\n",
    }))
    br = blast_radius(g, "algorithm:SHA-1")
    (ind,) = br["indirect"]
    assert ind["file"] == "tools/run.py" and ind["confidence"] == "inferred"
    assert br["summary"]["indirect_inferred"] == 1 and any("inferred" in l for l in br["limitations"])
    e = g.edges["IMPORTS:file:tools/run.py->file:a/utils.py"]
    assert e["confidence"] == "inferred" and "candidate" in e["basis"]
    assert "file:b/utils.py" not in g.nodes                       # not on a path to crypto: not shown


def test_confirmed_path_wins_over_inferred(tmp_path):
    g, _ = graph_for(tree(tmp_path, {
        "core/crypto_util.py": "import hashlib\nhashlib.sha1(b'x')\n",
        "core/__init__.py": "",
        "x/crypto_util.py": "",
        "app/main.py": "import crypto_util\nfrom core import crypto_util as c\n",
    }))
    (ind,) = blast_radius(g, "algorithm:SHA-1")["indirect"]
    assert ind["file"] == "app/main.py" and ind["confidence"] == "confirmed"


def test_unrelated_files_are_excluded(tmp_path):
    g, _ = graph_for(tree(tmp_path, {"c.py": "import hashlib\nhashlib.sha256(b'')\n", "other.py": "import os\n", "lone.py": "x=1\n"}))
    assert {n["label"] for n in g.nodes.values() if n["type"] == "file"} == {"c.py"}


def test_legacy_scan_without_imports_is_explicit(tmp_path):
    g, _ = graph_for(tree(tmp_path, {"c.py": "import hashlib\nhashlib.sha256(b'')\n", "u.py": "import c\n"}), with_imports=False)
    assert not g.stats["imports_available"] and "before dependency extraction" in g.limitations[0]
    br = blast_radius(g, "algorithm:SHA-256")
    assert br["indirect"] == [] and "unavailable" in br["limitations"][0]


def test_unresolved_imports_are_reported(tmp_path):
    g, _ = graph_for(tree(tmp_path, {"c.py": "import hashlib\nfrom .gone import x\nhashlib.sha256(b'')\n"}))
    assert g.stats["unresolved_imports"] == 1 and any("could not be resolved" in l for l in g.limitations)


def test_javascript_relative_chain(tmp_path):
    g, _ = graph_for(tree(tmp_path, {
        "web/crypto.ts": "import { createHash } from 'node:crypto';\nexport const h = () => createHash('sha256');\n",
        "web/api.ts": "import { h } from './crypto';\nexport const api = h;\n",
        "web/ui/page.tsx": "import { api } from '../api';\n",
    }))
    br = blast_radius(g, "algorithm:SHA-256")
    assert [x["file"] for x in br["direct"]] == ["web/crypto.ts"]
    assert [(x["file"], x["depth"], x["confidence"]) for x in br["indirect"]] == [("web/api.ts", 1, "confirmed"), ("web/ui/page.tsx", 2, "confirmed")]
    assert "IMPORTS:file:web/crypto.ts->library:node:crypto" in g.edges


def test_large_graph_is_fast_and_depth_bounded(tmp_path):
    import time
    files = {"m0.py": "import hashlib\nhashlib.sha1(b'')\n"}
    files.update({f"m{i}.py": f"import m{i - 1}\n" for i in range(1, 400)})        # a 399-deep import chain
    files.update({f"fan/f{i}.py": "import m0\n" for i in range(800)})
    t = time.time()
    g, _ = graph_for(tree(tmp_path, files))
    br = blast_radius(g, "algorithm:SHA-1")
    assert time.time() - t < 30
    chain = [x for x in br["indirect"] if not x["file"].startswith("fan/")]
    fan = [x for x in br["indirect"] if x["file"].startswith("fan/")]
    assert len(chain) == MAX_DEPTH and max(x["depth"] for x in chain) == MAX_DEPTH      # bounded, not infinite ...
    assert br["summary"]["depth_capped"] and any("not followed further" in l for l in br["limitations"])   # ... and said
    assert len(fan) == 800 and all(x["confidence"] == "inferred" for x in fan)   # `import m0` from another dir: sys.path-dependent
    small = blast_radius(g, f"file:m{399 - 3}.py")
    assert not small["summary"]["depth_capped"] and len(small["indirect"]) == 3


def test_java_same_package_dependency_reaches_the_blast_radius(tmp_path):
    g, _ = graph_for(tree(tmp_path, {
        "src/com/acme/sec/Signer.java": ("package com.acme.sec;\nimport java.security.*;\npublic class Signer {\n"
                                         "  byte[] s() throws Exception { return Signature.getInstance(\"SHA256withECDSA\").sign(); }\n}\n"),
        "src/com/acme/sec/Api.java": "package com.acme.sec;\npublic class Api {\n  Signer signer = new Signer();\n}\n",
        "src/com/acme/web/Controller.java": "package com.acme.web;\nimport com.acme.sec.Api;\nclass Controller { Api api; }\n",
    }))
    br = blast_radius(g, "algorithm:ECDSA")
    ind = {x["file"]: x for x in br["indirect"]}
    assert ind["src/com/acme/sec/Api.java"]["depth"] == 1 and ind["src/com/acme/sec/Api.java"]["confidence"] == "confirmed"
    assert ind["src/com/acme/web/Controller.java"]["depth"] == 2
    e = g.edges["IMPORTS:file:src/com/acme/sec/Api.java->file:src/com/acme/sec/Signer.java"]
    assert "same-package" in e["basis"] and e["evidence"][0]["line"] == 3


def test_ts_alias_dependency_reaches_the_blast_radius(tmp_path):
    g, _ = graph_for(tree(tmp_path, {
        "web/tsconfig.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["src/*"]}}}',
        "web/src/lib/hash.ts": "import { createHash } from 'node:crypto';\nexport const h = () => createHash('sha1');\n",
        "web/src/pages/home.tsx": "import { h } from '@/lib/hash';\n",
    }))
    (ind,) = blast_radius(g, "algorithm:SHA-1")["indirect"]
    assert ind["file"] == "web/src/pages/home.tsx" and ind["confidence"] == "confirmed"
    assert g.stats["unresolved_imports"] == 0
