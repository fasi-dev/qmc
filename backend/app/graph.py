"""Cryptographic dependency graph and blast-radius analysis (pure functions; no I/O, no FastAPI, no SQLAlchemy).

Built ONLY from scanner evidence:
  * findings      -> file CONTAINS finding, finding USES algorithm, finding USES library   (confirmed: the detection)
  * imports       -> file IMPORTS file       (confirmed if statically resolved to exactly one file;
                                              inferred if ambiguous / Java wildcard)
                     file IMPORTS library    (confirmed: an import statement of a known crypto library)
  * service.yaml  -> service CONTAINS file   (nearest service.yaml; repository default when there is none)

Blast radius of an algorithm / library / finding / file:
  direct    files that contain the selected crypto usage (or import the selected library)
  indirect  files that import a directly affected file, transitively (reverse IMPORTS closure). This means
            "depends on code that uses it", NOT "proven to call it": static imports cannot show the call path.
  confirmed vs inferred: an indirect file is confirmed only if a chain of confirmed edges reaches it.

Deterministic: node/edge ids are derived from content, all collections are sorted.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable

GRAPH_VERSION = 1
NODE_TYPES = ("service", "file", "finding", "algorithm", "library")
SELECTABLE = ("algorithm", "library", "finding", "file")
BAND_ORDER = ("Critical", "High", "Review", "Informational")
MAX_EVIDENCE_PER_EDGE = 5
MAX_DEPTH = 25
INFERRED_RESOLUTIONS = {"ambiguous", "wildcard"}


@dataclass
class Graph:
    nodes: dict[str, dict] = field(default_factory=dict)
    edges: dict[str, dict] = field(default_factory=dict)
    importers: dict[str, list[tuple[str, str]]] = field(default_factory=dict)   # file -> [(importing file, edge id)]
    findings_by: dict[str, list[str]] = field(default_factory=dict)              # node id -> finding node ids
    stats: dict = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------ construction helpers (dedupe by id)
    def node(self, nid: str, ntype: str, label: str, **attrs) -> dict:
        n = self.nodes.get(nid)
        if n is None:
            n = self.nodes[nid] = {"id": nid, "type": ntype, "label": label, **attrs}
        return n

    def edge(self, etype: str, src: str, dst: str, confidence: str, basis: str, evidence: dict | None) -> str:
        eid = f"{etype}:{src}->{dst}"
        e = self.edges.get(eid)
        if e is None:
            e = self.edges[eid] = {"id": eid, "type": etype, "source": src, "target": dst, "confidence": confidence,
                                   "basis": basis, "evidence": [], "evidence_count": 0}
        elif confidence == "confirmed" and e["confidence"] != "confirmed":
            e["confidence"], e["basis"] = "confirmed", basis      # a confirmed observation upgrades an inferred edge
        if evidence:
            e["evidence_count"] += 1
            if evidence not in e["evidence"]:
                e["evidence"].append(evidence)
                e["evidence"].sort(key=lambda x: (x.get("file", ""), x.get("line", 0), x.get("text", "")))
                del e["evidence"][MAX_EVIDENCE_PER_EDGE:]
        return eid

    def to_dict(self) -> dict:
        return {"version": GRAPH_VERSION,
                "nodes": [self.nodes[k] for k in sorted(self.nodes)],
                "edges": [self.edges[k] for k in sorted(self.edges)],
                "stats": self.stats, "limitations": self.limitations}


def file_id(path: str) -> str:
    return f"file:{path}"


def _band_rank(band: str | None) -> int:
    return BAND_ORDER.index(band) if band in BAND_ORDER else len(BAND_ORDER)


def _worst(a: str | None, b: str | None) -> str | None:
    return a if _band_rank(a) <= _band_rank(b) else b


def build_graph(findings: list[dict], imports: list[dict] | None, services: list[dict], repo_name: str,
                *, imports_truncated: bool = False, excluded: dict | None = None) -> Graph:
    """findings: scored, non-comment, non-suppressed finding records (see analysis.graph_inputs).
    imports: scanner import records, or None for scans analyzed before dependency extraction existed."""
    from qmc_scanner.services import service_for_path

    g = Graph()
    svc_meta = {s["service"]: s for s in services if s.get("service")}

    def file_node(path: str, language: str | None = None) -> str:
        fid_ = file_id(path)
        if fid_ not in g.nodes:
            svc = service_for_path(path, [s for s in services if s.get("service")]) or repo_name
            g.node(fid_, "file", path, path=path, language=language, service=svc, finding_count=0,
                   vulnerable_count=0, max_band=None, crypto=False)
            sid = f"service:{svc}"
            meta = svc_meta.get(svc)
            g.node(sid, "service", svc, metadata_file=meta.get("metadata_file") if meta else None)
            g.edge("CONTAINS", sid, fid_, "confirmed",
                   f"nearest service.yaml ({meta['metadata_file']})" if meta else "no service.yaml: repository default",
                   None)
        elif language and not g.nodes[fid_].get("language"):
            g.nodes[fid_]["language"] = language
        return fid_

    # ---- findings: CONTAINS + USES (confirmed by detection)
    for f in sorted(findings, key=lambda x: x["id"]):
        fnode = file_node(f["file"])
        fn = g.nodes[fnode]
        fn["crypto"] = True
        fn["finding_count"] += 1
        fn["vulnerable_count"] += int(bool(f["quantum_vulnerable"]))
        fn["max_band"] = _worst(fn["max_band"], f.get("band"))
        nid = f"finding:{f['id']}"
        g.node(nid, "finding", f"{f['id']} {f['algorithm']}", fid=f["id"], file=f["file"], line=f["line_start"],
               algorithm=f["algorithm"], operation=f["operation"], band=f.get("band"), qmp=f.get("qmp"), hndl=bool(f.get("hndl")),
               quantum_vulnerable=bool(f["quantum_vulnerable"]), already_pqc=bool(f.get("already_pqc")),
               confidence=f["confidence_level"], rule_id=f["rule_id"], service=f["service"],
               migration_rule=f.get("migration_rule"), migration_direction=f.get("migration_direction"),
               complexity=f.get("complexity"))
        ev = {"file": f["file"], "line": f["line_start"], "text": f["evidence"], "kind": "finding", "rule_id": f["rule_id"]}
        g.edge("CONTAINS", fnode, nid, "confirmed", f"detected by {f['rule_id']}", ev)
        aid = f"algorithm:{f['algorithm']}"
        a = g.node(aid, "algorithm", f["algorithm"], primitive=f["primitive"], quantum_vulnerable=False,
                   finding_count=0, max_band=None)
        a["finding_count"] += 1
        a["quantum_vulnerable"] = a["quantum_vulnerable"] or bool(f["quantum_vulnerable"])
        a["max_band"] = _worst(a["max_band"], f.get("band"))
        g.edge("USES", nid, aid, "confirmed", f"{f.get('api') or f['rule_id']} -> {f['algorithm']}", ev)
        g.findings_by.setdefault(aid, []).append(nid)
        g.findings_by.setdefault(fnode, []).append(nid)
        g.findings_by.setdefault(nid, []).append(nid)
        if f.get("library"):
            lid = f"library:{f['library']}"
            lib = g.node(lid, "library", f["library"], finding_count=0, importing_files=0)
            lib["finding_count"] += 1
            g.edge("USES", nid, lid, "confirmed", f"API {f.get('api') or '?'} of {f['library']}", ev)
            g.findings_by.setdefault(lid, []).append(nid)

    # ---- imports
    unresolved = ambiguous = internal = lib_imports = 0
    if imports is None:
        g.limitations.append("This scan was analyzed before dependency extraction existed: import relationships are not "
                             "available, so only direct usage is shown. Re-scan the repository to see indirect impact.")
    else:
        file_edges: list[tuple[str, str, str, dict]] = []
        for r in imports:
            ev = {"file": r["file"], "line": r["line"], "text": r["evidence"], "kind": r["kind"], "spec": r["spec"]}
            if r.get("crypto_library"):
                lib_imports += 1
                src = file_node(r["file"])
                g.nodes[src]["crypto"] = True
                lid = f"library:{r['crypto_library']}"
                lib = g.node(lid, "library", r["crypto_library"], finding_count=0, importing_files=0)
                if f"IMPORTS:{src}->{lid}" not in g.edges:
                    lib["importing_files"] += 1
                g.edge("IMPORTS", src, lid, "confirmed", f"import of {r['spec']}", ev)
            elif r["resolution"] == "resolved" or r["resolution"] in INFERRED_RESOLUTIONS:
                conf = "confirmed" if r["resolution"] == "resolved" else "inferred"
                if conf == "inferred":
                    ambiguous += 1
                internal += 1
                basis = ("import statically resolved to this file" if conf == "confirmed" else
                         f"{r['resolution']} import: {len(r['targets'])} candidate file(s); not proven")
                for t in r["targets"]:
                    file_edges.append((r["file"], t, conf, {**ev, "basis": basis}))
            elif r["resolution"] == "unresolved":
                unresolved += 1
        # Keep only the import edges that matter for crypto impact: those on a reverse path to a crypto file.
        rev: dict[str, list[tuple[str, str, dict]]] = {}
        for src, dst, conf, ev in file_edges:
            rev.setdefault(dst, []).append((src, conf, ev))
        crypto_files = sorted(n["path"] for n in g.nodes.values() if n["type"] == "file" and n["crypto"])
        keep: set[str] = set(crypto_files)
        queue = deque(crypto_files)
        while queue:
            cur = queue.popleft()
            for src, _, _ in sorted(rev.get(cur, []), key=lambda x: x[0]):
                if src not in keep:
                    keep.add(src)
                    queue.append(src)
        for src, dst, conf, ev in sorted(file_edges, key=lambda x: (x[0], x[1], x[3]["line"])):
            if src in keep and dst in keep:
                s, d = file_node(src), file_node(dst)
                basis = ev.pop("basis")
                eid = g.edge("IMPORTS", s, d, conf, basis, ev)
                pair = (s, eid)
                lst = g.importers.setdefault(d, [])
                if pair not in lst:
                    lst.append(pair)
        for lst in g.importers.values():
            lst.sort()
        if imports_truncated:
            g.limitations.append("The repository has more import statements than the analysis limit; some import "
                                 "relationships were not recorded, so indirect impact may be understated.")
        if unresolved:
            g.limitations.append(f"{unresolved} relative import(s) could not be resolved to a repository file (missing files, "
                                 "path aliases or generated code). Dependencies through them are not shown.")
        if ambiguous:
            g.limitations.append(f"{ambiguous} import(s) matched several candidate files or a whole Java package; those "
                                 "edges are marked inferred.")
    g.limitations.append("Static imports only: dynamic loading, reflection, dependency injection, runtime configuration "
                         "and calls across services or network APIs are not visible.")
    if excluded:
        if excluded.get("suppressed"):
            g.limitations.append(f"{excluded['suppressed']} finding(s) marked as false positives are excluded.")
        if excluded.get("comment_only"):
            g.limitations.append(f"{excluded['comment_only']} comment/documentation mention(s) are excluded (not executable evidence).")

    for lst in g.findings_by.values():
        lst.sort()
    types = {t: 0 for t in NODE_TYPES}
    for n in g.nodes.values():
        types[n["type"]] += 1
    g.stats = {"nodes": len(g.nodes), "edges": len(g.edges), "by_type": types,
               "crypto_files": sum(1 for n in g.nodes.values() if n["type"] == "file" and n["crypto"]),
               "dependent_files": sum(1 for n in g.nodes.values() if n["type"] == "file" and not n["crypto"]),
               "import_edges": sum(1 for e in g.edges.values() if e["type"] == "IMPORTS" and e["target"].startswith("file:")),
               "inferred_edges": sum(1 for e in g.edges.values() if e["confidence"] == "inferred"),
               "library_imports": lib_imports, "internal_imports": internal, "unresolved_imports": unresolved,
               "imports_available": imports is not None}
    return g


# ------------------------------------------------------------------ blast radius
class NodeNotFound(KeyError):
    pass


class NotSelectable(ValueError):
    pass


def _reverse_closure(g: Graph, start: Iterable[str], confirmed_only: bool) -> tuple[dict[str, tuple[int, list[str]]], bool]:
    """BFS over reverse IMPORTS edges. Returns ({file node: (depth, [edge ids from a start file to it])}, depth_capped).
    Visited-set based, so import cycles terminate."""
    seen: dict[str, tuple[int, list[str]]] = {s: (0, []) for s in start}
    queue = deque(sorted(seen))
    capped = False
    while queue:
        cur = queue.popleft()
        depth, path = seen[cur]
        if depth >= MAX_DEPTH:
            capped = capped or any(i not in seen for i, _ in g.importers.get(cur, []))
            continue
        for importer, eid in g.importers.get(cur, []):
            if confirmed_only and g.edges[eid]["confidence"] != "confirmed":
                continue
            if importer not in seen:
                seen[importer] = (depth + 1, path + [eid])
                queue.append(importer)
    return seen, capped


def blast_radius(g: Graph, node_id: str) -> dict:
    if node_id not in g.nodes:
        raise NodeNotFound(node_id)
    node = g.nodes[node_id]
    if node["type"] not in SELECTABLE:
        raise NotSelectable(node["type"])

    seed = list(g.findings_by.get(node_id, []))
    direct: dict[str, list[dict]] = {}                          # file node -> reasons with evidence
    for fnid in seed:
        f = g.nodes[fnid]
        direct.setdefault(file_id(f["file"]), []).append(
            {"reason": f"{f['fid']} {f['algorithm']} {f['operation'].replace('_', ' ')}", "confidence": "confirmed",
             "evidence": g.edges[f"CONTAINS:{file_id(f['file'])}->{fnid}"]["evidence"]})
    if node["type"] == "library":
        for e in sorted(g.edges.values(), key=lambda x: x["id"]):
            if e["type"] == "IMPORTS" and e["target"] == node_id:
                direct.setdefault(e["source"], []).append(
                    {"reason": f"imports {node['label']}", "confidence": "confirmed", "evidence": e["evidence"]})
    if node["type"] == "file":
        direct.setdefault(node_id, [])

    confirmed, _ = _reverse_closure(g, direct, confirmed_only=True)
    reach, capped = _reverse_closure(g, direct, confirmed_only=False)
    indirect = []
    for fn in sorted(reach):
        if fn in direct:
            continue
        conf = "confirmed" if fn in confirmed else "inferred"
        depth, path = confirmed[fn] if fn in confirmed else reach[fn]
        indirect.append({"node": fn, "file": g.nodes[fn]["label"], "service": g.nodes[fn]["service"], "depth": depth,
                         "confidence": conf,
                         "path": [{"edge": eid, "from": g.edges[eid]["source"], "to": g.edges[eid]["target"],
                                   "confidence": g.edges[eid]["confidence"], "basis": g.edges[eid]["basis"],
                                   "evidence": g.edges[eid]["evidence"][:2]} for eid in path]})
    indirect.sort(key=lambda x: (x["depth"], x["confidence"] != "confirmed", x["file"]))

    findings = [g.nodes[x] for x in seed]
    bands = {b: 0 for b in BAND_ORDER}
    for f in findings:
        if f.get("band") in bands:
            bands[f["band"]] += 1
    rules: dict[tuple, dict] = {}
    for f in findings:
        key = (f.get("migration_rule"), f.get("migration_direction"))
        r = rules.setdefault(key, {"rule_id": key[0], "direction": key[1], "findings": 0, "files": set()})
        r["findings"] += 1
        r["files"].add(f["file"])
    migration = [{**r, "files": len(r["files"])} for r in sorted(rules.values(), key=lambda r: (-r["findings"], str(r["rule_id"])))]
    complexity = sorted({f["complexity"] for f in findings if f.get("complexity") is not None})

    dfiles = sorted(direct)
    direct_services = sorted({g.nodes[f]["service"] for f in dfiles})
    indirect_services = sorted({x["service"] for x in indirect} - set(direct_services))
    limitations = []
    if not g.stats.get("imports_available"):
        limitations.append("Import relationships are unavailable for this scan (analyzed before dependency extraction); "
                           "indirect impact cannot be assessed. Re-scan to compute it.")
    elif not indirect:
        limitations.append("No repository file imports the directly affected files (according to resolvable static imports).")
    if any(x["confidence"] == "inferred" for x in indirect):
        limitations.append("Some indirect files are reachable only through inferred (ambiguous or wildcard) imports.")
    if capped:
        limitations.append(f"Import chains longer than {MAX_DEPTH} levels were not followed further; indirect impact may be larger.")
    if node["type"] == "library" and not seed:
        limitations.append(f"No detection rule matched an API call of {node['label']}; it is imported, but the algorithm "
                           "used could not be determined statically.")
    return {
        "node": node,
        "summary": {"direct_files": len(dfiles), "indirect_files": len(indirect),
                    "indirect_confirmed": sum(1 for x in indirect if x["confidence"] == "confirmed"),
                    "indirect_inferred": sum(1 for x in indirect if x["confidence"] == "inferred"),
                    "components": len(set(direct_services) | set(indirect_services)),
                    "findings": len(findings), "quantum_vulnerable": sum(1 for f in findings if f["quantum_vulnerable"]),
                    "hndl": sum(1 for f in findings if f["hndl"]), "max_depth": max((x["depth"] for x in indirect), default=0),
                    "depth_capped": capped},
        "direct": [{"node": f, "file": g.nodes[f]["label"], "service": g.nodes[f]["service"], "confidence": "confirmed",
                    "reasons": direct[f]} for f in dfiles],
        "indirect": indirect,
        "components": {"direct": direct_services, "indirect": indirect_services},
        "findings": sorted(findings, key=lambda f: (_band_rank(f.get("band")), -(f.get("qmp") or 0), f["fid"])),
        "severity": bands,
        "migration": {"by_rule": migration, "complexity_values": complexity,
                      "files_to_change": len(dfiles), "files_to_retest": len(indirect),
                      "note": "Counts of files and findings from scanner evidence only. QMC does not estimate effort or time."},
        "limitations": limitations,
        "meaning": {"direct": "Contains the selected cryptographic usage (or imports the selected library).",
                    "indirect": "Imports a directly affected file, possibly through other files. It depends on that code; "
                                "static analysis does not prove the cryptographic code path is called.",
                    "confirmed": "Every relationship on the path is an explicit, uniquely resolved import or a detection.",
                    "inferred": "At least one relationship on the path is an ambiguous or wildcard import."},
    }


def finding_record(data: dict, risk: dict | None, plan: dict | None) -> dict:
    """Flatten a stored scanner finding + its QMP breakdown + migration plan into a graph input record."""
    return {"id": data["id"], "file": data["file"], "line_start": data["line_start"], "algorithm": data["algorithm"],
            "primitive": data["primitive"], "operation": data["operation"], "library": data.get("library"),
            "api": data.get("api"), "service": data["service"], "evidence": data["evidence"], "rule_id": data["rule_id"],
            "confidence_level": data["confidence_level"], "quantum_vulnerable": data["quantum_vulnerable"],
            "already_pqc": data["already_pqc"], "band": (risk or {}).get("band"), "qmp": (risk or {}).get("qmp"),
            "hndl": bool(((risk or {}).get("hndl") or {}).get("flag")),
            "migration_rule": (plan or {}).get("rule_id"), "migration_direction": (plan or {}).get("direction"),
            "complexity": (plan or {}).get("complexity")}
