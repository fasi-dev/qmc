# Architecture

```
React + TypeScript SPA (frontend/src)                      FastAPI monolith (backend/app)                   Scanner (scanner/qmc_scanner)
───────────────────────────────────                        ───────────────────────────────                  ─────────────────────────────
ScannerPanel ─ upload / demo ────────────── POST /api/scans, /api/demo/acme ── ingestion/ (safe extraction, redaction)
Dashboard ──────────────────────────────── GET  /summary                      analysis.py ── scan_tree() ──► engine.py
Inventory / FindingDetail ──────────────── GET  /findings, /findings/{fid}       │   persist findings,         ├ pyscan.py   (ast)
DependencyGraph (graphLayout.ts) ───────── GET  /graph, /graph/blast-radius      │   risk, snippets,           ├ lexers.py + textscan.py (Java, JS/TS)
Readiness ──────────────────────────────── GET  /readiness                       │   import records           ├ confscan.py (config, X.509)
Simulator ──────────────────────────────── GET  /simulate                        │                             ├ imports.py  (import extraction/resolution)
Planner ────────────────────────────────── GET  /migration                       ├ risk.py      (QMP)          └ rules/      (78 versioned YAML rules)
Report download ────────────────────────── GET  /report.md                       ├ migration.py (07 rules)
                                                                                 ├ graph.py     (graph + blast radius)
     every /api/scans/{id}/... call carries X-QMC-Scan-Token ──► deps.scan_access├ readiness.py (PQC readiness)
                                                                                 ├ simulator.py (migration simulator)
                                                                                 └ db.py        (SQLite via SQLAlchemy)
```

## Pipeline

1. **Ingestion** (`backend/app/ingestion/`): archive type by magic bytes; bounded extraction (size, count,
   compression ratio, path traversal, links, devices); secret redaction; `service.yaml` metadata.
2. **Scan** (`scanner/`): deterministic, parse-only. Detections become schema-validated findings; imports are
   extracted and resolved against the tree (Python ast; Java/JS/TS masked lexer; tsconfig paths; Java same-package).
3. **Analysis** (`analysis.py`): QMP scoring, persistence (findings, risk, ±3-line redacted snippets, import records
   in `scans.graph`), then the extracted source tree is deleted.
4. **Derived views** (pure modules, no I/O): `graph.py` builds the dependency graph from findings + import records;
   `readiness.py` and `simulator.py` use the graph and the finding records. `analysis.graph_context()` caches them per
   scan state (analysis run + suppression state, LRU 16); readiness is memoized per context.

## Design principles

* **Evidence only.** Every edge, blocker, recommendation and simulated change cites scanner evidence. Ambiguous
  relationships are *inferred*, never presented as confirmed.
* **No invented numbers.** No readiness percentage, no effort estimates; sizes are published parameters.
* **Never execute scanned code.** Python is parsed with `ast`; other languages with a lexer; configs are composed,
  never constructed; certificates are parsed with `cryptography`.
* **Deterministic.** Sorted traversal, content-derived ids; the same input gives byte-identical output (tested).
* **Bounded work.** Regexes are linear (adversarial-input tests), import records capped at 100,000, blast radius
  depth 25, graph rendering culled above 300 nodes. Every limit that is hit is reported.

## Security model

No accounts. A per-scan bearer token (256-bit, returned once, stored as SHA-256) authorizes every scan route; wrong
tokens get the same 404 as unknown scans. An optional operator token lists scans. Scan creation is rate-limited per
client, analyses are capped by a concurrency gate, scans are deleted after the retention period. Errors use a
stable `{"error": {"code", "message"}}` envelope and never echo internal paths.

## Persistence

SQLite (`QMC_DATA_DIR/qmc.db`), schema created with `create_all` plus additive, idempotent upgrades in
`db.upgrade_schema` (columns `scans.token_hash`, `scans.graph`; unique index `findings(scan_id, fid)`). No data is
rewritten by upgrades. There is no Alembic yet; add a baseline before the next non-additive change.

## Frontend

Hash-routed React app without a UI framework or graph library. `graphLayout.ts` is a pure, unit-tested layered
layout used by the dependency graph and by the simulator's architecture views. Shared types are in `api.ts`.
