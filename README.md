# Quantum Migration Copilot

*Discover your cryptography. Understand your quantum exposure. Plan your migration.*

Prototype decision-support tool for post-quantum cryptography migration planning. Upload a repository; it is safely ingested,
statically scanned (deterministic, no AI), scored with the transparent **Quantum Migration Priority** model, and turned into an
inventory, risk ranking, migration plan and report. Specification: `docs/knowledge-pack/` (start with `DOCUMENT_MAP.md`).
Demo script with real numbers: `docs/DEMO.md`.

## Status

| Area | State |
|---|---|
| Safe ingestion (zip/tar, bombs, traversal, symlinks, redaction) | done, adversarially tested |
| Scanner: Python (AST), Java, JS/TS, YAML/JSON, nginx/SSH, Dockerfile/CI, X.509 certificates (74 versioned rules) | done |
| QMP risk engine (`06`), HNDL flag, guard rules, metadata badges | done |
| Inventory API + UI (filters, search, CSV, suppression/false positive) | done |
| Dashboard, finding detail (evidence snippet, factor bars), scanner screen with Acme demo loader | done |
| Migration rules (`07`) + planner screen + detail panel | done |
| Markdown report with limitations | done |
| Dependency graph / blast radius (`08`) | **not started** |
| PQC Lab (liboqs ML-KEM / ML-DSA) | **not started** |
| AI Copilot (template mode) | **not started** |
| PDF report, diff scanning, Go/Rust/C# | not started (stretch) |

## Run locally
    python -m venv .venv && source .venv/bin/activate
    pip install -r backend/requirements.txt && pip install -e scanner
    cd backend && uvicorn app.main:app --port 8000        # terminal 1
    cd frontend && npm install && npm run dev             # terminal 2 -> http://localhost:5173
Then open **Repository Scanner -> Load Acme Payments demo**. (Docker: `docker compose up --build`; not verified in CI here.)

## Tests
    cd scanner && pytest        # deterministic scanner (rules, config, certificates, determinism, DoS resistance)
    cd backend && pytest        # ingestion, risk engine, migration rules, analysis API, report
    cd frontend && npm run build && npm test   # strict TS build + UI end-to-end tests against a real backend (jsdom)

## API (all under /api)
    POST /scans?filename=x.zip (raw body)  ->  ingest           POST /scans/{id}/analyze  -> scan + score + persist
    POST /demo/acme                        ->  bundled demo, one call
    GET  /scans, /scans/{id}, /scans/{id}/summary, /scans/{id}/findings?band=&algorithm=&service=&q=&vulnerable=...
    GET  /scans/{id}/findings/{fid}  (evidence, snippet, risk factors, migration)   GET /scans/{id}/findings.csv
    POST|DELETE /scans/{id}/findings/{fid}/suppress   GET /scans/{id}/migration   GET /scans/{id}/report.md
Errors: `{"error": {"code", "message"}}`.

## Layout
- `frontend/` React + TypeScript + Vite
- `backend/`  Python + FastAPI monolith
- `scanner/`  Python package (deterministic discovery engine)
- `docs/knowledge-pack/` the source-of-truth spec

## Run (Docker)
    docker compose up --build      # UI :5173, API :8000

## Run (local dev)
    # backend
    python -m venv .venv && source .venv/bin/activate
    pip install -r backend/requirements.txt && pip install -e scanner
    cd backend && uvicorn app.main:app --port 8000
    # frontend (second terminal)
    cd frontend && npm install && npm run dev

## Test
    cd scanner && pytest
    cd backend && pytest           # includes the adversarial ingestion suite (tests/ingestion/)
    cd frontend && npm run build   # type-check + production build

## Scanner (Phase 3)
    python -m qmc_scanner sample-repos/acme-payments --summary          # table
    python -m qmc_scanner <tree> --manifest <manifest.json> > findings.json   # full JSON (05 section 4 schema)
Rules: `scanner/qmc_scanner/rules/<lang>/<RULE_ID>.yaml` (semver, strict loader). Python is parsed with `ast`
(never imported/executed); Java and JS/TS use a comment/string-aware lexer plus anchored regex rules.

## Ingestion API (Phase 2)
    curl -X POST --data-binary @repo.zip -H 'Content-Type: application/octet-stream' \
         'http://localhost:8000/api/scans?filename=repo.zip'      # -> 201 + manifest summary
    curl http://localhost:8000/api/scans/<scan_id>                # summary
    curl 'http://localhost:8000/api/scans/<scan_id>?include_files=true'
    curl -X DELETE http://localhost:8000/api/scans/<scan_id>/tree # drop extracted tree, keep manifest
    curl -X DELETE http://localhost:8000/api/scans/<scan_id>      # drop everything

Errors use `{"error": {"code": "...", "message": "..."}}` with codes such as `unsafe_path`,
`unsafe_entry_type`, `archive_bomb`, `extracted_too_large`, `too_many_files`,
`archive_too_large`, `unsupported_archive_type`, `malformed_archive`, `encrypted_entry`.

## Decisions log
See `DECISIONS.md` (spec ambiguities and how they were resolved).
