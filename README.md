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
| Scanner: Python (AST), Java, JS/TS, YAML/JSON, nginx/SSH, Dockerfile/CI, X.509 certificates (78 versioned rules; MD5 and legacy ciphers as classical hygiene) | done |
| QMP risk engine (`06`), HNDL flag, guard rules, metadata badges | done |
| Inventory API + UI (filters, search, CSV, suppression/false positive) | done |
| Per-scan access tokens, rate limiting, retention, capacity cap, atomic analysis | done (see Access model) |
| CI (scanner, backend, frontend, Docker builds) | workflow added (`.github/workflows/ci.yml`) |
| Dashboard, finding detail (evidence snippet, factor bars), scanner screen with Acme demo loader | done |
| Migration rules (`07`) + planner screen + detail panel | done |
| Markdown report with limitations | done |
| Dependency graph / blast radius (`08`) | **not started** |
| PQC Lab (liboqs ML-KEM / ML-DSA) | **not started** |
| AI Copilot | **not started** |
| PDF report, diff scanning, Go/Rust/C# | not started (stretch) |

## Run locally
    python -m venv .venv && source .venv/bin/activate
    pip install -r backend/requirements-dev.txt && pip install -e scanner
    cd backend && uvicorn app.main:app --port 8000        # terminal 1
    cd frontend && npm install && npm run dev             # terminal 2 -> http://localhost:5173
Then open **Repository Scanner -> Load Acme Payments demo**. Docker: `docker compose up --build` (images are built in CI).
Deployment, environment variables and the Render checklist: `docs/DEPLOYMENT.md`.

## Tests
    cd scanner && pytest        # deterministic scanner (rules, config, certificates, determinism, DoS resistance)
    cd scanner && python -m eval.evaluate   # precision/recall/F1 on the hand-labelled set (see scanner/eval/README.md)
    cd backend && pytest        # ingestion, risk engine, migration rules, analysis API, report
    cd frontend && npm run build && npm test   # strict TS build + UI end-to-end tests against a real backend (jsdom)

## Access model
No accounts. Creating a scan (upload or demo) returns an `access_token` **once**; every `/api/scans/{id}/...` call
needs it in the `X-QMC-Scan-Token` header (the UI stores it in the browser). Only a SHA-256 of the token is stored.
A wrong token gets the same 404 as an unknown scan. Listing all scans needs the operator token (`QMC_ADMIN_TOKEN`).
Scans are deleted after `QMC_RETENTION_HOURS` (default 24); scan creation is rate-limited per client.

## API (all under /api)
    POST /scans?filename=x.zip (raw body)  ->  ingest           POST /scans/{id}/analyze  -> scan + score + persist
    POST /demo/acme                        ->  bundled demo, one call
    GET  /scans (operator only), /scans/{id}, /scans/{id}/summary, /scans/{id}/findings?band=&algorithm=&service=&q=&vulnerable=...
    GET  /scans/{id}/findings/{fid}  (evidence, snippet, risk factors, migration)   GET /scans/{id}/findings.csv
    POST|DELETE /scans/{id}/findings/{fid}/suppress   GET /scans/{id}/migration   GET /scans/{id}/report.md
Errors: `{"error": {"code", "message"}}`.

## Layout
- `frontend/` React + TypeScript + Vite
- `backend/`  Python + FastAPI monolith
- `scanner/`  Python package (deterministic discovery engine)
- `docs/knowledge-pack/` the source-of-truth spec

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

## Audit
`docs/AUDIT.md`: November 2026 repository audit (verified features, confirmed issues, open security items such as
missing authentication on the public demo, ranked improvements and roadmap).
