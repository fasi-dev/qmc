# Quantum Migration Copilot

*Discover your cryptography. Understand your quantum exposure. Plan your migration.*

Evidence-driven post-quantum cryptography (PQC) readiness and migration analysis. Upload a repository; it is safely
ingested, statically scanned (deterministic, no AI, nothing executed), scored with the transparent **Quantum Migration
Priority** model, and turned into:

**Scan → Findings → Dependency graph → PQC readiness → Migration simulator → Report**

* **Inventory** of cryptographic usage with file:line evidence, confidence and QMP priority.
* **Dependency graph and blast radius**: which files use an algorithm/library directly and which depend on them through
  imports, confirmed vs inferred (`docs/DEPENDENCY_GRAPH.md`).
* **PQC readiness assessment**: rule-based level (no percentage), blockers, categories, prioritized recommendations,
  library PQC support with sources, and what was not analyzed (`docs/PQC_READINESS.md`).
* **Migration impact simulator**: current vs proposed (e.g. ECDH → hybrid ML-KEM, ECDSA → ML-DSA), affected files,
  integration changes with call sites, compatibility considerations, limitations (`docs/MIGRATION_SIMULATOR.md`).
* **Markdown report** with all of the above.

Architecture: `docs/ARCHITECTURE.md`. Specification: `docs/knowledge-pack/`. Demo script: `docs/DEMO.md`.
QMC never certifies an application as quantum-safe.

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
| Dependency graph + blast radius (Python/Java/JS/TS imports, Java same-package, tsconfig paths; evidence + confirmed/inferred) | done |
| PQC readiness assessment (`docs/PQC_READINESS.md`) | done |
| Migration impact simulator (`docs/MIGRATION_SIMULATOR.md`) | done (planning only) |
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
Run from the repository root with Python 3.12 and Node.js 22 (the versions CI uses; jsdom 30 needs Node >= 22.22).

    python -m venv .venv && source .venv/bin/activate
    pip install -r backend/requirements-dev.txt -e scanner
    (cd scanner && pytest -q && python -m eval.evaluate)   # scanner rules, imports, DoS resistance; precision/recall/F1
    (cd backend && pytest -q)                              # ingestion, risk, migration, graph, readiness, simulator, API, access control
    (cd frontend && npm ci && npm run build && npm test)   # strict TS build + UI tests against a real backend (started by vitest.global.ts)
    docker build -f backend/Dockerfile -t qmc-backend . && docker build -t qmc-frontend frontend

The UI tests start `uvicorn` from `backend/` with `python3` (or `.venv/bin/python`, or `$QMC_PYTHON`), so the backend
requirements must be installed first. The graph / readiness / simulator logic is pure Python and can be tested without
FastAPI: `cd backend && PYTHONPATH=../scanner pytest --noconftest tests/test_graph.py tests/test_readiness.py tests/test_simulator.py`.
CI (`.github/workflows/ci.yml`) runs all of the above on every push.

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
    GET  /scans/{id}/graph, /scans/{id}/graph/blast-radius?node=algorithm:ECDH
    GET  /scans/{id}/readiness          GET /scans/{id}/simulate?node=algorithm:ECDSA&target=ML-DSA-65
Errors: `{"error": {"code", "message"}}`.

## Supported inputs and limits
* Code: Python (ast), Java and JavaScript/TypeScript (comment/string-aware lexer). Config: nginx, sshd/ssh, YAML, JSON
  (incl. JSONC), Dockerfile, CI files. Certificates: PEM X.509. Not covered: Go, C/C++, C#, Rust, Kotlin, PHP, Ruby,
  binaries, container images, dependency manifests/versions.
* Large repositories: graph, blast-radius and simulator responses are gzip-compressed; the UI renders the first 150-200
  entries of long file lists ("Show all" reveals the rest; counts are always complete) and the simulator's architecture
  diagram shows at most 40 files (stated on the page). Import records are capped at 100,000 per scan (reported).
* Static analysis cannot see algorithms chosen at runtime, dynamically loaded code, reflection, external services or
  library defaults (e.g. whether hybrid TLS is negotiated). Each view lists its own limitations.

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
