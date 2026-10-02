# Quantum Migration Copilot

*Discover your cryptography. Understand your quantum exposure. Plan your migration.*

Prototype decision-support tool for post-quantum cryptography migration planning.
Deterministic static analysis; the AI Copilot (later phase) is advisory only.
Specification: `docs/knowledge-pack/` (start with `DOCUMENT_MAP.md`).

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
