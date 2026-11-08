# QMC: Repository audit and first improvement milestone

*Audit date: 2026-11-08. Baseline: `main` @ `4057826` ("fix(cors): allow deployed frontend"). Work branch: `audit/p0-p1-fixes`.*

This document separates **confirmed problems** (reproduced, with the command or test that shows them) from
**potential improvements** (judgement calls, not defects). Nothing here claims that QMC is secure, accurate or
production-ready; where a number is given, the way it was measured is given too.

**Environment note (affects what could be verified).** The audit environment had no network access for package
installs. Available: Python 3.13, pytest, PyYAML, cryptography, Node 22. Not available: FastAPI, SQLAlchemy, npm
packages. Therefore:

| Suite | Run here? | Result |
|---|---|---|
| `scanner/` pytest | yes | **338 passed** (baseline 301 passed) |
| `backend/tests/test_risk.py`, `test_migration.py` (pure Python, run with `--noconftest`) | yes | **63 passed**; 1 error = the one test that needs the FastAPI client fixture (environment, not a failure) |
| rest of `backend/` pytest (API, ingestion, DB) | **no** | needs FastAPI/SQLAlchemy; run locally (see section 13) |
| `frontend/` build + vitest | **no** | needs `npm install` |
| Docker images | **no** | not built |

---

## 1. Actual architecture (from the source, not the README)

```
browser ── React 18 + TS + Vite SPA (hash routing, no state library, fetch wrapper in src/api.ts)
   │  JSON over HTTP (CORS allow-list in backend/app/main.py)
   ▼
FastAPI monolith  backend/app/
   routes_scans.py     POST /api/scans (raw-body streamed upload) ─► ingestion/ (archive.py, redaction, metadata)
   routes_analysis.py  POST /scans/{id}/analyze, /demo/acme, GET summary|findings|csv|migration|report.md, suppress
   analysis.py         scan → score → persist → purge tree; query/summary/CSV helpers
   risk.py             QMP formula + guard rules + HNDL flag (pure functions)
   migration.py        deterministic rules R-01..R-12 (pure functions)
   report.py           Markdown report
   db.py               SQLAlchemy 2 models (ScanRow, FindingRow), SQLite file, create_all() (no migrations)
   │
   ▼
qmc_scanner (separate installable package)  scanner/qmc_scanner/
   engine.py   os.walk (sorted, no symlinks, skip dirs) → classify → per-language scanner → dedupe → number → validate
   pyscan.py   Python: ast.parse + import table → fully-qualified call names (never imports/executes)
   lexers.py   Java/JS/TS: comment/string/regex/template-aware lexer producing a same-length "code" + mask
   textscan.py anchored regex rules on lexed code (match must start in code, not string/comment)
   confscan.py nginx/ssh/Docker/CI directives, YAML/JSON (compose-only, alias-safe), X.509 PEM (cryptography lib)
   rules/      74 versioned YAML rules, strict loader (unknown keys, bad regex, bad enum → error)
   redaction.py secrets redaction (applied at ingestion AND to every evidence string)
```

Data flow: upload → magic-byte type detection → bounded extraction with redaction → `manifest.json` + `service.yaml`
metadata → static scan → per-finding QMP score → SQLite rows (finding JSON + risk JSON + ±3-line redacted snippet)
→ extracted tree deleted. Re-analysis is refused (409) because the tree is gone.

Assessment: the architecture fits the project's size. Scanner, risk and migration are pure, deterministic and
independently testable; the API layer is thin. No circular imports were found. The main structural weaknesses
are operational (no auth, no job model, no DB migrations), not modular.

## 2. Features that are genuinely implemented (verified in code and tests)

| Feature | Where | Evidence |
|---|---|---|
| Safe archive ingestion: ZIP/TAR(.gz/.bz2/.xz) by magic bytes; traversal, symlink/hardlink/device, duplicate, encrypted-entry rejection; size, count and compression-ratio caps; O_EXCL\|O_NOFOLLOW writes, 0600 files | `backend/app/ingestion/archive.py` | `backend/tests/ingestion/test_archive_adversarial.py` (not run here; code reviewed) |
| Secret redaction preserving line numbers | `scanner/qmc_scanner/redaction.py` | scanner + backend tests |
| Python AST scanning with import resolution | `pyscan.py` | positive/negative corpus |
| Java + JS/TS lexical scanning (comments/strings masked) | `lexers.py`, `textscan.py` | corpus + DoS tests |
| Config scanning (nginx, sshd, Dockerfile/CI, YAML/JSON) and X.509 parsing (key type, SHA-1 signature, expiry) | `confscan.py` | `test_config_rules.py` |
| 74 versioned rules, strict loader | `rules.py` | `test_rules_loader.py` |
| QMP score with factor explanations, guard rules, HNDL flag, metadata-missing badges | `backend/app/risk.py` | `test_risk.py` (run here) |
| Role-aware migration rules (KE→ML-KEM, signatures→ML-DSA/SLH-DSA, unknown→human review) | `backend/app/migration.py` | `test_migration.py` (run here) |
| Inventory API with filters, facets, CSV export (formula-injection guard), suppression with reason | `analysis.py`, `routes_analysis.py` | API tests (not run here) |
| Markdown report | `report.py` | `test_report.py` (not run here) |
| UI: dashboard, scanner + demo loader, inventory, finding detail (evidence snippet, factor bars, migration panel), planner | `frontend/src/*.tsx` | `App.test.tsx` (not run here) |
| Docker Compose with non-root, read-only backend container | `docker-compose.yml`, `backend/Dockerfile` | not built here |

## 3. Partially implemented, missing, or only documented

| Item | State |
|---|---|
| **AI Copilot (template mode)** | **Not implemented.** Only `QMC_LLM_BACKEND` and a `copilot_mode` field in `/api/health` exist (`main.py`). The health endpoint therefore advertises a mode for a feature that does not exist. |
| Dependency graph / blast radius (`08`) | Not started (README is honest about this). |
| PQC Lab | Not started. `sample-repos/.../pqc-lab/kem_demo.py` is only fixture code to be scanned. |
| Migration progress tracking | Not implemented; `migration_status` per service is derived ("not started" / "in progress: PQC already present"), not tracked. |
| `qmc-ignore.yaml` suppression file | Not implemented (UI suppression is). |
| `Settings.scan_timeout_seconds` | **Dead config**: `analysis.analyze_scan` never passes it to `scan_tree` (the scanner's own 300 s default applies). |
| Partial scans / skipped files | The scanner reports `status: "partial"` on timeout and lists `parse_error` / `skipped_minified` files, and the backend stores them in `ScanRow.analysis`, **but neither the UI nor the report shows them**. A timed-out or partly unparsable scan looks complete. |
| "Report" nav item | Listed as "soon" in `App.tsx` `LATER`, although the Markdown report works (dashboard button). |
| CI/CD | **No `.github/workflows`.** Nothing runs the tests on push. |
| DB migrations | None (`Base.metadata.create_all`). Any schema change needs a manual reset of `qmc.db`. |
| Language coverage | Python, Java, JS/TS, config. No Go, C/C++, C#, Rust, Kotlin, PHP, Ruby. Dependency manifests (`requirements.txt`, `package.json`, `pom.xml`) are not inventoried as libraries. |

## 4. Critical bugs and security issues

### Confirmed and fixed on this branch

| # | Issue | File / function | How it was confirmed | Commit |
|---|---|---|---|---|
| B1 | **UTF-8 BOM hides all findings in a Python file.** `ast.parse` rejects U+FEFF → `parse_error`, zero findings (silent false negative for files saved by Windows editors). | `scanner/qmc_scanner/engine.py` `scan_tree` | probe file with BOM → `files_skipped=[parse_error]`; regression test fails on `main` | `f246712` |
| B2 | **Context inference used substrings**, so `processor.py`/`compressor.py` (“sso”), `author_list()` (“auth”), `tokenizer.py` (“token”), `artifactory` (“artifact”) got wrong contexts. Context decides the RSA **role** (signature vs key establishment), which changes QE and MC and therefore the QMP score. | `scanner/qmc_scanner/context.py` `infer_context` | probe: RSA keygen in `processor/compressor.py` → `authentication` | `4949a0e` |
| B3 | **MD5 not detected at all** (Python `hashlib.md5`/`hashlib.new("md5")`, `hashes.MD5`, PyCryptodome, Java `MessageDigest`, Node `createHash`, forge, crypto-js). It was excluded by the spec catalog, and tests asserted it. Had it been detected as a generic hash, migration rule R-10 would have said "Retain". | hash rules; `risk.py` `_qe`; `migration.py` `pick_rule` | probe + existing negative tests | `2840f3c` (self-contained; revert it if you want the original catalog) |
| B4 | **Crypto calls inside JS/TS template interpolations were missed**: the whole template literal was masked as a string. | `scanner/qmc_scanner/lexers.py` `lex` | probe ``` `${createHash("sha256")…}` ``` → no finding | `ce0ef85` |
| B5 | Comment mention rule produced a spurious **classical "DSA"** for every comment naming ML-DSA or SLH-DSA. | `rules/generic/GEN-COMMENT-001.yaml` | probe | `a597d0e` |
| B6 | **AES-128 mislabelled "classical hygiene"** (badge and cap reason). AES-128 is not deprecated; its QE 1 is a Grover key-size margin. | `backend/app/risk.py` `score` | `test_risk.py` | `4b2fe3f` |
| B7 | **HNDL silently "no" when metadata is missing.** Midpoint defaults (DS 2, IE 1.5) can never meet the HNDL thresholds, so missing `data_classification`/`internet_exposed` hid HNDL without saying so. Now a `HNDL not assessed: metadata missing` badge. Flag, score and band unchanged. | `risk.py` `score` | `test_risk.py` | `4b2fe3f` |
| B8 | **CSV formula injection guard incomplete**: TAB and CR prefixes were not neutralised (OWASP lists both). | `backend/app/analysis.py` `export_csv` | verified in isolation (backend suite not runnable here) | `608fe91` |
| B9 | **Windows test failure** `ValueError: the environment variable is longer than 32767 characters`. Root cause: pathological-input tests embed multi-megabyte sources in parametrized test IDs (longest **1,470,295** chars); pytest exports the current ID in `PYTEST_CURRENT_TEST`. **Test-harness problem, not a scanner bug.** IDs now capped (longest 129). | `scanner/tests/conftest.py` | `pytest --collect-only` length measurement | `08a8af0` |

### Confirmed, NOT fixed (needs your decision or a runnable backend)

| # | Issue | File / function | Why it matters | Proposed solution | Priority |
|---|---|---|---|---|---|
| S1 | **No authentication or tenant isolation on a public deployment.** `GET /api/scans` lists every scan from every visitor; anyone with a scan id can read findings/evidence/snippets, export CSV, suppress findings or `DELETE` the scan. Scan ids are UUIDv4 (unguessable) but the list endpoint discloses them. | `routes_analysis.py` `list_scans`; `routes_scans.py` `delete_scan_route` | Uploaded code snippets (redacted, but still proprietary code) of one user are visible to all others on `qmc-frontend.onrender.com`. | Minimum: remove or gate `GET /api/scans` and `DELETE` behind an admin token env var; issue a per-scan secret (returned once at upload, required as a header) so only the uploader can read it. Changes the API contract and the deployed frontend: **needs approval**. | **P0** |
| S2 | **Unbounded resource use.** No rate limiting; `POST /api/demo/acme` and uploads create a new workspace + DB rows per call with no retention/cleanup; analysis runs synchronously in the request (up to 300 s, threadpool-bound). | `routes_analysis.py` `load_demo`, `analyze`; `routes_scans.py` `create_scan` | Disk exhaustion and worker starvation on the public instance. | Retention job (delete scans older than N hours), per-IP rate limit, cap concurrent analyses (semaphore), reuse a cached demo scan. | **P0** |
| S3 | **Race condition: concurrent `analyze` on the same scan** passes the `status == "analyzed"` check twice (check-then-act) and inserts **duplicate findings**. The UI disables the button while busy, which only hides it. | `analysis.py` `analyze_scan` | Data integrity: double counts in every total. | Atomic claim: `UPDATE scans SET status='analyzing' WHERE id=:id AND status='ingested'`; if `rowcount == 0` → 409; reset to `ingested` on failure. Add a `UniqueConstraint(scan_id, fid)`. Not done here because SQLAlchemy code could not be run. | **P0** |
| S4 | **Partial scans look complete** (see section 3). | `report.py`, `Dashboard.tsx` | A user can be told "0 findings in service X" when files were never parsed. | Show `analysis.scan_status`, `files_skipped` (by reason) on the dashboard and in report section 7; warning banner when `partial` or `parse_error > 0`. | **P1** |
| S5 | Frontend container runs the **Vite dev server** (`npm run dev`) and `npm install` without the lockfile. | `frontend/Dockerfile` | Dev server in production, non-reproducible builds. | Multi-stage: `npm ci && npm run build`, serve `dist/` with a static server (nginx/caddy). Check first how Render actually builds the frontend: **deployment change, needs approval**. | P1 |
| S6 | CORS origins hard-coded, including the production domain. | `main.py` | Every environment change is a code change. | `QMC_CORS_ORIGINS` env var defaulting to the current list (behaviour-preserving). Production config, so left for approval. | P2 |

Checked and found sound (no change needed): archive path traversal, symlink/hardlink rejection, ZIP and TAR bombs
(declared-size and streaming checks), magic-byte typing, `yaml.safe_load`/`compose` only, scan-id validation as
UUIDv4 before any filesystem access, SQL built only through SQLAlchemy expressions (no string SQL), uploaded code
never imported or executed, X.509 parse-only. SSRF: not applicable (no remote-repository ingestion exists).

## 5. Weak areas in the scanner

Confirmed by probes (`scanner/eval/cases.py`, `kind="limitation"`):

1. **No dataflow.** Function aliases (`gen = rsa.generate_private_key; gen(...)`), `getattr(hashlib, "sha1")`,
   algorithm names in constants (`static final String ALG = "RSA"`) or config objects (`createHash(cfg.hash)`) are
   missed. A cheap improvement: resolve same-file string constants and simple aliases (single assignment, module
   scope) before rule matching.
2. **Catalog gaps for weak symmetric crypto in code**: DES/3DES (`DES3.new`, `"DESede/…"`), RC4, Blowfish are not
   detected (only as nginx cipher-suite hygiene). Same treatment as MD5 is recommended (classical hygiene, never
   PQC-mapped).
3. **Python import table is file-global** (`ast.walk` over all imports), so an import inside one function applies
   everywhere and shadowing is ignored. Low impact; documented.
4. **Rule matching is by API, not by key material**: RSA key sizes are only captured when literal.
5. **Duplicate-looking findings by design** (one API usage = one finding, DECISIONS #29): `AESGCM` key generation +
   encryption, `ec.ECDSA(hashes.SHA256())` → ECDSA + SHA-256. Correct for an inventory, but see QMP item 3.
6. **Deadline is checked between files only.** Per-file cost is bounded by the linear lexers and the 10,000-char line
   cap (DoS tests pass), so this is acceptable; noted for honesty.
7. **Text decoding uses UTF-8 with replacement.** UTF-16 sources would be scanned as garbage (no finding, no
   warning). Rare in code; a BOM-based UTF-16 detection would be cheap.

Evaluation (new, `scanner/eval/`): 22 hand-labelled cases written separately from the unit-test corpus.
Precision 1.000; recall 1.000 on realistic and negative cases; overall recall 0.812, where all 6 misses are the
known limitations above. On the same set, baseline `main` had realistic recall 0.846. **This is a small,
author-written set**; several cases were added after the bugs were found, so it shows "no known regressions",
**not** accuracy on real repositories. See `scanner/eval/README.md`.

## 6. Weak areas in QMP scoring (`backend/app/risk.py`)

Formula (unchanged): `QMP = clamp(round_half_up(2·QE + 2·DS + 1.5·IE + 1.5·BC − 1.5·MC), 0, 20)`; bands
0–3 Informational, 4–9 Review, 10–14 High, 15–20 Critical; guard rules: QE 0 → Informational; QE 1 → capped at
Review; non-high confidence → capped at Review. HNDL is a separate flag (key establishment ∧ DS ≥ 3 ∧ IE ≥ 2 ∧
lifetime ≥ 5 y; "elevated" at ≥ 10 y). Scores are deterministic (tested).

Potential improvements (methodology, not bugs: they need your decision because they change scores):

1. **Migration complexity lowers priority.** That is defensible for "quick wins first", but it is the opposite of
   Mosca's inequality (shelf life X + migration time Y > time to a CRQC Z ⇒ act now), where *harder* migrations
   must *start earlier*. Recommendation: keep QMP as is, but show MC separately as "lead time" and document the
   trade-off, or make the MC sign configurable. Be ready to explain this choice in an interview.
2. **Weights are not empirically derived.** The doc correctly calls QMP an internal prototype. Keep that wording;
   add a sensitivity table (how bands change if each weight ±0.5) to `06_RISK_SCORING.md`.
3. **Aggregate counts double-count one usage** (e.g. AES-GCM keygen + encrypt = 2; `Critical` count per service
   counts every API call). Proposal: add a "distinct (file, algorithm, role)" count next to the raw count on the
   dashboard; do not merge findings in the scanner.
4. **IE is binary** (internet-exposed 3, else 0): partner/VPN/internal-with-TLS-termination cannot be expressed.
   Add an optional `exposure: public|partner|internal` field with 3/2/0, keeping the bool for compatibility.
5. **NIST IR 8547 (final, 2026-10-27)** now deprecates *all* quantum-vulnerable public-key algorithms after 2030 and
   disallows them after 2035, regardless of key size. QMC does not use dates in scoring (good: no false precision),
   but the report could add a one-line "NIST transition: deprecated after 2030 / disallowed after 2035" note on
   quantum-vulnerable findings. Added to `03_NIST_STANDARDS.md` in this milestone.

## 7. Weak areas in migration planning (`backend/app/migration.py`)

Checked against FIPS 203/204/205 and NIST IR 8547: the directions are correct (RSA/DH/ECDH key establishment →
ML-KEM; RSA/ECDSA/EdDSA/DSA signatures → ML-DSA or SLH-DSA; symmetric/hash/MAC never mapped to PQC; unknown role →
human review). The KEM caveat ("KEM → KDF → AEAD, not encrypt-with-RSA rewritten") and the hybrid example
(X25519 + ML-KEM-768) are accurate.

Improvements:

1. **Context-specific caveats.** JWT/JOSE signatures: ML-DSA identifiers for JOSE/COSE were standardised in
   RFC 9964 (May 2026, `ML-DSA-44/65/87`), but every JWT library *and every verifier* must support them before
   signers switch, and ML-DSA signatures (2,420-4,627 bytes) make tokens far larger than ES256. X.509:
   CA and client support is the gating factor. TLS: the migration is usually a library/config upgrade (hybrid
   groups), not an application code change. Add a short, rule-keyed caveat for `context in {authentication,
   tls-termination}` and `CFG-X509-*`.
2. **Language-appropriate pointers** (which library exposes ML-KEM/ML-DSA for Python, Java, Node), listed as
   "verify availability at migration time", never as code rewrites.
3. **FN-DSA (FIPS 206)** is still a draft; keep it out of recommendations (current behaviour) and say so in the docs.
4. **Planner ordering** follows QMP rank; consider grouping rows by (service, role) so one migration task covers
   all usages that move together.

## 8. Backend and frontend improvements

Backend (in priority order): S1-S4 above; then wire `scan_timeout_seconds` into `scan_tree`; separate runtime and
dev requirements (`pytest`, `httpx` are installed into the production image) and pin versions (lockfile or
`pip-tools`); structured logging of scan lifecycle (id, duration, counts, no content); remove `copilot_mode` from
`/api/health` until a Copilot exists; add an Alembic baseline before the next schema change; move `list_findings`
filtering into SQL when scans grow beyond a few thousand findings (it currently loads all rows twice per request,
once for results and once for facets).

Frontend: clickable `<tr onClick>` rows in Inventory, Dashboard and Planner are **not keyboard-accessible**: use a
link in the first cell or `tabIndex=0` + Enter handler + `role="link"`. Remove "Report" from the "soon" list.
Show partial/skipped-file warnings (S4). Upload: check archive size client-side before sending (the server already
enforces it). Consider a URL-addressable scan id (`#/scan/<id>/inventory`) instead of `localStorage` only, so links
can be shared once S1 is solved.

## 9. Testing gaps

* Backend API/ingestion/DB suites exist and look meaningful (adversarial archives, real Acme pipeline), but **no CI
  runs them**. Biggest gap: add `.github/workflows/ci.yml` running scanner, backend and frontend suites on push.
* No test for concurrent analysis (S3), retention, or rate limits (S2).
* No test that a `partial` scan is surfaced (S4).
* Scanner: no corpus from real open-source repositories; `scanner/eval/` is the start of one.
* Frontend tests are end-to-end against a real backend (good), but there are no accessibility assertions.
* Tests mostly validate behaviour, not implementation details. Exception: golden lists (`test_acme_fixture.py`)
  need deliberate updates on every intended change; that is acceptable for a fixture of this size.

## 10. Deployment risks

* No CI gate before deploy (any push can break production).
* Frontend served by the Vite dev server in the container (S5).
* SQLite on the container filesystem: on Render's default (ephemeral) disk, all scans are lost on restart or
  redeploy unless a persistent disk is attached. Verify the Render service configuration.
* Unpinned dependencies (`>=`): a new FastAPI/Starlette/SQLAlchemy release can change behaviour on redeploy.
* No health check in `docker-compose.yml`; `depends_on` does not wait for the backend.
* `scanner/qmc_scanner.egg-info/` is committed build output (add to `.gitignore`, `git rm --cached`).
* None of the commits on this branch change Docker, Compose, CORS, env vars or domains.

## 11. Top 15 improvements, ranked

| Rank | Improvement | Priority | Status |
|---|---|---|---|
| 1 | Auth / tenant isolation for scans; remove public scan list (S1) | P0 | needs approval |
| 2 | Retention, rate limit, concurrency cap (S2) | P0 | proposed |
| 3 | Atomic analyze + unique (scan_id, fid) (S3) | P0 | proposed (exact fix in S3) |
| 4 | UTF-8 BOM false negatives (B1) | P0 | **done** `f246712` |
| 5 | Token-based context inference (B2) | P0 | **done** `4949a0e` |
| 6 | MD5 detection + correct scoring/migration (B3) | P0 | **done** `2840f3c` (revertable) |
| 7 | JS/TS template interpolation false negatives (B4) | P0 | **done** `ce0ef85` |
| 8 | CI workflow running all three suites | P1 | proposed |
| 9 | Surface partial scans and skipped files (S4) | P1 | proposed |
| 10 | Scanner evaluation set with P/R/F1 | P1 | **done** `740d819` (to be grown with real repos) |
| 11 | Windows-safe test IDs (B9) | P1 | **done** `08a8af0` |
| 12 | Detect 3DES/DES/RC4/Blowfish in code; resolve same-file constants/aliases | P1 | proposed |
| 13 | Production frontend build + pinned deps + health checks (S5, section 10) | P1 | needs approval |
| 14 | Scoring/terminology fixes: AES-128 label, HNDL not assessed, CSV guard (B6-B8) | P1 | **done** `4b2fe3f`, `608fe91` |
| 15 | Keyboard-accessible tables; context-specific migration caveats (JOSE/X.509/TLS) | P2 | proposed |

## 12. Milestone roadmap

| Milestone | Scope | Exit criteria |
|---|---|---|
| **M0: scanner correctness (this branch)** | B1-B9, eval set, NIST IR 8547 note | scanner suite green; backend + frontend suites green **on your machine** |
| **M1: safe public demo** | S1 (per-scan token or admin gate), S2 (retention, rate limit), S3 (atomic analyze) | tests for each; deployed demo cannot list or delete other users' scans |
| **M2: engineering hygiene** | CI workflow; runtime/dev requirements split + pins; frontend production build; health checks; egg-info cleanup | CI badge green on `main`; Docker images build in CI |
| **M3: honest results** | S4 partial-scan surfacing; distinct-usage counts; context-specific migration caveats; a11y fixes | report and dashboard show skipped/partial; UI tests updated |
| **M4: scanner depth** | weak symmetric crypto rules; same-file constant/alias resolution; eval set grown with labelled snippets from 3-5 real OSS repos | precision/recall reported per language on real code |
| **M5: product (P2)** | evidence-backed finding cards, migration progress tracking (status per finding), dependency/blast-radius view only if built from real evidence (imports + service.yaml) | — |
| **M6: optional (P3)** | PQC Lab (separate from recommendations), AI explanations grounded in finding JSON with deterministic fallback | only after M1-M3 |

---

## 13. Milestone M0 report

**What changed and why**: see section 4 (B1-B9) plus `scanner/eval/` and the NIST IR 8547 note.
Engine version bumped `0.1.0 → 0.2.0` (`2ed45de`) because detection output changed.

**Commits** (branch `audit/p0-p1-fixes`, on top of `4057826`, not pushed):

| Commit | Summary |
|---|---|
| `08a8af0` | test(scanner): cap parametrized test ID length (Windows env-var limit) |
| `f246712` | fix(scanner): strip UTF-8 BOM |
| `4949a0e` | fix(scanner): whole-token context inference |
| `a597d0e` | fix(scanner): no classical DSA mention inside ML-DSA/SLH-DSA |
| `2840f3c` | feat(scanner,risk,migration): MD5 as classical-hygiene hash (revertable) |
| `4b2fe3f` | fix(risk): AES-128 label; HNDL not-assessed badge |
| `ce0ef85` | fix(scanner): JS/TS template interpolation scanning |
| `740d819` | test(scanner): hand-labelled evaluation set with P/R/F1 |
| `2ed45de` | chore(scanner): engine version 0.2.0 |
| `608fe91` | fix(api): CSV guard for TAB/CR |
| (last commit) | docs: this audit, NIST IR 8547 note, README test notes |

**Files modified**: `scanner/qmc_scanner/{engine,context,lexers,_version}.py`, 9 rule YAMLs (versions bumped),
`scanner/pyproject.toml`, `scanner/tests/{conftest,corpus,test_engine,test_detection_negative,test_confidence_comments}.py`,
new `scanner/tests/{test_context,test_eval}.py`, new `scanner/eval/`, `backend/app/{risk,migration,analysis}.py`,
`backend/tests/{test_risk,test_migration,test_health}.py`, new `backend/tests/test_csv_export.py`, `DECISIONS.md`,
`docs/knowledge-pack/03_NIST_STANDARDS.md`, `README.md`, this file.

**Tests executed here**: scanner suite 338 passed; `backend/tests/test_risk.py` + `test_migration.py` 63 passed
(+1 environment error: needs FastAPI). Regression check: the full Acme pipeline (scan → score → migration) was run
through the real functions on `main` and on this branch; the output is **byte-identical** (19 crypto findings,
10 quantum-vulnerable, 5 Critical, 3 elevated HNDL). New tests were checked to fail without their fix.

**Run before pushing** (needs network for installs):

    pip install -r backend/requirements.txt && pip install -e scanner
    cd scanner && pytest && python -m eval.evaluate
    cd ../backend && pytest
    cd ../frontend && npm ci && npm run build && npm test

Expected backend change: `test_health.py` now expects engine `0.2.0`. If any backend test asserts exact rule
versions or exact badge lists for findings without service metadata, it will need updating; no such assertion was
found by reading the tests.

**Could the deployed application be affected?** Only after you push and redeploy. Then: scan results change in the
ways listed in B1-B7 (more findings for MD5/BOM/template-literal code, corrected contexts, new badges); API shapes,
routes, DB schema, CORS, Docker and environment configuration are unchanged. Existing stored scans are not migrated
and keep their `engine_version 0.1.0` label.

**Remaining issues**: S1-S6 and sections 5-10.
