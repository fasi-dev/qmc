# Decisions log

Spec issues found during the readiness check, and the default resolution used.

1. **`09` expected bands vs `06` formula.** `09` lists findings 2-5 as "High", but on
   payment-api (DS4/IE3/BC3) the `06` formula yields 19-20 (Critical). Decision: follow `06`;
   self-test (phase 11) asserts formula-derived bands.
2. **Dashboard demo numbers** ("38 findings / 12 vulnerable") in `10` do not match the 12
   seeded findings in `09`. Decision: the UI always shows computed numbers.
3. **Hygiene findings** (TLS 1.0, SHA-1, expired cert) are listed under "quantum-vulnerable"
   in `09` section 6 but are classical issues per `02`/`07` R-09. Decision:
   `quantum_vulnerable=false` plus a "classical hygiene" tag.
4. **Rounding**: `06` Example B needs 8.5 -> 9. Decision: round half up (not Python banker's).
   Guard rule: QE == 0 -> Informational regardless of arithmetic (Example D).
5. **Fixture gaps** (settlement-worker, gRPC, internal-sdk/crypto-utils for the `08` blast-radius
   example). Decision: author these fixtures in phase 11 (per-service `service.yaml`).
6. Lint-level items: RSA-OAEP expected in `05` section 11 but absent from `09`; SHA-1 confidence
   (Medium in `09` vs High per `05` section 5 rule). Decision: decide when writing rules; document here.

---
## Phase 2 decisions (safe ingestion)

7. **Raw-body upload instead of multipart.** `POST /api/scans?filename=...` streams the request
   body to disk with the size cap enforced while streaming (and via Content-Length up front).
   Multipart parsing happens before handler code runs, so it cannot enforce `04`'s 100 MB cap early.
   `04` does not specify the transport.
8. **Single file over 5 MB is skipped, not fatal.** `04` gives the limit but not the behaviour.
   Rejecting the whole archive would make real repos (with a large asset) unusable. Skipped files are
   listed in the manifest with reason `too_large`. A file that turns out larger than its *declared*
   size is treated as an archive bomb and rejects the archive.
9. **Binary files are not persisted** (NUL byte in the first 8 KB): recorded as `skipped: binary`.
   Rationale: binary analysis is a non-goal (`01` section 8) and binaries could hide private keys
   that text redaction cannot see. Consequence: DER certificates and `.so` files are not scanned.
10. **Nested archives are not unpacked** (they are ordinary, usually binary, files).
11. **Compression-ratio cap (`04` "e.g., <= 100:1") details:** enforced only above a 1 MiB output
    floor (otherwise 1 KB of zeros would be a false positive). ZIP: checked from central-directory
    sizes before writing anything (per entry and overall). TAR: checked while streaming. Members
    that are skipped for size still count toward the decompressed-stream cap, so a gigantic skipped
    member cannot be used for CPU/disk denial of service.
12. **Redaction policy** (`04` section 4 says "redacted marker + location metadata"):
    * Applied to the *stored copy* at ingestion, so later scanner evidence strings can never contain
      the secret. Consequence: if a secret is part of a crypto call (e.g. a key literal argument), the
      evidence shows `***REDACTED***` in that position.
    * Line numbers are preserved (redaction never adds/removes lines) so finding line numbers match
      the original file. PEM header and END lines are kept (key type is useful evidence); body lines
      are replaced. Public certificates are NOT redacted.
    * No hash or length of any secret is stored. Manifest records only file, line range and kind.
    * Patterns: PEM private keys, JWTs, AWS/GitHub/Slack/Google/Stripe key formats, and
      `password|secret|token|api_key...` assignments (quoted anywhere; unquoted only in config-style
      files). Heuristic: **not a guarantee** that every secret is found. The UI says so.
13. **Single top-level directory is lifted** (e.g. `repo-main/` from GitHub zips) so paths read
    `src/auth.py`, matching `09`. Recorded as `stripped_root_dir`.
14. **Scan records are a `manifest.json` per scan** for now. SQLite persistence arrives in Phase 4
    as specified in the build order; the manifest remains the source for ingestion facts.
15. **Unsupported inputs (by design):** 7z/RAR, encrypted ZIP entries, tar files without the
    `ustar` magic (very old v7 tar). They are rejected with clear error codes.
16. **`service.yaml` parsing:** exact filename `service.yaml`; `yaml.safe_load` only; 64 KB cap;
    missing/invalid fields are recorded (not guessed) so the risk engine can apply the `06` section 6
    midpoint default with a "metadata missing" badge. `service_for_path()` implements the
    nearest-ancestor mapping from `09` section 3.

### New spec observations (Phase 2)
* `04` lists "reject non-zip/tar archives" but the 05 scanner/09 fixture never mention `.tgz`
  variants; we accept tar, tar.gz, tar.bz2, tar.xz (all tar). No contradiction, just noted.
* `04` section 4 puts the sandbox (non-root, no network, RO fs, rlimits) on the *scanner*. Ingestion
  runs in the backend process, hardened by the controls above and the container settings, but it is
  not inside the scanner sandbox. Consistent with `10` section 2, noted for honesty.

---
## Phase 3 decisions (scanner: Python / Java / JS-TS)

17. **Scope.** Implemented: Python (AST), Java, JS/TS, plus comment/doc mention handling. NOT implemented
    (README build-order step 4, deferred): YAML/JSON/Nginx/TLS/Docker rules and certificate parsing, therefore
    `09` rows 6 (nginx TLS) and 11 (expired cert) are not detectable yet. Suppression (`qmc-ignore.yaml`, UI
    false-positive marking) is also deferred (Phase 4/step 4).
18. **Rules location:** `scanner/qmc_scanner/rules/<language>/<RULE_ID>.yaml` (one rule per file, semver, strict
    loader) instead of `scanner/rules/...` so rules ship inside the installed package (verified in a built wheel).
    Language dirs: `python`, `java`, `js` (covers .js/.jsx/.mjs/.cjs/.ts/.tsx), `generic`.
19. **Comment-only / documentation matches** (`05` section 5 says comments are Low, section 3 says strip comments
    first). Interpretation: executable rules run on comment-stripped code; a *separate* pass emits Low findings
    (`GEN-COMMENT-001`, confidence 0.30, engine hard-caps at 0.45) for algorithm names in real comments and in
    `.md/.rst/.txt` files. These findings have `comment_only=true`, `quantum_vulnerable=false` (no executable
    evidence; keeps the `09` section 6 vulnerable set correct), `operation="unspecified"`, `library=null`,
    `api=null`, `context="unknown"`. Python docstrings are not scanned. Generic words ("crypto", "secure") never match.
20. **`test_path` widened.** `05` lists `test_*`, `*.test.*`, `tests/`; but `09` row 10 (`scripts/gen_test_keys.py`)
    must count as a test path (also `06` Example C). Rule used: any whole token `test|tests|__tests__` in a
    directory name or in the filename split on `._-`. `contest.py`, `latest.py` stay false. Flag only; nothing is
    filtered or lowered.
21. **Schema.** Fields exactly as `05` section 4 (validated on every finding). `04` also asks for a timestamp and
    evidence hash per finding; these are *excluded* from scanner output to keep it deterministic and are to be added by the
    persistence layer (helper `evidence_hash()` provided). `in_dead_code` is always `false` (static dead-code
    detection is not attempted). `library`/`api` may be `null` only for comment-only findings.
22. **SHA-1 confidence.** `09` row 7 says Medium; `05` section 5 says a resolved API call with exact algorithm
    is High. Followed `05`: `hashlib.sha1(...)` is **High**, `quantum_vulnerable=false` (classical hygiene, `07` R-09).
23. **Operation vs role.** `operation` records what the API does (e.g. `X25519PrivateKey.generate()` =
    `ECDH`/`key_generation`; `padding.OAEP` inside `.encrypt()` = `RSA`/`encryption`). Cryptographic *role*
    (key establishment vs signature, `02` section 9) is derived later (Phase 5/7) from algorithm+operation+context.
    Open point for Phase 5: RSA `key_generation` has no role by itself (use `context`; ambiguous => lower QE).
24. **Ambiguous algorithms stay honest.** Generic EC key generation is labelled `EC` (medium 0.70) and promoted to
    `ECDSA`/`ECDH` (0.85) only if the SAME FILE shows exactly one of them. Node `createSign`/`crypto.sign` is
    `RSA/ECDSA` (0.70) and `crypto.diffieHellman` is `DH/ECDH` (0.80) because the key type is not visible.
    Migration rules for these treat them by role (signature/key agreement); nothing is guessed beyond that.
25. **`context` inference** is deterministic keyword matching on algorithm/operation, enclosing function/class
    names and path tokens (`auth`, `jwt`, `token`, `settle`, ...), else `unknown`. No dataflow. Heuristic.
26. **Walk rules.** Skipped (and reported in `skipped_directories`): `.git node_modules .venv venv __pycache__
    site-packages .tox .mypy_cache`. Symlinks never followed. Files with a line > 10,000 chars -> `skipped_minified`;
    Python files that do not parse (Python 2, syntax errors) -> `parse_error` (reported, not silently dropped).
    Timeout (default 300 s, checked between files) -> `status: "partial"`.
27. **Redaction module moved** to `qmc_scanner/redaction.py` (backend re-exports it). The scanner re-applies it to
    every evidence string as defense in depth; evidence is also capped at 300 chars and cut at the balanced call end.
28. **Known limits (surfaced, not hidden).** Algorithm given by a variable/config is not guessed (no finding);
    MD5/3DES/etc. are outside the `05` catalog (no finding); AES key size is recorded only when literal at the call
    (`generate_key(bit_length=256)`, `aes-256-gcm`, `AES256`); WebCrypto `{name: ...}` objects are Medium; Python
    `from x import *` and relative imports are not resolved; CR-only line endings skew Python line numbers; lexing
    is regex-based (Java/JS), with bounded worst-case ~3 s/MB on adversarial `(/[` floods.
29. **Finding counts differ from `09` row counts by design.** One API usage = one finding, so e.g. `ec.ECDSA(hashes.SHA256())`
    also yields a SHA-256 finding and AES-GCM yields key_generation + encryption findings. The draft fixture is
    scanned to 16 findings (see `tests/test_acme_fixture.py` golden list). Phase 11 must complete the fixture
    (settlement-worker service, nginx/TLS, cert, gRPC) and the demo narration must use computed numbers.
30. **Draft fixture** lives in `sample-repos/acme-payments/` (code rows only). Authored so evidence strings are
    real API calls as `09` section 5 requires; no secrets. Expected behaviour from `09` was not changed.

---
## Demo-prototype build decisions (persistence, risk, API, UI, migration, report)

31. **Fixture metadata.** Added `scripts/service.yaml` (dev-scripts: internal, low, not exposed, 1y) and
    `src/legacy/service.yaml` (settlement-worker) to the Acme fixture. Needed for the `06` Example B/C contrast (dev script
    vs payment-api) and `10`'s planner row (SHA-1 in settlement-worker). Consistent with `09` section 3 (nearest service.yaml).
32. **Persistence.** SQLite via SQLAlchemy (plain columns + JSON, PostgreSQL-compatible). A scan is analyzed once; after analysis the
    extracted tree is deleted (`04` section 5) and only findings, risk, evidence and a +-3-line redacted snippet are kept.
    `manifest.json` stays on disk. Re-analysis returns 409.
33. **Risk inputs not fixed by `06`.** Role derivation (`risk.role_of`): ECDH/DH => key establishment; ECDSA/EdDSA/DSA => signature;
    RSA by operation, else by context (authentication/code-signing/integrity => signature); RSA key generation with unknown context =>
    role "unclear", scored QE 4 (conservative, matches `06` Example B). Medium/low confidence public-key => QE 2 (`06` F1 row 3).
    Migration complexity: PQC 0; protocol config 0; X.509 3; key establishment 2; authentication signatures 2; code-signing 3; other 1.
    IE: `internet_exposed` true => 3, false => 0 (no private-network/partner signal exists in service.yaml).
34. **Classical-hygiene cap.** `09` expects SHA-1 / TLS 1.0 / weak ciphers to be "Review", but the `06` formula alone would make them
    High/Critical in a sensitive service. Implemented as a guard: QE == 1 (SHA-1, deprecated TLS, weak ciphers, AES-128) caps the
    band at Review with an explicit "classical hygiene" badge. The numeric QMP is still shown. Interpretation of `09`, not a new score.
35. **Ranking** is by displayed band, then QMP, raw score, HNDL, QE, scanner order (so a capped "Review 20" never outranks a Critical).
36. **Critical counts.** The `06` formula yields Critical for every high-confidence public-key finding in payment-api (DS4/IE3/BC3), so
    the demo shows 5 Critical (not `10`'s "2 Critical"; `09` also lists some as "High"). Computed numbers are shown everywhere
    (reaffirms #1/#2). Real Acme output: 19 crypto findings, 10 quantum-vulnerable, 5 Critical, 3 elevated HNDL.
37. **Comment/doc mentions** are never scored, hidden from default inventory views with a visible count (toggle to show).
38. **HNDL** is role-based (`06` does not condition it on confidence), so ECDHE named in an nginx `ssl_ciphers` line (Medium confidence,
    band capped at Review) still carries the HNDL flag in a 10-year sensitive service.
39. **Migration rules** follow `07` exactly; undetermined roles (RSA key generation without context, generic EC) go to R-12 manual review
    and show which directions are possible without choosing one. TLS/protocol hygiene rows show "No PQC mapping: classical hygiene"
    (presentation only; `07` has no rule for them, so no direction is invented).
40. **Certificate expiry** is evaluated against the scan's UTC date (`as_of`, recorded in the analysis). Scanner output is deterministic
    for a given `as_of`.
41. **UI.** Hash routing, scan id in localStorage, no UI framework. Not verified in a real browser here: tested with jsdom + Testing Library
    driving the real app against a real backend process (`frontend/vitest.global.ts`). Docker images were not built in this environment.
42. **Report** is Markdown only (PDF deferred). **Not built:** dependency graph, PQC Lab, AI Copilot (see README Status).
