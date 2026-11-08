# Migration Impact Simulator

`GET /api/scans/{id}/simulate?node=<node id>[&target=<target id>]` · UI: **Migration Simulator** · Code: `backend/app/simulator.py`

A **planning** tool. It never rewrites code and never declares a migration compatible: replacements depend on
protocols, libraries and their versions, key formats, message-size budgets, performance requirements and every
peer that must interoperate.

## Input

Any selectable dependency-graph node: `algorithm:ECDSA`, `library:cryptography`, `finding:CRYPTO-007`,
`file:src/auth.py` (from the graph, the readiness recommendations or a finding's detail page). Optionally a target
from the track's option list; anything else returns `422 invalid_target`.

## Tracks

The selection's findings (its blast-radius scope) are split into tracks, each with its own target options:

| Track | Findings | Target options (default first) |
|---|---|---|
| Key establishment | quantum-vulnerable, role key establishment | X25519MLKEM768 (hybrid), ML-KEM-768, ML-KEM-1024, ML-KEM-512 |
| Digital signatures | quantum-vulnerable, role signature | ML-DSA-65, ML-DSA-44, ML-DSA-87, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-128f |
| Undetermined role | quantum-vulnerable, role unknown | none: the role must be decided first |
| Broken hashes | MD5 / SHA-1 | SHA-256, SHA3-256 |
| Legacy ciphers | 3DES / DES / RC4 / Blowfish | AES-256-GCM |
| AES-128 | AES with a literal 128-bit key | AES-256-GCM |

Findings that need no migration (already PQC, or not vulnerable and not a hygiene issue) are listed separately.

## Output per track

1. **Current implementation**: algorithms, operations, APIs, libraries, literal key sizes, classical encoding sizes.
2. **Target**: name, standard, note and **published** parameter sizes (FIPS 203/204/205; hybrid share sizes from
   draft-ietf-tls-ecdhe-mlkem). These are specification values, not measurements of the application.
3. **Affected files and components**: the track's directly affected files and *its own* dependents (reverse import
   closure from those files, with confirmed/inferred status and `file:line` evidence for every hop).
4. **Migration rules**: the `07` rules that apply, with their steps.
5. **Integration changes**, derived from the operations actually detected, each listing its call sites, e.g.
   *key agreement → encapsulate/decapsulate*, *RSA encryption → KEM → KDF → AEAD*, *verifiers before signers*,
   *TLS: hybrid group on a supporting stack*.
6. **Compatibility considerations**: rule caveats, interoperability notes, context caveats (JWT/JOSE RFC 9964, TLS,
   X.509) and the library-support table from the readiness module.
7. **Architecture, current vs proposed**: the affected files with the algorithm/library they use today, and the
   same files pointing at the proposed target (dashed, marked "proposed change, not implemented"). Import edges are
   identical in both views. The diagram shows at most 40 files (directly affected first, then the nearest
   dependents); when it is cut, `architecture.truncated` is true, `total_files` / `shown_files` give the numbers and
   the note says so. The affected-file lists in step 4 are never truncated.
8. **Unresolved dependencies and limitations**: blast-radius limitations, unverified libraries, unknown versions,
   undetermined roles, depth caps.

## Not provided, on purpose

Effort, time or cost estimates; compatibility verdicts; generated code.
