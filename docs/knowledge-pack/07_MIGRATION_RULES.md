# 07_MIGRATION_RULES.md

Deterministic migration rules. **The rules engine is the source of truth — not the AI
Copilot.** Each rule: current primitive + cryptographic role → candidate PQC direction,
with why/caveats/interoperability/steps/human-review requirements. See `02` §9 for the
role mapping and `03` for standards.

## Rule table

| Rule ID | Current primitive + role | Candidate direction | Why |
|---|---|---|---|
| R-01 | RSA for key establishment | **ML-KEM** (FIPS 203) | KEMs are the standardized PQC replacement for key transport/agreement |
| R-02 | DH for key establishment | **ML-KEM** (FIPS 203) | Same role; discrete-log based → Shor-vulnerable |
| R-03 | ECDH (incl. X25519/X448) for key establishment | **ML-KEM** (FIPS 203) | Same role; ECDLP → Shor-vulnerable |
| R-04 | RSA signatures (PKCS#1 v1.5 / PSS) | **ML-DSA** (FIPS 204) or **SLH-DSA** (FIPS 205) | Signature role → standardized PQC signatures |
| R-05 | ECDSA signatures | **ML-DSA** or **SLH-DSA** | Signature role; ECDLP → Shor-vulnerable |
| R-06 | EdDSA (Ed25519/Ed448) signatures | **ML-DSA** or **SLH-DSA** | Signature role; ECDLP → Shor-vulnerable |
| R-07 | DSA signatures | **ML-DSA** or **SLH-DSA** | Signature role; DLP → Shor-vulnerable |
| R-08 | AES | **No PQC mapping** — retain symmetric | Symmetric crypto is not Shor-vulnerable; consider AES-256 for Grover headroom |
| R-09 | SHA-1 | **No PQC mapping** — replace with SHA-256/SHA-3 (classical hygiene) | SHA-1 is deprecated for classical reasons, not quantum |
| R-10 | SHA-2 / SHA-3 | **No PQC mapping** — retain; prefer ≥256-bit output | Hash functions face only generic quantum speedups |
| R-11 | HMAC | **No PQC mapping** — retain | MACs are symmetric; adequate key/tag sizes suffice |
| R-12 | Unknown / unclassified crypto | **Manual review** — no candidate emitted | Never guess a migration direction |

## Rule detail templates

### R-01/02/03 — key establishment → ML-KEM
- **Why:** Shor's algorithm defeats RSA/DH/ECDH on a future CRQC; FIPS 203 is NIST's
  finalized KEM standard.
- **Caveats:** A KEM outputs a shared secret — callers must switch to the
  **KEM → KDF → symmetric cipher (e.g., AES-GCM)** pattern; it is not "encrypt this
  message with RSA" rewritten. Key/signature sizes differ; check protocol message budgets.
- **Interoperability:** Both peers must migrate together or use a **hybrid** scheme
  (classical + ML-KEM, e.g., X25519+ML-KEM-768) during transition; otherwise connections
  downgrade or fail.
- **Migration steps:** 1) Abstract crypto behind an interface. 2) Add ML-KEM alongside
  existing ECDH (hybrid). 3) Deploy to both endpoints. 4) Monitor. 5) Remove classical
  component after transition period.
- **Human review required:** Yes — protocol design, peer coordination, performance testing.

### R-04…R-07 — signatures → ML-DSA / SLH-DSA
- **Why:** Signature schemes based on factoring/DLP are Shor-vulnerable; FIPS 204/205 are
  finalized signature standards.
- **Candidate choice guidance:** ML-DSA = default (smaller signatures, faster). SLH-DSA =
  when hash-based security assumptions are preferred (diversity/backup role per NIST).
- **Caveats:** Signatures and public keys are **larger** — token/certificate/message-size
  budgets must be re-checked (JWTs, cert chains, embedded messages). Signature generation
  can be slower (esp. SLH-DSA). Verify **all** verifiers upgrade before switching signers.
- **Interoperability:** Dual-sign during transition if mixed-version verifiers exist.
- **Migration steps:** 1) Inventory verifiers. 2) Add PQC verification support everywhere
  first. 3) Switch signing to ML-DSA (dual-sign if needed). 4) Deprecate classical
  verification after cutover.
- **Human review required:** Yes — trust-chain and storage-budget analysis.

### R-08…R-11 — symmetric/hash/MAC (no PQC mapping)
- Emitted as **informational** findings. The planner shows: "No PQC migration required."
  Optionally suggests AES-256 / SHA-384 for long-term headroom. **Never** ML-KEM/ML-DSA.

### R-12 — unknown crypto
- Finding is routed to a "Requires human review" queue with all evidence attached. The
  system states it does not know — never invents a direction.

## Crypto-agility recommendations (always included in migration plans)

1. **Abstraction layer** — route all crypto through one internal interface (e.g.,
   `CryptoProvider.encapsulate/sign/verify`); no algorithm names outside it.
2. **Centralized crypto policy** — a single versioned policy file naming allowed
   algorithms/key sizes/modes; enforced at build time.
3. **Algorithm identifiers in configuration** — no hard-coded algorithm strings.
4. **Provider abstraction** — swap OpenSSL↔liboqs↔HSM without touching call sites.
5. **Versioned crypto policies** — policy v1 (classical) → v2 (hybrid) → v3 (PQC-only);
   roll out progressively.
6. **Regression & interoperability testing** — cross-version handshake/signature tests in CI.

## Honesty notes (rendered with every plan)

- Recommendations are **candidate directions**, not certifications of security.
- The plan assumes peer ecosystems (libraries, clients, CAs, HSMs) support the targets at
  deployment time — verify before committing dates.
- Final decisions require human security review, per `02` and NCCoE guidance.
