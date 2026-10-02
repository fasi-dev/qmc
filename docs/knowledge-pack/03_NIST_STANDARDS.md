# 03_NIST_STANDARDS.md

Standards-focused reference. Primary authority: NIST CSRC and NCCoE. Full URL list:
`SOURCE_INDEX.md`. **No transition deadlines or claims are invented here** — where an
official source states a date, it is quoted with its source.

---

## 1. FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)

| Field | Value |
|---|---|
| Document number | FIPS 203 (Final) |
| Publication date | 2024-08-13 |
| URL | https://csrc.nist.gov/pubs/fips/203/final |
| Purpose | Specifies ML-KEM, derived from CRYSTALS-Kyber |
| Cryptographic role | **Key establishment (KEM)** — produces a shared secret |
| What problem it solves | Replaces quantum-vulnerable key establishment (RSA/DH/ECDH) with a lattice-based mechanism resistant to known quantum attacks |
| Relationship to migration | The primary NIST-standardized PQC direction for key-establishment findings |
| Important terminology | **KEM** (key encapsulation mechanism); encapsulation key / decapsulation key; ciphertext; shared secret; ML-KEM-512/768/1024 parameter sets |
| Limitations/caveats | **Not a signature scheme.** Not a drop-in replacement for "RSA encrypt data" — KEMs establish shared secrets used with symmetric ciphers. Correctness requires implicit-rejection decapsulation as specified. Derived from Kyber; NIST renamed algorithms in the final standards. |

## 2. FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)

| Field | Value |
|---|---|
| Document number | FIPS 204 (Final) |
| Publication date | 2024-08-13 |
| URL | https://csrc.nist.gov/pubs/fips/204/final |
| Purpose | Specifies ML-DSA, derived from CRYSTALS-Dilithium |
| Cryptographic role | **Digital signatures** (sign/verify: authenticity, integrity, non-repudiation support) |
| What problem it solves | Replaces quantum-vulnerable signature schemes (RSA signatures, ECDSA, EdDSA, DSA) |
| Relationship to migration | Primary NIST-standardized PQC direction for signature findings |
| Important terminology | Signing key / verification key; signature; ML-DSA-44/65/87 parameter sets; hedged vs deterministic signing (hedged recommended where side-channel RNG concerns exist) |
| Limitations/caveats | **Not key establishment.** Larger keys/signatures than ECDSA — protocol and storage budgets must be checked. Not intended for hashing arbitrary messages directly — pre-hash variant (HashML-DSA) exists for constrained contexts; default remains the standard interface. |

## 3. FIPS 205 — Stateless Hash-Based Digital Signature Standard (SLH-DSA)

| Field | Value |
|---|---|
| Document number | FIPS 205 (Final) |
| Publication date | 2024-08-13 |
| URL | https://csrc.nist.gov/pubs/fips/205/final |
| Purpose | Specifies SLH-DSA, derived from SPHINCS+ |
| Cryptographic role | **Digital signatures** (stateless, hash-based) |
| What problem it solves | Provides a signature scheme whose security rests on hash-function properties rather than lattices — diversity against a hypothetical break of ML-DSA |
| Relationship to migration | Candidate signature direction where hash-based security is preferred; NIST frames it as a backup in case ML-DSA proves vulnerable |
| Important terminology | Stateless (no state management between signatures, unlike SP 800-208 stateful schemes); SLH-DSA-SHA2 / SLH-DSA-SHAKE variants; larger signatures than ML-DSA |
| Limitations/caveats | **Not key establishment.** Significantly larger signatures and slower signing than ML-DSA — bandwidth/storage-sensitive protocols may not tolerate it. Do not confuse with stateful hash-based signatures (SP 800-208), which this project does **not** recommend. |

## 4. Related current standards status [FACT]

- **FIPS 206 (FN-DSA, derived from FALCON)**: in development — **not final**. Prototype
  does not recommend it. Source: https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization
- **HQC**: selected for standardization on 2025-03-11 (NIST IR 8545) as a backup KEM —
  no final FIPS yet at pack creation. Prototype does not recommend it.
- **FIPS 186-5** remains the current classical signature standard (RSA, ECDSA, EdDSA, DSA)
  — these are the **sources** of migration, not destinations.
  Source: https://csrc.nist.gov/pubs/fips/186-5/final

## 5. NIST PQC migration guidance

| Guidance | What it contributes to this project | URL |
|---|---|---|
| NCCoE "Migration to Post-Quantum Cryptography" project | Validates our entire concept: automated **discovery tools**, **inventory**, **risk-based prioritization**, interoperability/performance testing | https://www.nccoe.nist.gov/projects/migration-post-quantum-cryptography |
| NCCoE project description (PDF, Aug 2021) | Demonstration scenarios mirror our pipeline: discovery → criticality → characteristics → candidate selection → priority | https://www.nccoe.nist.gov/sites/default/files/legacy-files/pqc-migration-project-description-final.pdf |
| Preliminary Draft SP 1800-38A "Migration to Post-Quantum Cryptography" | Practice-guide structure for migration phases | https://www.nccoe.nist.gov/projects/migration-post-quantum-cryptography |
| CSWP 38 "Getting Ready for Post-Quantum Cryptography" | Early-planning rationale; inventory-first approach | https://csrc.nist.gov/pubs/cswp/38/final |
| CSWP 48 (draft) "Mappings of Migration to PQC Project Capabilities to Risk Framework Documents" | Maps migration capabilities (Discovery & Inventory, Interoperability, Performance) to NIST CSF 2.0 and SP 800-53 — inspiration for our explainable risk dimensions | https://www.nccoe.nist.gov/news-insights/new-draft-white-paper-pqc-migration-mappings-risk-framework-docs |

Key NCCoE themes adopted in this project **[ENGINEERING RECOMMENDATION]**:
- **Discovery and inventory first** — you cannot migrate what you cannot see.
- **Risk-based prioritization** — criticality of protected data/processes drives order.
- **Crypto-agility** — design so future algorithm swaps are cheap.
- **Not drop-in replacements** — key/signature sizes, performance, and protocol
  characteristics differ; plan for regression and interoperability testing.
- **Hybrid/interim implementations** — preserve interoperability during transition.

## 6. Crypto-agility concepts (from NCCoE guidance)

- Abstraction layers / provider interfaces between application code and algorithms.
- Centralized, versioned **cryptographic policy** (which algorithms, key sizes, modes are
  allowed) enforced at build/deploy time.
- Algorithm identifiers in configuration, not hard-coded.
- Regression/interoperability testing as part of every policy change.
- Inventory maintained continuously, not as a one-time project.

## 7. Explicit non-claims

- ❌ This project does not state or imply any government compliance obligation, deadline,
  or mandate for users.
- ❌ No dates beyond those quoted from official sources appear anywhere in the product.
- ❌ Recommending ML-KEM/ML-DSA/SLH-DSA is **not** a claim that they are "unbreakable" —
  NIST's multi-algorithm strategy (incl. SLH-DSA as backup) itself assumes single-algorithm
  risk.
