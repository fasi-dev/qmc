# SOURCE_INDEX — Authoritative References

All URLs below were verified against official sources. **Do not fabricate citations**;
if a claim cannot be sourced from the list below or a similarly authoritative source,
remove the claim.

## NIST standards (primary)

| Standard | Title | URL |
|---|---|---|
| FIPS 203 (final, 2024-08-13) | Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) | https://csrc.nist.gov/pubs/fips/203/final |
| FIPS 204 (final, 2024-08-13) | Module-Lattice-Based Digital Signature Standard (ML-DSA) | https://csrc.nist.gov/pubs/fips/204/final |
| FIPS 205 (final, 2024-08-13) | Stateless Hash-Based Digital Signature Standard (SLH-DSA) | https://csrc.nist.gov/pubs/fips/205/final |
| FIPS 186-5 | Digital Signature Standard (DSA, ECDSA, EdDSA, RSA signatures) | https://csrc.nist.gov/pubs/fips/186-5/final |
| SP 800-56A Rev. 3 | Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography | https://csrc.nist.gov/pubs/sp/800/56/a/r3/final |
| SP 800-56B Rev. 2 | Recommendation for Pair-Wise Key Establishment Using Integer Factorization Cryptography (RSA) | https://csrc.nist.gov/pubs/sp/800/56/b/r2/final |
| SP 800-57 Part 1 Rev. 5 | Recommendation for Key Management (key lifetimes, cryptoperiods) | https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final |
| SP 800-131A Rev. 2 | Transitioning Cryptographic Algorithms and Key Lengths | https://csrc.nist.gov/pubs/sp/800/131/a/r2/final |
| SP 800-208 | Recommendation for Stateful Hash-Based Signature Schemes | https://csrc.nist.gov/pubs/sp/800/208/final |
| FIPS 197 | Advanced Encryption Standard (AES) | https://csrc.nist.gov/pubs/fips/197/final |
| FIPS 180-4 | Secure Hash Standard (SHA-1, SHA-2) | https://csrc.nist.gov/pubs/fips/180-4/final |
| FIPS 202 | SHA-3 Standard | https://csrc.nist.gov/pubs/fips/202/final |
| FIPS 140-3 | Security Requirements for Cryptographic Modules | https://csrc.nist.gov/pubs/fips/140-3/final |

## NIST PQC program and migration guidance

| Document | URL |
|---|---|
| NIST PQC Standardization project (process home) | https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization |
| NIST news: "NIST Releases First 3 Finalized Post-Quantum Encryption Standards" (2024-08-13) | https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards |
| NCCoE Migration to Post-Quantum Cryptography project page | https://www.nccoe.nist.gov/projects/migration-post-quantum-cryptography |
| NCCoE project description, "Migration to Post-Quantum Cryptography" (PDF) | https://www.nccoe.nist.gov/sites/default/files/legacy-files/pqc-migration-project-description-final.pdf |
| CSWP 48 (draft), "Mappings of Migration to PQC Project Capabilities to Risk Framework Documents" | https://www.nccoe.nist.gov/news-insights/new-draft-white-paper-pqc-migration-mappings-risk-framework-docs |
| Preliminary Draft SP 1800-38A, "Migration to Post-Quantum Cryptography" | https://www.nccoe.nist.gov/projects/migration-post-quantum-cryptography |
| NIST CSRC "Getting Ready for Post-Quantum Cryptography" (cybersecurity white paper) | https://csrc.nist.gov/pubs/cswp/38/final (CSWP 38) |

Notes on currency (verified as of pack creation, October 2026):

- FIPS 203, 204, 205 are **final** and were published **2024-08-13**.
- **FIPS 206 (FN-DSA, derived from FALCON)** is in development; HQC was selected for
  standardization on **2025-03-11** as a backup KEM (see NIST IR 8545). The prototype
  recommends only the three finalized standards; do not present drafts as final.
- This pack cites **no transition deadline dates** beyond what official sources state.
  Do not invent deadlines.

## Open Quantum Safe (implementation reference)

| Resource | URL |
|---|---|
| liboqs (open-source C library of NIST PQC algorithms; maintained) | https://github.com/open-quantum-safe/liboqs |
| Open Quantum Safe project site / documentation | https://openquantumsafe.org/ |
| liboqs Python wrappers (e.g., `liboqs-python`) | https://github.com/open-quantum-safe/liboqs-python |

Rule: all PQC operations in the PQC Lab must be performed via a **maintained, peer-reviewed
implementation** (liboqs or equivalent). **Never implement PQC primitives from scratch.**

## Secondary / background (use sparingly; never as sole authority)

- P. Shor, "Algorithms for Quantum Computation: Discrete Logarithms and Factoring" (1994) — foundational; cite via NIST materials rather than paywalled copies.
- L. Grover, "A Fast Quantum Mechanical Algorithm for Database Search" (1996) — same policy.
- Wikipedia's NIST PQC Standardization article — background orientation only, never cited as authority.

## Citation discipline

- Every important technical claim in the docs cites one of the NIST/OQS sources above.
- Facts that may have changed recently (standard status, algorithm names, selection results)
  must be re-verified against the official source at build time.
