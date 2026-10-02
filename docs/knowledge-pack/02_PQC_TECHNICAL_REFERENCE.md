# 02_PQC_TECHNICAL_REFERENCE.md

Ground-truth cryptographic reference for the whole project. Every document must agree
with this one. Citations: `SOURCE_INDEX.md`.

**Labels used throughout:**
- **[FACT]** — established cryptographic or standards fact (cite source).
- **[ENGINEERING RECOMMENDATION]** — prudent practice from NIST/NCCoE guidance; a recommendation, not a law of physics.
- **[PROJECT ASSUMPTION]** — a simplification this prototype makes for the hackathon.

---

## 1. Post-quantum cryptography (PQC)

[FACT] PQC refers to cryptographic algorithms designed to run on conventional computers
and resist attacks by both conventional **and** (future) quantum computers. NIST
standardized the first three PQC FIPS on 2024-08-13: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA),
FIPS 205 (SLH-DSA).

## 2. Quantum threat model

[FACT] A **cryptographically relevant quantum computer (CRQC)** is a hypothetical future
large-scale fault-tolerant quantum computer capable of running Shor's algorithm against
realistic key sizes. No such machine exists today. **[PROJECT ASSUMPTION]** "Quantum-vulnerable"
throughout this pack means *vulnerable to a future CRQC*, never "broken today."

- **Confidentiality threat**: Shor's algorithm breaks RSA, DH, ECDH key establishment →
  recorded ciphertext can be decrypted in the future (**harvest-now-decrypt-later**, §11).
- **Authenticity/integrity threat**: Shor's also breaks RSA, ECDSA, EdDSA signatures →
  forged signatures and impersonation once a CRQC exists.

## 3. Shor's algorithm (conceptual level)

[FACT] Shor's algorithm (1994) solves integer factorization and discrete logarithms in
polynomial time on a sufficiently large fault-tolerant quantum computer. It therefore
defeats: RSA (factoring), DH and ECDH/ECDLP (discrete log), DSA/ECDSA (discrete log).
It does **not** apply to symmetric ciphers or hash functions (which is why AES/SHA need
different treatment, §9–§10).

## 4. Grover's algorithm (conceptual level)

[FACT] Grover's algorithm (1996) gives a quadratic speedup for unstructured search. Against
a b-bit key it offers roughly the effect of halving the security bits (e.g., AES-128 →
~64-bit security against a quantum brute-force attacker). **[ENGINEERING RECOMMENDATION]**
NIST guidance treats AES-256 / SHA-384+ as comfortable for a post-quantum world, while
AES-128 is generally considered acceptably robust against realistic Grover costs for most
purposes. **[PROJECT ASSUMPTION]** The prototype flags symmetric/hash uses as
*informational*, recommends larger key/hash sizes where configured small, and **never**
maps AES→ML-KEM or SHA→ML-DSA.

## 5. Public-key algorithms (quantum-vulnerable)

| Algorithm | Basis | Roles | Quantum status [FACT] |
|---|---|---|---|
| RSA | Integer factorization | Key establishment (encryption/KEX), digital signatures | Broken by Shor on a CRQC |
| Diffie-Hellman (DH) | Finite-field discrete log | Key establishment | Broken by Shor on a CRQC |
| ECDH (incl. X25519/X448) | Elliptic-curve discrete log | Key establishment | Broken by Shor on a CRQC |
| ECDSA | Elliptic-curve discrete log | Digital signatures | Broken by Shor on a CRQC |
| EdDSA (Ed25519/Ed448) | Elliptic-curve discrete log | Digital signatures | Broken by Shor on a CRQC |
| DSA | Finite-field discrete log | Digital signatures | Broken by Shor on a CRQC |

Sources: FIPS 186-5, SP 800-56A, SP 800-56B; Shor (1994) — see `SOURCE_INDEX.md`.
[FACT] None of these are broken by today's quantum computers.

## 6. Symmetric encryption: AES

[FACT] AES (FIPS 197) is a symmetric block cipher (128/192/256-bit keys). It is **not**
a public-key algorithm and is **not** affected by Shor. Grover considerations only
(§4). **[PROJECT ASSUMPTION]** Scanner records AES with mode/key size; risk model notes
key size; no PQC migration mapping is generated for AES.

## 7. Hashing: SHA-1, SHA-2, SHA-3

[FACT] SHA-1 is deprecated for signature use (collision weaknesses are classical, not
quantum, but real). SHA-2 (FIPS 180-4) and SHA-3 (FIPS 202) are hash standards; quantum
impact is limited to generic Grover-style collision/preimage speedups. **[ENGINEERING
RECOMMENDATION]** avoid SHA-1 everywhere; prefer SHA-256+; use SHA-384/512 for
long-term post-quantum headroom. **[PROJECT ASSUMPTION]** Hash findings never map to
ML-DSA. (Note: SLH-DSA is *built from* a hash function internally, but it is still a
signature scheme — see `03`.)

## 8. Post-quantum algorithms

### 8.1 ML-KEM — FIPS 203 [FACT]

- **Type: Key Encapsulation Mechanism (KEM).** Role: **key establishment only.**
- Derived from CRYSTALS-Kyber; parameter sets ML-KEM-512 / 768 / 1024 (targeting
  approximately AES-128/192/256-equivalent security categories).
- API: keygen → (encapsulation key, decapsulation key); encaps(ek) → (ciphertext, shared
  secret); decaps(dk, ct) → shared secret. KEMs produce a **shared secret**, not a
  signature and not "encryption of arbitrary data" by themselves.
- **Never** describe ML-KEM as a signature algorithm. **[PROJECT ASSUMPTION]** Scanner
  detects ML-KEM usage (e.g., via `liboqs`, `pqcrypto`, oqs-provider imports) as
  *already-migrated* key establishment.

### 8.2 ML-DSA — FIPS 204 [FACT]

- **Type: digital signature scheme.** Role: signing, verification, authenticity, integrity.
- Derived from CRYSTALS-Dilithium; parameter sets ML-DSA-44/65/87.
- API: keygen; sign(sk, msg) → signature; verify(pk, msg, sig) → boolean.
- NIST's primary PQC signature standard.

### 8.3 SLH-DSA — FIPS 205 [FACT]

- **Type: stateless hash-based digital signature scheme.** Role: signatures.
- Derived from SPHINCS+; different mathematical foundation (hash-based) than ML-DSA.
- NIST positions it as a **backup / diversity** option in case ML-DSA proves vulnerable.
- Larger signatures, different performance trade-offs. **Stateless** — no state management
  (contrast SP 800-208 stateful schemes, which this project does not recommend).

### 8.4 Not in scope

[FACT] FIPS 206 (FN-DSA, from FALCON) is in development; HQC was selected 2025-03-11 for
standardization as a backup KEM. **[PROJECT ASSUMPTION]** The prototype recommends only
the three **final** standards. Drafts are never presented as final.

## 9. Cryptographic roles (never conflate)

| Role | Classical examples | PQC direction |
|---|---|---|
| Key establishment | RSA-KEM/encryption, DH, ECDH | **ML-KEM** (FIPS 203) |
| Digital signatures | RSA-PSS/PKCS#1, DSA, ECDSA, EdDSA | **ML-DSA** (FIPS 204) or **SLH-DSA** (FIPS 205) |
| Symmetric encryption | AES | Stay symmetric; increase key size if needed (no PQC mapping) |
| Hashing | SHA-2/SHA-3 | Stay hash-based; increase output size if needed (no PQC mapping) |
| MAC | HMAC | No change required (Grover-resilient with adequate key/tag size) |

## 10. KEMs vs "public-key encryption"

[FACT] A KEM outputs a shared secret used with a symmetric algorithm (e.g., AES-GCM);
it is not a drop-in replacement for "RSA encrypt this message." Migration work must
restructure code around the KEM-then-symmetric pattern. This caveat appears in every
key-establishment migration recommendation (`07`).

## 11. Harvest-now-decrypt-later (HNDL)

[FACT] Adversaries may record ciphertext today and decrypt later when a CRQC exists.
[FACT] Long confidentiality lifetimes + long migration timelines = risk **now** for data
that must stay secret for years/decades (per NIST/NCCoE migration guidance). **[PROJECT
ASSUMPTION]** The risk model adds a dedicated HNDL consideration (see `06` §HNDL) for
long-lived, highly sensitive, recorded-in-transit data.

## 12. Crypto-agility

[FACT] Crypto-agility = the ability to swap cryptographic algorithms without redesigning
systems: abstraction layers, centralized policy, algorithm identifiers, configuration-
driven algorithm selection, provider abstraction, versioned policies, regression tests.
**[ENGINEERING RECOMMENDATION]** NCCoE migration guidance explicitly identifies
crypto-agility as essential because future transitions (not just this one) are certain.
Implementations: see `07` §Crypto-agility recommendations.

## 13. Hybrid migration

[FACT] "Hybrid" combines classical + PQC (e.g., X25519 + ML-KEM-768 in TLS) so security
does not depend on a single assumption during transition. **[ENGINEERING RECOMMENDATION]**
NCCoE/IETF work demonstrates hybrid key establishment as an interoperability-preserving
transition pattern. **[PROJECT ASSUMPTION]** The migration planner **suggests** hybrid as
a transition option where both peers can be upgraded; it never forces it.

## 14. Consistency checklist (mirrors the required review)

- [x] ML-KEM = KEM/key-establishment only (§8.1).
- [x] ML-DSA/SLH-DSA = signature only (§8.2, §8.3).
- [x] AES/SHA never mapped to PQC algorithms (§6, §7, §9).
- [x] RSA/ECC not described as currently broken (§2, §5).
- [x] No security guarantees ("unbreakable", "100% quantum safe") anywhere.
- [x] HNDL treated as a present-day planning driver, not a claim of current compromise.
