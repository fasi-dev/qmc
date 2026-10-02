# DOCUMENT_MAP — How the Knowledge Pack Fits Together

## Reading order for humans

1. `01_PROJECT_SPEC.md` — what we are building and why
2. `02_PQC_TECHNICAL_REFERENCE.md` — the cryptographic ground truth
3. `03_NIST_STANDARDS.md` — the authoritative standards backing that ground truth
4. `04_THREAT_MODEL.md` — what the *platform itself* must defend
5. `05_CRYPTO_SCANNER_SPEC.md` → `06_RISK_SCORING.md` → `07_MIGRATION_RULES.md` → `08_DEPENDENCY_GRAPH.md` — the analytical pipeline, in data-flow order
6. `09_SAMPLE_REPOSITORY_SPEC.md` — the demo fixture
7. `10_UI_ARCHITECTURE_AND_DEMO.md` — screens, architecture, demo script

## Data / control flow

```
09_SAMPLE_REPOSITORY_SPEC.md  (input fixture)
        │
        ▼
05_CRYPTO_SCANNER_SPEC.md     (deterministic discovery → findings)
        │
        ▼
06_RISK_SCORING.md            (Quantum Migration Priority per finding)
        │
        ▼
08_DEPENDENCY_GRAPH.md        (findings + code structure → graph, blast radius)
        │
        ▼
07_MIGRATION_RULES.md         (primitive+role → PQC candidate direction)
        │
        ▼
10_UI_ARCHITECTURE_AND_DEMO.md (all of the above rendered; PQC Lab; AI Copilot; report)
        ▲
04_THREAT_MODEL.md            (security constraints applied at every ingestion/analysis step)
```

## Consistency contract (all documents must agree)

| Concept | Canonical definition (source of truth) |
|---|---|
| ML-KEM (FIPS 203) | Key Encapsulation Mechanism for **key establishment**. Never described as a signature scheme. |
| ML-DSA (FIPS 204) | Digital signature scheme (signing/authenticity/integrity). Never key establishment. |
| SLH-DSA (FIPS 205) | Stateless **hash-based** digital signature scheme. Backup/diversity signature option. |
| RSA / DH / ECDH / ECDSA / EdDSA | Quantum-vulnerable public-key cryptography (Shor). **Not currently broken.** |
| AES / SHA-2 / SHA-3 | Symmetric encryption / hashing. Grover-related considerations only. **Never mapped to PQC algorithms.** |
| Risk score | Internal prototype methodology named **Quantum Migration Priority** — never presented as a NIST score. |
| AI Copilot | Advisory explanation layer only. Scanner + rules engine are the source of truth. |
| Findings | Evidence-based, confidence-scored, suppressible, rule-versioned, **require human review**. |

If any document is edited, re-check these rows across the whole pack.

## Cross-reference index

- Problem → solution mapping: `01` §Proposed solution
- Every scanner detection rule: `05` → risk factors in `06` → migration rule in `07`
- Graph node/edge schema: `08` (consumed by UI screens 4–5 in `10`)
- Seeded findings in Acme Payments: `09` ↔ expected scanner output in `05` §Expected detection examples
- Security controls on upload pipeline: `04` §Security controls ↔ `10` §Architecture
- All citations: centralized in `SOURCE_INDEX.md`; documents cite inline too
