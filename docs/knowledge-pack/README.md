# Quantum Migration Copilot — Knowledge Pack

**Tagline:** *Discover your cryptography. Understand your quantum exposure. Plan your migration.*

This knowledge pack is the complete technical foundation and build specification for the
**Quantum Migration Copilot** project, a national-level 36-hour hackathon entry in the
Post-Quantum Cryptography (PQC) track.

It is written to be handed, as-is, to a coding AI (or a human engineering team) as the
single source of truth for building the prototype. It contains **no application code** —
only requirements, technical facts, schemas, rules, and demo design.

## What the product is

Quantum Migration Copilot is a **prototype decision-support / security-engineering tool**.
A user uploads a source-code or configuration repository (or archive); the platform:

1. Safely ingests it (never executing uploaded code),
2. Performs deterministic static analysis to build a **cryptographic inventory**,
3. Flags **quantum-vulnerable** public-key cryptography,
4. Scores findings with a transparent, explainable **Quantum Migration Priority** model,
5. Builds a **dependency graph** and estimates **migration blast radius**,
6. Produces deterministic **PQC migration recommendations** (rules, not guesses),
7. Demonstrates real PQC operations (ML-KEM / ML-DSA) in a **PQC Lab**,
8. Optionally explains findings via an **AI Copilot** (strictly advisory — never the source of truth),
9. Generates an evidence-backed **migration report**.

## Honesty principles (apply everywhere)

- RSA/ECC/DH are **quantum-vulnerable** (to future cryptographically relevant quantum
  computers running Shor's algorithm) — they are **NOT currently broken** by any existing
  quantum computer.
- ML-KEM is a **Key Encapsulation Mechanism** (key establishment). Never a signature scheme.
- ML-DSA and SLH-DSA are **digital signature schemes**. Never key-establishment mechanisms.
- AES and SHA are **symmetric / hash primitives** with different quantum-security
  considerations; they are **never** "migrated to" ML-KEM or ML-DSA.
- The tool never claims "100% quantum safe", "unbreakable", or formal certification.
- Static analysis **cannot** detect every cryptographic use. Findings are
  **evidence-based and require human review**.
- The risk score is a **prototype internal methodology**, not an official NIST score.
- The AI Copilot **never** invents vulnerabilities, replaces scanner logic, or certifies security.

## Directory contents

| File | Purpose |
|---|---|
| `DOCUMENT_MAP.md` | How all documents relate; recommended reading order |
| `SOURCE_INDEX.md` | All authoritative sources with URLs (NIST, OQS, etc.) |
| `01_PROJECT_SPEC.md` | Product spec: problem, features, MVP, non-goals, feasibility |
| `02_PQC_TECHNICAL_REFERENCE.md` | Technical reference: algorithms, threat model, FACT vs RECOMMENDATION vs ASSUMPTION |
| `03_NIST_STANDARDS.md` | FIPS 203/204/205 and NIST migration guidance, with citations |
| `04_THREAT_MODEL.md` | Assets, threats, trust boundaries, security controls for the platform itself |
| `05_CRYPTO_SCANNER_SPEC.md` | Static discovery engine: languages, detections, finding schema, confidence model |
| `06_RISK_SCORING.md` | Quantum Migration Priority scoring model (prototype) |
| `07_MIGRATION_RULES.md` | Deterministic migration rules + crypto-agility recommendations |
| `08_DEPENDENCY_GRAPH.md` | Graph schema, blast-radius estimation |
| `09_SAMPLE_REPOSITORY_SPEC.md` | "Acme Payments" fictional demo repository with seeded findings |
| `10_UI_ARCHITECTURE_AND_DEMO.md` | UI screens, system architecture, and the 5–8 minute judge demo |

## RECOMMENDED BUILD ORDER

A coding AI should implement in this order (each step ends with a working, demoable state):

1. **Repository setup** — monorepo scaffold: `frontend/` (React + TypeScript + Vite),
   `backend/` (Python + FastAPI), `scanner/` (Python package), `docker-compose.yml`.
2. **Safe ingestion service** — archive upload, safe extraction (path-traversal prevention,
   size limits), repo metadata parsing (`service.yaml`). *Security-critical: build before anything else.*
3. **Scanner core + Python/Java/JS rules** — AST-based detection for `cryptography`, `PyCrypto`,
   `java.security`/`Bouncy Castle`, `crypto`/`node-forge`; finding schema from `05_CRYPTO_SCANNER_SPEC.md`.
4. **Config/YAML/JSON/Docker/TLS rules** — regex+parser rules for TLS settings, cert blocks,
   algorithm strings; confidence model + suppression.
5. **Inventory API + Crypto Inventory UI** — store findings (SQLite), searchable/filterable table.
6. **Risk engine** — implement Quantum Migration Priority exactly as specified in `06_RISK_SCORING.md`;
   Finding Detail screen with risk-factor breakdown.
7. **Dependency graph** — NetworkX backend, graph API, React Flow frontend; blast-radius endpoint.
8. **Migration planner** — rules engine from `07_MIGRATION_RULES.md`; roadmap view.
9. **PQC Lab** — wrap a maintained implementation (e.g., liboqs via Python bindings):
   ML-KEM keygen/encaps/decaps/shared-secret comparison, ML-DSA sign/verify, benchmarks.
   **Do not implement cryptography from scratch.**
10. **AI Copilot** — grounded explanation layer (retrieval over findings + rules; strict guardrails).
11. **Report generator** — Markdown/PDF export with executive summary, limitations, scan metadata.
12. **Polish + demo rehearsal** — seeded Acme Payments repo (`09_SAMPLE_REPOSITORY_SPEC.md`),
    loading states, error states, run the full demo sequence from `10_UI_ARCHITECTURE_AND_DEMO.md`.

Do not start with the AI Copilot, authentication, or microservices. Discovery → inventory →
risk → graph → migration planning is the spine of the demo.

## Constraint

Everything in this pack is scoped to be buildable as a **polished prototype** by a small
team within ~36 hours of focused hackathon work (with pre-hackathon preparation allowed).
Non-goals are listed explicitly in `01_PROJECT_SPEC.md` and should be resisted.
