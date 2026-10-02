# 01_PROJECT_SPEC.md — Quantum Migration Copilot

**Tagline:** *Discover your cryptography. Understand your quantum exposure. Plan your migration.*

## 1. Problem statement

Organizations deploy cryptography everywhere: APIs, authentication, TLS, certificates,
digital signatures, key establishment, package signing, service-to-service communication,
databases, and third-party libraries. Yet most organizations lack a complete,
dependency-aware inventory of **where** cryptography is used.

As the industry transitions to post-quantum cryptography, organizations must answer:

1. Where is cryptography being used?
2. Which mechanisms are **quantum-vulnerable** (public-key algorithms based on integer
   factorization or discrete logarithms)?
3. What systems **depend on** those mechanisms?
4. Which findings deserve attention **first**?
5. Which PQC migration direction is **appropriate** (KEM vs signature; never conflated)?
6. What is the migration **impact / blast radius**?
7. How to begin a **controlled, crypto-agile** migration?

## 2. Real-world motivation

- NIST finalized FIPS 203 / 204 / 205 on **2024-08-13**, and the NCCoE Migration to PQC
  project explicitly calls for **automated discovery tools** to find quantum-vulnerable
  cryptography in enterprise code, configurations, and protocols.
- Historical algorithm transitions (e.g., SHA-1 deprecation, TLS 1.0/1.1 retirement) took
  **many years**; NIST's guidance stresses starting migration planning early because
  cryptographic transitions are slow.
- **Harvest-now-decrypt-later**: adversaries can record encrypted traffic today and decrypt
  it later once a cryptographically relevant quantum computer exists. Data with long
  confidentiality lifetimes is already exposed.

## 3. Target users

- **Security engineers** building a cryptographic inventory and migration plan.
- **Platform/DevOps teams** maintaining TLS, certificates, and service configuration.
- **Engineering managers** prioritizing migration work with limited budget.
- **Hackathon judges / evaluators** assessing prototype feasibility and technical honesty.

## 4. Proposed solution

Quantum Migration Copilot accepts a repository/archive and performs **deterministic static
analysis** to produce an evidence-backed pipeline:

```
Repository
  → Safe ingestion (no code execution)
  → Cryptographic discovery (AST + config rules)
  → Cryptographic inventory
  → Quantum exposure analysis
  → Business/contextual risk assessment
  → Dependency graph + blast radius
  → Deterministic PQC migration recommendations
  → Migration roadmap / report
  → Optional AI Copilot explanation (advisory only)
```

## 5. Core features

| # | Feature | Deterministic? | Source of truth |
|---|---|---|---|
| 1 | Safe repo ingestion & metadata parsing | Yes | `04`, `05` |
| 2 | Multi-language crypto discovery (Python, Java, JS/TS, YAML/JSON, Nginx, Docker/CI) | Yes | `05` |
| 3 | Crypto inventory (searchable/filterable, evidence + confidence) | Yes | `05` |
| 4 | Quantum exposure analysis | Yes | `02`, `03`, `05` |
| 5 | Quantum Migration Priority scoring | Yes (transparent formula) | `06` |
| 6 | Dependency graph + migration blast radius | Yes (static estimate) | `08` |
| 7 | Migration planner (primitive+role → PQC candidate) | Yes (rule table) | `07` |
| 8 | PQC Lab (ML-KEM KEM ops, ML-DSA sign/verify via liboqs) | Yes | `10`, `03` |
| 9 | AI Copilot explanation | **No — advisory only** | `10` guardrails |
| 10 | Report generation | Yes | `10` |

## 6. Product differentiator

Most "crypto scanners" stop at **"RSA detected."** Quantum Migration Copilot answers the
next four questions: **what depends on it, why it matters, what to migrate it toward, and
how an engineering team starts a controlled migration** — with an explainable score, a
dependency graph, deterministic rules, and live PQC demonstrations of the actual target
algorithms. The AI layer explains; it never decides.

## 7. Scope

- Static analysis of uploaded repos/archives (see `04` for safety controls).
- The languages/configs listed in `05`.
- The PQC standards FIPS 203 / 204 / 205 only (final standards).
- Single-tenant, local/demo deployment via Docker Compose.

## 8. Non-goals (explicit)

- ❌ Runtime/binary analysis, firmware, HSM internals.
- ❌ Network scanning of live infrastructure.
- ❌ Formal verification or security certification of any kind.
- ❌ Enterprise auth / multi-tenancy / SSO.
- ❌ Production-grade HA deployment.
- ❌ Custom cryptographic implementations (PQC Lab uses liboqs only).
- ❌ Claiming detection completeness — static analysis will miss things.

## 9. MVP (must work on demo day)

1. Upload Acme Payments repo (zip) → safe extraction.
2. Scan completes with seeded findings discovered (see `09`).
3. Inventory table with filters (algorithm, primitive, service, confidence).
4. Finding detail with evidence, line numbers, confidence, risk-factor breakdown.
5. Quantum Migration Priority scores rendered with per-dimension explanation.
6. Dependency graph for at least the payment-api service; blast-radius view.
7. Migration planner showing RSA→ML-KEM, ECDSA→ML-DSA/SLH-DSA rows with caveats.
8. PQC Lab: ML-KEM keygen/encaps/decaps + ML-DSA sign/verify working via liboqs.
9. AI Copilot explains one finding using retrieved evidence (with disclaimer).
10. Report export (Markdown at minimum) with limitations section.

## 10. Stretch features (only after MVP is stable)

- More languages (Go, Rust, C#) and dependency manifest parsing (requirements.txt, pom.xml, package.json → package nodes in graph).
- Diff scanning between two commits (migration progress tracking).
- Certificate expiry/weakness checks on PEM blocks found in repo.
- PDF report with charts.
- Suppression file support (`qmc-ignore.yaml`) honored by scanner.

## 11. Expected demo

The 5–8 minute judge demo is fully scripted in `10_UI_ARCHITECTURE_AND_DEMO.md`
§Demo sequence. It must communicate: *"Here is where your cryptography is, what depends
on it, why it matters, and how an engineering team can begin a controlled PQC migration."*

## 12. Success criteria

- All MVP items functional end-to-end in Docker Compose on a judge's laptop.
- Zero crashes during the scripted demo; graceful error states everywhere.
- Scanner recall on seeded Acme Payments repo: **all findings in `09` discovered**.
- No false "high confidence" on comment-only matches (per `05` confidence rules).
- Technical honesty: demo script contains none of the forbidden claims (§Limitations).
- Every UI finding traces to file + line + evidence string.

## 13. Limitations (stated in-product and in the report)

- Static analysis **misses** dynamically loaded crypto, native binaries, external services, and obfuscated code.
- Confidence scores are heuristic; low/medium findings **require human review**.
- Blast radius is a **static estimate**, not a perfect enterprise dependency map.
- Quantum-vulnerable ≠ broken today; we are planning for a future threat (see `02`).
- The risk model is a **prototype methodology**, not a NIST-endorsed score.
- PQC Lab is an **educational demonstration** of standardized algorithms via a maintained
  library — not a deployment recommendation.

## 14. Hackathon feasibility

- Pre-hackathon: documents (this pack), repo scaffold, scanner rules for Python/JS, UI shell.
- In-hackathon: wiring, Java + config rules, risk engine, graph, PQC Lab, polish, rehearsal.
- All heavy dependencies (liboqs, tree-sitter, FastAPI, React) are well-documented, open
  source, and installable offline if mirrored. Everything in the MVP is local and
  deterministic except the optional AI Copilot, which degrades gracefully (canned
  explanations from templates) if the network/LLM is unavailable.
