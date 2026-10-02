# 10_UI_ARCHITECTURE_AND_DEMO.md

UI screens, system architecture, and the judge demo sequence.

## 1. UI screens

### 1.1 Dashboard
Cards + charts showing:
- total crypto assets (findings), by primitive category
- quantum-vulnerable assets count + list
- high-priority findings (QMP High/Critical) with HNDL badges
- affected services count
- migration status per service (from `already_pqc` findings + planner state)
- Honesty footer: "Static-analysis estimates. Not a certification."

### 1.2 Repository Scanner
- Upload (zip/tar) or point at bundled demo repo ("Load Acme Payments").
- Progress: ingestion → extraction (safe) → scanning (per-language rule counts) →
  enrichment → risk scoring → graph build. Live rule ticker shows which rule fired last.
- Result summary: N findings, M quantum-vulnerable, K high-confidence.

### 1.3 Crypto Inventory
Searchable/filterable table: algorithm, primitive, operation, service, file, confidence,
QMP band, quantum_vulnerable. Filters: language, service, primitive category, band,
already_pqc. Export CSV.

### 1.4 Finding Detail
- Header: algorithm + operation + QMP band + HNDL badge.
- Evidence panel: file path, line range, literal evidence string, syntax-highlighted
  snippet, rule id + version.
- Confidence: score + level + why (rule type, comment-only check result).
- Risk factors: the five factor bars (QE/DS/IE/BC/MC) with values and sources
  (`06` §1).
- Dependencies: mini-graph of this finding's 2-hop neighborhood (`08`).
- Migration candidate: rule output from `07` (e.g., ECDH → ML-KEM) + caveats + "requires
  human review" notice.
- Actions: mark false positive (with reason), copy evidence, ask AI Copilot.

### 1.5 Dependency Graph
Interactive React Flow graph: nodes colored by type (service=blue, crypto=red/orange by
band, protocol=purple, data asset=green). Click any node → focus view with the chain
rendered as a sentence ("Payment API → auth.py → ECDSA → JWT signing → customer
authentication"). Blast-radius panel (`08` §5) for primitive nodes.

### 1.6 Migration Planner
Table + roadmap view per service:

```
Current crypto → cryptographic role → PQC candidate → affected systems → complexity → next steps
ECDH (keys.py) → key establishment    → ML-KEM (FIPS 203) → payment-api, settlement-worker → 2 (cross-service) → 1) abstract behind provider 2) hybrid deploy 3) monitor 4) retire
ECDSA (auth.py) → signatures          → ML-DSA (FIPS 204) → payment-api + JWT verifiers  → 2 → ...
AES-256-GCM     → symmetric encryption → no PQC migration  → — → 0 → key-size headroom note only
SHA-1 (legacy)  → hashing (deprecated) → SHA-256 (classical hygiene) → settlement-worker → 1 → ...
Unknown (old_hash?) → unclassified    → manual review queue → — → — → assign to security team
```

Every row renders its caveats and the human-review requirement (`07`).

### 1.7 PQC Lab
Real operations via a maintained implementation (**liboqs** — never from scratch):
- ML-KEM: key generation (parameter set selectable: 512/768/1024) → encapsulate →
  decapsulate → **shared-secret equality check** displayed.
- ML-DSA: keygen → sign message → verify → show tamper test (flip one byte → verify fails).
- Benchmarks: keygen/encaps/sign times for each parameter set (measured live, cached).
- Education panel: one-paragraph distinction — ML-KEM = **key establishment**;
  ML-DSA/SLH-DSA = **signatures**; AES/SHA unaffected by Shor.

### 1.8 AI Copilot
Can (grounded on retrieved finding JSON + rule text):
- explain a finding in plain language (with citation to file/line),
- explain PQC terminology (KEM, hybrid, crypto-agility, HNDL),
- generate migration checklists from `07` templates,
- summarize affected services from graph data.

Must NOT (enforced):
- replace deterministic scanner logic; findings/scores come only from the engine,
- invent vulnerabilities or algorithms,
- certify security or claim "quantum-safe" outcomes,
- guarantee timelines. Every response carries: *"Advisory explanation generated from
  scan evidence. Verify against the cited finding. Not a security certification."*

Graceful degradation: if no LLM backend is configured, template-based explanations
(canned, deterministic) keep the demo working offline.

### 1.9 Report
Generated Markdown/PDF containing:
executive summary → full inventory → findings with evidence → risk priorities (factor
tables) → dependency graph snapshot → migration roadmap (rules + caveats) → **limitations**
(static-analysis estimate, no certification, prototype methodology) → scan metadata
(engine/rule versions, timestamps, scan id).

## 2. Architecture

```
┌────────────────────────── Docker Compose ──────────────────────────┐
│  frontend/   React + TypeScript + Vite        (dev :5173)          │
│  backend/    Python + FastAPI                 (:8000)              │
│    ├─ ingestion service   (safe extract, redaction, size limits)   │
│    ├─ scanner worker      (Python AST / Tree-sitter / regex rules) │
│    ├─ risk engine         (QMP formula, `06`)                      │
│    ├─ graph engine        (NetworkX build + blast radius, `08`)    │
│    ├─ rules engine        (migration rules, `07`)                  │
│    ├─ pqc service         (liboqs via python bindings)             │
│    └─ copilot service     (retrieval + guardrails, optional LLM)   │
│  db          SQLite (PostgreSQL-compatible schema/ORM)             │
│  scanner sandbox: non-root, no network, RO fs, rlimits, timeouts   │
└────────────────────────────────────────────────────────────────────┘
```

Key decisions:
- **Monolith backend** (FastAPI) — no microservices; modules, not services.
- **SQLite** first; SQLAlchemy models kept PostgreSQL-compatible for the story.
- **Deterministic-first**: scanner, risk, rules, graph contain zero AI calls.
- **PQC**: liboqs (https://github.com/open-quantum-safe/liboqs,
  https://openquantumsafe.org/) behind a thin internal provider interface.

## 3. Demo sequence (5–8 minutes, judge-facing)

1. **Upload** the Acme Payments repository (or one-click "Load demo repo"). Show safe
   ingestion progress with rule ticker.
2. **Scan completes** → Dashboard: "38 findings, 12 quantum-vulnerable, 2 Critical."
3. **Crypto Inventory** → filter `primitive=public-key`. Narrate: "This is more than
   'RSA detected' — every row has file, line, evidence, confidence."
4. **Open top finding** (ECDH, payment-api): show evidence snippet, five risk factors,
   **HNDL elevated** badge — "data must stay secret 10 years; recorded traffic is at risk."
5. **Dependency graph**: click ECDH node → chain renders: payment-api → keys.py → ECDH →
   TLS/gRPC sessions → cardholder sessions. Narrate the "why it matters" sentence.
6. **Blast radius** of ECDH: "2 services, 2 protocols, 2 data assets affected."
7. **Migration planner**: ECDH → ML-KEM (FIPS 203) with hybrid-transition steps; ECDSA →
   ML-DSA; AES row explicitly shows "no PQC migration required."
8. **PQC Lab**: generate ML-KEM-768 keys, encapsulate, decapsulate, show shared secrets
   match; sign + verify with ML-DSA; flip a byte → verification fails. Mention liboqs.
9. **AI Copilot**: "Explain finding CRYPTO-001 like I'm a product manager." Response cites
   file/line; disclaimer visible.
10. **Generate report** → scroll executive summary + limitations; close with the tagline:
    *"Discover your cryptography. Understand your quantum exposure. Plan your migration."*

## 4. Demo risks & mitigations

- LLM unavailable → template Copilot mode (prepared).
- liboqs build issues → prebuilt wheel / vendored build; fallback: pre-recorded benchmark
  numbers clearly labeled as cached.
- Demo repo typo breaking a rule → `09` fixture ships with an automated self-test script
  asserting all 12 seeded findings fire before hackathon day.
