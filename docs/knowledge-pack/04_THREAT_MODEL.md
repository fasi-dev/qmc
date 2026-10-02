# 04_THREAT_MODEL.md

Threat model for the **Quantum Migration Copilot platform itself**. (The cryptographic
threat model of *users' systems* is covered in `02` §2 and §11.)

## 1. Assets

| Asset | Why it matters |
|---|---|
| Sensitive data (in analyzed repos) | Repos may contain secrets, PII, proprietary code |
| Application identities / credentials found in repos | Scanner output may reveal live credentials |
| Certificates & keys (public and, accidentally, private) | Private keys in repos are a critical exposure |
| Signatures / cryptographic metadata | Business-sensitive security posture information |
| Source repositories (uploaded) | Intellectual property; tamper target |
| Service communications data (TLS configs, endpoints) | Attack-surface intelligence |
| Software artifacts (Dockerfiles, CI configs) | Supply-chain insight |
| Scan results (findings, scores, graph) | Sensitive security-posture map; must be tamper-evident |
| AI Copilot prompts/outputs | May contain proprietary code snippets |

## 2. Threats

| # | Threat | Description | Primary mitigations |
|---|---|---|---|
| T1 | Future quantum attacks against vulnerable public-key crypto | Adversaries with a future CRQC break RSA/DH/ECDH/ECDSA/EdDSA (see `02`) | The product's purpose: discovery + migration planning. We claim **no** protection by ourselves. |
| T2 | Harvest-now-decrypt-later | Recorded ciphertext decrypted later; long-lived sensitive data at risk now | HNDL-aware prioritization (`06` §HNDL); long-lifetime data assets flagged |
| T3 | Cryptographic blind spots | Org doesn't know where crypto is used → unmanaged quantum exposure | Inventory + evidence-backed findings (`05`) |
| T4 | Dependency propagation | One quantum-vulnerable library affects many services | Dependency graph + blast radius (`08`) |
| T5 | Outdated certificates/configuration | Weak TLS, expired/SHA-1 certs compound exposure | Config scanning rules (`05`) |
| T6 | Migration/interoperability failure | Bad migration breaks systems or reduces security (e.g., downgrade) | Migration rules with caveats (`07`); hybrid recommendations; human-review gates |
| T7 | False positives | Tool noise wastes engineering time, erodes trust | Confidence model + suppression (`05` §Confidence) |
| T8 | False negatives | Missed crypto → false sense of security | Documented limitations everywhere; "requires human review" labels |
| T9 | Incorrect AI-generated security advice | LLM hallucination in security context is dangerous | AI is advisory-only, grounded in scanner evidence; deterministic rules remain source of truth (`10` guardrails) |
| T10 | Malicious uploaded repositories/files | Zip bombs, path traversal, polyglot files, embedded malware targeting the scanner host | Safe ingestion controls (§4); **never execute uploaded code** |
| T11 | Tampering with findings/scores | Altered scan results mislead migration decisions | Immutable scan records, rule-versioned findings, audit log |
| T12 | Data leakage via AI layer | Repo snippets sent to external LLM provider | Privacy controls (§4); local/redacted mode |

## 3. Trust boundaries

```
User
 │ (HTTPS)
 ▼
Web UI ──► Backend API ──► Scanner (isolated worker)
              │                │
              ▼                ▼
           Database ◄──── Risk engine ──► Graph engine
              │
              ▼
        PQC demonstration service (liboqs)
              │
              ▼
        Optional AI layer (external or local LLM)
```

Boundaries and rules:
1. **User → Web UI**: session-scoped; upload auth (demo: single-tenant, local).
2. **Backend → Scanner**: queued jobs; scanner receives a **sandboxed extracted tree only**;
   no network access inside the scanner sandbox.
3. **Scanner → Database**: findings persist with rule version, evidence hash, scan ID.
4. **Risk/Graph engines → Database**: read findings; write scores/edges. Deterministic, no AI.
5. **PQC demo service**: stateless; performs real operations via liboqs on **generated** keys
   only; never touches scanned material.
6. **AI layer**: receives (a) finding records, (b) user questions, (c) retrieved rule text —
   never raw repo dumps by default; external-provider calls are opt-in and disclosed.

## 4. Security controls (implementation requirements)

| Control | Requirement |
|---|---|
| Never execute uploaded code | Static analysis only. No `import` of scanned code, no subprocess on repo files, no eval of extracted scripts. |
| Safe archive extraction | Reject non-zip/tar archives; validate magic bytes; use safe-extract with symlink/absolute-path rejection. |
| Path traversal prevention | Normalize all extracted paths; reject `..`, absolute paths, drive letters; confine extraction to a per-scan UUID directory. |
| File size limits | Archive ≤ 100 MB default; single file ≤ 5 MB; extracted total ≤ 300 MB; max file count ≤ 50k (configurable). |
| Zip-bomb defense | Compression-ratio cap (e.g., ≤ 100:1) checked before full extraction. |
| Secret/private-key redaction | Detect PEM private key blocks, common API-key patterns, and JWTs in files **at ingestion**; store only a redacted marker `***REDACTED***` + location metadata in findings. Never persist secrets. |
| Sandboxing | Scanner runs in a container with: read-only FS except scratch dir, no network, non-root user, CPU/memory limits, timeout (≤ 5 min/scan). |
| LLM data privacy | Default = local/template explanations. If an external LLM is configured: disclose it, minimize payload (finding records + retrieved text only), strip secrets pre-send, never send full repos. |
| Auditability | Every finding stores: scan_id, rule_id, rule_version, engine_version, timestamp, evidence hash. Scores store factor values. Graph stores derivation edges. |
| Evidence-based findings | Every finding must carry file path + line range + literal evidence string; no finding without evidence is renderable. |
| AI guardrails | Copilot responses are generated only from: finding JSON, `02/03/07` rule text, and user question. UI always shows "Advisory — verify with the cited finding" disclaimer. Copilot cannot modify findings, scores, or plans. |

## 5. Out of scope for the prototype (acknowledged, not defended)

- Multi-user authorization/tenancy (single-tenant local demo).
- Network exposure of the demo beyond localhost.
- Persistence of uploaded repos after scan (delete extracted tree after analysis; keep only findings).
