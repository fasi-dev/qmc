# 05_CRYPTO_SCANNER_SPEC.md

Specification for the static cryptographic discovery engine ("the scanner").

## 1. Design principles

1. **Deterministic**: every finding comes from an explicit rule, never from an LLM.
2. **Evidence-based**: no finding without file + line + literal evidence string.
3. **Confidence, not certainty**: heuristics are labeled; comments alone are never
   high-confidence.
4. **Safe**: see `04` §4 — static only, sandboxed, redacting.
5. **Rule-versioned**: every finding records `rule_id` + `rule_version` for auditability.

## 2. Input languages (MVP)

| Language/config | Detection technique |
|---|---|
| Python | AST (builtin `ast`) — resolves imports and call targets |
| Java | Tree-sitter / regex-anchored rules on `javax.crypto`, `java.security`, Bouncy Castle APIs |
| JavaScript/TypeScript | Regex-anchored + lightweight parse (`node:crypto`, `crypto-js`, `node-forge`, `jose`) |
| YAML / JSON | Parser-based key inspection (metadata, TLS-ish keys, algorithm strings) |
| Nginx / config files | Directive-aware regex (`ssl_certificate`, `ssl_protocols`, `ssl_ciphers`) |
| Docker / CI (Dockerfile, `*.yml` CI) | Instruction/keyword rules (base images with TLS, cert copy steps) |

## 3. Detection catalog

| Algorithm | Primitive category | Typical operations | Example evidence patterns |
|---|---|---|---|
| RSA | public-key | key_generation, encryption, signature, verification | `rsa.generate_private_key(`, `RSA/ECB/`, `RSAPrivateKey`, `forge.pki.rsa` |
| DSA | public-key | key_generation, signature | `DSAParameterSpec`, `dsa.Sign` |
| DH | public-key | key_agreement | `KeyAgreement.getInstance("DH")`, `DHParameterSpec` |
| ECDH | public-key | key_agreement | `KeyAgreement.getInstance("ECDH")`, `ecdh.generateKeys? (forge)`, `X25519` |
| ECDSA | public-key | signature, verification | `ecdsa.SigningKey`, `SHA256withECDSA`, `crypto.createSign('sha256')` + EC key |
| EdDSA (Ed25519) | public-key | signature, verification | `Ed25519`, `EdDSA`, `nacl.sign` |
| AES | symmetric | encryption, decryption | `AES.new(`, `Cipher.getInstance("AES...")`, `createCipheriv('aes-256-gcm'` |
| SHA-1 | hash | hashing (deprecated) | `sha1`, `SHA-1`, `createHash('sha1')`, `SHA1withRSA` |
| SHA-256/384/512 | hash | hashing | `sha256`, `SHA-384`, `MessageDigest.getInstance("SHA-512")` |
| SHA-3 | hash | hashing | `sha3_256`, `SHA3-512` |
| HMAC | MAC | authentication-code generation/verification | `hmac.new(`, `Mac.getInstance("HmacSHA256")` |
| TLS | protocol | configuration, termination | `ssl_protocols TLSv1 TLSv1.1`, `min_version`, `ssl_ciphers` |
| SSH | protocol | configuration | `HostKeyAlgorithms`, `KexAlgorithms` in sshd_config-style files |
| ML-KEM | PQC KEM | key_generation, encapsulation, decapsulation | `oqs.KeyEncapsulation("ML-KEM-768")`, `liboqs`, `MLKEM` |
| ML-DSA | PQC signature | key_generation, signing, verification | `oqs.Signature("ML-DSA-65")`, `MLDSA` |
| SLH-DSA | PQC signature | key_generation, signing, verification | `oqs.Signature("SLH-DSA-SHA2-128s")` |

PQC detections mark findings as `already_pqc: true` and exclude them from quantum-vulnerable
counts (they demonstrate migration coverage instead).

## 4. Finding schema

```json
{
  "id": "CRYPTO-001",
  "scan_id": "uuid",
  "rule_id": "PY-CRYPTOGRAPHY-RSA-001",
  "rule_version": "1.2.0",
  "engine_version": "0.1.0",
  "file": "src/auth.py",
  "line_start": 42,
  "line_end": 42,
  "algorithm": "RSA",
  "primitive": "public-key",
  "operation": "key_generation",
  "library": "cryptography",
  "api": "rsa.generate_private_key",
  "context": "authentication",
  "service": "payment-api",
  "evidence": "rsa.generate_private_key(public_exponent=65537, key_size=2048)",
  "confidence": 0.97,
  "confidence_level": "high",
  "quantum_vulnerable": true,
  "already_pqc": false,
  "metadata": {
    "key_size": 2048,
    "comment_only": false,
    "in_dead_code": false,
    "test_path": false
  }
}
```

Field rules:
- `primitive` ∈ {public-key, symmetric, hash, mac, pqc-kem, pqc-signature, protocol}.
- `operation` from a closed enum per primitive (key_generation, key_agreement, encryption,
  decryption, signature, verification, hashing, config, …).
- `context` ∈ {authentication, key-establishment, data-protection, integrity, tls-termination,
  code-signing, unknown} — inferred from call site (function name, surrounding identifiers,
  service metadata), else `unknown`.
- `confidence` ∈ [0,1]; `confidence_level` derived per §5.
- `service` from `service.yaml` metadata (`09`), else repo name.

## 5. Confidence model

| Level | Range | Meaning | Example |
|---|---|---|---|
| High | ≥ 0.90 | Resolved API call (AST node or anchored pattern in executable code) with exact algorithm | `Cipher.getInstance("ECDSA")` in Java code |
| Medium | 0.50–0.89 | Anchored pattern with partial context, or config directive, or string literal naming the algorithm | `ssl_ciphers` line naming ECDHE-RSA; `algorithm: "ES256"` in YAML JWT config |
| Low | < 0.50 | Comment mention, generic word ("secure", "crypto"), TODO note, doc-only reference | `# TODO: replace with RSA` |

Hard rules:
- **Comment-only matches can never exceed Low.** Stripping comments must be the first
  step of every rule (lex before matching).
- Generic words ("security", "crypto", "cipher" without algorithm) produce no finding.
- Test paths (`test_`, `*.test.*`, `tests/`) are flagged with `metadata.test_path=true`
  and default-filtered in the UI (not deleted — test crypto can still matter).

## 6. False-positive handling & suppression

- UI groups by rule; "Mark false positive" attaches `suppression` to the finding
  (persisted with reason + author + timestamp) — it stays in the DB but is excluded from
  default views and scores.
- File-based suppression: `qmc-ignore.yaml` at repo root:
  ```yaml
  suppress:
    - rule: "PY-CRYPTOGRAPHY-RSA-001"
      path: "docs/examples/**"
      reason: "Documentation examples only"
  ```
- Every suppressed item is listed in the report's appendix (nothing silently disappears).

## 7. Rule versioning

- Rules live in `scanner/rules/<lang>/<RULE_ID>.yaml` with semantic versions.
- A finding is reproducible given `(engine_version, rule_id, rule_version)`.
- Changing a rule's matching logic requires a version bump; report shows rule versions
  next to findings.

## 8. Contextual metadata enrichment

Post-detection, enrich with:
- `service.yaml` fields: owner, data_classification, business_criticality,
  internet_exposed, data_lifetime_years (schema in `09`).
- Call-graph-lite: enclosing function/class name (AST), imported modules, file→module map.
- Protocol linking: TLS/SSH config findings link to the service node that loads them (`08`).

## 9. Performance & limits

- Target: Acme Payments repo (~40 files) scanned in < 30 s.
- Global timeout 5 min/scan (`04`); partial results returned with `status: "partial"`.

## 10. Known limitations (surfaced in-product)

- Dynamic/indirect crypto (reflection, `eval`, DI frameworks, native `.so`) can evade rules.
- Operation inference (`key_generation` vs `signature`) is heuristic for some libraries.
- Multi-language polyglot files are scanned per primary extension only.
- Minified JS is skipped (files > 10k chars on one line → `status: skipped_minified`).

## 11. Expected detection examples on Acme Payments

Seeded fixtures in `09` must yield (at minimum): RSA-2048 keygen + RSA-OAEP encryption
(Python, `payment-api`, high), ECDSA P-256 JWT signing (Python, high), Java ECDH
`KeyAgreement` (high), TLS 1.0/TLS1.1 enabled in nginx config (medium→high), SHA-1
(Medium), AES-256-GCM (informational, not quantum-vulnerable), and ML-KEM-768 usage in
`pqc-lab/` (already_pqc, excluded from vulnerable counts).
