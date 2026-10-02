# 09_SAMPLE_REPOSITORY_SPEC.md — "Acme Payments" Demo Fixture

A **fictional** organization and repository used for the demo and tests. All data is
fabricated. **Prohibited:** real credentials, real private keys, real API keys, real
customer data, real production domains. Use example domains (`acme-payments.example`).

## 1. Organization

**Acme Payments** — fictional payment-processing company. Services:

| Service | Owner | Classification | Criticality | Internet-exposed | Data lifetime |
|---|---|---|---|---|---|
| payment-api | payments-team | highly-sensitive | critical | true | 10 years |
| settlement-worker | payments-team | highly-sensitive | high | false | 10 years |
| notifications-svc | platform-team | internal | medium | false | 1 year |

## 2. Repo layout (fixture the scanner ingests)

```
acme-payments/
├── service.yaml                    # metadata (below)
├── requirements.txt                # cryptography==42.0.0, pycryptodome, ...
├── src/
│   ├── auth.py                     # RSA-2048 keygen + JWT signed with ECDSA P-256
│   ├── payments/
│   │   ├── keys.py                 # ECDH (X25519) key agreement for session keys
│   │   └── settle.py               # AES-256-GCM data at rest, HMAC-SHA256 webhooks
│   ├── legacy/
│   │   └── old_hash.py             # SHA-1 file digests (legacy path)
│   └── java/                       # mirror of a Java service module
│       └── TokenSigner.java        # java.security: ECDSA SHA256withECDSA; KeyAgreement ECDH
├── deploy/
│   ├── nginx/
│   │   └── tls.conf                # TLS 1.0 + TLS 1.1 enabled, ssl_ciphers list
│   └── docker-compose.yml          # service wiring
├── certs/
│   └── api.acme-payments.example.crt  # self-signed EXAMPLE cert (expired on purpose)
├── scripts/
│   └── gen_test_keys.py            # unused RSA example in a dev script
└── pqc-lab/
    └── kem_demo.py                 # ML-KEM-768 via liboqs (already migrated)
```

## 3. service.yaml (metadata consumed by scanner/risk engine)

```yaml
service: payment-api
owner: payments-team
data_classification: highly-sensitive
business_criticality: critical
internet_exposed: true
data_lifetime_years: 10
```

(One per service root; the fixture scanner maps files to the nearest `service.yaml`.)

## 4. Seeded findings the scanner MUST discover

| # | Location | Algorithm/role | Confidence | Expected QMP |
|---|---|---|---|---|
| 1 | src/payments/keys.py | ECDH (X25519) key establishment | High | **Critical (20)** + HNDL elevated |
| 2 | src/auth.py | RSA-2048 key generation (auth) | High | High |
| 3 | src/auth.py | ECDSA P-256 JWT signing | High | High (cross-service verifier → MC=2) |
| 4 | java/TokenSigner.java | ECDSA SHA256withECDSA | High | High |
| 5 | java/TokenSigner.java | KeyAgreement("ECDH") | High | High |
| 6 | deploy/nginx/tls.conf | TLS 1.0/1.1 enabled + weak ciphers | Medium | Review |
| 7 | src/legacy/old_hash.py | SHA-1 digests | Medium | Review (classical hygiene) |
| 8 | src/payments/settle.py | AES-256-GCM at rest | High | **Informational** (guard rule) |
| 9 | src/payments/settle.py | HMAC-SHA256 | High | Informational |
| 10 | scripts/gen_test_keys.py | RSA keygen, test path + unused | High | Review, then suppressible (contrast demo) |
| 11 | certs/*.crt | Expired self-signed cert | Medium | Review |
| 12 | pqc-lab/kem_demo.py | ML-KEM-768 KEM | High | `already_pqc` — excluded from vulnerable counts |

These fixtures exercise: discovery (1–12), inventory filtering, risk scoring bands
(Critical/High/Review/Informational), HNDL flag (1), guard rule (8), suppression demo (10),
and migration rules R-01/R-03/R-05 with real contrast.

## 5. Seeded code requirements (for fixture authors)

- Evidence strings must be **real API calls** (e.g., `cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(ec.SECP256R1(), ...)`, `KeyAgreement.getInstance("ECDH")`) so the evidence column is compelling in the demo.
- The ML-KEM fixture must use a maintained binding (`oqs` Python package over liboqs), never a hand-rolled implementation.
- Include one comment-only trap: `# TODO: consider RSA` in a README — scanner must rate it **Low**, proving the confidence model (`05` §5).

## 6. What the full pipeline demo must show on this repo

discovery (12 findings) → inventory → quantum-vulnerable set (1–7, 10, 11) →
risk ranking (1 on top, Critical + HNDL elevated) → dependency graph
(payment-api → auth.py → ECDSA → JWT → customer sessions) → blast radius of ECDH
(2 services, TLS + gRPC-internal, cardholder sessions) → migration planner
(R-01/R-03 → ML-KEM; R-05 → ML-DSA/SLH-DSA) → report.
