# PQC Readiness Assessment

`GET /api/scans/{id}/readiness` · UI: **PQC Readiness** · Report section 9 · Code: `backend/app/readiness.py`

The assessment answers *how prepared is this code base for the move to post-quantum cryptography?* using only
scanner findings, QMP risk data and the dependency graph. Every category, blocker and recommendation lists the
findings it is based on (`file:line`, evidence text, finding id).

## No percentage score

There is deliberately no readiness percentage: any weighting of "how ready" would be arbitrary. The overall result
is an **ordinal level** chosen by the first matching rule:

| Order | Level | Rule |
|---|---|---|
| 1 | **Not ready: critical blockers** | At least one blocker (below). |
| 2 | **In transition** | Quantum-vulnerable public-key crypto in use AND standardized PQC (ML-KEM / ML-DSA / SLH-DSA) used outside test / lab / demo / example paths. |
| 3 | **Not ready** | Quantum-vulnerable public-key crypto in use, no PQC outside those paths. |
| 4 | **No quantum-vulnerable usage detected** | Nothing quantum-vulnerable found in the analyzed files. **Never** reported as "quantum-safe". |

(Rules 2 and 3 are checked in that order; the API returns them as `level_rules`.)

## Blockers

| Blocker | Condition | Why |
|---|---|---|
| Harvest-now-decrypt-later exposure | Quantum-vulnerable key establishment with the QMP HNDL flag "elevated" (sensitive data, internet-exposed, confidentiality lifetime of 10+ years, from `service.yaml`) | Recorded traffic can be decrypted later; NIST IR 8547 asks for the earliest transition for long-term confidentiality. |
| Disallowed legacy ciphers | DES / 3DES / RC4 / Blowfish in code | SP 800-131A Rev. 2 (DES, 3DES encryption disallowed), RFC 7465 (RC4 in TLS). |
| Deprecated TLS/SSL versions | nginx / YAML / JSON settings enabling SSLv3, TLS 1.0, TLS 1.1 | RFC 8996. |
| Weak TLS cipher suites | RC4 / 3DES / NULL / EXPORT / MD5 suites enabled | RFC 7465, SP 800-131A. |
| SHA-1-signed certificates | PEM certificates signed with SHA-1 | SHA-1 is disallowed for signature generation. |

Without service metadata no HNDL blocker can be raised; the assessment then says so in its limitations.

## Categories

Key establishment · Digital signatures · Certificates and PKI · Undetermined role · Protocol configuration ·
Legacy symmetric ciphers · Broken hash functions · Symmetric key strength (AES-128) · Post-quantum adoption ·
Crypto agility. Each has a status (`blocker`, `action`, `review`, `positive`, `partial`, `not_detected`, `info`),
counts, files, components, algorithms and evidence.

*Crypto agility* is computed from the dependency graph: how many files call quantum-vulnerable APIs directly, and
which of them other files already import ("hubs", candidates for a central crypto interface).

*Post-quantum adoption* treats test paths and paths with a `lab`, `demo`, `example(s)`, `sample(s)`, `poc`,
`sandbox` or `playground` token as non-production (the Acme demo's `pqc-lab/` is therefore "partial").

## Recommendations

Ordered by priority (P1 to P4), each with its evidence, references and a link into the Migration Simulator:
hybrid key establishment for HNDL-exposed services; removal of disallowed classical crypto; ML-KEM for remaining key
establishment; verifier inventory then ML-DSA / SLH-DSA; role review for undetermined usage; centralization behind
hub files; MD5 / SHA-1 replacement; AES-256 for long-lived data; moving PQC out of lab code; library version checks.

## Library PQC support

Known support is listed with its source; **installed versions are never determined** because dependency manifests
and lock files are not analyzed. Libraries not in the table are shown as "not verified", not as unsupported.

| Library (as named by the rules) | Known PQC support | Source |
|---|---|---|
| `cryptography` (pyca) | ML-KEM and ML-DSA modules: 47.0+ with AWS-LC/BoringSSL builds, 49.0+ also with OpenSSL 3.5+; no SLH-DSA yet | cryptography.io changelog |
| `java.security`, `javax.crypto` | ML-KEM (KEM API) and ML-DSA (Signature API) since JDK 24 | JEP 496, JEP 497 |
| `bouncycastle` | ML-KEM, ML-DSA, SLH-DSA since Bouncy Castle Java 1.79 | bouncycastle.org |
| `node:crypto`, `webcrypto` | ML-KEM (`crypto.encapsulate`/`decapsulate`) and ML-DSA (`crypto.sign`/`verify`) since Node.js 24.7.0 (OpenSSL 3.5 builds) | Node.js 24.7.0 release notes |
| `nginx` | Hybrid TLS groups depend on the linked OpenSSL (3.5 offers X25519MLKEM768 by default) | OpenSSL 3.5 announcement |
| `openssh` | Hybrid `mlkem768x25519-sha256` key exchange in recent releases | OpenSSH release notes |

## What is analyzed / not analyzed

Analyzed: the files the scanner covers (Python, Java, JavaScript/TypeScript, nginx, SSH, YAML/JSON, Dockerfile/CI,
PEM certificates), their detections, service metadata and import relationships. The response lists file counts by
language, scan status, skipped files by reason, exclusions and services with complete metadata.

Not analyzed: installed library/runtime versions; binaries, container images, HSM/KMS and cloud-managed keys;
TLS/SSH settings outside the repository and library defaults; other languages; runtime-selected algorithms and
dynamically loaded code; third-party services.

## References

FIPS 203, FIPS 204, FIPS 205; NIST IR 8547 (final, 27 Oct 2026); NIST SP 800-131A Rev. 2; NIST SP 800-227;
RFC 9964 (ML-DSA for JOSE/COSE); draft-ietf-tls-ecdhe-mlkem (X25519MLKEM768; approved, in the RFC Editor queue as of
mid-2026); RFC 7465; RFC 8996; NIST CSWP 39 (crypto agility). URLs are in the API response (`references`).
