# 06_RISK_SCORING.md — Quantum Migration Priority (Prototype Methodology)

> **Labeling requirement (show in UI and report):** *"Quantum Migration Priority (QMP) is
> an internal prototype prioritization methodology of Quantum Migration Copilot. It is **not**
> an official NIST score, not a CVSS score, and not a security certification."*

Design goals: **transparent** (every factor visible), **explainable** (users can see why),
**deterministic** (same inputs → same score), **separate dimensions** (no single
mysterious number).

## 1. Dimensions

| # | Factor | Range | What it measures | Source |
|---|---|---|---|---|
| F1 | Quantum exposure (QE) | 0–4 | How quantum-vulnerable is this finding? | Algorithm/primitive of the finding (`05`) |
| F2 | Data sensitivity (DS) | 0–4 | How sensitive is the protected data? | `service.yaml` `data_classification` |
| F3 | Internet/network exposure (IE) | 0–3 | Can adversaries reach it (record traffic now)? | `service.yaml` `internet_exposed` + protocol context |
| F4 | Business criticality (BC) | 0–3 | Impact if this service's crypto fails | `service.yaml` `business_criticality` |
| F5 | Migration complexity (MC) | 0–3 | Effort/risk to migrate (higher = harder) | Rule metadata (`07`) + finding context |

### Factor value tables

**F1 Quantum exposure**
| Condition | Value |
|---|---|
| Not cryptographic / informational (e.g., AES, SHA-2, HMAC) | 0 |
| Symmetric with short key (AES-128) or SHA-1 in non-signature role | 1 |
| Quantum-vulnerable public-key **usage found but context unclear** (confidence < high) | 2 |
| Quantum-vulnerable public-key, high confidence, **signature** role | 3 |
| Quantum-vulnerable public-key, high confidence, **key establishment** role | 4 |

Key establishment scores highest because of harvest-now-decrypt-later (§3): recorded
key-establishment traffic is retroactively decryptable.

**F2 Data sensitivity**
| `data_classification` | Value |
|---|---|
| public | 0 |
| internal | 1 |
| confidential | 2 |
| sensitive | 3 |
| highly-sensitive / regulated (payments, PII, health) | 4 |

**F3 Internet exposure**
| Condition | Value |
|---|---|
| internal-only service | 0 |
| private network reachable (VPC/peer) | 1 |
| exposed to partner networks / egress | 2 |
| `internet_exposed: true` | 3 |

**F4 Business criticality**
| `business_criticality` | Value |
|---|---|
| low | 0 |
| medium | 1 |
| high | 2 |
| critical | 3 |

**F5 Migration complexity (from rule metadata + context)**
| Condition | Value |
|---|---|
| Already PQC / config-only change | 0 |
| Self-contained library call swap | 1 |
| Cross-service protocol change (TLS peers, JWT verifiers must upgrade together) | 2 |
| Embedded/legacy constraints, HSM, external-party dependency, data-format change | 3 |

## 2. Prototype formula

```
raw = (QE * 2) + (DS * 2) + (IE * 1.5) + (BC * 1.5) - (MC * 1.5)
QMP = clamp(round(raw), 0, 20)
```

Maximum: 4·2 + 4·2 + 3·1.5 + 3·1.5 = 8+8+4.5+4.5 = **25** → clamped at 20.
Complexity is subtractive: it does not reduce *exposure*, it reduces *near-term priority*
because migration takes longer — surfaced as a separate dimension, never hidden.

### Priority bands

| Band | QMP | UI color | Meaning |
|---|---|---|---|
| Informational | 0–3 | gray | Not quantum-vulnerable; no PQC action (e.g., AES-256-GCM) |
| Review | 4–9 | yellow | Quantum-vulnerable but low context; human review needed |
| High | 10–14 | orange | Plausible near-term migration target |
| Critical | 15–20 | red | Start migration planning now |

Bands are internal to the project and labeled as such.

## 3. Harvest-now-decrypt-later consideration (separate flag)

HNDL is **not folded into the QMP number**; it is a separate boolean+severity flag so it
cannot be averaged away:

```
HNDL_flag = (primitive == public-key key establishment)
         AND DS >= 3
         AND IE >= 2
         AND data_lifetime_years >= 5
HNDL_severity = "elevated" if data_lifetime_years >= 10 else "noted"
```

UI shows: *"Elevated harvest-now-decrypt-later risk: this service protects data with a
10-year confidentiality lifetime and its key establishment is quantum-vulnerable. Recorded
traffic may be decryptable by a future quantum computer."*

## 4. Why every factor exists

- **QE** — the whole point: distinguishes a quantum-vulnerable key-agreement from a hash call.
- **DS** — NCCoE guidance: prioritize by the sensitivity of what the crypto protects.
- **IE** — externally reachable quantum-vulnerable key establishment is recordable *today*.
- **BC** — a failing payment service outranks a failing internal widget; migration order
  should reflect mission impact.
- **MC** — an honest plan accounts for effort; hiding it produces fantasy roadmaps.

## 5. Worked examples

**Example A — the payment API (Critical + HNDL elevated)**
`payment-api`: ECDH key agreement (`QE=4`), highly-sensitive (`DS=4`), internet-exposed
(`IE=3`), critical (`BC=3`), cross-service protocol change (`MC=2`).
raw = 8 + 8 + 4.5 + 4.5 − 3 = 22 → clamp 20 → **Critical**. HNDL: key establishment +
DS 4 + IE 3 + lifetime 10y → **elevated**.

**Example B — dev script (Informational)**
`scripts/gen_test_keys.py`: RSA keygen (`QE=4`) but internal (`DS=1`), not exposed
(`IE=0`), low (`BC=0`), self-contained (`MC=1`).
raw = 8 + 2 + 0 + 0 − 1.5 = 8.5 → 9 → **Review (high end)** — visible but far below A.

**Example C — unused RSA example in a dev script (the required contrast)**
Same RSA keygen, but flagged `metadata.test_path=true` and confirmed dead code via human
review → suppression applies; excluded from default views. *A highly sensitive,
internet-facing, business-critical service using ECDH for key establishment receives
substantially more attention than a development script containing an unused RSA example.*

**Example D — AES-256-GCM at rest**
`QE=0` → raw = 0+2·DS… wait — QE 0 makes it informational: raw ≤ 4+3+3 = 10 possible;
guard rule: if `QE == 0`, band = Informational regardless of arithmetic. QMP displays
"Informational — no PQC migration required; consider key-size headroom."

## 6. Guard rules & honesty

- If metadata fields are missing, DS/IE/BC default to the **midpoint with a "metadata
  missing" badge** — never silently zero.
- Confidence < high caps the band at **Review** ("requires human review").
- The report includes the factor table for every Critical/High finding.
