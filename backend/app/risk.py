"""Quantum Migration Priority (QMP) - prototype methodology from 06_RISK_SCORING.md.

Deterministic and explainable: every factor value is returned with its source and a plain-language reason.
It is NOT an official NIST score, not CVSS, and not a security certification.
"""
from __future__ import annotations

import math

LABEL = ("Quantum Migration Priority (QMP) is an internal prototype prioritization methodology of Quantum "
         "Migration Copilot. It is not an official NIST score, not a CVSS score, and not a security certification.")
FORMULA = "QMP = clamp(round_half_up(QE*2 + DS*2 + IE*1.5 + BC*1.5 - MC*1.5), 0, 20)"

DS_TABLE = {"public": 0, "internal": 1, "confidential": 2, "sensitive": 3, "highly-sensitive": 4, "regulated": 4}
BC_TABLE = {"low": 0, "medium": 1, "high": 2, "critical": 3}
MIDPOINT = {"DS": 2, "IE": 1.5, "BC": 1.5}          # 06 section 6: missing metadata -> midpoint + badge
BANDS = ("Informational", "Review", "High", "Critical")
KE_ALGORITHMS = {"ECDH", "DH", "DH/ECDH"}
SIGNATURE_ONLY = {"ECDSA", "EdDSA", "DSA", "RSA/ECDSA"}
HYGIENE_RULES = {"CFG-NGINX-TLS-001", "CFG-NGINX-CIPHER-004", "CFG-STRUCT-TLS-001", "CFG-STRUCT-TLS-002"}


def round_half_up(x: float) -> int:
    return int(math.floor(x + 0.5))


def band_for(qmp: int) -> str:
    return "Informational" if qmp <= 3 else "Review" if qmp <= 9 else "High" if qmp <= 14 else "Critical"


def role_of(f: dict) -> str | None:
    """Cryptographic role (02 section 9): 'key-establishment' | 'signature' | 'unclear' | None (not public-key)."""
    if f["primitive"] != "public-key":
        return None
    alg, op, ctx = f["algorithm"], f["operation"], f["context"]
    if alg in KE_ALGORITHMS or op == "key_agreement":
        return "key-establishment"
    if alg in SIGNATURE_ONLY:
        return "signature"
    if alg == "RSA":
        if op in ("encryption", "decryption"):
            return "key-establishment"
        if op in ("signature", "verification"):
            return "signature"
        if ctx in ("authentication", "code-signing", "integrity"):
            return "signature"
        if ctx in ("key-establishment", "data-protection"):
            return "key-establishment"
    return "unclear"


def _qe(f: dict, role: str | None) -> tuple[int, str]:
    if f["already_pqc"]:
        return 0, "Already uses a post-quantum algorithm; nothing to migrate."
    if f["primitive"] == "public-key":
        if f["confidence_level"] != "high":
            return 2, f"Quantum-vulnerable public-key usage ({f['algorithm']}) found, but confidence is {f['confidence_level']}: context unclear."
        if role == "key-establishment":
            return 4, f"{f['algorithm']} used for key establishment: quantum-vulnerable and exposed to harvest-now-decrypt-later."
        if role == "signature":
            return 3, f"{f['algorithm']} used for digital signatures: quantum-vulnerable (forgeable on a future quantum computer)."
        return 4, (f"{f['algorithm']} key generation: the role cannot be determined from key generation alone, so it is "
                   "conservatively treated like key establishment (06 Example B).")
    if f["rule_id"] in HYGIENE_RULES or f["algorithm"] == "SHA-1":
        return 1, f"{f['algorithm']} is a classical-hygiene issue (deprecated for non-quantum reasons), not a quantum vulnerability."
    if f["primitive"] == "symmetric" and f["metadata"].get("key_size") == 128:
        return 1, "AES-128 has reduced Grover headroom; AES-256 is recommended for long-term data."
    return 0, "Symmetric/hash/MAC/protocol use is not vulnerable to Shor's algorithm; no PQC migration needed."


def _mc(f: dict, role: str | None) -> tuple[int, str]:
    if f["already_pqc"]:
        return 0, "Already post-quantum."
    if f["primitive"] == "protocol":
        return 0, "Configuration-only change."
    if f["rule_id"].startswith("CFG-X509"):
        return 3, "Certificates involve CAs, trust chains and external parties; formats and size budgets change."
    if f["primitive"] != "public-key":
        return 1, "Self-contained library call swap."
    if role == "key-establishment":
        return 2, "Cross-service protocol change: both peers must migrate together or use a hybrid scheme."
    if role == "signature":
        if f["context"] == "code-signing":
            return 3, "Code-signing verifiers are often external or embedded; hard to upgrade together."
        if f["context"] == "authentication":
            return 2, "Token/JWT verifiers across services must support the new signature before signers switch."
        return 1, "Self-contained signing change; check signature and key size budgets."
    return 1, "Self-contained library call swap."


def score(f: dict, service_meta: dict | None) -> dict | None:
    """Return the QMP breakdown for a finding, or None for comment/doc-only mentions (not scored)."""
    if f["metadata"]["comment_only"]:
        return None
    meta = service_meta or {}
    badges: list[str] = []
    role = role_of(f)
    qe, qe_why = _qe(f, role)
    mc, mc_why = _mc(f, role)

    def meta_factor(key: str, field: str, table: dict | None, label: str):
        v = meta.get(field)
        if v is None or (table is not None and v not in table):
            badges.append(f"metadata missing: {field}")
            return MIDPOINT[key], f"{field} not provided in service.yaml: midpoint default used.", "default midpoint (metadata missing)"
        return (table[v] if table else v), f"{field} = {v}", "service.yaml"

    ds, ds_why, ds_src = meta_factor("DS", "data_classification", DS_TABLE, "Data sensitivity")
    bc, bc_why, bc_src = meta_factor("BC", "business_criticality", BC_TABLE, "Business criticality")
    exp = meta.get("internet_exposed")
    if exp is None:
        badges.append("metadata missing: internet_exposed")
        ie, ie_why, ie_src = MIDPOINT["IE"], "internet_exposed not provided: midpoint default used.", "default midpoint (metadata missing)"
    else:
        ie, ie_why, ie_src = (3, "Service is internet-exposed: traffic can be recorded today.", "service.yaml") if exp else \
                             (0, "Internal-only service.", "service.yaml")

    raw = qe * 2 + ds * 2 + ie * 1.5 + bc * 1.5 - mc * 1.5
    qmp = max(0, min(20, round_half_up(raw)))
    band = uncapped = band_for(qmp)
    cap_reason = None
    if qe == 0:
        band, cap_reason = "Informational", "Guard rule: no quantum exposure, so Informational regardless of context."
    elif qe == 1 and BANDS.index(band) > 1:
        band, cap_reason = "Review", "Capped at Review: classical hygiene issue, not a quantum vulnerability."
    elif f["confidence_level"] != "high" and BANDS.index(band) > 1:
        band, cap_reason = "Review", f"Capped at Review: confidence is {f['confidence_level']}; requires human review."
    if qe == 1:
        badges.append("classical hygiene")
    if f["metadata"]["test_path"]:
        badges.append("test/dev path")

    lifetime = meta.get("data_lifetime_years")
    hndl: dict = {"flag": False}
    if role == "key-establishment" and f["primitive"] == "public-key":
        if lifetime is None:
            badges.append("metadata missing: data_lifetime_years")
        elif ds >= 3 and ie >= 2 and lifetime >= 5:
            sev = "elevated" if lifetime >= 10 else "noted"
            hndl = {"flag": True, "severity": sev, "text": (
                f"{'Elevated' if sev == 'elevated' else 'Noted'} harvest-now-decrypt-later risk: this service protects data with a "
                f"{lifetime}-year confidentiality lifetime and its key establishment is quantum-vulnerable. "
                "Recorded traffic may be decryptable by a future quantum computer.")}

    def fac(v, w, label, why, src):
        return {"value": v, "weight": w, "label": label, "why": why, "source": src}
    return {
        "qmp": qmp, "raw": round(raw, 2), "band": band, "band_uncapped": uncapped, "cap_reason": cap_reason,
        "role": role, "hndl": hndl, "badges": sorted(set(badges)), "formula": FORMULA, "label": LABEL,
        "factors": {
            "QE": fac(qe, 2, "Quantum exposure", qe_why, "scanner finding"),
            "DS": fac(ds, 2, "Data sensitivity", ds_why, ds_src),
            "IE": fac(ie, 1.5, "Internet exposure", ie_why, ie_src),
            "BC": fac(bc, 1.5, "Business criticality", bc_why, bc_src),
            "MC": fac(mc, -1.5, "Migration complexity (subtracts)", mc_why, "rule metadata + finding context"),
        },
    }


def priority_key(f: dict, r: dict | None) -> tuple:
    """Deterministic ranking: scored findings first, by DISPLAYED band, then QMP, raw score, HNDL, QE; then scanner order."""
    if r is None:
        return (1, 0, 0, 0, 0, 0, f["id"])
    return (0, -BANDS.index(r["band"]), -r["qmp"], -r["raw"], -int(r["hndl"]["flag"]), -r["factors"]["QE"]["value"], f["id"])
