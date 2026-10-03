"""Deterministic migration rules (07_MIGRATION_RULES.md). The rules engine is the source of truth, never the AI Copilot.

Role-aware: RSA is mapped by ROLE (key establishment -> ML-KEM, signature -> ML-DSA/SLH-DSA); an undetermined role is
routed to human review instead of guessing (R-12). Symmetric/hash/MAC are never mapped to a PQC algorithm.
"""
from __future__ import annotations

ML_KEM = "ML-KEM (FIPS 203)"
SIG = "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"

KE_TEXT = {
    "why": "Shor's algorithm defeats RSA/DH/ECDH on a future CRQC; FIPS 203 is NIST's finalized KEM standard.",
    "caveats": ["A KEM outputs a shared secret: callers must switch to the KEM -> KDF -> symmetric cipher (e.g. AES-GCM) pattern. "
                "It is not 'encrypt this message with RSA' rewritten.",
                "Key/ciphertext sizes differ; check protocol message budgets."],
    "interoperability": "Both peers must migrate together or use a hybrid scheme (classical + ML-KEM, e.g. X25519+ML-KEM-768) during "
                        "transition; otherwise connections downgrade or fail.",
    "steps": ["Abstract crypto behind an interface.", "Add ML-KEM alongside the existing key exchange (hybrid).",
              "Deploy to both endpoints.", "Monitor.", "Remove the classical component after the transition period."],
    "human_review_note": "Required: protocol design, peer coordination and performance testing.",
}
SIG_TEXT = {
    "why": "Signature schemes based on factoring/discrete logs are Shor-vulnerable; FIPS 204/205 are finalized signature standards.",
    "caveats": ["Signatures and public keys are larger: re-check token, certificate and message size budgets (JWTs, cert chains).",
                "Signature generation can be slower (especially SLH-DSA).",
                "Verify that ALL verifiers upgrade before switching signers.",
                "Candidate choice: ML-DSA is the default (smaller, faster); SLH-DSA when hash-based assumptions are preferred (diversity/backup)."],
    "interoperability": "Dual-sign during the transition if verifiers of mixed versions exist.",
    "steps": ["Inventory verifiers.", "Add PQC verification support everywhere first.",
              "Switch signing to ML-DSA (dual-sign if needed).", "Deprecate classical verification after cutover."],
    "human_review_note": "Required: trust-chain and storage-budget analysis.",
}
RULES = {
    "R-01": ("RSA for key establishment", ML_KEM, "KE"), "R-02": ("DH for key establishment", ML_KEM, "KE"),
    "R-03": ("ECDH (incl. X25519/X448) for key establishment", ML_KEM, "KE"),
    "R-04": ("RSA signatures", SIG, "SIG"), "R-05": ("ECDSA signatures", SIG, "SIG"),
    "R-06": ("EdDSA (Ed25519/Ed448) signatures", SIG, "SIG"), "R-07": ("DSA signatures", SIG, "SIG"),
    "R-08": ("AES", None, None), "R-09": ("SHA-1", None, None), "R-10": ("SHA-2 / SHA-3", None, None),
    "R-11": ("HMAC", None, None), "R-12": ("Unknown / unclassified crypto", None, None),
}
NO_PQC = {
    "R-08": ("Symmetric crypto is not Shor-vulnerable. Consider AES-256 for Grover headroom.", ["AES-256 (or AES-128 with adequate planning) remains appropriate."]),
    "R-09": ("SHA-1 is deprecated for classical reasons, not quantum ones. Replace with SHA-256/SHA-3 (classical hygiene).", ["SHA-1 collisions are practical today; this is a classical fix."]),
    "R-10": ("Hash functions face only generic quantum speedups. Retain; prefer >= 256-bit output (SHA-384 for long-term headroom).", []),
    "R-11": ("MACs are symmetric; adequate key and tag sizes suffice. Retain.", []),
}
CRYPTO_AGILITY = [
    "Abstraction layer: route all crypto through one internal interface (e.g. CryptoProvider.encapsulate/sign/verify); no algorithm names outside it.",
    "Centralized crypto policy: a single versioned policy file naming allowed algorithms, key sizes and modes, enforced at build time.",
    "Algorithm identifiers in configuration: no hard-coded algorithm strings.",
    "Provider abstraction: swap OpenSSL / liboqs / HSM without touching call sites.",
    "Versioned crypto policies: v1 (classical) -> v2 (hybrid) -> v3 (PQC-only), rolled out progressively.",
    "Regression and interoperability testing: cross-version handshake and signature tests in CI.",
]
HONESTY = [
    "Recommendations are candidate directions, not certifications of security.",
    "The plan assumes peer ecosystems (libraries, clients, CAs, HSMs) support the targets at deployment time: verify before committing dates.",
    "Final decisions require human security review.",
]


def pick_rule(f: dict, role: str | None) -> tuple[str, str | None]:
    """(rule_id, note). Deterministic; undetermined roles go to R-12 (human review)."""
    alg, prim = f["algorithm"], f["primitive"]
    if prim == "public-key":
        if role == "key-establishment":
            return {"DH": "R-02"}.get(alg, "R-01" if alg == "RSA" else "R-03"), None
        if role == "signature":
            return {"RSA": "R-04", "ECDSA": "R-05", "EdDSA": "R-06", "DSA": "R-07", "RSA/ECDSA": "R-05"}.get(alg, "R-05"), \
                   ("Signature scheme could be RSA or ECDSA (key type not visible); the PQC direction is the same." if alg == "RSA/ECDSA" else None)
        names = {"RSA": "key establishment (ML-KEM) or signatures (ML-DSA/SLH-DSA)", "EC": "key agreement (ML-KEM) or signatures (ML-DSA/SLH-DSA)"}
        return "R-12", (f"The role of this {alg} usage cannot be determined statically; depending on its role the direction would be "
                        f"{names.get(alg, 'role-dependent')}. Not guessed: assign to a human reviewer.")
    if prim == "symmetric":
        return "R-08", None
    if prim == "hash":
        return ("R-09" if alg == "SHA-1" else "R-10"), None
    if prim == "mac":
        return "R-11", None
    return "R-12", None


def plan_for(f: dict, risk: dict | None) -> dict | None:
    """Migration candidate for one finding, or None for comment/doc-only mentions (no executable evidence)."""
    if f["metadata"]["comment_only"]:
        return None
    base = {"honesty": HONESTY, "crypto_agility": CRYPTO_AGILITY}
    if f["already_pqc"]:
        return {**base, "rule_id": None, "current": f"{f['algorithm']} (already post-quantum)", "direction": "No migration needed",
                "standard": None, "no_pqc_mapping": True, "human_review": False,
                "why": "This code already uses a NIST-standardized post-quantum algorithm.",
                "caveats": ["Confirm the parameter set and consider a hybrid deployment while peers migrate."], "interoperability": None, "steps": [],
                "complexity": 0}
    if f["primitive"] == "protocol":
        return {**base, "rule_id": None, "current": f"TLS configuration ({f['rule_id']})", "direction": "No PQC mapping: classical hygiene",
                "standard": None, "no_pqc_mapping": True, "human_review": False,
                "why": "Deprecated protocol versions, weak cipher suites and certificate handling are classical hardening items, not quantum migrations.",
                "caveats": ["Disable TLS 1.0/1.1 and weak ciphers; keep certificates valid. Hybrid key exchange is a separate transport decision."],
                "interoperability": None, "steps": ["Remove deprecated protocol versions and weak cipher suites.", "Re-test client compatibility."],
                "complexity": (risk or {}).get("factors", {}).get("MC", {}).get("value", 0)}
    role = (risk or {}).get("role")
    rid, note = pick_rule(f, role)
    cur, direction, kind = RULES[rid]
    out = {**base, "rule_id": rid, "current": f"{cur} ({f['algorithm']}, {f['operation'].replace('_', ' ')})", "direction": direction or "",
           "standard": direction, "no_pqc_mapping": direction is None, "human_review": True, "note": note,
           "complexity": (risk or {}).get("factors", {}).get("MC", {}).get("value")}
    if kind == "KE":
        out.update(KE_TEXT)
    elif kind == "SIG":
        out.update(SIG_TEXT)
    elif rid == "R-12":
        out.update(direction="Manual review: no candidate emitted", why="The system does not know: it never invents a migration direction.",
                   caveats=[], interoperability=None, steps=["Route to the security team with the attached evidence."], human_review=True)
    else:
        why, caveats = NO_PQC[rid]
        out.update(direction="No PQC migration required", why=why, caveats=caveats, interoperability=None, human_review=False,
                   steps=["Replace with SHA-256 or SHA-3."] if rid == "R-09" else [])
    return out
