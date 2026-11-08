"""PQC Readiness Assessment (pure functions; no I/O).

Answers "how prepared is this code base for the transition to post-quantum cryptography?" from scanner evidence
and the dependency graph only. There is deliberately NO percentage score: the overall level is an ordinal
classification produced by the explicit rules in `LEVEL_RULES`, and every category, blocker and recommendation
lists the findings (file:line + evidence) it is based on.

Never concludes "quantum-safe": the best possible outcome is "no quantum-vulnerable usage DETECTED", always paired
with what was and was not analyzed.

Standards used (see REFERENCES): FIPS 203 / 204 / 205, NIST IR 8547 (final, Oct 2026), SP 800-131A Rev. 2,
SP 800-227, RFC 9964, draft-ietf-tls-ecdhe-mlkem, RFC 7465, RFC 8996.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

from .graph import Graph

ASSESSMENT_VERSION = 1

REFERENCES: dict[str, dict[str, str]] = {
    "FIPS203": {"title": "FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)", "url": "https://csrc.nist.gov/pubs/fips/203/final"},
    "FIPS204": {"title": "FIPS 204: Module-Lattice-Based Digital Signature Algorithm (ML-DSA)", "url": "https://csrc.nist.gov/pubs/fips/204/final"},
    "FIPS205": {"title": "FIPS 205: Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)", "url": "https://csrc.nist.gov/pubs/fips/205/final"},
    "IR8547": {"title": "NIST IR 8547 (final, Oct 2026): Transition to Post-Quantum Cryptography Standards", "url": "https://csrc.nist.gov/pubs/ir/8547/final"},
    "SP800-131A": {"title": "NIST SP 800-131A Rev. 2: Transitioning the Use of Cryptographic Algorithms and Key Lengths", "url": "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"},
    "SP800-227": {"title": "NIST SP 800-227: Recommendations for Key-Encapsulation Mechanisms", "url": "https://csrc.nist.gov/pubs/sp/800/227/final"},
    "RFC9964": {"title": "RFC 9964: ML-DSA for JOSE and COSE", "url": "https://www.rfc-editor.org/rfc/rfc9964"},
    "TLS-HYBRID": {"title": "draft-ietf-tls-ecdhe-mlkem: Hybrid ECDHE-MLKEM key agreement for TLS 1.3 (X25519MLKEM768; approved, in RFC Editor queue mid-2026)",
                   "url": "https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/"},
    "RFC7465": {"title": "RFC 7465: Prohibiting RC4 Cipher Suites", "url": "https://www.rfc-editor.org/rfc/rfc7465"},
    "RFC8996": {"title": "RFC 8996: Deprecating TLS 1.0 and TLS 1.1", "url": "https://www.rfc-editor.org/rfc/rfc8996"},
    "NIST-PQC-PUBS": {"title": "NIST PQC publications (incl. CSWP 39: Considerations for Achieving Crypto Agility)",
                      "url": "https://csrc.nist.gov/Projects/post-quantum-cryptography/publications"},
    "JEP496": {"title": "JEP 496: ML-KEM in the JDK (JDK 24)", "url": "https://openjdk.org/jeps/496"},
    "JEP497": {"title": "JEP 497: ML-DSA in the JDK (JDK 24)", "url": "https://openjdk.org/jeps/497"},
    "NODE-24.7": {"title": "Node.js 24.7.0: ML-KEM (crypto.encapsulate/decapsulate) and ML-DSA (crypto.sign/verify)", "url": "https://nodejs.org/en/blog/release/v24.7.0"},
    "PYCA-CHANGELOG": {"title": "pyca/cryptography changelog (ML-KEM / ML-DSA modules)", "url": "https://cryptography.io/en/latest/changelog/"},
    "BC-1.79": {"title": "Bouncy Castle Java 1.79: ML-KEM, ML-DSA, SLH-DSA", "url": "https://bouncycastle.org/resources/latest-nist-pqc-standards-and-more-bouncy-castle-java-1-79/"},
    "OPENSSH-RELEASES": {"title": "OpenSSH release notes (mlkem768x25519-sha256 hybrid key exchange)", "url": "https://www.openssh.com/releasenotes.html"},
    "OPENSSL-3.5": {"title": "OpenSSL 3.5: ML-KEM, ML-DSA, SLH-DSA; X25519MLKEM768 offered by default in TLS", "url": "https://openssl-library.org/post/2025-04-08-openssl-35-final-release/"},
}

# Library-level PQC support known to QMC, with sources. QMC does not read dependency manifests, so the INSTALLED
# version is never known: every entry says "verify your version". Absence from this table means "not verified".
LIBRARY_SUPPORT: dict[str, dict] = {
    "cryptography": {"support": "ML-KEM and ML-DSA modules (pyca/cryptography 47.0+ with AWS-LC/BoringSSL builds; 49.0+ also with OpenSSL 3.5+). SLH-DSA not yet.",
                     "refs": ["PYCA-CHANGELOG"]},
    "java.security": {"support": "ML-KEM (KEM API) and ML-DSA (Signature API) in the JDK since JDK 24.", "refs": ["JEP496", "JEP497"]},
    "javax.crypto": {"support": "ML-KEM via javax.crypto.KEM since JDK 24.", "refs": ["JEP496"]},
    "bouncycastle": {"support": "ML-KEM, ML-DSA and SLH-DSA since Bouncy Castle Java 1.79.", "refs": ["BC-1.79"]},
    "node:crypto": {"support": "ML-KEM (crypto.encapsulate/decapsulate) and ML-DSA (crypto.sign/verify) since Node.js 24.7.0 (OpenSSL 3.5 builds).",
                    "refs": ["NODE-24.7"]},
    "webcrypto": {"support": "Node.js Web Crypto supports ML-KEM / ML-DSA since 24.7.0; browser support varies and is not assessed.", "refs": ["NODE-24.7"]},
    "nginx": {"support": "Hybrid TLS key exchange (X25519MLKEM768) depends on the OpenSSL version nginx is linked against (offered by default in OpenSSL 3.5).",
              "refs": ["OPENSSL-3.5", "TLS-HYBRID"]},
    "liboqs": {"support": "Open Quantum Safe library: already provides NIST PQC algorithms.", "refs": []},
    "openssh": {"support": "Hybrid ML-KEM key exchange (mlkem768x25519-sha256) is available in recent OpenSSH releases; check the server and client versions.",
                "refs": ["OPENSSH-RELEASES"]},
    "x509": {"support": "Not a library: PEM certificates stored in the repository. ML-DSA certificates need CA, client and HSM support.",
             "refs": ["FIPS204", "IR8547"]},
    "hashlib": {"support": "Hashes: not Shor-vulnerable; no PQC replacement needed (replace MD5/SHA-1 for classical reasons).", "refs": ["IR8547"]},
    "hmac": {"support": "MACs: not Shor-vulnerable; no PQC replacement needed.", "refs": ["IR8547"]},
}

LEGACY_CIPHERS = {"3DES", "DES", "RC4", "Blowfish"}
# Paths whose code is not production: test paths (scanner flag) plus these whole path tokens.
NON_PRODUCTION_TOKENS = {"lab", "labs", "demo", "demos", "example", "examples", "sample", "samples", "poc", "sandbox", "playground"}


def non_production(r: dict) -> bool:
    toks = {t.lower() for t in re.split(r"[/._\-]", r["file"]) if t}
    return bool(r.get("test_path")) or bool(toks & NON_PRODUCTION_TOKENS)
BROKEN_HASHES = {"SHA-1", "MD5"}
DEPRECATED_PROTOCOL_RULES = {"CFG-NGINX-TLS-001", "CFG-STRUCT-TLS-001", "CFG-STRUCT-TLS-002"}
WEAK_SUITE_RULES = {"CFG-NGINX-CIPHER-004"}

LEVEL_RULES = [
    ("not_ready_blockers", "Not ready: critical blockers",
     "At least one blocker: quantum-vulnerable key establishment protecting long-lived sensitive, internet-exposed data "
     "(elevated harvest-now-decrypt-later), or classical cryptography that NIST/IETF already disallow (DES/3DES/RC4/"
     "Blowfish, TLS 1.0/1.1, weak TLS cipher suites, SHA-1-signed certificates)."),
    ("not_ready", "Not ready",
     "Quantum-vulnerable public-key cryptography (key establishment, signatures, certificates or keys of undetermined "
     "role) is in use and no standardized PQC algorithm was found outside test/lab/demo/example paths."),
    ("in_transition", "In transition",
     "Quantum-vulnerable public-key cryptography is still in use, but standardized PQC (ML-KEM / ML-DSA / SLH-DSA) is "
     "already used outside test/lab/demo/example paths."),
    ("no_vulnerable_usage_detected", "No quantum-vulnerable usage detected",
     "The scanner found no quantum-vulnerable public-key usage in the analyzed files. This is NOT a statement that the "
     "application is quantum-safe: see what was not analyzed."),
]


def _ev(f: dict) -> dict:
    return {"fid": f["id"], "file": f["file"], "line": f["line_start"], "text": f["evidence"], "algorithm": f["algorithm"],
            "band": f.get("band"), "service": f["service"], "rule_id": f["rule_id"]}


def _category(cid: str, title: str, status: str, summary: str, findings: list[dict], refs: list[str], **extra) -> dict:
    fs = sorted(findings, key=lambda f: (f["file"], f["line_start"], f["id"]))
    return {"id": cid, "title": title, "status": status, "summary": summary, "count": len(fs),
            "files": len({f["file"] for f in fs}), "services": sorted({f["service"] for f in fs}),
            "algorithms": dict(sorted(Counter(f["algorithm"] for f in fs).items())),
            "evidence": [_ev(f) for f in fs], "references": refs, **extra}


def _hub_files(g: Graph, files: set[str]) -> list[dict]:
    """Files with vulnerable usage that other files import (candidate central crypto modules / wrappers)."""
    out = []
    for f in sorted(files):
        importers = g.importers.get(f"file:{f}", [])
        if importers:
            out.append({"file": f, "imported_by": sorted(g.nodes[i]["label"] for i, _ in importers)})
    return sorted(out, key=lambda h: (-len(h["imported_by"]), h["file"]))


def assess(records: list[dict], g: Graph, *, analysis: dict | None, services: list[dict], excluded: dict | None = None) -> dict:
    """records: live (non-suppressed, non-comment) finding records from graph.finding_record."""
    an = analysis or {}
    vuln = [r for r in records if r["quantum_vulnerable"]]
    ke = [r for r in vuln if r.get("role") == "key-establishment"]
    sig = [r for r in vuln if r.get("role") == "signature" and not r["rule_id"].startswith("CFG-X509")]
    certs_pk = [r for r in vuln if r["rule_id"].startswith("CFG-X509")]
    unclear = [r for r in vuln if r.get("role") not in ("key-establishment", "signature") and not r["rule_id"].startswith("CFG-X509")]
    sha1_certs = [r for r in records if r["rule_id"] == "CFG-X509-002"]
    legacy = [r for r in records if r["algorithm"] in LEGACY_CIPHERS]
    deprecated_tls = [r for r in records if r["rule_id"] in DEPRECATED_PROTOCOL_RULES]
    weak_suites = [r for r in records if r["rule_id"] in WEAK_SUITE_RULES]
    broken_hashes = [r for r in records if r["algorithm"] in BROKEN_HASHES and r["rule_id"] != "CFG-X509-002"]
    aes128 = [r for r in records if r["primitive"] == "symmetric" and r.get("key_size") == 128 and r["algorithm"] == "AES"]
    pqc = [r for r in records if r.get("already_pqc")]
    pqc_prod = [r for r in pqc if not non_production(r)]
    hndl_ke = [r for r in ke if r.get("hndl_severity") == "elevated"]
    ke_prod = [r for r in ke if not non_production(r)]

    categories: list[dict] = []
    categories.append(_category(
        "key_establishment", "Key establishment (KEM / key exchange)",
        "blocker" if hndl_ke else "action" if ke else "not_detected",
        (f"{len(ke)} quantum-vulnerable key-establishment usage(s) (RSA key transport, ECDH, DH, ECDHE suites); "
         f"{len(hndl_ke)} protect long-lived sensitive data in internet-exposed services (elevated HNDL)." if ke else
         "No quantum-vulnerable key establishment detected in the analyzed files."),
        ke, ["FIPS203", "SP800-227", "TLS-HYBRID", "IR8547"], hndl=len(hndl_ke)))
    categories.append(_category(
        "signatures", "Digital signatures (code, tokens, messages)", "action" if sig else "not_detected",
        (f"{len(sig)} quantum-vulnerable signature usage(s) (RSA, ECDSA, EdDSA, DSA). Signatures are not exposed to "
         "harvest-now-decrypt-later, but every verifier must support the new algorithm before signers switch." if sig else
         "No quantum-vulnerable signature usage detected in the analyzed files."),
        sig, ["FIPS204", "FIPS205", "RFC9964", "IR8547"]))
    categories.append(_category(
        "certificates", "Certificates and PKI", "blocker" if sha1_certs else "action" if certs_pk else "not_detected",
        (f"{len(certs_pk)} certificate(s) with quantum-vulnerable public keys"
         + (f"; {len(sha1_certs)} signed with SHA-1 (disallowed for signatures)" if sha1_certs else "") + "." if certs_pk or sha1_certs else
         "No PEM certificates with quantum-vulnerable keys found in the repository (certificates managed outside it are not visible)."),
        certs_pk + sha1_certs, ["FIPS204", "SP800-131A", "IR8547"]))
    categories.append(_category(
        "undetermined", "Public-key usage with undetermined role", "review" if unclear else "not_detected",
        (f"{len(unclear)} quantum-vulnerable usage(s) whose role (key establishment vs signature) cannot be determined "
         "statically, e.g. bare key generation. They need human review before a migration target can be chosen." if unclear else
         "Every quantum-vulnerable usage has a determined role."),
        unclear, ["IR8547"]))
    proto = deprecated_tls + weak_suites
    categories.append(_category(
        "protocols", "Protocol configuration (TLS / SSH)", "blocker" if proto else "not_detected",
        (f"{len(deprecated_tls)} deprecated protocol version setting(s) and {len(weak_suites)} weak cipher-suite setting(s). "
         "Fix these classical issues before or alongside adding hybrid PQC key exchange." if proto else
         "No deprecated TLS versions or weak cipher suites detected in nginx / YAML / JSON configuration."),
        proto, ["RFC8996", "RFC7465", "SP800-131A"],
        note="Whether hybrid PQC groups (e.g. X25519MLKEM768) are enabled is not detected: it usually depends on library defaults."))
    categories.append(_category(
        "legacy_symmetric", "Legacy symmetric ciphers", "blocker" if legacy else "not_detected",
        (f"{len(legacy)} use(s) of 3DES/DES/RC4/Blowfish. These are weak or disallowed for classical reasons." if legacy else
         "No 3DES/DES/RC4/Blowfish usage detected in code."), legacy, ["SP800-131A", "RFC7465"]))
    categories.append(_category(
        "hashes", "Broken hash functions", "action" if broken_hashes else "not_detected",
        (f"{len(broken_hashes)} use(s) of MD5/SHA-1. Replace for security uses; non-security checksums can be documented instead." if broken_hashes else
         "No MD5/SHA-1 usage detected in code."), broken_hashes, ["SP800-131A"]))
    categories.append(_category(
        "symmetric_strength", "Symmetric key strength", "review" if aes128 else "not_detected",
        (f"{len(aes128)} AES-128 usage(s). AES-128 is not broken; AES-256 gives more margin for long-lived data." if aes128 else
         "No AES-128 with an explicit key size detected (key sizes are only known when literal at the call site)."),
        aes128, ["IR8547"]))
    categories.append(_category(
        "pqc_adoption", "Post-quantum adoption",
        "positive" if pqc_prod else "partial" if pqc else "not_detected",
        (f"Standardized PQC is already used outside test paths ({len(pqc_prod)} usage(s))." if pqc_prod else
         f"PQC appears only in test/lab/demo paths ({len(pqc)} usage(s)): not yet part of production code paths." if pqc else
         "No ML-KEM / ML-DSA / SLH-DSA usage detected."), pqc, ["FIPS203", "FIPS204", "FIPS205"]))

    # ---- crypto agility (graph facts only)
    vuln_files = {r["file"] for r in vuln}
    hubs = _hub_files(g, vuln_files)
    agility = {"id": "agility", "title": "Crypto agility (from the dependency graph)", "status": "info",
               "summary": (f"Quantum-vulnerable calls are made directly in {len(vuln_files)} file(s) across "
                           f"{len({r['service'] for r in vuln})} component(s). {len(hubs)} of these files are imported by other "
                           "files and are candidates for a central crypto interface; calls spread across many files make an "
                           "algorithm swap harder." if vuln_files else "No quantum-vulnerable call sites to centralize."),
               "count": len(vuln_files), "files": len(vuln_files), "services": sorted({r["service"] for r in vuln}),
               "algorithms": {}, "evidence": [], "hubs": hubs[:20], "hubs_total": len(hubs), "references": ["NIST-PQC-PUBS"],
               "imports_available": bool(g.stats.get("imports_available"))}
    categories.append(agility)

    # ---- libraries
    lib_counts: dict[str, dict] = defaultdict(lambda: {"findings": 0, "vulnerable": 0, "files": set()})
    for r in records:
        if r.get("library"):
            d = lib_counts[r["library"]]
            d["findings"] += 1
            d["vulnerable"] += int(r["quantum_vulnerable"])
            d["files"].add(r["file"])
    for n in g.nodes.values():
        if n["type"] == "library" and n["label"] not in lib_counts:
            lib_counts[n["label"]]                                # imported but no detected call
    libraries = []
    for name, d in sorted(lib_counts.items()):
        known = LIBRARY_SUPPORT.get(name)
        libraries.append({"library": name, "findings": d["findings"], "vulnerable_findings": d["vulnerable"], "files": len(d["files"]),
                          "pqc_support": known["support"] if known else None, "references": known["refs"] if known else [],
                          "status": "known" if known else "not_verified",
                          "note": "Installed version not determined (dependency manifests are not analyzed): verify it."})

    # ---- blockers
    blockers = []
    if hndl_ke:
        blockers.append({"id": "hndl_key_establishment", "title": "Harvest-now-decrypt-later exposure",
                         "why": "Quantum-vulnerable key establishment protects data with a 10+ year confidentiality lifetime in "
                                "internet-exposed services: recorded traffic could be decrypted later. NIST IR 8547 asks for the "
                                "earliest transition for systems with long-term confidentiality needs.",
                         "evidence": [_ev(r) for r in sorted(hndl_ke, key=lambda r: (r["file"], r["line_start"]))],
                         "services": sorted({r["service"] for r in hndl_ke}), "references": ["IR8547", "FIPS203", "TLS-HYBRID"]})
    for key, rows, title, why, refs in (
        ("legacy_ciphers", legacy, "Disallowed legacy ciphers in use", "DES and 3DES encryption are disallowed by NIST SP 800-131A Rev. 2; "
         "RC4 is prohibited in TLS; Blowfish's 64-bit block is unsafe for bulk data.", ["SP800-131A", "RFC7465"]),
        ("deprecated_protocols", deprecated_tls, "Deprecated TLS/SSL versions enabled", "TLS 1.0/1.1 and SSL are deprecated (RFC 8996).", ["RFC8996"]),
        ("weak_suites", weak_suites, "Weak TLS cipher suites enabled", "RC4/3DES/NULL/EXPORT/MD5 suites are disallowed or broken.", ["RFC7465", "SP800-131A"]),
        ("sha1_certificates", sha1_certs, "SHA-1-signed certificates", "SHA-1 is disallowed for digital-signature generation.", ["SP800-131A"]),
    ):
        if rows:
            blockers.append({"id": key, "title": title, "why": why + " Fix classical weaknesses before layering PQC on top.",
                             "evidence": [_ev(r) for r in sorted(rows, key=lambda r: (r["file"], r["line_start"]))],
                             "services": sorted({r["service"] for r in rows}), "references": refs})

    # ---- level (explicit rules, in order)
    has_vuln = bool(ke or sig or certs_pk or unclear)
    level_id = ("not_ready_blockers" if blockers else
                "in_transition" if has_vuln and pqc_prod else
                "not_ready" if has_vuln else "no_vulnerable_usage_detected")
    label, rule = next((lbl, r) for i, lbl, r in LEVEL_RULES if i == level_id)

    # ---- recommendations (ordered by priority; each tied to evidence)
    recs: list[dict] = []

    def rec(priority: int, title: str, action: str, rows: list[dict], refs: list[str], simulate: str | None = None, **extra):
        recs.append({"priority": priority, "title": title, "action": action, "references": refs,
                     "evidence": [_ev(r) for r in sorted(rows, key=lambda r: (r["file"], r["line_start"]))[:25]],
                     "evidence_total": len(rows), "services": sorted({r["service"] for r in rows}),
                     "simulate": simulate, **extra})

    def first_alg(rows: list[dict]) -> str | None:
        return f"algorithm:{Counter(r['algorithm'] for r in rows).most_common(1)[0][0]}" if rows else None

    if hndl_ke:
        rec(1, "Protect long-lived data first: hybrid key establishment",
            "Introduce hybrid key establishment for these services (classical + ML-KEM, e.g. X25519MLKEM768 in TLS 1.3 where both "
            "endpoints support it; ML-KEM-768 with a KDF and AEAD in application protocols).", hndl_ke,
            ["FIPS203", "SP800-227", "TLS-HYBRID", "IR8547"], first_alg(hndl_ke))
    if legacy or deprecated_tls or weak_suites or sha1_certs:
        rec(1, "Remove disallowed classical cryptography",
            "Replace 3DES/DES/RC4/Blowfish with AES-256-GCM, disable TLS 1.0/1.1 and weak suites, re-issue SHA-1-signed certificates.",
            legacy + deprecated_tls + weak_suites + sha1_certs, ["SP800-131A", "RFC8996", "RFC7465"], first_alg(legacy))
    other_ke = [r for r in ke_prod if r not in hndl_ke]
    if other_ke:
        rec(2, "Plan ML-KEM for the remaining key establishment",
            "Migrate RSA key transport and (EC)DH to ML-KEM (FIPS 203), hybrid during the transition. RSA 'encrypt' calls must be "
            "restructured as KEM -> KDF -> AEAD.", other_ke, ["FIPS203", "SP800-227", "IR8547"], first_alg(other_ke))
    if sig or certs_pk:
        rec(2, "Inventory verifiers, then plan ML-DSA / SLH-DSA",
            "List every verifier of these signatures (services, clients, JWT consumers, certificate relying parties); add ML-DSA "
            "(FIPS 204) verification first, then switch signers. JOSE/JWT: RFC 9964 identifiers.", sig + certs_pk,
            ["FIPS204", "FIPS205", "RFC9964", "IR8547"], first_alg(sig + certs_pk))
    if unclear:
        rec(3, "Determine the role of undetermined public-key usage",
            "Review these call sites (key generation without visible use) to decide whether they serve key establishment (-> ML-KEM) "
            "or signatures (-> ML-DSA).", unclear, ["IR8547"], first_alg(unclear))
    if hubs:
        rec(3, "Centralize cryptography behind an interface",
            "Route algorithm choices through the files other code already imports (listed as hubs) so that a later swap changes one "
            "module, not every call site.", [r for r in vuln if r["file"] in {h['file'] for h in hubs}], ["NIST-PQC-PUBS"],
            hubs=hubs[:10])
    if broken_hashes:
        rec(3, "Replace MD5 / SHA-1", "Use SHA-256 or SHA-3 for security uses; document non-security checksums.", broken_hashes,
            ["SP800-131A"], first_alg(broken_hashes))
    if aes128:
        rec(4, "Consider AES-256 for long-lived data", "AES-128 remains acceptable; AES-256 increases the margin against Grover-type attacks.",
            aes128, ["IR8547"], "algorithm:AES")
    if pqc and not pqc_prod:
        rec(4, "Move PQC from lab code to production paths",
            "PQC is only exercised in test/lab paths; plan how it reaches the production code paths above.", pqc, ["FIPS203", "FIPS204"])
    if libraries:
        rec(4, "Verify library versions and PQC capability",
            "QMC cannot see installed versions. Confirm each library listed below supports ML-KEM / ML-DSA in the version you deploy "
            "(and, for TLS, which OpenSSL/JDK/Node version terminates it).", [], sorted({x for l in libraries for x in l["references"]}),
            libraries=[l["library"] for l in libraries])

    # ---- coverage
    skipped = an.get("files_skipped") or []
    analyzed = {"files_scanned": an.get("files_scanned") or {}, "engine_version": an.get("engine_version"),
                "scan_status": an.get("scan_status"), "skipped_files": len(skipped),
                "skipped_by_reason": dict(Counter(s.get("reason", "other") for s in skipped)),
                "import_relationships": bool(g.stats.get("imports_available")),
                "services_with_metadata": sorted(s["service"] for s in services if s.get("service") and not s.get("missing_fields")),
                "excluded": excluded or {}}
    not_analyzed = [
        "Installed library and runtime versions (dependency manifests and lock files are not parsed).",
        "Compiled binaries, container images, HSM/KMS configuration and cloud-managed keys.",
        "TLS/SSH settings outside the repository and library defaults (e.g. whether X25519MLKEM768 is negotiated).",
        "Languages other than Python, Java, JavaScript/TypeScript (plus nginx/SSH/YAML/JSON/Dockerfile/CI and PEM certificates).",
        "Algorithms chosen at runtime (from variables, configuration services or reflection) and dynamically loaded code.",
        "Third-party services and APIs the application calls, and their cryptography.",
    ]
    limitations = []
    if an.get("scan_status") == "partial":
        limitations.append("The scan hit its time limit: the assessment covers only the files scanned before it.")
    if skipped:
        limitations.append(f"{len(skipped)} file(s) were skipped (see 'analyzed'); findings in them are not reflected.")
    if any(s.get("missing_fields") for s in services) or not services:
        limitations.append("Some services have no or incomplete service.yaml metadata, so harvest-now-decrypt-later exposure could "
                           "not be assessed for them (no blocker can be raised without it).")
    if not g.stats.get("imports_available"):
        limitations.append("Import relationships are unavailable for this scan; agility observations are limited (re-scan).")
    limitations.append("Static analysis estimates, not a certification. Low/medium-confidence findings need human review.")

    counts = {"findings": len(records), "quantum_vulnerable": len(vuln), "key_establishment": len(ke), "signatures": len(sig),
              "certificates": len(certs_pk), "undetermined": len(unclear), "classical_blocking": len(legacy) + len(proto) + len(sha1_certs),
              "pqc": len(pqc), "pqc_outside_tests": len(pqc_prod), "hndl_elevated": len(hndl_ke),
              "vulnerable_files": len(vuln_files), "vulnerable_services": len({r["service"] for r in vuln})}
    return {"version": ASSESSMENT_VERSION,
            "level": {"id": level_id, "label": label, "rule": rule},
            "level_rules": [{"id": i, "label": lbl, "rule": r} for i, lbl, r in LEVEL_RULES],
            "counts": counts, "categories": categories, "blockers": blockers,
            "recommendations": sorted(recs, key=lambda r: r["priority"]),
            "libraries": libraries, "analyzed": analyzed, "not_analyzed": not_analyzed, "limitations": limitations,
            "references": REFERENCES,
            "statement": ("QMC never certifies an application as quantum-safe. This assessment summarizes what static analysis of "
                          "the uploaded repository shows; validate it with your teams and with the runtime environment.")}
