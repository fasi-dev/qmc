"""Migration Impact Simulator (pure functions; no I/O).

Planning and analysis only: it never rewrites code and never declares a migration compatible. For a selected
algorithm / library / finding / file it groups the in-scope findings into migration TRACKS (key establishment,
signatures, undetermined role, broken hashes, legacy ciphers, AES-128), and for each track shows:

  current implementation (algorithms, APIs, call sites with evidence)  ->  a chosen target from a fixed, standards-based
  option list, with published size parameters; affected direct/indirect files from the dependency graph; the migration
  rules (07) that apply; integration changes derived from the operations actually found; compatibility considerations;
  unresolved dependencies and limitations; and a current-vs-proposed architecture view built from graph evidence.

Sizes are the published parameter values (FIPS 203/204/205, draft-ietf-tls-ecdhe-mlkem) and classical encodings; they
are NOT measurements of this application.
"""
from __future__ import annotations

from collections import Counter

from .graph import Graph, blast_radius, file_id, indirect_impact
from .migration import CRYPTO_AGILITY, KE_TEXT, NO_PQC, RULES, SIG_TEXT, context_caveats
from .readiness import LIBRARY_SUPPORT, REFERENCES

SIMULATOR_VERSION = 1

# ---- targets: id -> description + published sizes (bytes)
TARGETS: dict[str, dict] = {
    "X25519MLKEM768": {"name": "Hybrid X25519 + ML-KEM-768", "family": "kem", "standard": "FIPS 203 + draft-ietf-tls-ecdhe-mlkem",
                       "refs": ["FIPS203", "TLS-HYBRID", "SP800-227"],
                       "sizes": {"client key share": 1216, "server key share": 1120, "shared secret": 64},
                       "note": "TLS 1.3 hybrid group (classical + PQC): secure while either component is unbroken. Use where both "
                               "endpoints support it; outside TLS, combine X25519 and ML-KEM-768 secrets with a KDF."},
    "ML-KEM-768": {"name": "ML-KEM-768", "family": "kem", "standard": "FIPS 203", "refs": ["FIPS203", "SP800-227"],
                   "sizes": {"encapsulation key": 1184, "ciphertext": 1088, "shared secret": 32},
                   "note": "NIST security category 3; the common default parameter set."},
    "ML-KEM-1024": {"name": "ML-KEM-1024", "family": "kem", "standard": "FIPS 203", "refs": ["FIPS203", "SP800-227"],
                    "sizes": {"encapsulation key": 1568, "ciphertext": 1568, "shared secret": 32},
                    "note": "NIST security category 5; larger messages."},
    "ML-KEM-512": {"name": "ML-KEM-512", "family": "kem", "standard": "FIPS 203", "refs": ["FIPS203", "SP800-227"],
                   "sizes": {"encapsulation key": 800, "ciphertext": 768, "shared secret": 32},
                   "note": "NIST security category 1; smallest messages."},
    "ML-DSA-65": {"name": "ML-DSA-65", "family": "sig", "standard": "FIPS 204", "refs": ["FIPS204"],
                  "sizes": {"public key": 1952, "signature": 3309}, "note": "NIST security category 3; the common default."},
    "ML-DSA-44": {"name": "ML-DSA-44", "family": "sig", "standard": "FIPS 204", "refs": ["FIPS204"],
                  "sizes": {"public key": 1312, "signature": 2420}, "note": "NIST security category 2; smallest ML-DSA."},
    "ML-DSA-87": {"name": "ML-DSA-87", "family": "sig", "standard": "FIPS 204", "refs": ["FIPS204"],
                  "sizes": {"public key": 2592, "signature": 4627}, "note": "NIST security category 5."},
    "SLH-DSA-SHA2-128s": {"name": "SLH-DSA-SHA2-128s", "family": "sig", "standard": "FIPS 205", "refs": ["FIPS205"],
                          "sizes": {"public key": 32, "signature": 7856},
                          "note": "Hash-based (conservative assumptions); small keys, large and slow signatures. Suited to rare "
                                  "signing such as firmware or release artifacts."},
    "SLH-DSA-SHA2-128f": {"name": "SLH-DSA-SHA2-128f", "family": "sig", "standard": "FIPS 205", "refs": ["FIPS205"],
                          "sizes": {"public key": 32, "signature": 17088}, "note": "Hash-based, faster signing, larger signatures."},
    "SHA-256": {"name": "SHA-256", "family": "hash", "standard": "FIPS 180-4", "refs": ["SP800-131A"], "sizes": {"digest": 32},
                "note": "Classical replacement; not a PQC change."},
    "SHA3-256": {"name": "SHA3-256", "family": "hash", "standard": "FIPS 202", "refs": ["SP800-131A"], "sizes": {"digest": 32},
                 "note": "Classical replacement; not a PQC change."},
    "AES-256-GCM": {"name": "AES-256-GCM", "family": "sym", "standard": "FIPS 197 + SP 800-38D", "refs": ["SP800-131A"],
                    "sizes": {"key": 32, "nonce": 12, "tag": 16}, "note": "Authenticated encryption; not a PQC change."},
}

TRACKS = {
    "kem": {"title": "Key establishment", "targets": ["X25519MLKEM768", "ML-KEM-768", "ML-KEM-1024", "ML-KEM-512"], "default": "X25519MLKEM768"},
    "sig": {"title": "Digital signatures", "targets": ["ML-DSA-65", "ML-DSA-44", "ML-DSA-87", "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f"],
            "default": "ML-DSA-65"},
    "unclear": {"title": "Public-key usage with undetermined role", "targets": [], "default": None},
    "hash": {"title": "Broken hash functions", "targets": ["SHA-256", "SHA3-256"], "default": "SHA-256"},
    "legacy": {"title": "Legacy symmetric ciphers", "targets": ["AES-256-GCM"], "default": "AES-256-GCM"},
    "aes128": {"title": "AES-128 key size", "targets": ["AES-256-GCM"], "default": "AES-256-GCM"},
}
NO_ACTION = "no_action"


def track_of(f: dict) -> str:
    if f.get("already_pqc"):
        return NO_ACTION
    if f["quantum_vulnerable"]:
        return {"key-establishment": "kem", "signature": "sig"}.get(f.get("role") or "", "unclear")
    if f["algorithm"] in ("SHA-1", "MD5"):
        return "hash"
    if f["algorithm"] in ("3DES", "DES", "RC4", "Blowfish"):
        return "legacy"
    if f["algorithm"] == "AES" and f.get("key_size") == 128:
        return "aes128"
    return NO_ACTION


def _current_sizes(alg: str, key_sizes: set[int | None], family: str) -> dict[str, str]:
    """Classical encodings for comparison; only what follows from the algorithm and a literal key size."""
    out: dict[str, str] = {}
    bits = sorted(k for k in key_sizes if k)
    if alg == "RSA":
        if bits:
            out = {"public key (modulus)": " / ".join(f"{b // 8}" for b in bits),
                   ("signature" if family == "sig" else "ciphertext"): " / ".join(f"{b // 8}" for b in bits)}
        else:
            out = {"public key (modulus)": "key size not determined (e.g. 256 for RSA-2048)"}
    elif alg in ("ECDSA", "EC"):
        out = {"public key (P-256, uncompressed)": "65", "signature (P-256, raw r||s)": "64"}
    elif alg == "EdDSA":
        out = {"public key (Ed25519)": "32", "signature (Ed25519)": "64"}
    elif alg in ("ECDH", "DH/ECDH"):
        out = {"public key share (X25519 / P-256)": "32 / 65"}
    elif alg == "DH":
        out = {"public key share": f"{bits[0] // 8}" if bits else "group size not determined (e.g. 256 for 2048-bit)"}
    return out


def _changes(track: str, findings: list[dict], target: dict | None) -> list[dict]:
    """Integration changes derived from the operations and contexts actually found (each with its call sites)."""
    by_op: dict[str, list[dict]] = {}
    for f in findings:
        by_op.setdefault(f["operation"], []).append(f)
    tname = target["name"] if target else "the chosen target"
    plans: list[tuple[str, str, str]] = []                                 # (operation, change, why)
    if track == "kem":
        plans = [
            ("key_generation", f"Generate {tname} key pairs (encapsulation / decapsulation keys) where these classical keys are generated.",
             "KEM keys replace the classical key pair; key storage and serialization formats change."),
            ("key_agreement", "Replace the Diffie-Hellman exchange with encapsulate (initiator) / decapsulate (responder); protocol "
             "messages carry a KEM ciphertext instead of a public share.", "A KEM is not a drop-in DH: the message flow changes."),
            ("encryption", "Replace RSA encryption / key transport with KEM encapsulate -> KDF -> AEAD encrypt.",
             "ML-KEM produces a shared secret, it does not encrypt data (SP 800-227)."),
            ("decryption", "Replace RSA decryption with KEM decapsulate -> KDF -> AEAD decrypt.", "Mirror of the encryption change."),
            ("config", "Enable a hybrid TLS group (e.g. X25519MLKEM768) on a TLS stack that supports it, keeping a classical fallback "
             "until clients are confirmed.", "Usually a library / configuration upgrade rather than application code."),
        ]
    elif track == "sig":
        plans = [
            ("key_generation", f"Generate {tname} signing keys; plan key distribution, storage (HSM/KMS) and rotation.",
             "New key types and encodings (SPKI / PKCS#8) must be supported by every party that loads them."),
            ("signature", f"Switch these signing call sites to {tname} only after all verifiers support it (or dual-sign).",
             "Signers switching first break every verifier that has not upgraded."),
            ("verification", f"Add {tname} verification at these call sites first (accept both during the transition).",
             "Verifiers upgrade before signers."),
            ("config", "Update configured signature/host-key algorithms (e.g. TLS certificates, SSH host keys) once the peers support them.",
             "Configuration-level change coordinated with clients."),
        ]
    elif track == "hash":
        plans = [("hashing", f"Replace with {tname} where the digest has a security purpose; stored digests may need re-computation.",
                  "Digest length and stored values change; comparisons against old values must be handled.")]
    elif track in ("legacy", "aes128"):
        plans = [(op, f"Use {tname} for {op.replace('_', ' ')}; re-encrypt stored data and rotate keys.",
                  "Ciphertexts and key sizes change; data at rest needs a migration path.") for op in ("encryption", "decryption", "key_generation")]
    out = []
    for op, change, why in plans:
        rows = by_op.get(op, [])
        if rows:
            out.append({"operation": op, "change": change, "why": why, "call_sites": [
                {"fid": f["id"], "file": f["file"], "line": f["line_start"], "text": f["evidence"], "api": f.get("api")}
                for f in sorted(rows, key=lambda r: (r["file"], r["line_start"]))]})
    covered = {c["operation"] for c in out}
    rest = [f for f in findings if f["operation"] not in covered]
    if rest:
        out.append({"operation": "other", "change": "Review these call sites manually: their operation does not map to a standard change.",
                    "why": "Not derivable from the detected operation.", "call_sites": [
                        {"fid": f["id"], "file": f["file"], "line": f["line_start"], "text": f["evidence"], "api": f.get("api")} for f in rest]})
    return out


def _architecture(g: Graph, track_findings: list[dict], indirect: list[dict], target: dict | None) -> dict:
    """Current vs proposed view, restricted to evidence: affected files -> algorithm/library they use today, and the
    same files -> the proposed target. Indirect files keep their import edges (they are unchanged by the swap)."""
    direct = sorted({f["file"] for f in track_findings})
    files = direct + [x["file"] for x in indirect if x["file"] not in direct]

    def file_nodes() -> list[dict]:
        return [{**g.nodes[file_id(p)], "role_in_change": "direct" if p in direct else "indirect"} for p in files if file_id(p) in g.nodes]
    imports = [e for e in g.edges.values() if e["type"] == "IMPORTS" and e["source"][5:] in files and e["target"][5:] in files]
    cur_nodes, cur_edges = file_nodes(), list(imports)
    for alg in sorted({f["algorithm"] for f in track_findings}):
        aid = f"algorithm:{alg}"
        if aid in g.nodes:
            cur_nodes.append(g.nodes[aid])
    for lib in sorted({f["library"] for f in track_findings if f.get("library")}):
        lid = f"library:{lib}"
        if lid in g.nodes:
            cur_nodes.append(g.nodes[lid])
    seen = set()
    for f in track_findings:
        for tgt in (f"algorithm:{f['algorithm']}", f"library:{f['library']}" if f.get("library") else None):
            if not tgt or tgt not in g.nodes:
                continue
            eid = f"USES:{file_id(f['file'])}->{tgt}"
            if eid not in seen:
                seen.add(eid)
                cur_edges.append({"id": eid, "type": "USES", "source": file_id(f["file"]), "target": tgt, "confidence": "confirmed",
                                  "basis": "detected usage", "evidence": [], "evidence_count": 0})
    prop_nodes, prop_edges = file_nodes(), list(imports)
    if target:
        tid = f"algorithm:{target['name']} (proposed)"
        prop_nodes.append({"id": tid, "type": "algorithm", "label": f"{target['name']} (proposed)", "proposed": True,
                           "quantum_vulnerable": False, "finding_count": 0, "max_band": None})
        for p in direct:
            prop_edges.append({"id": f"USES:{file_id(p)}->{tid}", "type": "USES", "source": file_id(p), "target": tid,
                               "confidence": "inferred", "basis": "proposed change (not implemented)", "evidence": [], "evidence_count": 0})
    return {"current": {"nodes": cur_nodes, "edges": sorted(cur_edges, key=lambda e: e["id"])},
            "proposed": {"nodes": prop_nodes, "edges": sorted(prop_edges, key=lambda e: e["id"])},
            "note": "The proposed view only changes the algorithm used by the directly affected files. Whether the same library can "
                    "provide it depends on the installed version (see compatibility)."}


class InvalidTarget(ValueError):
    pass


def simulate(g: Graph, records: list[dict], node_id: str, target: str | None = None) -> dict:
    """Raises graph.NodeNotFound / graph.NotSelectable for bad nodes, InvalidTarget for a target outside the options."""
    br = blast_radius(g, node_id)                       # validates the node
    by_id = {r["id"]: r for r in records}
    scope = [by_id[f["fid"]] for f in br["findings"] if f["fid"] in by_id]
    groups: dict[str, list[dict]] = {}
    for f in scope:
        groups.setdefault(track_of(f), []).append(f)
    if target is not None and target not in TARGETS:
        raise InvalidTarget(target)
    if target is not None and not any(target in TRACKS[t]["targets"] for t in groups if t in TRACKS):
        raise InvalidTarget(target)

    tracks = []
    for tid in [t for t in TRACKS if t in groups]:
        fs = sorted(groups[tid], key=lambda r: (r["file"], r["line_start"], r["id"]))
        spec = TRACKS[tid]
        chosen = target if target in spec["targets"] else spec["default"]
        tgt = TARGETS.get(chosen) if chosen else None
        algs = Counter(f["algorithm"] for f in fs)
        family = "sig" if tid == "sig" else "kem"
        current = {"algorithms": dict(sorted(algs.items())),
                   "operations": dict(sorted(Counter(f["operation"] for f in fs).items())),
                   "apis": sorted({f.get("api") or f["rule_id"] for f in fs}),
                   "libraries": sorted({f["library"] for f in fs if f.get("library")}),
                   "key_sizes": sorted({f["key_size"] for f in fs if f.get("key_size")}),
                   "sizes": {a: _current_sizes(a, {f.get("key_size") for f in fs if f["algorithm"] == a}, family) for a in sorted(algs)}}
        rules = []
        for rid in sorted({f.get("migration_rule") for f in fs if f.get("migration_rule")}):
            name, direction, kind = RULES.get(rid, (rid, None, None))
            text = KE_TEXT if kind == "KE" else SIG_TEXT if kind == "SIG" else None
            rules.append({"rule_id": rid, "name": name, "direction": direction or (NO_PQC.get(rid, ("", []))[0] if rid in NO_PQC else None),
                          "steps": (text or {}).get("steps", []), "findings": sum(1 for f in fs if f.get("migration_rule") == rid)})
        compat: list[str] = []
        if tid == "kem":
            compat += KE_TEXT["caveats"] + [KE_TEXT["interoperability"]]
        elif tid == "sig":
            compat += SIG_TEXT["caveats"] + [SIG_TEXT["interoperability"]]
        elif tid in ("hash", "legacy"):
            compat += NO_PQC["R-09" if tid == "hash" else "R-13"][1]
        for f in fs:
            for c in context_caveats({"rule_id": f["rule_id"], "context": f.get("context")}, f.get("role")):
                if c not in compat:
                    compat.append(c)
        libs = []
        for lib in current["libraries"]:
            known = LIBRARY_SUPPORT.get(lib)
            libs.append({"library": lib, "pqc_support": known["support"] if known else None,
                         "references": known["refs"] if known else [],
                         "status": "known" if known else "not_verified"})
        direct_files = sorted({f["file"] for f in fs})
        indirect, capped = indirect_impact(g, [file_id(p) for p in direct_files])   # this track's own dependents
        limitations = [l for l in br["limitations"] if not l.startswith("No repository file imports")]
        if g.stats.get("imports_available") and not indirect:
            limitations.append("No repository file imports the directly affected files of this track (by resolvable static imports).")
        if capped:
            limitations.append("Import chains longer than the analysis depth were not followed further.")
        if tid == "unclear":
            limitations.insert(0, "The cryptographic role is undetermined, so no target is proposed. Decide whether these keys are "
                                  "used for key establishment (ML-KEM) or signatures (ML-DSA / SLH-DSA), then re-run the simulation.")
        if any(l["status"] == "not_verified" for l in libs):
            limitations.append("PQC support of some libraries is not verified by QMC: a different provider may be needed.")
        limitations.append("Installed library / runtime versions are unknown to QMC; size values are published parameters, not measurements.")
        tracks.append({
            "id": tid, "title": spec["title"], "findings": [
                {"fid": f["id"], "file": f["file"], "line": f["line_start"], "algorithm": f["algorithm"], "operation": f["operation"],
                 "band": f.get("band"), "qmp": f.get("qmp"), "hndl": f.get("hndl"), "service": f["service"], "evidence": f["evidence"],
                 "confidence": f["confidence_level"], "test_path": f.get("test_path")} for f in fs],
            "current": current,
            "target": ({"id": chosen, **tgt} if tgt else None),
            "target_options": [{"id": t, "name": TARGETS[t]["name"], "standard": TARGETS[t]["standard"]} for t in spec["targets"]],
            "affected": {"direct_files": direct_files, "components": sorted({f["service"] for f in fs}),
                         "indirect_files": indirect, "indirect_confirmed": sum(1 for x in indirect if x["confidence"] == "confirmed"),
                         "indirect_inferred": sum(1 for x in indirect if x["confidence"] == "inferred"),
                         "hndl": sum(1 for f in fs if f.get("hndl"))},
            "rules": rules, "integration_changes": _changes(tid, fs, tgt), "compatibility": compat, "libraries": libs,
            "references": sorted(set((tgt or {}).get("refs", [])) | {r for l in libs for r in l["references"]}),
            "architecture": _architecture(g, fs, indirect, tgt), "limitations": limitations})

    no_action = sorted(groups.get(NO_ACTION, []), key=lambda r: (r["file"], r["line_start"]))
    return {"version": SIMULATOR_VERSION, "selection": br["node"], "target_requested": target,
            "summary": {"findings_in_scope": len(scope), "tracks": len(tracks), "direct_files": br["summary"]["direct_files"],
                        "indirect_files": br["summary"]["indirect_files"], "indirect_inferred": br["summary"]["indirect_inferred"],
                        "components": br["summary"]["components"], "no_migration_needed": len(no_action)},
            "tracks": tracks,
            "no_migration_needed": [{"fid": f["id"], "file": f["file"], "line": f["line_start"], "algorithm": f["algorithm"],
                                     "reason": "already post-quantum" if f.get("already_pqc") else
                                     "not quantum-vulnerable and not a classical-hygiene issue"} for f in no_action],
            "blast_radius": {"summary": br["summary"], "components": br["components"], "limitations": br["limitations"]},
            "crypto_agility": CRYPTO_AGILITY,
            "references": REFERENCES,
            "statement": ("Planning simulation only: QMC does not change code and does not confirm compatibility. Whether a replacement "
                          "works depends on protocols, libraries and their versions, key formats, message-size budgets, performance "
                          "requirements and every peer that must interoperate. Validate with tests before migrating.")}
