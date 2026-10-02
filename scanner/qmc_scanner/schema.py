"""Finding schema, exactly as specified in 05_CRYPTO_SCANNER_SPEC.md section 4.

Closed vocabularies live here so rules, engine and (later) risk/migration code share one definition.
Fields NOT in the schema (timestamp, evidence hash) are deliberately excluded to keep scanner output
deterministic; the persistence layer adds them (see DECISIONS.md).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

PRIMITIVES = ("public-key", "symmetric", "hash", "mac", "pqc-kem", "pqc-signature", "protocol")

# Closed operation enum per primitive (05 section 4). "unspecified" is only used by comment/doc-only findings.
OPERATIONS: dict[str, tuple[str, ...]] = {
    "public-key": ("key_generation", "key_agreement", "encryption", "decryption", "signature", "verification"),
    "symmetric": ("key_generation", "encryption", "decryption"),
    "hash": ("hashing",),
    "mac": ("mac_generation", "mac_verification"),
    "pqc-kem": ("key_generation", "encapsulation", "decapsulation"),
    "pqc-signature": ("key_generation", "signing", "verification"),
    "protocol": ("config", "termination"),
}
UNSPECIFIED = "unspecified"

CONTEXTS = ("authentication", "key-establishment", "data-protection", "integrity",
            "tls-termination", "code-signing", "unknown")

FINDING_KEYS = ("id", "scan_id", "rule_id", "rule_version", "engine_version", "file", "line_start", "line_end",
                "algorithm", "primitive", "operation", "library", "api", "context", "service", "evidence",
                "confidence", "confidence_level", "quantum_vulnerable", "already_pqc", "metadata")
METADATA_KEYS = ("key_size", "comment_only", "in_dead_code", "test_path")


def confidence_level(c: float) -> str:
    """05 section 5: High >= 0.90, Medium 0.50-0.89, Low < 0.50."""
    if c >= 0.90:
        return "high"
    if c >= 0.50:
        return "medium"
    return "low"


def valid_operation(primitive: str, operation: str) -> bool:
    return operation == UNSPECIFIED or operation in OPERATIONS.get(primitive, ())


def evidence_hash(evidence: str) -> str:
    """Helper for the persistence layer (04: 'evidence hash'); not part of the finding schema."""
    return hashlib.sha256(evidence.encode("utf-8")).hexdigest()


@dataclass
class Finding:
    id: str
    scan_id: str
    rule_id: str
    rule_version: str
    engine_version: str
    file: str
    line_start: int
    line_end: int
    algorithm: str
    primitive: str
    operation: str
    library: str | None
    api: str | None
    context: str
    service: str
    evidence: str
    confidence: float
    confidence_level: str
    quantum_vulnerable: bool
    already_pqc: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {k: getattr(self, k) for k in FINDING_KEYS}
        d["metadata"] = {k: self.metadata.get(k) for k in METADATA_KEYS}
        return d


def validate_finding(d: dict[str, Any]) -> None:
    """Raise ValueError if `d` does not conform to the 05 section 4 schema."""
    if tuple(d.keys()) != FINDING_KEYS:
        raise ValueError(f"finding keys differ from schema: {tuple(d.keys())}")
    if tuple(d["metadata"].keys()) != METADATA_KEYS:
        raise ValueError("metadata keys differ from schema")
    if d["primitive"] not in PRIMITIVES:
        raise ValueError(f"bad primitive {d['primitive']!r}")
    if not valid_operation(d["primitive"], d["operation"]):
        raise ValueError(f"bad operation {d['operation']!r} for {d['primitive']}")
    if d["context"] not in CONTEXTS:
        raise ValueError(f"bad context {d['context']!r}")
    if not (0.0 <= d["confidence"] <= 1.0) or d["confidence_level"] != confidence_level(d["confidence"]):
        raise ValueError("confidence / confidence_level inconsistent")
    if d["line_start"] < 1 or d["line_end"] < d["line_start"]:
        raise ValueError("bad line range")
    if not d["evidence"] or not d["file"]:
        raise ValueError("finding without file/evidence is not renderable (04)")
    if d["metadata"]["comment_only"] and d["confidence_level"] != "low":
        raise ValueError("comment-only finding above Low confidence")
    if d["already_pqc"] and d["quantum_vulnerable"]:
        raise ValueError("already_pqc finding cannot be quantum_vulnerable")
