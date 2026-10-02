"""Internal match record shared by the language scanners."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .rules import Rule

EVIDENCE_MAX = 300


def clean_evidence(text: str) -> str:
    s = " ".join(text.split())
    return s if len(s) <= EVIDENCE_MAX else s[:EVIDENCE_MAX - 1] + "…"


@dataclass
class RawMatch:
    rule: Rule
    line_start: int
    line_end: int
    algorithm: str
    primitive: str
    operation: str
    library: str | None
    api: str | None
    confidence: float
    evidence: str
    key_size: int | None = None
    comment_only: bool = False
    scope: tuple[str, ...] = ()        # enclosing function/class names (for context inference)
    resolvable: bool = False           # rule has sibling_resolution and algorithm == its 'from'


def entry_value(rule: Rule, entry: dict | None, key: str):
    if entry and key in entry:
        return entry[key]
    return getattr(rule, key)


# ---- comment / doc mentions (05 section 5: comment-only matches can never exceed Low) ----
def scan_mentions(rule: Rule, items: list[tuple[int, str]]) -> list[RawMatch]:
    out: list[RawMatch] = []
    seen: set[tuple[int, str]] = set()
    for line_no, text in items:
        for pat, algorithm, primitive in rule.mentions:
            if pat.search(text) and (line_no, algorithm) not in seen:
                seen.add((line_no, algorithm))
                out.append(RawMatch(rule, line_no, line_no, algorithm, primitive, "unspecified", None, None,
                                    rule.confidence, clean_evidence(text), comment_only=True))
    return out
