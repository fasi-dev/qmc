"""Secret / private-key redaction applied at ingestion (04 section 4).

Secrets are replaced in the persisted copy with the marker `***REDACTED***`.
Line numbers are PRESERVED (redaction never adds/removes lines) so scanner
evidence line numbers match the original file. Only location + kind are recorded;
secret values are never stored (not even hashed).

These are conservative heuristics, not a guarantee that every secret is found.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass

MARKER = "***REDACTED***"


@dataclass
class Redaction:
    line_start: int
    line_end: int
    kind: str


# ---- PEM private keys (line-based state machine: linear time, no regex backtracking) ----
_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{16,}")
_MAX_BEGIN_PROBES = 50


def _find_private_begin(line: str) -> int | None:
    """Index just after a '-----BEGIN ... PRIVATE KEY...-----' header on this line."""
    idx = line.find("-----BEGIN ")
    for _ in range(_MAX_BEGIN_PROBES):
        if idx == -1:
            return None
        close = line.find("-----", idx + 11)
        if close == -1:
            return None
        if "PRIVATE KEY" in line[idx + 11:close]:
            return close + 5
        idx = line.find("-----BEGIN ", idx + 11)
    return None


def _is_private_end(line: str) -> int:
    idx = line.find("-----END ")
    if idx != -1 and "PRIVATE KEY" in line[idx:idx + 60]:
        return idx
    return -1


def _redact_pem(lines: list[str], out: list[Redaction]) -> None:
    i, n = 0, len(lines)
    in_block, start = False, 0
    while i < n:
        line = lines[i]
        if in_block:
            if _find_private_begin(line) is not None:
                # Unterminated previous block: close it here, re-process this line as a new header.
                out.append(Redaction(start + 1, i, "pem_private_key"))
                in_block = False
                continue
            end = _is_private_end(line)
            if end != -1:
                lines[i] = _B64_RUN.sub(MARKER, line[:end]) + line[end:]
                out.append(Redaction(start + 1, i + 1, "pem_private_key"))
                in_block = False
            elif line.strip():
                lines[i] = MARKER
            i += 1
            continue
        b = _find_private_begin(line)
        if b is None:
            i += 1
            continue
        end = line.find("-----END ", b)
        if end != -1 and "PRIVATE KEY" in line[end:end + 60]:
            if line[b:end].strip():  # same-line key material (e.g. escaped "\n" string literal)
                lines[i] = line[:b] + MARKER + line[end:]
            out.append(Redaction(i + 1, i + 1, "pem_private_key"))
            i += 1
            continue
        lines[i] = line[:b] + _B64_RUN.sub(MARKER, line[b:])
        in_block, start = True, i
        i += 1
    if in_block:  # truncated key at EOF
        out.append(Redaction(start + 1, n, "pem_private_key"))


# ---- Inline credential patterns ----
_NAMES = r"(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?key|auth[_-]?token|token|passw(?:or)?d|pwd)"
_INLINE: list[tuple[str, re.Pattern[str], int]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), 0),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), 0),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"), 0),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), 0),
    ("credential_assignment",
     re.compile(r"(?i)\b" + _NAMES + r"\b[\"']?\s*[:=]\s*([\"'])([^\"'\s\\]{8,})\1"), 2),
]
# Unquoted `name: value` -- only for config-style files (avoids mangling Python annotations).
_YAML_UNQUOTED = re.compile(
    r"(?im)^\s*[A-Za-z0-9_.-]*" + _NAMES + r"\s*:[ \t]*([^\s\"'#${<][^\s#]{7,})"
)
_CONFIG_EXT = (".yaml", ".yml", ".env", ".properties", ".ini", ".conf", ".cfg", ".toml")


def redact_text(text: str, path: str) -> tuple[str, list[Redaction]]:
    """Return (redacted_text, redactions). Line count is unchanged."""
    redactions: list[Redaction] = []
    lines = text.split("\n")
    if "PRIVATE KEY" in text:
        _redact_pem(lines, redactions)
    text = "\n".join(lines)

    spans: list[tuple[int, int, str]] = []
    for kind, rx, grp in _INLINE:
        for m in rx.finditer(text):
            spans.append((m.start(grp), m.end(grp), kind))
    if path.lower().endswith(_CONFIG_EXT):
        for m in _YAML_UNQUOTED.finditer(text):
            spans.append((m.start(1), m.end(1), "credential_assignment"))

    if spans:
        starts = [0]
        for ln in lines:
            starts.append(starts[-1] + len(ln) + 1)
        spans.sort(key=lambda s: (s[0], -s[1]))
        pieces, cursor = [], 0
        for s, e, kind in spans:
            if s < cursor:  # overlaps an already-redacted span
                continue
            pieces.append(text[cursor:s])
            pieces.append(MARKER)
            cursor = e
            ln = bisect_right(starts, s)
            redactions.append(Redaction(ln, ln, kind))
        pieces.append(text[cursor:])
        text = "".join(pieces)
    redactions.sort(key=lambda r: (r.line_start, r.kind))
    return text, redactions
