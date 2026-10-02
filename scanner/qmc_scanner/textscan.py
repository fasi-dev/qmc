"""Anchored-regex detection for Java and JS/TS on lexed source (comments blanked, strings kept)."""
from __future__ import annotations

import re
from bisect import bisect_right

from .lexers import Lexed
from .matches import RawMatch, clean_evidence, entry_value
from .rules import Rule, lookup

_DECL = re.compile(r"\b(?:function\s+([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)\s*\([^;(){}]*\)\s*(?:throws\s+[\w.,\s]+)?\{)")
_WINDOW_MAX = 600
_NOT_NAMES = {"if", "for", "while", "switch", "catch", "synchronized", "try", "else", "do", "return", "function"}


def _decl_index(code: str) -> list[tuple[int, str]]:
    out = []
    for m in _DECL.finditer(code):
        name = m.group(1) or m.group(2)
        if name and name not in _NOT_NAMES:
            out.append((m.start(), name))
    return out


_CALL_SCAN_MAX = 200


def _call_end(code: str, m: re.Match) -> int:
    """Offset just past the balanced ')' of the call whose '(' is inside the match (bounded); else match end."""
    rel = m.group(0).find("(")
    if rel == -1:
        return m.end()
    depth = 0
    limit = min(len(code), m.start() + rel + _CALL_SCAN_MAX)
    for i in range(m.start() + rel, limit):
        c = code[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return m.end()


def scan_regex(lx: Lexed, rules: list[Rule]) -> list[RawMatch]:
    code, mask = lx.code, lx.mask
    decls: list[tuple[int, str]] | None = None
    decl_pos: list[int] = []
    results: list[RawMatch] = []
    for rule in rules:
        if rule.match_type != "regex":
            continue
        if rule.file_requires and not rule.file_requires.search(code):
            continue
        for m in rule.pattern.finditer(code):  # type: ignore[union-attr]
            if mask[m.start()] != 0:   # anchor inside a string literal / comment / regex literal: ignore
                continue
            entry: dict | None = None
            if rule.value_group:
                raw = m.group(rule.value_group)
                entry = lookup(rule.value_map, raw) if raw is not None else lookup(rule.value_map, "")
                if entry is None:
                    continue
            op = entry_value(rule, entry, "operation")
            tail = code[m.end():m.end() + _WINDOW_MAX]
            for window, pat, refined in rule.refine:
                if pat.search(tail[:window]):
                    op = refined
                    break
            ks = (entry or {}).get("key_size")
            if ks is None and rule.key_size_group:
                g = m.group(rule.key_size_group)
                ks = int(g) if g else None
            if ks is None and rule.key_size_after:
                window, kpat = rule.key_size_after
                km = kpat.search(tail[:window])
                ks = int(km.group("bits")) if km else None
            if decls is None:
                decls = _decl_index(code)
                decl_pos = [d[0] for d in decls]
            scope: tuple[str, ...] = ()
            k = bisect_right(decl_pos, m.start()) - 1
            if k >= 0:
                scope = (decls[k][1],)
            alg = entry_value(rule, entry, "algorithm")
            end = _call_end(code, m)
            results.append(RawMatch(
                rule=rule, line_start=lx.line_of(m.start()), line_end=lx.line_of(max(end - 1, m.start())),
                algorithm=alg, primitive=entry_value(rule, entry, "primitive"), operation=op,
                library=rule.library, api=(entry or {}).get("api") or rule.api,
                confidence=float(entry_value(rule, entry, "confidence")),
                evidence=clean_evidence(code[m.start():end]), key_size=ks, scope=scope,
                resolvable=bool(rule.sibling_resolution and alg == rule.sibling_resolution["from"])))
    return results
