"""Scan engine: walk an extracted (Phase 2, already redacted) tree and produce findings.

Deterministic: files are visited in sorted order, findings are sorted and numbered after the fact,
and no timestamps/randomness are involved. Never imports, executes or evals scanned code.
"""
from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._version import ENGINE_VERSION
from .confscan import hash_comments, scan_directives, scan_pem, scan_structured
from .context import infer_context
from .lexers import lex
from .matches import RawMatch, clean_evidence, scan_mentions
from .pyscan import mentions_python, scan_python
from .redaction import redact_text
from functools import lru_cache

from .rules import RuleSet, load_rules
from .schema import Finding, confidence_level, validate_finding
from .services import service_for_path
from .textscan import scan_regex

LANG_BY_EXT = {".py": "python", ".pyw": "python", ".java": "java",
               ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js",
               ".md": "doc", ".rst": "doc", ".txt": "doc"}
PEM_EXT = (".crt", ".pem", ".cer", ".cert")
STRUCT_MAX_BYTES = 1024 * 1024      # YAML/JSON are parsed fully; cap the size
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "site-packages", ".tox", ".mypy_cache"}
MINIFIED_LINE = 10_000          # 05 section 10
COMMENT_CAP = 0.45              # 05 section 5: comment-only can never exceed Low
_TEST_TOKENS = {"test", "tests", "__tests__"}


@lru_cache(maxsize=1)
def _default_rules() -> RuleSet:
    return load_rules()


def classify(rel: str) -> str | None:
    """File kind: code languages, doc, or a config kind (yaml/json/text/pem). None = not scanned."""
    base = rel.rsplit("/", 1)[-1].lower()
    ext = Path(base).suffix
    if ext in LANG_BY_EXT:
        return LANG_BY_EXT[ext]
    if ext in PEM_EXT:
        return "pem"
    if ext == ".json":
        return "json"
    if ext in (".yaml", ".yml"):
        return "yaml"
    if (ext in (".conf", ".dockerfile") or base == "dockerfile" or base.startswith("dockerfile.")
            or base in ("sshd_config", "ssh_config", "jenkinsfile")):
        return "text"
    return None


def is_test_path(path: str) -> bool:
    """05 section 5 patterns (test_*, *.test.*, tests/) generalized to whole path tokens (DECISIONS #20)."""
    parts = path.lower().split("/")
    if any(p in _TEST_TOKENS for p in parts[:-1]):
        return True
    return any(t in _TEST_TOKENS for t in re.split(r"[._\-]", parts[-1]))


@dataclass
class ScanResult:
    scan_id: str
    status: str                                   # "complete" | "partial" (timeout, 05 section 9)
    findings: list[dict[str, Any]]
    files_scanned: dict[str, int]
    files_skipped: list[dict[str, str]]
    skipped_directories: list[str]
    rule_hits: dict[str, int]
    rule_versions: dict[str, str]
    engine_version: str = ENGINE_VERSION
    as_of: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"engine_version": self.engine_version, "scan_id": self.scan_id, "as_of": self.as_of, "status": self.status,
                "files_scanned": self.files_scanned, "files_skipped": self.files_skipped,
                "skipped_directories": self.skipped_directories, "rule_hits": self.rule_hits,
                "rule_versions": self.rule_versions, "findings": self.findings}


def _resolve_siblings(matches: list[RawMatch]) -> None:
    """EC key generation is ambiguous alone; if the SAME FILE shows exactly one of ECDSA/ECDH, adopt it."""
    algs = {m.algorithm for m in matches if not m.comment_only}
    for m in matches:
        sr = m.rule.sibling_resolution
        if m.resolvable and sr:
            cands = [target for src, target in sr["map"].items() if src in algs]
            if len(set(cands)) == 1:
                m.algorithm = cands[0]
                m.confidence = float(sr["confidence"])
            m.resolvable = False


def scan_tree(root: Path | str, *, scan_id: str = "00000000-0000-4000-8000-000000000000",
              services: list[dict] | None = None, repo_name: str = "repo", rules: RuleSet | None = None,
              deadline_seconds: float | None = 300, max_file_bytes: int = 5 * 1024 * 1024,
              as_of: datetime | None = None) -> ScanResult:
    root = Path(root)
    ruleset = rules or _default_rules()
    services = services or []
    as_of = as_of or datetime.now(timezone.utc)    # certificate expiry is evaluated against this explicit input
    if as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=timezone.utc)
    cfg_rules = ruleset.for_language("config")
    py_rules, java_rules, js_rules = (ruleset.for_language(x) for x in ("python", "java", "js"))
    mention_rule = next((r for r in ruleset.for_language("generic") if r.match_type == "comment_mention"), None)
    start = time.monotonic()
    status = "complete"
    scanned: dict[str, int] = {}
    skipped: list[dict[str, str]] = []
    skipped_dirs: list[str] = []
    collected: list[tuple[str, RawMatch]] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        keep = []
        for d in sorted(dirnames):
            full = Path(dirpath, d)
            if d in SKIP_DIRS or full.is_symlink():
                skipped_dirs.append((d if rel_dir == "." else f"{rel_dir}/{d}"))
            else:
                keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            if deadline_seconds is not None and time.monotonic() - start > deadline_seconds:
                status = "partial"
                break
            full = Path(dirpath, fn)
            rel = fn if rel_dir == "." else f"{rel_dir}/{fn}"
            lang = classify(rel)
            if lang is None or full.is_symlink():
                continue
            try:
                if full.stat().st_size > (STRUCT_MAX_BYTES if lang in ("yaml", "json") else max_file_bytes):
                    skipped.append({"file": rel, "reason": "too_large"})
                    continue
                text = full.read_bytes().decode("utf-8", errors="replace")
            except OSError:
                skipped.append({"file": rel, "reason": "read_error"})
                continue
            if lang in ("python", "java", "js", "text") and max((len(l) for l in text.split("\n")), default=0) > MINIFIED_LINE:
                skipped.append({"file": rel, "reason": "skipped_minified"})
                continue
            matches: list[RawMatch] = []
            if lang == "python":
                matches, why = scan_python(text, py_rules)
                if why:
                    skipped.append({"file": rel, "reason": why})
                    continue
                if mention_rule:
                    matches += mentions_python(text, mention_rule)
            elif lang in ("java", "js"):
                lx = lex(text, lang)
                matches = scan_regex(lx, java_rules if lang == "java" else js_rules)
                if mention_rule:
                    matches += scan_mentions(mention_rule, lx.comments)
            elif lang == "pem":
                matches, why = scan_pem(text, cfg_rules, as_of)
                if why:
                    skipped.append({"file": rel, "reason": why})
            elif lang in ("yaml", "json", "text"):
                if lang in ("yaml", "json"):
                    matches, why = scan_structured(text, cfg_rules)
                    if why:
                        skipped.append({"file": rel, "reason": why})
                        continue
                if lang in ("yaml", "text"):
                    matches += scan_directives(text, rel, cfg_rules)
                    if mention_rule:
                        matches += scan_mentions(mention_rule, hash_comments(text))
            elif mention_rule:  # doc files: every line is documentation, never executable
                matches = scan_mentions(mention_rule, [(i + 1, l.strip()) for i, l in enumerate(text.split("\n")) if l.strip()])
            scanned[lang] = scanned.get(lang, 0) + 1
            _resolve_siblings(matches)
            collected.extend((rel, m) for m in matches)
        else:
            continue
        break

    findings = _finalize(collected, scan_id, services, repo_name)
    hits: dict[str, int] = {}
    for f in findings:
        hits[f["rule_id"]] = hits.get(f["rule_id"], 0) + 1
    used = {r.rule_id: r.rule_version for r in ruleset.rules}
    return ScanResult(scan_id, status, findings, dict(sorted(scanned.items())),
                      sorted(skipped, key=lambda s: (s["file"], s["reason"])), sorted(skipped_dirs),
                      dict(sorted(hits.items())), dict(sorted(used.items())),
                      as_of=as_of.date().isoformat())


def _finalize(collected: list[tuple[str, RawMatch]], scan_id: str, services: list[dict], repo: str) -> list[dict]:
    rows: list[dict] = []
    seen: set[tuple] = set()
    for rel, m in collected:
        ev, _ = redact_text(m.evidence, rel)       # defense in depth: evidence can never carry a secret
        key = (rel, m.rule.rule_id, m.line_start, m.line_end, m.algorithm, m.operation, ev)
        if key in seen:
            continue
        seen.add(key)
        conf = round(min(m.confidence, COMMENT_CAP) if m.comment_only else m.confidence, 2)
        pqc = m.primitive in ("pqc-kem", "pqc-signature") and not m.comment_only
        rows.append({
            "sort": (rel, m.line_start, m.line_end, m.rule.rule_id, m.algorithm, m.operation, ev),
            "rel": rel, "m": m, "ev": ev, "conf": conf, "pqc": pqc})
    rows.sort(key=lambda r: r["sort"])
    out: list[dict] = []
    for i, r in enumerate(rows, 1):
        m: RawMatch = r["m"]
        rel = r["rel"]
        ctx = "unknown" if m.comment_only else infer_context(rel, m.scope, m.algorithm, m.primitive, m.operation)
        f = Finding(
            id=f"CRYPTO-{i:03d}", scan_id=scan_id, rule_id=m.rule.rule_id, rule_version=m.rule.rule_version,
            engine_version=ENGINE_VERSION, file=rel, line_start=m.line_start, line_end=m.line_end,
            algorithm=m.algorithm, primitive=m.primitive, operation=m.operation, library=m.library, api=m.api,
            context=ctx, service=service_for_path(rel, services) or repo, evidence=r["ev"],
            confidence=r["conf"], confidence_level=confidence_level(r["conf"]),
            quantum_vulnerable=(m.primitive == "public-key" and not m.comment_only),
            already_pqc=r["pqc"],
            metadata={"key_size": m.key_size, "comment_only": m.comment_only, "in_dead_code": False,
                      "test_path": is_test_path(rel)})
        d = f.to_dict()
        validate_finding(d)
        out.append(d)
    return out
