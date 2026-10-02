"""Versioned rule files: rules/<language>/<RULE_ID>.yaml (05 section 7).

Loading is strict: unknown keys, bad regexes, bad enums, filename/id mismatch, duplicate ids or
non-semver versions raise RuleError, so a typo can never silently disable a detection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .schema import PRIMITIVES, valid_operation

RULES_DIR = Path(__file__).parent / "rules"
LANGUAGES = ("python", "java", "js", "generic", "config")
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
_TOP = {"rule_id", "rule_version", "language", "description", "library", "api", "algorithm",
        "primitive", "operation", "confidence", "match"}
_MATCH = {"type", "qualified_names", "value_from", "value_map", "literal_args", "operation_by_parent",
          "key_size", "pattern", "flags", "value_group", "file_requires", "key_size_group",
          "key_size_after", "refine", "sibling_resolution", "mentions",
          "file_pattern", "key_pattern", "split", "skip_prefixes", "emit"}
_ENTRY = {"algorithm", "primitive", "operation", "confidence", "key_size", "api"}
FLAGS = {"IGNORECASE": re.I, "MULTILINE": re.M, "DOTALL": re.S}


class RuleError(ValueError):
    pass


def _norm_key(k: str) -> str:
    return "".join(str(k).lower().split())


def lookup(entries: tuple[tuple[str, dict], ...], raw: str) -> dict | None:
    """First matching entry in file order. Keys: exact, 'pre*', '*suf', '*mid*' (case/space-insensitive)."""
    v = _norm_key(raw)
    for key, entry in entries:
        if key.startswith("*") and key.endswith("*") and len(key) > 2:
            ok = key[1:-1] in v
        elif key.endswith("*"):
            ok = v.startswith(key[:-1])
        elif key.startswith("*"):
            ok = v.endswith(key[1:])
        else:
            ok = v == key
        if ok:
            return entry
    return None


@dataclass(frozen=True)
class Rule:
    rule_id: str
    rule_version: str
    language: str
    description: str
    library: str | None
    api: str | None
    algorithm: str
    primitive: str
    operation: str
    confidence: float
    match_type: str
    value_from: str | None = None
    value_map: tuple[tuple[str, dict], ...] = ()
    qualified_names: tuple[tuple[str, dict], ...] = ()
    literal_args: tuple[dict, ...] = ()
    operation_by_parent: dict = field(default_factory=dict)
    key_size: dict | None = None
    pattern: re.Pattern | None = None
    value_group: str | None = None
    file_requires: re.Pattern | None = None
    key_size_group: str | None = None
    key_size_after: tuple[int, re.Pattern] | None = None
    refine: tuple[tuple[int, re.Pattern, str], ...] = ()
    sibling_resolution: dict | None = None
    mentions: tuple[tuple[re.Pattern, str, str], ...] = ()
    file_pattern: re.Pattern | None = None     # directive rules: which relative paths the rule applies to
    key_pattern: re.Pattern | None = None      # structured rules: which YAML/JSON keys are inspected
    split: re.Pattern | None = None            # directive/structured: how a value is split into tokens
    skip_prefixes: tuple[str, ...] = ()        # tokens starting with these are ignored (e.g. '!' = disabled cipher)
    emit: str | None = None                    # pem_certificate rules: public_key | sha1_signature


def _check_entry(where: str, e: dict, rule_prim: str) -> None:
    extra = set(e) - _ENTRY
    if extra:
        raise RuleError(f"{where}: unknown value_map keys {sorted(extra)}")
    prim = e.get("primitive", rule_prim)
    if prim not in PRIMITIVES:
        raise RuleError(f"{where}: bad primitive {prim!r}")
    if "operation" in e and not valid_operation(prim, e["operation"]):
        raise RuleError(f"{where}: operation {e['operation']!r} invalid for primitive {prim}")
    if "confidence" in e and not (0 < float(e["confidence"]) <= 1):
        raise RuleError(f"{where}: bad confidence")


def _compile(pat: str, flags: list[str], where: str) -> re.Pattern:
    f = 0
    for name in flags:
        if name not in FLAGS:
            raise RuleError(f"{where}: unknown regex flag {name}")
        f |= FLAGS[name]
    try:
        return re.compile(pat, f)
    except re.error as e:
        raise RuleError(f"{where}: invalid regex: {e}")


def parse_rule(doc: Any, path: Path) -> Rule:
    where = path.name
    if not isinstance(doc, dict):
        raise RuleError(f"{where}: rule file must be a mapping")
    missing = _TOP - set(doc)
    extra = set(doc) - _TOP
    if missing or extra:
        raise RuleError(f"{where}: missing keys {sorted(missing)}, unknown keys {sorted(extra)}")
    if doc["rule_id"] != path.stem:
        raise RuleError(f"{where}: rule_id {doc['rule_id']!r} must equal the file name")
    if doc["language"] not in LANGUAGES or path.parent.name != doc["language"]:
        raise RuleError(f"{where}: language must be one of {LANGUAGES} and match its directory")
    if not isinstance(doc["rule_version"], str) or not SEMVER.match(doc["rule_version"]):
        raise RuleError(f"{where}: rule_version must be semver 'X.Y.Z' (quoted string)")
    if doc["primitive"] not in PRIMITIVES:
        raise RuleError(f"{where}: bad primitive {doc['primitive']!r}")
    if not valid_operation(doc["primitive"], doc["operation"]):
        raise RuleError(f"{where}: operation {doc['operation']!r} invalid for {doc['primitive']}")
    conf = float(doc["confidence"])
    if not 0 < conf <= 1:
        raise RuleError(f"{where}: confidence must be in (0,1]")
    m = doc["match"]
    if not isinstance(m, dict) or m.get("type") not in ("python_call", "regex", "comment_mention", "directive", "structured", "pem_certificate"):
        raise RuleError(f"{where}: match.type must be python_call | regex | comment_mention | directive | structured | pem_certificate")
    extra = set(m) - _MATCH
    if extra:
        raise RuleError(f"{where}: unknown match keys {sorted(extra)}")
    kw: dict[str, Any] = {}
    vm_raw = m.get("value_map") or {}
    for k, e in vm_raw.items():
        _check_entry(f"{where}: value_map[{k!r}]", e or {}, doc["primitive"])
    vm = tuple((_norm_key(k), dict(e or {})) for k, e in vm_raw.items())
    kw["value_map"] = vm
    mt = m["type"]
    if mt == "python_call":
        if doc["language"] != "python":
            raise RuleError(f"{where}: python_call rules must be language python")
        vf = m.get("value_from")
        if vf not in (None, "fqn", "literal"):
            raise RuleError(f"{where}: value_from must be fqn or literal")
        kw["value_from"] = vf
        if vf == "fqn":
            if not vm:
                raise RuleError(f"{where}: value_from fqn needs value_map")
            kw["qualified_names"] = tuple((k, e) for k, e in vm)
        else:
            names = m.get("qualified_names") or []
            if not names:
                raise RuleError(f"{where}: python_call needs qualified_names")
            kw["qualified_names"] = tuple((_norm_key(n), {}) for n in names)
        if vf == "literal":
            la = m.get("literal_args") or []
            if not la or not vm:
                raise RuleError(f"{where}: literal rules need literal_args and value_map")
            kw["literal_args"] = tuple(dict(a) for a in la)
        kw["operation_by_parent"] = dict(m.get("operation_by_parent") or {})
        for op in kw["operation_by_parent"].values():
            if not valid_operation(doc["primitive"], op):
                raise RuleError(f"{where}: bad operation_by_parent value {op!r}")
        kw["key_size"] = m.get("key_size")
    elif mt == "regex":
        if doc["language"] not in ("java", "js"):
            raise RuleError(f"{where}: regex rules must be language java or js")
        pat = _compile(m.get("pattern", ""), m.get("flags") or [], where)
        kw["pattern"] = pat
        vg = m.get("value_group")
        if vg:
            if vg not in pat.groupindex:
                raise RuleError(f"{where}: value_group {vg!r} not in pattern")
            if not vm:
                raise RuleError(f"{where}: value_group needs value_map")
        kw["value_group"] = vg
        if m.get("file_requires"):
            kw["file_requires"] = _compile(m["file_requires"], [], where)
        ksg = m.get("key_size_group")
        if ksg and ksg not in pat.groupindex:
            raise RuleError(f"{where}: key_size_group {ksg!r} not in pattern")
        kw["key_size_group"] = ksg
        if m.get("key_size_after"):
            ka = m["key_size_after"]
            p = _compile(ka["pattern"], [], where)
            if "bits" not in p.groupindex:
                raise RuleError(f"{where}: key_size_after pattern needs a (?P<bits>) group")
            kw["key_size_after"] = (int(ka.get("window", 400)), p)
        ref = []
        for r in m.get("refine") or []:
            if not valid_operation(doc["primitive"], r["operation"]):
                raise RuleError(f"{where}: bad refine operation {r['operation']!r}")
            ref.append((int(r.get("window", 400)), _compile(r["pattern"], [], where), r["operation"]))
        kw["refine"] = tuple(ref)
    elif mt in ("directive", "structured", "pem_certificate"):
        if doc["language"] != "config":
            raise RuleError(f"{where}: {mt} rules must be language config")
        if mt == "pem_certificate":
            if m.get("emit") not in ("public_key", "sha1_signature"):
                raise RuleError(f"{where}: pem_certificate needs emit: public_key | sha1_signature")
            kw["emit"] = m["emit"]
        else:
            if not vm:
                raise RuleError(f"{where}: {mt} rules need a value_map")
            kw["split"] = _compile(m.get("split") or r"[\s:,;]+", [], where)
            kw["skip_prefixes"] = tuple(m.get("skip_prefixes") or ())
        if mt == "directive":
            pat = _compile(m.get("pattern", ""), m.get("flags") or [], where)
            if "value" not in pat.groupindex:
                raise RuleError(f"{where}: directive pattern needs a (?P<value>...) group")
            if not m.get("file_pattern"):
                raise RuleError(f"{where}: directive rules need file_pattern")
            kw["pattern"] = pat
            kw["file_pattern"] = _compile(m["file_pattern"], [], where)
        if mt == "structured":
            if not m.get("key_pattern"):
                raise RuleError(f"{where}: structured rules need key_pattern")
            kw["key_pattern"] = _compile(m["key_pattern"], [], where)
    else:  # comment_mention
        if doc["language"] != "generic":
            raise RuleError(f"{where}: comment_mention rules must be language generic")
        ms = []
        for item in m.get("mentions") or []:
            if item["primitive"] not in PRIMITIVES:
                raise RuleError(f"{where}: bad mention primitive")
            ms.append((_compile(item["pattern"], item.get("flags") or [], where), item["algorithm"], item["primitive"]))
        if not ms:
            raise RuleError(f"{where}: comment_mention needs mentions")
        kw["mentions"] = tuple(ms)
    sr = m.get("sibling_resolution")
    if sr:
        if set(sr) != {"from", "map", "confidence"}:
            raise RuleError(f"{where}: sibling_resolution needs from/map/confidence")
        kw["sibling_resolution"] = dict(sr)
    return Rule(rule_id=doc["rule_id"], rule_version=doc["rule_version"], language=doc["language"],
                description=str(doc["description"]), library=doc["library"], api=doc["api"],
                algorithm=doc["algorithm"], primitive=doc["primitive"], operation=doc["operation"],
                confidence=conf, match_type=mt, **kw)


@dataclass
class RuleSet:
    rules: list[Rule]

    def for_language(self, language: str) -> list[Rule]:
        return [r for r in self.rules if r.language == language]

    def versions(self) -> dict[str, str]:
        return {r.rule_id: r.rule_version for r in self.rules}


def load_rules(rules_dir: Path | None = None) -> RuleSet:
    base = rules_dir or RULES_DIR
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in sorted(base.glob("*/*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise RuleError(f"{path.name}: invalid YAML: {e}")
        r = parse_rule(doc, path)
        if r.rule_id in seen:
            raise RuleError(f"duplicate rule_id {r.rule_id}")
        seen.add(r.rule_id)
        rules.append(r)
    if not rules:
        raise RuleError(f"no rules found in {base}")
    rules.sort(key=lambda r: (r.language, r.rule_id))
    return RuleSet(rules)
