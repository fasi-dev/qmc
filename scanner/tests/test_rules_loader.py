import shutil
from pathlib import Path

import pytest
import yaml

from qmc_scanner import RuleError, load_rules
from qmc_scanner.rules import RULES_DIR, SEMVER

BASE = {"rule_id": "PY-X-001", "rule_version": "1.0.0", "language": "python", "description": "d", "library": "x", "api": "x.y",
        "algorithm": "RSA", "primitive": "public-key", "operation": "key_generation", "confidence": 0.9,
        "match": {"type": "python_call", "qualified_names": ["x.y"]}}


def rules_dir(tmp_path, doc, name=None, lang="python"):
    d = tmp_path / "rules" / lang
    d.mkdir(parents=True)
    (d / f"{name or doc.get('rule_id', 'PY-X-001')}.yaml").write_text(yaml.safe_dump(doc))
    return tmp_path / "rules"


def mod(**kw):
    d = {**BASE, "match": dict(BASE["match"])}
    for k, v in kw.items():
        if k.startswith("match_"):
            d["match"][k[6:]] = v
        else:
            d[k] = v
    return d


def test_minimal_valid_rule_loads(tmp_path):
    assert [r.rule_id for r in load_rules(rules_dir(tmp_path, BASE)).rules] == ["PY-X-001"]


@pytest.mark.parametrize("label,doc,kw", [
    ("missing key", {k: v for k, v in BASE.items() if k != "api"}, {}),
    ("unknown top key", mod(extra=1), {}),
    ("unknown match key", mod(match_bogus=1), {}),
    ("id != filename", BASE, {"name": "PY-OTHER-001"}),
    ("language != dir", mod(language="java"), {}),
    ("unquoted float version", mod(rule_version=1.0), {}),
    ("non-semver version", mod(rule_version="1.0"), {}),
    ("bad primitive", mod(primitive="quantum"), {}),
    ("operation invalid for primitive", mod(primitive="hash", operation="signature"), {}),
    ("confidence zero", mod(confidence=0), {}),
    ("confidence above one", mod(confidence=1.2), {}),
    ("bad match type", mod(match_type="magic"), {}),
    ("python_call without names", mod(match_qualified_names=[]), {}),
    ("fqn without value_map", mod(match_value_from="fqn", match_qualified_names=None), {}),
    ("bad value_map entry key", mod(match_value_from="fqn", match_value_map={"a.b": {"bogus": 1}}), {}),
    ("bad value_map operation", mod(match_value_from="fqn", match_value_map={"a.b": {"operation": "hashing"}}), {}),
    ("literal without literal_args", mod(match_value_from="literal", match_value_map={"x": {}}), {}),
    ("bad operation_by_parent", mod(match_operation_by_parent={"sign": "hashing"}), {}),
])
def test_invalid_rules_are_rejected_loudly(tmp_path, label, doc, kw):
    with pytest.raises(RuleError):
        load_rules(rules_dir(tmp_path, doc, name=kw.get("name")))


@pytest.mark.parametrize("match", [
    {"type": "regex", "pattern": "(unclosed"},
    {"type": "regex", "pattern": "a", "flags": ["BOGUS"]},
    {"type": "regex", "pattern": "a", "value_group": "nope", "value_map": {"x": {}}},
    {"type": "regex", "pattern": "(?P<a>x)", "value_group": "a"},
    {"type": "regex", "pattern": "a", "key_size_group": "nope"},
    {"type": "regex", "pattern": "a", "key_size_after": {"pattern": "\\d+"}},
    {"type": "regex", "pattern": "a", "refine": [{"pattern": "x", "operation": "hashing"}]},
    {"type": "regex", "pattern": "a", "sibling_resolution": {"from": "EC"}},
])
def test_invalid_regex_rules_rejected(tmp_path, match):
    doc = mod(language="java", match=match)
    with pytest.raises(RuleError):
        load_rules(rules_dir(tmp_path, doc, lang="java"))


def test_python_call_rule_in_wrong_language_rejected(tmp_path):
    with pytest.raises(RuleError):
        load_rules(rules_dir(tmp_path, mod(language="java"), lang="java"))


def test_empty_rules_dir_and_bad_yaml_rejected(tmp_path):
    (tmp_path / "r" / "python").mkdir(parents=True)
    with pytest.raises(RuleError):
        load_rules(tmp_path / "r")
    (tmp_path / "r" / "python" / "PY-X-001.yaml").write_text("a: [unclosed")
    with pytest.raises(RuleError):
        load_rules(tmp_path / "r")


def test_shipped_rules_are_consistent():
    rs = load_rules()
    assert len(rs.rules) >= 55
    ids = [r.rule_id for r in rs.rules]
    assert len(ids) == len(set(ids))
    for r in rs.rules:
        assert SEMVER.match(r.rule_version) and r.rule_id.upper() == r.rule_id
        assert (RULES_DIR / r.language / f"{r.rule_id}.yaml").is_file()
    assert {r.language for r in rs.rules} == {"python", "java", "js", "generic"}


def test_changing_a_rule_version_is_reflected_in_findings(tmp_path):
    from qmc_scanner import scan_tree
    d = tmp_path / "rules"; shutil.copytree(RULES_DIR, d)
    p = d / "python" / "PY-HASHLIB-001.yaml"
    p.write_text(p.read_text().replace("rule_version: 1.0.0", "rule_version: 1.1.0"))
    t = tmp_path / "t"; t.mkdir(); (t / "a.py").write_text("import hashlib\nhashlib.sha1(b)\n")
    f = scan_tree(t, rules=load_rules(d)).findings[0]
    assert (f["rule_id"], f["rule_version"]) == ("PY-HASHLIB-001", "1.1.0")
