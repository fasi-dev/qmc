"""05 section 5: comment-only matches can never exceed Low; docs are non-executable; no generic-word findings."""
import pytest

from qmc_scanner import validate_finding
from tests.conftest import code_findings

COMMENTS = {
    "t.py": "# TODO: replace with RSA\n",
    "A.java": "// TODO: replace with RSA\nclass A {}\n",
    "t.js": "// TODO: replace with RSA\n",
    "t.ts": "/* TODO: replace with RSA */\n",
    "README.md": "# Notes\n\n# TODO: consider RSA\n",
    "NOTES.txt": "We might use RSA here.\n",
    "guide.rst": "RSA is mentioned in docs only.\n",
}


@pytest.mark.parametrize("fname", list(COMMENTS))
def test_comment_or_doc_mention_is_low_and_not_vulnerable(scan, fname):
    res = scan({fname: COMMENTS[fname]})
    (f,) = res.findings
    assert (f["algorithm"], f["confidence_level"], f["rule_id"]) == ("RSA", "low", "GEN-COMMENT-001")
    assert f["confidence"] < 0.50 and f["metadata"]["comment_only"] is True
    assert f["quantum_vulnerable"] is False and f["already_pqc"] is False
    assert f["operation"] == "unspecified" and f["library"] is None and f["api"] is None and f["context"] == "unknown"
    validate_finding(f)


def test_comment_finding_points_at_the_comment_line(scan):
    res = scan({"README.md": "# Acme\n\n# TODO: consider RSA\n"})
    assert res.findings[0]["line_start"] == 3 and "TODO: consider RSA" in res.findings[0]["evidence"]


def test_comment_next_to_real_call_does_not_raise_or_lower_the_real_one(scan):
    src = "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(65537, 2048)  # RSA key\n"
    res = scan({"t.py": src})
    by = {f["metadata"]["comment_only"]: f for f in res.findings}
    assert by[False]["confidence_level"] == "high" and by[True]["confidence_level"] == "low"


@pytest.mark.parametrize("text", ["# secure crypto cipher", "# AESTHETIC", "# ecdsa-like", "# the word DSAX", "# trsa", "# hash"])
def test_generic_words_and_substrings_produce_no_finding(scan, text):
    assert scan({"t.py": text + "\n"}).findings == []


def test_ecdsa_comment_is_not_also_a_dsa_mention(scan):
    res = scan({"t.py": "# uses ECDSA\n"})
    assert [f["algorithm"] for f in res.findings] == ["ECDSA"]


def test_pqc_mention_in_comment_is_not_already_pqc(scan):
    f = scan({"t.py": "# migrate to ML-KEM later\n"}).findings[0]
    assert f["already_pqc"] is False and f["confidence_level"] == "low"


def test_docstring_is_not_scanned(scan):
    assert scan({"t.py": '"""This module uses RSA and ECDSA."""\n'}).findings == []


def test_docs_never_produce_executable_findings(scan):
    res = scan({"README.md": "```python\nrsa.generate_private_key(65537, 2048)\n```\n"})
    assert all(f["metadata"]["comment_only"] and f["confidence_level"] == "low" for f in res.findings)


def test_confidence_levels_follow_spec_thresholds():
    from qmc_scanner.schema import confidence_level as cl
    assert [cl(x) for x in (0.0, 0.49, 0.50, 0.89, 0.90, 1.0)] == ["low", "low", "medium", "medium", "high", "high"]


def test_ambiguous_findings_are_medium_not_high(scan):
    res = scan({"t.js": "const crypto = require('crypto');\ncrypto.createSign('sha256');\ncrypto.generateKeyPairSync('ec');\n"})
    assert {f["confidence_level"] for f in code_findings(res)} == {"medium"}


def test_engine_caps_comment_only_even_if_a_rule_author_sets_high_confidence(tmp_path):
    """Hard rule (05 section 5) is enforced by the engine, not by trusting rule files."""
    import shutil
    from qmc_scanner import load_rules, scan_tree
    from qmc_scanner.rules import RULES_DIR
    rules_dir = tmp_path / "rules"
    shutil.copytree(RULES_DIR, rules_dir)
    f = rules_dir / "generic" / "GEN-COMMENT-001.yaml"
    f.write_text(f.read_text().replace("confidence: 0.3", "confidence: 0.99"))
    assert "0.99" in f.read_text()
    tree = tmp_path / "t"; tree.mkdir(); (tree / "a.py").write_text("# TODO: RSA\n")
    res = scan_tree(tree, rules=load_rules(rules_dir))
    assert res.findings[0]["confidence"] == 0.45 and res.findings[0]["confidence_level"] == "low"
