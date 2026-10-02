import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from qmc_scanner import scan_tree, validate_finding
from qmc_scanner.engine import is_test_path
from qmc_scanner.schema import FINDING_KEYS, METADATA_KEYS, evidence_hash
from tests.conftest import code_findings, write_tree

RSA = "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(65537, 2048)\n"
HASH = "import hashlib\nh = hashlib.sha1(b'x')\n"
FILES = {"a/z.py": RSA, "a/b.py": HASH, "m.js": "const crypto = require('crypto');\ncrypto.createHash('sha1');\n",
         "T.java": "import java.security.*;\nclass T{void f(){KeyAgreement.getInstance(\"ECDH\");}}\n", "README.md": "# TODO: RSA\n"}


# ---------------------------------------------------------------- schema exactness (05 section 4)
def test_findings_match_schema_exactly(scan):
    res = scan(FILES)
    assert res.findings
    for f in res.findings:
        assert tuple(f) == FINDING_KEYS and tuple(f["metadata"]) == METADATA_KEYS
        validate_finding(f)
        assert re.fullmatch(r"CRYPTO-\d{3,}", f["id"]) and f["scan_id"] == "11111111-1111-4111-8111-111111111111"
        assert f["engine_version"] == "0.1.0" and re.fullmatch(r"\d+\.\d+\.\d+", f["rule_version"])
        assert isinstance(f["line_start"], int) and isinstance(f["confidence"], float) and isinstance(f["quantum_vulnerable"], bool)
        assert f["metadata"]["in_dead_code"] is False
    json.dumps(res.to_dict())   # fully JSON-serialisable


def test_schema_example_from_spec_is_reproducible(scan):
    """05 section 4 example: RSA key generation, cryptography lib, auth context, 2048 bits, confidence 0.97."""
    res = scan({"src/auth.py": "from cryptography.hazmat.primitives.asymmetric import rsa\n\n\ndef make_key():\n    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"},
               services=[{"service": "payment-api", "root": ""}])
    f = code_findings(res)[0]
    assert (f["rule_id"], f["file"], f["algorithm"], f["primitive"], f["operation"], f["library"], f["api"], f["context"], f["service"],
            f["confidence"], f["confidence_level"], f["quantum_vulnerable"], f["already_pqc"]) == (
        "PY-CRYPTOGRAPHY-RSA-001", "src/auth.py", "RSA", "public-key", "key_generation", "cryptography", "rsa.generate_private_key",
        "authentication", "payment-api", 0.97, "high", True, False)
    assert f["evidence"] == "rsa.generate_private_key(public_exponent=65537, key_size=2048)"
    assert f["metadata"] == {"key_size": 2048, "comment_only": False, "in_dead_code": False, "test_path": False}
    assert (f["line_start"], f["line_end"]) == (5, 5)


def test_ids_sequential_and_sorted_by_file_then_line(scan):
    res = scan(FILES)
    assert [f["id"] for f in res.findings] == [f"CRYPTO-{i:03d}" for i in range(1, len(res.findings) + 1)]
    keys = [(f["file"], f["line_start"]) for f in res.findings]
    assert keys == sorted(keys)


def test_multiline_call_has_line_range_and_normalised_evidence(scan):
    src = "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(\n    public_exponent=65537,\n    key_size=3072,\n)\n"
    f = code_findings(scan({"t.py": src}))[0]
    assert (f["line_start"], f["line_end"]) == (2, 5) and "\n" not in f["evidence"] and f["metadata"]["key_size"] == 3072


def test_unicode_before_call_keeps_evidence_exact(scan):
    src = "from cryptography.hazmat.primitives.asymmetric import rsa\ns = 'héllo wörld ✓'; k = rsa.generate_private_key(65537, 2048)\n"
    assert code_findings(scan({"t.py": src}))[0]["evidence"] == "rsa.generate_private_key(65537, 2048)"


def test_evidence_hash_helper_is_stable():
    assert evidence_hash("x") == evidence_hash("x") and len(evidence_hash("x")) == 64


# ---------------------------------------------------------------- determinism
def test_identical_input_identical_output(scan, tmp_path):
    a = json.dumps(scan(FILES).to_dict(), sort_keys=False)
    b = json.dumps(scan(FILES).to_dict(), sort_keys=False)
    assert a == b


def test_file_creation_order_and_mtime_do_not_matter(tmp_path):
    t1, t2 = tmp_path / "one", tmp_path / "two"
    write_tree(t1, dict(FILES))
    write_tree(t2, dict(reversed(list(FILES.items()))))
    for i, p in enumerate(sorted(t2.rglob("*"))):
        os.utime(p, (1_000_000 + i * 977, 1_000_000 + i * 977))
    r1 = scan_tree(t1, scan_id="x").to_dict()
    r2 = scan_tree(t2, scan_id="x").to_dict()
    assert r1 == r2


@pytest.mark.parametrize("seed", ["0", "1", "424242"])
def test_output_independent_of_python_hash_seed(tmp_path, seed):
    root = write_tree(tmp_path / "t", dict(FILES))
    base = subprocess.run([sys.executable, "-m", "qmc_scanner", str(root)], capture_output=True, text=True,
                          env={**os.environ, "PYTHONHASHSEED": "0"}, check=True).stdout
    other = subprocess.run([sys.executable, "-m", "qmc_scanner", str(root)], capture_output=True, text=True,
                           env={**os.environ, "PYTHONHASHSEED": seed}, check=True).stdout
    assert base == other and json.loads(base)["findings"]


def test_no_timestamps_or_random_values_in_findings(scan):
    blob = json.dumps(scan(FILES).to_dict())
    assert not re.search(r"\d{4}-\d{2}-\d{2}T", blob)


# ---------------------------------------------------------------- service / test path metadata
def test_service_from_nearest_service_yaml_else_repo_name(scan):
    services = [{"service": "root-svc", "root": ""}, {"service": "settle", "root": "svc/settle"}]
    res = scan({"svc/settle/a.py": HASH, "other/b.py": HASH, "svc/settlement/c.py": HASH}, services=services, repo_name="acme")
    assert {f["file"]: f["service"] for f in res.findings} == {"svc/settle/a.py": "settle", "other/b.py": "root-svc", "svc/settlement/c.py": "root-svc"}
    res = scan({"a.py": HASH}, repo_name="acme")
    assert res.findings[0]["service"] == "acme"


@pytest.mark.parametrize("path,expected", [
    ("tests/test_x.py", True), ("test_utils.py", True), ("src/a.test.js", True), ("src/test/java/A.java", True),
    ("scripts/gen_test_keys.py", True), ("__tests__/a.js", True), ("src/auth.py", False), ("src/contest.py", False),
    ("src/latest.py", False), ("src/attestation.py", False), ("src/testing_utils.py", False)])
def test_test_path_flag(path, expected):
    assert is_test_path(path) is expected


def test_test_path_recorded_in_metadata_not_filtered(scan):
    res = scan({"tests/test_a.py": HASH})
    assert len(res.findings) == 1 and res.findings[0]["metadata"]["test_path"] is True


# ---------------------------------------------------------------- walking
def test_vendor_dirs_skipped_and_reported(scan):
    res = scan({"node_modules/x/a.js": "const crypto=require('crypto');crypto.createHash('sha1')", ".git/c.py": HASH, "src/ok.py": HASH})
    assert [f["file"] for f in res.findings] == ["src/ok.py"]
    assert res.skipped_directories == [".git", "node_modules"]


def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside"; outside.mkdir(); (outside / "secret.py").write_text(HASH)
    root = write_tree(tmp_path / "t", {"ok.py": "x = 1\n"})
    os.symlink(outside, root / "linkdir")
    os.symlink(outside / "secret.py", root / "linkfile.py")
    res = scan_tree(root)
    assert res.findings == []


def test_language_counts_and_unsupported_files_ignored(scan):
    res = scan({**FILES, "data.bin": b"\x00\x01", "x.yaml": "algorithm: RSA\n", "Dockerfile": "FROM x\n"})
    assert res.files_scanned == {"doc": 1, "java": 1, "js": 1, "python": 2}


def test_timeout_returns_partial(scan):
    res = scan(FILES, deadline_seconds=-1)
    assert res.status == "partial" and res.findings == []


def test_oversized_file_skipped(scan):
    res = scan({"big.py": "x = 1\n" * 100}, max_file_bytes=50)
    assert res.files_skipped == [{"file": "big.py", "reason": "too_large"}]


# ---------------------------------------------------------------- safety: never executes / imports scanned code
def test_scanning_never_executes_or_imports_repo_code(tmp_path):
    marker = tmp_path / "PWNED"
    evil = (f"import pathlib\npathlib.Path({str(marker)!r}).write_text('x')\n"
            "import hashlib\nhashlib.sha1(b'x')\n")
    root = write_tree(tmp_path / "t", {"evil.py": evil, "setup.py": evil, "conftest.py": evil, "pkg/__init__.py": evil,
                                       "run.js": f"require('fs').writeFileSync({str(marker)!r}, 'x');\nconst c=require('crypto');c.createHash('sha1');\n",
                                       "E.java": f"import java.security.*;\nclass E {{ static {{ new java.io.File({str(marker)!r}); }} }}\n"})
    before = set(sys.modules)
    res = scan_tree(root)
    assert not marker.exists()
    assert set(sys.modules) == before          # nothing imported
    assert {f["file"] for f in res.findings} >= {"evil.py", "run.js"}   # but it WAS analysed statically


def test_scanner_source_has_no_dynamic_execution():
    src = "\n".join(p.read_text() for p in Path(__file__).parents[1].joinpath("qmc_scanner").glob("*.py"))
    for banned in (r"\beval\(", r"\bexec\(", r"\b__import__\(", r"importlib", r"subprocess", r"os\.system", r"(?<![\w.])compile\("):
        assert not re.search(banned, src), banned


def test_scanner_has_no_ai_or_network_dependencies():
    src = "\n".join(p.read_text() for p in Path(__file__).parents[1].joinpath("qmc_scanner").glob("*.py"))
    for banned in (r"anthropic", r"openai", r"\bhttpx?\b", r"requests", r"urllib", r"socket"):
        assert not re.search(banned, src, re.I), banned


# ---------------------------------------------------------------- evidence can never expose secrets
def test_evidence_guard_redacts_secrets_even_if_source_was_not_prefiltered(scan):
    jwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX3ZhbHVl"
    src = f"import jwt\nt = jwt.encode(p, k, algorithm='ES256', headers={{'kid': '{jwt}'}})\n"
    f = code_findings(scan({"t.py": src}))[0]
    assert jwt not in f["evidence"] and "***REDACTED***" in f["evidence"] and f["algorithm"] == "ECDSA"


def test_evidence_is_length_bounded(scan):
    src = "import hashlib\nh = hashlib.sha1(" + "a" + ",a" * 400 + ")\n"
    f = scan({"t.py": src}).findings[0]
    assert len(f["evidence"]) <= 300


# ---------------------------------------------------------------- performance / DoS resistance
@pytest.mark.parametrize("name,fname,src", [
    ("java anchors without args", "A.java", "import java.security.*;\n" + "KeyAgreement.getInstance(" * 30000),
    ("java long whitespace after anchor", "A.java", "import java.security.*;\n" + ("KeyAgreement" + " " * 900) * 1000),
    ("java escaped quote flood", "A.java", ('\\"' * 4900 + "\n") * 100),
    ("js escaped quote flood", "a.js", ('\\"' * 4900 + "\n") * 100),
    ("js regex start flood", "a.js", ("(/[" * 3300 + "\n") * 100),
    ("js crypto anchors", "a.js", "const crypto=require('crypto');\n" + "createHash(" * 50000),
    ("python wide expression", "a.py", "import hashlib\nx = [" + ",".join(["hashlib.sha1(b)"] * 3000) + "]\n"),
])
def test_pathological_inputs_finish_quickly(scan, name, fname, src):
    t = time.time()
    res = scan({fname: src})
    assert time.time() - t < 15, name
    assert res.status == "complete"


def test_many_files_scale(scan):
    files = {f"pkg{i // 50}/m{i}.py": f"import hashlib\ndef f{i}(b):\n    return hashlib.sha1(b)\n" for i in range(600)}
    t = time.time()
    res = scan(files)
    assert len(res.findings) == 600 and time.time() - t < 20
