import pytest

from qmc_scanner import load_rules
from tests import corpus
from tests.conftest import code_findings, sig

ALL_CASES = ([(f"py_{c[0]}", c[1], c[2], c[3]) for c in corpus.PY] +
             [(f"java_{c[0]}", "T.java", c[1], c[2]) for c in corpus.JAVA] +
             [(f"js_{c[0]}", c[1], c[2], c[3]) for c in corpus.JS])


@pytest.mark.parametrize("cid,fname,src,expected", ALL_CASES, ids=[c[0] for c in ALL_CASES])
def test_positive_case_exact(scan, cid, fname, src, expected):
    res = scan({fname: src})
    got = sorted(map(sig, code_findings(res)), key=str)
    assert got == sorted(expected, key=str), f"\n got: {got}\n want: {sorted(expected, key=str)}"
    for f in code_findings(res):                       # evidence is the real API text, with file+line
        assert f["evidence"] and f["line_start"] >= 1 and f["file"] == fname


def test_every_shipped_rule_has_a_positive_test(scan):
    hit: set[str] = set()
    for cid, fname, src, _ in ALL_CASES:
        hit |= {f["rule_id"] for f in scan({fname: src}).findings}
    hit |= {f['rule_id'] for f in scan({'t.py': '# TODO: replace with RSA\n'}).findings}
    shipped = {r.rule_id for r in load_rules().rules}
    assert shipped - hit == set(), f"rules without a positive test: {sorted(shipped - hit)}"


@pytest.mark.parametrize("src,alg,level,ks", [
    ("rsa.generate_private_key(65537, 2048)", "RSA", "high", 2048),
])
def test_high_confidence_for_resolved_api_call(scan, src, alg, level, ks):
    res = scan({"t.py": "from cryptography.hazmat.primitives.asymmetric import rsa\nk = " + src + "\n"})
    f = code_findings(res)[0]
    assert (f["algorithm"], f["confidence_level"], f["metadata"]["key_size"]) == (alg, level, ks) and f["confidence"] == 0.97


def test_pqc_findings_flagged_already_pqc_and_not_vulnerable(scan):
    res = scan({"t.py": "import oqs\nk = oqs.KeyEncapsulation('ML-KEM-768')\n"})
    f = res.findings[0]
    assert f["already_pqc"] is True and f["quantum_vulnerable"] is False and f["primitive"] == "pqc-kem"


def test_quantum_vulnerable_only_for_public_key(scan):
    res = scan({"t.py": "import hashlib, hmac\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n"
                        "a = hashlib.sha256(b)\nb = hmac.new(k, m, 'sha256')\nc = rsa.generate_private_key(65537, 2048)\n"})
    by_alg = {f["algorithm"]: f["quantum_vulnerable"] for f in res.findings}
    assert by_alg == {"SHA-256": False, "HMAC": False, "RSA": True}
