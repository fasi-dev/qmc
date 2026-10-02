"""False-positive defenses: comments, strings, docstrings, shadowing, missing imports, regex literals."""
import pytest

from tests.conftest import code_findings

JH = "import java.security.*;\nimport javax.crypto.*;\n"
RSA_IMPORT = "from cryptography.hazmat.primitives.asymmetric import rsa\n"
CALL = "rsa.generate_private_key(public_exponent=65537, key_size=2048)"

PY_NEG = {
    "call_in_string": RSA_IMPORT + f"s = \"{CALL}\"\n",
    "call_in_triple_quote_docstring": RSA_IMPORT + f'def f():\n    """Example: {CALL}"""\n',
    "call_in_comment": RSA_IMPORT + f"# k = {CALL}\n",
    "unimported_local_shadow": "class rsa:\n    @staticmethod\n    def generate_private_key(**k): ...\nrsa.generate_private_key()\n",
    "unrelated_module_same_name": "import rsa\nrsa.generate_private_key()\n",   # python-rsa has no such API
    "reference_not_call": "import hashlib\nf = hashlib.sha1\n",
    "md5_not_in_catalog": "import hashlib\nhashlib.md5(b'x')\n",
    "variable_algorithm_not_guessed": "import jwt\nalg = 'ES256'\njwt.encode(p, k, algorithm=alg)\n",
    "jwt_default_algorithm_not_guessed": "import jwt\njwt.encode(p, k)\n",
    "oqs_unknown_name_not_guessed": "import oqs\noqs.KeyEncapsulation(name)\n",
    "no_imports_no_resolution": "k = rsa.generate_private_key(65537, 2048)\nh = hashlib.sha1(b)\n",
    "hash_name_in_dict_key": "import hashlib\nd = {'sha1': 1}\n",
    "generic_words": "# we use secure crypto with a strong cipher\nx = 1\n",
}


@pytest.mark.parametrize("name", list(PY_NEG))
def test_python_negative(scan, name):
    res = scan({"t.py": PY_NEG[name]})
    assert code_findings(res) == [], [f["evidence"] for f in code_findings(res)]
    assert all(f["confidence_level"] == "low" for f in res.findings)     # only comment mentions may remain


JAVA_NEG = {
    "api_in_string": JH + 'System.out.println("KeyAgreement.getInstance(\\"ECDH\\")");\n',
    "api_in_line_comment": JH + '// KeyAgreement.getInstance("ECDH");\n',
    "api_in_block_comment": JH + '/* Signature.getInstance("SHA256withRSA");\n   more */\n',
    "api_in_javadoc": JH + '/** Uses {@code MessageDigest.getInstance("SHA-1")}. */\nclass A {}\n',
    "api_in_text_block": JH + 'String s = """\n  KeyAgreement.getInstance("ECDH")\n""";\n',
    "unterminated_block_comment_hides_rest": JH + '/* never closed\nKeyAgreement.getInstance("ECDH");\n',
    "commented_out_import_and_no_crypto_import": '// import java.security.*;\nclass A { void f(){ KeyAgreement.getInstance("ECDH"); } }\n',
    "other_library_signature_class": "import com.acme.Signature;\nclass A { void f(){ Signature.getInstance(\"SHA256withECDSA\"); } }\n",
    "md5_not_in_catalog": JH + 'MessageDigest.getInstance("MD5");\n',
    "bc_class_without_bc_import": "class A { void f(){ var a = new ECDSASigner(); } }\n",
    "algorithm_from_variable_not_guessed": JH + 'String alg = "ECDH";\nKeyAgreement.getInstance(alg);\n',
}


@pytest.mark.parametrize("name", list(JAVA_NEG))
def test_java_negative(scan, name):
    res = scan({"A.java": JAVA_NEG[name]})
    assert code_findings(res) == [], [f["evidence"] for f in code_findings(res)]


def test_java_slashes_in_string_do_not_hide_real_call(scan):
    src = JH + 'String u = "http://x"; KeyAgreement.getInstance("ECDH");\nchar q = \'"\'; Mac.getInstance("HmacSHA256");\n'
    res = scan({"A.java": src})
    assert sorted(f["algorithm"] for f in code_findings(res)) == ["ECDH", "HMAC"]


JS_H = "const crypto = require('crypto');\n"
JS_NEG = {
    "api_in_string": JS_H + "const doc = \"use crypto.createHash('sha1') carefully\";\n",
    "api_in_template_literal": JS_H + "const doc = `hash with createHash('sha1')`;\n",
    "api_in_line_comment": JS_H + "// crypto.createHash('sha1');\n",
    "api_in_block_comment": JS_H + "/* crypto.createECDH('secp256k1') */\n",
    "api_in_regex_literal": JS_H + "const re = /createHash('sha1')/;\n",
    "no_crypto_import_user_function": "function createHash(x){return x}\ncreateHash('sha1');\n",
    "md5_not_in_catalog": JS_H + "crypto.createHash('md5');\n",
    "webcrypto_name_without_subtle": "const o = { name: \"ECDSA\" };\n",
    "jose_alg_without_jose_import": "const header = { alg: 'ES256' };\n",
    "algorithm_variable_not_guessed": JS_H + "crypto.createHash(algo);\n",
    "hs256_is_not_public_key": "import jwt from 'jsonwebtoken';\njwt.sign(p, k, { algorithm: 'HS256' });\n",
}


@pytest.mark.parametrize("name", list(JS_NEG))
def test_js_negative(scan, name):
    res = scan({"t.js": JS_NEG[name]})
    assert code_findings(res) == [], [f["evidence"] for f in code_findings(res)]


def test_js_division_is_not_mistaken_for_regex(scan):
    res = scan({"t.js": JS_H + "const x = a / b; const y = c / d;\ncrypto.createHash('sha1');\n"})
    assert [f["algorithm"] for f in code_findings(res)] == ["SHA-1"]


def test_js_real_regex_literal_followed_by_real_call(scan):
    res = scan({"t.js": JS_H + "const ok = /^a\\/b$/.test(s);\ncrypto.createHash('sha1');\n"})
    assert [f["algorithm"] for f in code_findings(res)] == ["SHA-1"]


def test_minified_js_skipped_and_reported(scan):
    res = scan({"min.js": "var a=" + "x+" * 6000 + "1;crypto.createHash('sha1');\n"})
    assert res.findings == [] and res.files_skipped == [{"file": "min.js", "reason": "skipped_minified"}]


def test_python_syntax_error_reported_not_crashing(scan):
    res = scan({"old.py": "print 'hello'\nimport hashlib\nhashlib.sha1(b)\n", "ok.py": "import hashlib\nhashlib.sha1(b)\n"})
    assert res.files_skipped == [{"file": "old.py", "reason": "parse_error"}]
    assert [f["file"] for f in code_findings(res)] == ["ok.py"]


def test_python_parser_bomb_does_not_crash(scan):
    res = scan({"bomb.py": "x = " + "(" * 20000 + "1" + ")" * 20000 + "\n"})
    assert res.status == "complete"
