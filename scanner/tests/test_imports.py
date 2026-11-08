"""Static import extraction + resolution used by the dependency graph (imports.py). Nothing is imported or executed."""
import json

import pytest

PYC = "cryptography.hazmat.primitives"


def recs(res, file=None):
    return [(r["file"], r["line"], r["spec"], r["targets"], r["resolution"]) for r in res.imports if file is None or r["file"] == file]


def by_file(res, file):
    return [r for r in res.imports if r["file"] == file]


# ---------------------------------------------------------------- Python
def test_python_absolute_relative_and_submodule_imports(scan):
    res = scan({
        "app/__init__.py": "",
        "app/crypto/__init__.py": "",
        "app/crypto/signer.py": f"from {PYC}.asymmetric import ec\ndef sign(d):\n    return d\n",
        "app/api/routes.py": "from app.crypto.signer import sign\nfrom ..crypto import signer\nfrom . import helpers\nimport app.crypto.signer as s\n",
        "app/api/helpers.py": "x = 1\n",
        "app/api/__init__.py": "",
    })
    got = {(r["line"], r["spec"]): (r["targets"], r["resolution"]) for r in by_file(res, "app/api/routes.py")}
    assert got[(1, "app.crypto.signer")] == (["app/crypto/signer.py"], "resolved")
    assert got[(2, "..crypto")] == (["app/crypto/signer.py"], "resolved")         # submodule via relative import
    assert got[(3, ".")] == (["app/api/helpers.py"], "resolved")
    assert got[(4, "app.crypto.signer")] == (["app/crypto/signer.py"], "resolved")


def test_python_crypto_library_imports_are_mapped_to_rule_library_names(scan):
    res = scan({"a.py": f"import hashlib\nfrom {PYC} import hashes\nfrom Crypto.Cipher import AES\nimport os\nimport jwt\n"})
    lib = {r["spec"]: (r["resolution"], r["external"], r["crypto_library"]) for r in res.imports}
    assert lib["hashlib"] == ("external", "hashlib", "hashlib")
    assert lib[PYC] == ("external", "cryptography", "cryptography")
    assert lib["Crypto.Cipher"] == ("external", "Crypto", "pycryptodome")
    assert lib["jwt"] == ("external", "jwt", "pyjwt")
    assert lib["os"] == ("external", "os", None)                                   # external, not crypto


def test_python_ambiguous_names_are_not_confirmed(scan):
    res = scan({"svc_a/utils.py": "", "svc_b/utils.py": "", "tools/run.py": "import utils\nfrom svc_a import utils as u\n"})
    got = {r["line"]: (r["targets"], r["resolution"]) for r in by_file(res, "tools/run.py")}
    assert got[1] == (["svc_a/utils.py", "svc_b/utils.py"], "ambiguous")           # depends on sys.path: inferred
    assert got[2] == (["svc_a/utils.py"], "resolved")


def test_python_bare_name_resolves_only_in_the_same_directory(scan):
    res = scan({"svc/main.py": "import keys\n", "svc/keys.py": "", "other/keys.py": ""})
    (r,) = by_file(res, "svc/main.py")
    assert (r["targets"], r["resolution"]) == (["svc/keys.py"], "resolved")
    res = scan({"svc/main.py": "import keys\n", "other/keys.py": ""})
    (r,) = by_file(res, "svc/main.py")
    assert (r["targets"], r["resolution"]) == (["other/keys.py"], "ambiguous")


def test_python_relative_import_outside_tree_is_unresolved(scan):
    res = scan({"a.py": "from ...nowhere import x\nfrom .missing import y\n"})
    assert [r["resolution"] for r in res.imports] == ["unresolved", "unresolved"]


def test_python_imports_in_strings_and_comments_are_ignored(scan):
    res = scan({"a.py": '# import hashlib\ns = "from cryptography import x"\n"""import jwt"""\n'})
    assert res.imports == []


def test_python_unparsable_file_has_no_imports_and_is_reported(scan):
    res = scan({"bad.py": "print 'py2'\nimport hashlib\n"})
    assert res.imports == [] and res.files_skipped == [{"file": "bad.py", "reason": "parse_error"}]


# ---------------------------------------------------------------- JS / TS
def test_js_ts_relative_resolution_variants(scan):
    res = scan({
        "web/src/app.ts": ("import { sign } from './crypto/signer';\nimport util from \"./util.js\";\n"
                           "const h = require('./hash');\nexport * from './crypto';\nconst lazy = import('./lazy');\n"
                           "import type { T } from './types';\n"),
        "web/src/crypto/signer.ts": "import { createSign } from 'node:crypto';\nexport const sign = 1;\n",
        "web/src/crypto/index.ts": "export {};\n",
        "web/src/util.ts": "export default 1;\n",
        "web/src/hash.js": "module.exports = 1;\n",
        "web/src/lazy.tsx": "export default 1;\n",
        "web/src/types.d.ts": "",
    })
    got = {r["spec"]: (r["line"], r["kind"], r["targets"], r["resolution"]) for r in by_file(res, "web/src/app.ts")}
    assert got["./crypto/signer"] == (1, "import", ["web/src/crypto/signer.ts"], "resolved")
    assert got["./util.js"] == (2, "import", ["web/src/util.ts"], "resolved")       # TS ESM ".js" -> .ts
    assert got["./hash"] == (3, "require", ["web/src/hash.js"], "resolved")
    assert got["./crypto"] == (4, "export", ["web/src/crypto/index.ts"], "resolved")
    assert got["./lazy"][1:] == ("dynamic", ["web/src/lazy.tsx"], "resolved")
    assert got["./types"][3] == "unresolved"            # .d.ts is not scanned as a code file: reported, not guessed
    (lib,) = by_file(res, "web/src/crypto/signer.ts")
    assert (lib["resolution"], lib["external"], lib["crypto_library"]) == ("external", "node:crypto", "node:crypto")


def test_js_bare_specifiers_aliases_and_masking(scan):
    res = scan({"a.js": ("import CryptoJS from 'crypto-js';\nimport x from '@/lib/x';\nimport { a } from '@scope/pkg/sub';\n"
                         "// import y from './commented';\nconst s = \"require('./in-string')\";\n"
                         "const crypto = require('crypto');\nconst t = `${require('./in-template')}`;\n")})
    got = {r["spec"]: (r["resolution"], r["external"], r["crypto_library"]) for r in res.imports}
    assert got["crypto-js"] == ("external", "crypto-js", "crypto-js")
    assert got["crypto"] == ("external", "crypto", "node:crypto")
    assert got["@/lib/x"] == ("external", "@/lib", None)                            # path alias: not resolved, not guessed
    assert got["@scope/pkg/sub"] == ("external", "@scope/pkg", None)
    assert "./commented" not in got and "./in-string" not in got
    assert got["./in-template"][0] == "unresolved"                                  # code inside ${} is code


# ---------------------------------------------------------------- Java
def test_java_imports_static_and_wildcard(scan):
    res = scan({
        "src/main/java/com/acme/crypto/TokenSigner.java": "package com.acme.crypto;\nimport java.security.Signature;\npublic class TokenSigner {}\n",
        "src/main/java/com/acme/crypto/Keys.java": "package com.acme.crypto;\npublic class Keys { public static int SIZE = 1; }\n",
        "src/main/java/com/acme/api/Handler.java": ("package com.acme.api;\nimport com.acme.crypto.TokenSigner;\n"
                                                    "import static com.acme.crypto.Keys.SIZE;\nimport com.acme.crypto.*;\n"
                                                    "import javax.crypto.Cipher;\n// import com.acme.crypto.Hidden;\n"),
    })
    got = {r["kind"]: (r["targets"], r["resolution"], r["crypto_library"]) for r in by_file(res, "src/main/java/com/acme/api/Handler.java")}
    java = [r for r in by_file(res, "src/main/java/com/acme/api/Handler.java") if r["kind"] == "java"]
    assert [(r["spec"], r["targets"], r["resolution"], r["crypto_library"]) for r in java] == [
        ("com.acme.crypto.TokenSigner", ["src/main/java/com/acme/crypto/TokenSigner.java"], "resolved", None),
        ("javax.crypto.Cipher", [], "external", "javax.crypto")]
    assert got["java-static"][:2] == (["src/main/java/com/acme/crypto/Keys.java"], "resolved")
    assert got["java-wildcard"][1] == "wildcard" and len(got["java-wildcard"][0]) == 2   # package import: inferred
    assert all("Hidden" not in r["spec"] for r in res.imports)


# ---------------------------------------------------------------- properties
def test_cycles_are_recorded_without_special_cases(scan):
    res = scan({"pkg/__init__.py": "", "pkg/a.py": "from pkg import b\n", "pkg/b.py": "from pkg import a\n"})
    assert recs(res) == [("pkg/a.py", 1, "pkg", ["pkg/b.py"], "resolved"), ("pkg/b.py", 1, "pkg", ["pkg/a.py"], "resolved")]


def test_self_import_is_not_an_edge(scan):
    res = scan({"pkg/__init__.py": "from pkg import x\nx = 1\n"})
    assert all(r["targets"] == [] or "pkg/__init__.py" not in r["targets"] for r in res.imports)


def test_imports_are_deterministic_and_json_serialisable(scan):
    files = {f"m{i}.py": f"import m{(i + 1) % 30}\nimport hashlib\n" for i in range(30)}
    a, b = scan(files), scan(dict(reversed(list(files.items()))))
    assert json.dumps(a.imports) == json.dumps(b.imports) and len(a.imports) == 60
    assert a.code_files == {f"m{i}.py": "python" for i in range(30)}


def test_import_evidence_is_redacted(scan):
    res = scan({"a.js": "import k from './k'; const t = 'ghp_" + "a" * 36 + "';\n", "k.js": ""})
    assert all("ghp_" not in r["evidence"] for r in res.imports)


def test_code_files_index_lists_scanned_code_only(scan):
    res = scan({"a.py": "", "B.java": "class B {}\n", "c.ts": "", "README.md": "RSA\n", "x.yaml": "k: v\n"})
    assert res.code_files == {"B.java": "java", "a.py": "python", "c.ts": "js"}
