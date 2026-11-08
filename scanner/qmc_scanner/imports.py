"""Static import extraction and resolution (Python, Java, JS/TS) for the cryptographic dependency graph.

Parse-only, like the rest of the scanner: Python is read with `ast`, Java/JS/TS with the comment/string-aware lexer.
Nothing is imported, executed or installed. Imports are resolved against the files of the scanned tree only.

Each import record says how well it is established:
  resolved    exactly one repository file matches the import (an explicit import statement => confirmed edge)
  ambiguous   several repository files match (e.g. two `utils.py`); all candidates are listed, edges are INFERRED
  wildcard    Java `import a.b.*`: the package is imported, but use of a specific class is not proven (INFERRED)
  external    no repository file matches; the import names a package (stdlib, npm, Maven, ...)
  unresolved  a relative import / path that should be in the repository but no file matches

Known blind spots (reported, never guessed): dynamic imports with computed names or runtime import-machinery calls, TS path
aliases (`@/x`), webpack aliases, Java same-package references (no import statement), reflection, classpath scanning.
"""
from __future__ import annotations

import ast
import posixpath
import re
from dataclasses import dataclass, field

from .lexers import Lexed
from .matches import clean_evidence
from .redaction import redact_text

MAX_IMPORT_RECORDS = 100_000
EVIDENCE_MAX = 200
PY_EXT = (".py", ".pyw")
JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")

# Import roots that ARE cryptographic libraries, mapped to the library names the detection rules use, so that an
# IMPORTS edge and a finding's USES edge meet at the same library node.
CRYPTO_LIBRARIES: dict[str, dict[str, str]] = {
    "python": {"cryptography": "cryptography", "Crypto": "pycryptodome", "Cryptodome": "pycryptodome",
               "hashlib": "hashlib", "hmac": "hmac", "jwt": "pyjwt", "nacl": "pynacl", "ecdsa": "ecdsa",
               "rsa": "rsa", "oqs": "liboqs", "ssl": "ssl"},
    "js": {"crypto": "node:crypto", "node:crypto": "node:crypto", "jose": "jose", "crypto-js": "crypto-js",
           "node-forge": "node-forge", "tweetnacl": "tweetnacl", "jsonwebtoken": "jsonwebtoken"},
    "java": {"java.security": "java.security", "javax.crypto": "javax.crypto", "org.bouncycastle": "bouncycastle",
             "javax.net.ssl": "javax.net.ssl"},
}


@dataclass
class RawImport:
    file: str
    line: int
    kind: str                     # import | from | require | dynamic | export | java | java-static | java-wildcard
    spec: str                     # module / path as written (relative Python imports keep their leading dots)
    names: list[str] = field(default_factory=list)
    evidence: str = ""


def _evidence(line_text: str, rel: str) -> str:
    ev = clean_evidence(line_text)[:EVIDENCE_MAX]
    return redact_text(ev, rel)[0]


# ------------------------------------------------------------------ Python
def python_imports(text: str, rel: str) -> list[RawImport]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
        return []
    lines = text.split("\n")
    out: list[RawImport] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                out.append(RawImport(rel, n.lineno, "import", a.name, [], _evidence(lines[n.lineno - 1], rel)))
        elif isinstance(n, ast.ImportFrom):
            spec = "." * n.level + (n.module or "")
            names = sorted(a.name for a in n.names)
            out.append(RawImport(rel, n.lineno, "from", spec, names, _evidence(lines[n.lineno - 1], rel)))
    return out


# ------------------------------------------------------------------ JS / TS (on lexed code: comments are blanked)
_JS_PATTERNS = (
    ("import", re.compile(r"\bimport\s+(?:type\s+)?(?:[\w$*{}\s,]+?\s+from\s+)?([\"'])([^\"'\n]{1,300})\1")),
    ("export", re.compile(r"\bexport\s+(?:type\s+)?(?:\*(?:\s+as\s+[\w$]+)?|\{[^}]{0,2000}\})\s*from\s*([\"'])([^\"'\n]{1,300})\1")),
    ("require", re.compile(r"\brequire\s*\(\s*([\"'])([^\"'\n]{1,300})\1\s*\)")),
    ("dynamic", re.compile(r"\bimport\s*\(\s*([\"'])([^\"'\n]{1,300})\1\s*\)")),
)


def js_imports(lx: Lexed, rel: str) -> list[RawImport]:
    lines = lx.code.split("\n")
    out: dict[tuple[int, str], RawImport] = {}
    for kind, pat in _JS_PATTERNS:
        for m in pat.finditer(lx.code):
            if lx.mask[m.start()] != 0:          # keyword inside a string / comment / regex literal
                continue
            line = lx.line_of(m.start())
            key = (line, m.group(2))
            if key not in out:                   # `import(...)` also matches the generic import pattern
                out[key] = RawImport(rel, line, kind, m.group(2), [], _evidence(lines[line - 1], rel))
    return list(out.values())


# ------------------------------------------------------------------ Java
_JAVA_IMPORT = re.compile(r"(?m)^[ \t]*import[ \t]+(static[ \t]+)?([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)(\.\*)?[ \t]*;")


def java_imports(lx: Lexed, rel: str) -> list[RawImport]:
    lines = lx.code.split("\n")
    out = []
    for m in _JAVA_IMPORT.finditer(lx.code):
        start = m.start(2)
        if lx.mask[start] != 0:
            continue
        line = lx.line_of(start)
        kind = "java-wildcard" if m.group(3) else "java-static" if m.group(1) else "java"
        out.append(RawImport(rel, line, kind, m.group(2), [], _evidence(lines[line - 1], rel)))
    return out


# ------------------------------------------------------------------ resolution
def _module_parts(path: str) -> list[str] | None:
    if not path.endswith(PY_EXT):
        return None
    parts = path.rsplit(".", 1)[0].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return parts or None


class Resolver:
    """Resolves import specs against the scanned tree. Deterministic: candidate lists are sorted."""

    def __init__(self, files: dict[str, str]):          # rel path -> language ("python" | "java" | "js")
        self.files = files
        self.py_suffix: dict[tuple[str, ...], list[str]] = {}
        self.java_suffix: dict[tuple[str, ...], list[str]] = {}
        self.java_pkg: dict[tuple[str, ...], list[str]] = {}
        for path, lang in sorted(files.items()):
            if lang == "python":
                parts = _module_parts(path)
                if parts:
                    for i in range(len(parts)):
                        self.py_suffix.setdefault(tuple(parts[i:]), []).append(path)
            elif lang == "java" and path.endswith(".java"):
                parts = path[:-5].split("/")
                for i in range(len(parts)):
                    self.java_suffix.setdefault(tuple(parts[i:]), []).append(path)
                for i in range(len(parts) - 1):
                    self.java_pkg.setdefault(tuple(parts[i:-1]), []).append(path)

    def resolve(self, imp: RawImport, lang: str) -> dict:
        if lang == "python":
            targets, status = self._python(imp)
        elif lang == "java":
            targets, status = self._java(imp)
        else:
            targets, status = self._js(imp)
        root = None
        if status == "external":
            root = _external_root(imp.spec, lang)
        library = CRYPTO_LIBRARIES.get(lang, {}).get(root) if root else None
        return {"file": imp.file, "line": imp.line, "kind": imp.kind, "spec": imp.spec, "names": imp.names,
                "targets": [t for t in targets if t != imp.file], "resolution": status,
                "external": root, "crypto_library": library, "evidence": imp.evidence}

    # Python: relative imports resolve from the importing file's package; absolute ones by module-path suffix.
    def _python(self, imp: RawImport) -> tuple[list[str], str]:
        spec = imp.spec
        if spec.startswith("."):
            level = len(spec) - len(spec.lstrip("."))
            base = imp.file.split("/")[:-1]
            if level - 1 > len(base):
                return [], "unresolved"
            base = base[:len(base) - (level - 1)]
            module = base + [p for p in spec.lstrip(".").split(".") if p]
            found: set[str] = set()
            attribute_names = False
            for n in imp.names:                          # `from .m import x`: x may be a submodule m/x.py ...
                sub = self._py_exact(module + [n]) if n != "*" else None
                if sub:
                    found.add(sub)
                else:
                    attribute_names = True               # ... or an attribute of module m itself
            if attribute_names or not imp.names:
                f = self._py_exact(module)
                if f:
                    found.add(f)
            return (sorted(found), "resolved") if found else ([], "unresolved")
        parts = spec.split(".")
        candidates: list[list[str]] = []
        if imp.kind == "from":                           # `from a.b import c` may name a submodule a/b/c.py
            candidates += [parts + [n] for n in imp.names if n != "*"]
        candidates.append(parts)
        hits: set[str] = set()
        for c in candidates:
            hits.update(self.py_suffix.get(tuple(c), []))
            if hits:
                break
        if not hits:
            return [], "external"
        if len(c) == 1:
            # A bare top-level name (`import utils`) only resolves to a repository file if Python would find it:
            # same directory as the importer (script-style). Matches elsewhere depend on sys.path -> inferred only.
            here = posixpath.dirname(imp.file)
            local = sorted(h for h in hits if posixpath.dirname(h) == here or posixpath.dirname(posixpath.dirname(h)) == here
                           and h.endswith("/__init__.py"))
            if len(local) == 1:
                return local, "resolved"
            return sorted(hits), "ambiguous"
        return sorted(hits), ("resolved" if len(hits) == 1 else "ambiguous")

    def _py_exact(self, parts: list[str]) -> str | None:
        if not parts:
            return "__init__.py" if "__init__.py" in self.files else None
        for cand in ("/".join(parts) + ".py", "/".join(parts) + "/__init__.py"):
            if self.files.get(cand) == "python":
                return cand
        return None

    def _java(self, imp: RawImport) -> tuple[list[str], str]:
        parts = imp.spec.split(".")
        if imp.kind == "java-wildcard":
            hits = self.java_pkg.get(tuple(parts), [])
            return (sorted(hits), "wildcard") if hits else ([], "external")
        tries = [parts] + ([parts[:-1]] if imp.kind == "java-static" and len(parts) > 1 else [])
        for t in tries:
            hits = self.java_suffix.get(tuple(t), [])
            if hits:
                return sorted(hits), ("resolved" if len(hits) == 1 else "ambiguous")
        return [], "external"

    def _js(self, imp: RawImport) -> tuple[list[str], str]:
        spec = imp.spec
        if not spec.startswith((".", "/")):
            return [], "external"                        # bare specifier (npm / node builtin) or path alias
        base = posixpath.dirname(imp.file)
        target = posixpath.normpath(posixpath.join(base, spec)) if not spec.startswith("/") else spec.lstrip("/")
        if target.startswith(".."):
            return [], "unresolved"
        cands = [target, *(target + e for e in JS_EXTS), *(f"{target}/index{e}" for e in JS_EXTS)]
        if target.endswith((".js", ".jsx", ".mjs", ".cjs")):   # TS ESM style: "./x.js" refers to x.ts
            stem = target.rsplit(".", 1)[0]
            cands += [stem + ".ts", stem + ".tsx"]
        for c in cands:
            if self.files.get(c) == "js":
                return [c], "resolved"
        return [], "unresolved"


def _external_root(spec: str, lang: str) -> str:
    if lang == "python":
        return spec.lstrip(".").split(".")[0]
    if lang == "js":
        if spec.startswith("@"):
            return "/".join(spec.split("/")[:2])
        return spec.split("/")[0] if not spec.startswith("node:") else spec
    parts = spec.split(".")                             # java: longest known crypto prefix, else first two parts
    for n in (3, 2):
        if ".".join(parts[:n]) in CRYPTO_LIBRARIES["java"]:
            return ".".join(parts[:n])
    return ".".join(parts[:2])


def resolve_all(raw: list[tuple[RawImport, str]], files: dict[str, str]) -> tuple[list[dict], bool]:
    """Resolve every raw import; returns (records sorted deterministically, truncated?)."""
    r = Resolver(files)
    recs = [r.resolve(imp, lang) for imp, lang in raw]
    recs.sort(key=lambda d: (d["file"], d["line"], d["spec"], d["kind"]))
    truncated = len(recs) > MAX_IMPORT_RECORDS
    return recs[:MAX_IMPORT_RECORDS], truncated
