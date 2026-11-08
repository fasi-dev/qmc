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
    # The import clause is length-bounded (600 chars, roughly 50 named imports): an unbounded lazy class that also
    # matches newlines made a file full of `import a` statements quadratic (46 s for 180 KB). Longer clauses are not
    # matched (reported via the unresolved/limitations path, never guessed).
    ("import", re.compile(r"\bimport\s+(?:type\s+)?(?:[\w$*{}\s,]{1,600}?\s+from\s+)?([\"'])([^\"'\n]{1,300})\1")),
    ("export", re.compile(r"\bexport\s+(?:type\s+)?(?:\*(?:\s+as\s+[\w$]+)?|\{[^}]{0,2000}\})\s*from\s*([\"'])([^\"'\n]{1,300})\1")),
    ("require", re.compile(r"\brequire\s*\(\s*([\"'])([^\"'\n]{1,300})\1\s*\)")),
    ("dynamic", re.compile(r"\bimport\s*\(\s*([\"'])([^\"'\n]{1,300})\1\s*\)")),
)


_IMPORT_KW = re.compile(r"\bimport\b")


def _import_matches(code: str, pat: re.Pattern):
    """Run the import pattern only where it can match: a quote within the bounded window after `import` (either the
    module specifier or the one after `from`). str.find is C-speed, so `import` floods without quotes cost ~nothing."""
    for k in _IMPORT_KW.finditer(code):
        end = min(len(code), k.end() + 640)
        if code.find('"', k.end(), end) == -1 and code.find("'", k.end(), end) == -1:
            continue
        m = pat.match(code, k.start())
        if m:
            yield m


def js_imports(lx: Lexed, rel: str) -> list[RawImport]:
    lines = lx.code.split("\n")
    out: dict[tuple[int, str], RawImport] = {}
    code = lx.code
    for kind, pat in _JS_PATTERNS:
        if kind == "import":
            matches = _import_matches(code, pat)
        else:
            matches = pat.finditer(code)
        for m in matches:
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


_JAVA_PACKAGE = re.compile(r"(?m)^[ \t]*package[ \t]+([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)[ \t]*;")
_JAVA_TYPE_NAME = re.compile(r"\b[A-Z][A-Za-z0-9_]*\b")
MAX_JAVA_IDENTIFIERS = 5_000


@dataclass
class JavaUnit:
    """What the same-package pass needs from one Java file: its package and the type-like identifiers it uses in code
    (comments and string literals are masked by the lexer, so mentions there do not count)."""
    file: str
    package: str
    identifiers: dict[str, tuple[int, str]]   # name -> (first line, evidence)


def java_unit(lx: Lexed, rel: str) -> JavaUnit:
    pm = _JAVA_PACKAGE.search(lx.code)
    pkg = pm.group(1) if pm and lx.mask[pm.start(1)] == 0 else ""
    lines = lx.code.split("\n")
    ids: dict[str, tuple[int, str]] = {}
    for m in _JAVA_TYPE_NAME.finditer(lx.code):
        if lx.mask[m.start()] != 0 or m.group(0) in ids:
            continue
        line = lx.line_of(m.start())
        if lines[line - 1].lstrip().startswith(("import ", "package ")):
            continue
        ids[m.group(0)] = (line, "")
        if len(ids) >= MAX_JAVA_IDENTIFIERS:
            break
    return JavaUnit(rel, pkg, {k: (ln, _evidence(lines[ln - 1], rel)) for k, (ln, _) in ids.items()})


def same_package_records(units: list[JavaUnit], records: list[dict]) -> list[dict]:
    """Java resolves simple type names of the same package without any import. For each file, a class of its own
    package whose (top-level, file-named) type is used in code becomes a dependency, unless a single-type import of
    the same simple name shadows it. Several files declaring the same package+class (e.g. main and test roots) make
    the edge ambiguous (inferred)."""
    by_pkg: dict[str, dict[str, list[str]]] = {}
    for u in units:
        cls = posixpath.basename(u.file)[:-5]
        group = u.package or f"<default>:{posixpath.dirname(u.file)}"
        by_pkg.setdefault(group, {}).setdefault(cls, []).append(u.file)
    explicit: dict[str, set[str]] = {}
    for r in records:
        if r["kind"] == "java":
            explicit.setdefault(r["file"], set()).add(r["spec"].rsplit(".", 1)[-1])
    out = []
    for u in sorted(units, key=lambda x: x.file):
        own = posixpath.basename(u.file)[:-5]
        group = u.package or f"<default>:{posixpath.dirname(u.file)}"
        for cls, files in sorted(by_pkg.get(group, {}).items()):
            if cls == own or cls not in u.identifiers or cls in explicit.get(u.file, set()):
                continue
            targets = sorted(f for f in files if f != u.file)
            line, ev = u.identifiers[cls]
            out.append({"file": u.file, "line": line, "kind": "java-same-package",
                        "spec": f"{u.package}.{cls}" if u.package else cls, "names": [cls], "targets": targets,
                        "resolution": "resolved" if len(targets) == 1 else "ambiguous", "external": None,
                        "crypto_library": None, "evidence": ev})
    return out


# ------------------------------------------------------------------ TS / JS path mapping (tsconfig.json / jsconfig.json)
@dataclass
class TsConfig:
    dir: str                                  # directory of the tsconfig file ("" = repository root)
    base: str                                 # directory that `paths` targets are relative to
    base_url: str | None                      # baseUrl directory if set (non-relative imports resolve from it)
    paths: list[tuple[str, list[str]]]        # (pattern, targets) in TypeScript's matching priority


def parse_tsconfig(rel: str, text: str) -> TsConfig | None:
    """compilerOptions.baseUrl / paths only. `extends` is not followed (reported as a limitation in the docs)."""
    import json
    from .confscan import strip_jsonc
    try:
        doc = json.loads(strip_jsonc(text))
    except (ValueError, RecursionError):
        return None
    co = doc.get("compilerOptions") if isinstance(doc, dict) else None
    if not isinstance(co, dict):
        return None
    d = posixpath.dirname(rel)
    base_url = co.get("baseUrl")
    base_dir = posixpath.normpath(posixpath.join(d, base_url)) if isinstance(base_url, str) else None
    if base_dir == ".":
        base_dir = ""
    raw = co.get("paths") if isinstance(co.get("paths"), dict) else {}
    paths = [(k, [t for t in v if isinstance(t, str)]) for k, v in raw.items() if isinstance(k, str) and isinstance(v, list)]
    # TypeScript: exact patterns win; otherwise the pattern with the longest prefix before '*'
    paths.sort(key=lambda kv: ("*" in kv[0], -len(kv[0].split("*")[0]), kv[0]))
    if not paths and base_dir is None:
        return None
    return TsConfig(d, base_dir if base_dir is not None else d, base_dir, paths)


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

    def __init__(self, files: dict[str, str], tsconfigs: list[TsConfig] | None = None):   # rel path -> language
        self.files = files
        self.tsconfigs = sorted(tsconfigs or [], key=lambda c: -len(c.dir))   # nearest (deepest) first
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
        keys: list[list[str]] = []
        if imp.kind == "from":
            # `from a.b import c, d`: c may be a submodule (a/b/c.py); any name that is not a submodule is an
            # attribute of module a.b itself, so a.b is a target too. Several targets here are NOT ambiguity.
            attribute = not imp.names or "*" in imp.names
            for n in imp.names:
                if n == "*":
                    continue
                if self.py_suffix.get(tuple(parts + [n])):
                    keys.append(parts + [n])
                else:
                    attribute = True
            if attribute:
                keys.append(parts)
        else:
            keys.append(parts)
        targets: set[str] = set()
        ambiguous = False
        here = posixpath.dirname(imp.file)
        for k in keys:
            hits = self.py_suffix.get(tuple(k), [])
            if not hits:
                continue
            if len(k) == 1:
                # A bare top-level name (`import utils`) only resolves to a repository file if Python would find it:
                # same directory as the importer (script-style). Matches elsewhere depend on sys.path -> inferred.
                local = [h for h in hits if posixpath.dirname(h) == here
                         or (h.endswith("/__init__.py") and posixpath.dirname(posixpath.dirname(h)) == here)]
                if len(local) == 1:
                    hits = local
                else:
                    ambiguous = True
            elif len(hits) > 1:
                ambiguous = True
            targets.update(hits)
        if not targets:
            return [], "external"
        return sorted(targets), ("ambiguous" if ambiguous else "resolved")

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
            hit = self._ts_mapped(imp.file, spec)        # tsconfig/jsconfig paths + baseUrl (explicit configuration)
            return ([hit], "resolved") if hit else ([], "external")   # else: npm package / node builtin
        base = posixpath.dirname(imp.file)
        target = posixpath.normpath(posixpath.join(base, spec)) if not spec.startswith("/") else spec.lstrip("/")
        if target.startswith(".."):
            return [], "unresolved"
        hit = self._js_file(target)
        return ([hit], "resolved") if hit else ([], "unresolved")

    def _js_file(self, target: str) -> str | None:
        target = posixpath.normpath(target) if target else target
        cands = [target, *(target + e for e in JS_EXTS), *(f"{target}/index{e}" for e in JS_EXTS)]
        if target.endswith((".js", ".jsx", ".mjs", ".cjs")):   # TS ESM style: "./x.js" refers to x.ts
            stem = target.rsplit(".", 1)[0]
            cands += [stem + ".ts", stem + ".tsx"]
        for c in cands:
            if self.files.get(c) == "js":
                return c
        return None

    def _ts_mapped(self, importer: str, spec: str) -> str | None:
        for cfg in self.tsconfigs:
            if cfg.dir and not importer.startswith(cfg.dir + "/"):
                continue                                  # only the tsconfig that governs the importing file
            for pattern, targets in cfg.paths:
                if "*" in pattern:
                    pre, _, suf = pattern.partition("*")
                    if not (spec.startswith(pre) and spec.endswith(suf) and len(spec) >= len(pre) + len(suf)):
                        continue
                    star = spec[len(pre):len(spec) - len(suf)]
                elif spec == pattern:
                    star = ""
                else:
                    continue
                for t in targets:
                    hit = self._js_file(posixpath.join(cfg.base, t.replace("*", star)) if cfg.base else t.replace("*", star))
                    if hit:
                        return hit
            if cfg.base_url is not None:
                hit = self._js_file(posixpath.join(cfg.base_url, spec) if cfg.base_url else spec)
                if hit:
                    return hit
            return None                                   # nearest config decides; outer configs do not apply
        return None


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


def resolve_all(raw: list[tuple[RawImport, str]], files: dict[str, str], *, java_units: list[JavaUnit] | None = None,
                tsconfigs: list[TsConfig] | None = None) -> tuple[list[dict], bool]:
    """Resolve every raw import (+ Java same-package references); returns (records sorted deterministically, truncated?)."""
    r = Resolver(files, tsconfigs)
    recs = [r.resolve(imp, lang) for imp, lang in raw]
    if java_units:
        recs += same_package_records(java_units, recs)
    recs.sort(key=lambda d: (d["file"], d["line"], d["spec"], d["kind"]))
    truncated = len(recs) > MAX_IMPORT_RECORDS
    return recs[:MAX_IMPORT_RECORDS], truncated
