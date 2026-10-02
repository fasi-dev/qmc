"""Python detection via the builtin `ast` module (parse only: nothing is imported or executed).

Calls are resolved to fully-qualified names through the file's import statements, so
`from cryptography.hazmat.primitives.asymmetric import rsa as r; r.generate_private_key(...)`
matches, while an unimported local function named `rsa.generate_private_key` does not.
Strings, docstrings and comments are never executable matches.
"""
from __future__ import annotations

import ast
import io
import tokenize
import warnings

from .matches import RawMatch, clean_evidence, entry_value, scan_mentions
from .rules import Rule, lookup


def _dotted(node: ast.AST) -> list[str] | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return parts[::-1]
    return None


def _imports(tree: ast.AST) -> dict[str, str]:
    table: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.asname:
                    table[a.asname] = a.name
                else:
                    root = a.name.split(".")[0]
                    table[root] = root
        elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
            for a in n.names:
                if a.name != "*":
                    table[a.asname or a.name] = f"{n.module}.{a.name}"
    return table


def _segment(lines: list[str], node: ast.AST) -> str:
    """Source text of a node (ast offsets are UTF-8 byte offsets)."""
    l0, l1 = node.lineno - 1, node.end_lineno - 1  # type: ignore[attr-defined]
    c0, c1 = node.col_offset, node.end_col_offset  # type: ignore[attr-defined]
    if l0 == l1:
        return lines[l0].encode("utf-8")[c0:c1].decode("utf-8", "replace")
    parts = [lines[l0].encode("utf-8")[c0:].decode("utf-8", "replace")]
    parts += lines[l0 + 1:l1]
    parts.append(lines[l1].encode("utf-8")[:c1].decode("utf-8", "replace"))
    return "\n".join(parts)


def _int_arg(call: ast.Call, spec: dict | None) -> int | None:
    if not spec:
        return None
    node = None
    kw = spec.get("kw")
    if kw:
        node = next((k.value for k in call.keywords if k.arg == kw), None)
    if node is None and spec.get("pos") is not None and len(call.args) > spec["pos"]:
        node = call.args[spec["pos"]]
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    return None


def _literals(call: ast.Call, specs: tuple[dict, ...]) -> list[str]:
    out: list[str] = []
    for spec in specs:
        node = None
        if spec.get("kw"):
            node = next((k.value for k in call.keywords if k.arg == spec["kw"]), None)
        if node is None and spec.get("pos") is not None and len(call.args) > spec["pos"]:
            node = call.args[spec["pos"]]
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.append(node.value)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            out += [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        if out:
            break
    return out


def scan_python(text: str, rules: list[Rule]) -> tuple[list[RawMatch], str | None]:
    """Returns (matches, skip_reason). Executable matches only; comments are handled by python_comments()."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
        return [], "parse_error"

    imports = _imports(tree)
    lines = text.split("\n")
    call_rules = [r for r in rules if r.match_type == "python_call"]
    parent_attrs = {a for r in call_rules for a in r.operation_by_parent}
    arg_parent: dict[int, str] = {}
    results: list[RawMatch] = []

    stack: list[tuple[ast.AST, tuple[str, ...]]] = [(tree, ())]
    while stack:
        node, scope = stack.pop()
        for child in ast.iter_child_nodes(node):
            sc = scope + (child.name,) if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else scope
            stack.append((child, sc))
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute) and node.func.attr in parent_attrs:
            for a in [*node.args, *[k.value for k in node.keywords]]:
                if isinstance(a, ast.Call):
                    arg_parent[id(a)] = node.func.attr
        parts = _dotted(node.func)
        if not parts or parts[0] not in imports:
            continue
        fqn = ".".join([imports[parts[0]], *parts[1:]])
        for rule in call_rules:
            entry = lookup(rule.qualified_names, fqn)
            if entry is None:
                continue
            _emit(rule, entry, node, fqn, scope, lines, arg_parent, results)
    return results, None


def _emit(rule: Rule, qentry: dict, call: ast.Call, fqn: str, scope: tuple[str, ...], lines: list[str],
          arg_parent: dict[int, str], results: list[RawMatch]) -> None:
    evidence = clean_evidence(_segment(lines, call))
    base_entries: list[dict] = []
    if rule.value_from == "literal":
        for lit in _literals(call, rule.literal_args):
            e = lookup(rule.value_map, lit)
            if e is not None:
                base_entries.append(e)
    else:
        base_entries.append(qentry)
    for entry in base_entries:
        op = entry_value(rule, entry, "operation")
        parent = arg_parent.get(id(call))
        if parent and parent in rule.operation_by_parent:
            op = rule.operation_by_parent[parent]
        alg = entry_value(rule, entry, "algorithm")
        api = entry.get("api") or (".".join(fqn.split(".")[-2:]) if rule.value_from == "fqn" else rule.api)
        ks = entry.get("key_size") or _int_arg(call, rule.key_size)
        results.append(RawMatch(
            rule=rule, line_start=call.lineno, line_end=call.end_lineno, algorithm=alg,  # type: ignore[arg-type]
            primitive=entry_value(rule, entry, "primitive"), operation=op, library=rule.library, api=api,
            confidence=float(entry_value(rule, entry, "confidence")), evidence=evidence, key_size=ks,
            scope=scope,
            resolvable=bool(rule.sibling_resolution and alg == rule.sibling_resolution["from"])))


def python_comments(text: str) -> list[tuple[int, str]]:
    """(line, comment text) for real '#' comments, via the tokenizer (so '#' inside strings is ignored)."""
    out: list[tuple[int, str]] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                out.append((tok.start[0], tok.string.strip()))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        pass
    return out


def mentions_python(text: str, mention_rule: Rule) -> list[RawMatch]:
    return scan_mentions(mention_rule, python_comments(text))
