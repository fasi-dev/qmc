"""Static configuration coverage (05 section 2: YAML/JSON, nginx/config, Docker/CI) and X.509 PEM parsing.

Everything here is parse-only: YAML is *composed* (never constructed into Python objects), certificates are
decoded with the maintained `cryptography` x509 parser, config text is matched line by line. Nothing is executed.
Three rule types:
  directive        - one config line (comments stripped) -> value split into tokens -> value_map -> findings
  structured       - YAML/JSON key/value inspection with line numbers (alias-safe, size/depth bounded)
  pem_certificate  - '-----BEGIN CERTIFICATE-----' blocks parsed for key algorithm / signature hash / expiry
"""
from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime, timezone

import yaml

from .matches import RawMatch, clean_evidence, entry_value
from .rules import Rule, lookup

_COMMENT = re.compile(r"(?:^|\s)#(.*)$")
MAX_LINE = 10_000
MAX_NODES = 200_000
MAX_DEPTH = 32
MAX_CERTS = 50
_TOKEN_STRIP = "'\";+^"


def hash_comments(text: str) -> list[tuple[int, str]]:
    out = []
    for i, raw in enumerate(text.split("\n"), 1):
        if len(raw) <= MAX_LINE:
            m = _COMMENT.search(raw)
            if m and m.group(1).strip():
                out.append((i, "# " + m.group(1).strip()))
    return out


def _make(rule: Rule, entry: dict | None, line: int, line_end: int, evidence: str, scope: tuple[str, ...] = ()) -> RawMatch:
    return RawMatch(rule=rule, line_start=line, line_end=line_end, algorithm=entry_value(rule, entry, "algorithm"),
                    primitive=entry_value(rule, entry, "primitive"), operation=entry_value(rule, entry, "operation"),
                    library=rule.library, api=(entry or {}).get("api") or rule.api,
                    confidence=float(entry_value(rule, entry, "confidence")), evidence=clean_evidence(evidence),
                    key_size=(entry or {}).get("key_size"), scope=scope)


# ------------------------------------------------------------------ directive rules (nginx / ssh / Docker / CI)
def scan_directives(text: str, rel: str, rules: list[Rule]) -> list[RawMatch]:
    applicable = [r for r in rules if r.match_type == "directive" and r.file_pattern.search(rel)]  # type: ignore[union-attr]
    if not applicable:
        return []
    out: list[RawMatch] = []
    for i, raw in enumerate(text.split("\n"), 1):
        if len(raw) > MAX_LINE:
            continue
        cm = _COMMENT.search(raw)
        code = raw[:cm.start()] if cm else raw
        if not code.strip():
            continue
        for rule in applicable:
            dm = rule.pattern.search(code)  # type: ignore[union-attr]
            if not dm:
                continue
            for tok in rule.split.split(dm.group("value")):  # type: ignore[union-attr]
                tok = tok.strip(_TOKEN_STRIP)
                if not tok or tok.startswith(rule.skip_prefixes):
                    continue
                entry = lookup(rule.value_map, tok)
                if entry is not None:
                    out.append(_make(rule, entry, i, i, code.strip()))
    return out


# ------------------------------------------------------------------ structured rules (YAML / JSON)
def _compose(text: str):
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    try:
        return list(yaml.compose_all(text, Loader=loader))
    except (yaml.YAMLError, ValueError, RecursionError):
        if "\t" in text:      # tab-indented JSON is valid JSON but not valid YAML indentation
            try:
                return list(yaml.compose_all(text.replace("\t", "  "), Loader=loader))
            except (yaml.YAMLError, ValueError, RecursionError):
                return None
        return None


def scan_structured(text: str, rules: list[Rule]) -> tuple[list[RawMatch], str | None]:
    docs = _compose(text)
    if docs is None:
        return [], "parse_error"
    srules = [r for r in rules if r.match_type == "structured"]
    lines = text.split("\n")
    out: list[RawMatch] = []
    seen: set[int] = set()
    count = 0
    stack = [(d, (), None) for d in docs if d is not None]
    while stack:
        node, scope, key = stack.pop()
        if id(node) in seen:          # aliases/anchors: visit each node once (billion-laughs safe)
            continue
        seen.add(id(node))
        count += 1
        if count > MAX_NODES:
            return [], "too_complex"
        if isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                if isinstance(k, yaml.ScalarNode):
                    stack.append((v, (scope + (k.value,))[-MAX_DEPTH:], k.value))
        elif isinstance(node, yaml.SequenceNode):
            stack.extend((item, scope, key) for item in node.value)
        elif isinstance(node, yaml.ScalarNode) and key is not None:
            for rule in srules:
                if not rule.key_pattern.search(key):  # type: ignore[union-attr]
                    continue
                for tok in rule.split.split(str(node.value)):  # type: ignore[union-attr]
                    tok = tok.strip(_TOKEN_STRIP)
                    if not tok or tok.startswith(rule.skip_prefixes):
                        continue
                    entry = lookup(rule.value_map, tok)
                    if entry is None:
                        continue
                    ln = node.start_mark.line + 1
                    src = lines[ln - 1].strip() if ln - 1 < len(lines) else ""
                    out.append(_make(rule, entry, ln, ln, src if 0 < len(src) <= 300 else f"{key}: {node.value}", scope))
    return out, None


# ------------------------------------------------------------------ X.509 PEM certificates
def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _cert_blocks(text: str) -> list[tuple[int, int, str]]:
    blocks, start, body = [], None, []
    for i, line in enumerate(text.split("\n"), 1):
        s = line.strip()
        if start is None:
            if s == "-----BEGIN CERTIFICATE-----":
                start, body = i, []
        elif s == "-----END CERTIFICATE-----":
            blocks.append((start, i, "".join(body)))
            start = None
            if len(blocks) >= MAX_CERTS:
                break
        elif len(body) < 2000:
            body.append(s)
    return blocks


def scan_pem(text: str, rules: list[Rule], as_of: datetime) -> tuple[list[RawMatch], str | None]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    prules = {r.emit: r for r in rules if r.match_type == "pem_certificate"}
    out: list[RawMatch] = []
    bad = False
    for first, last, b64 in _cert_blocks(text):
        try:
            cert = x509.load_der_x509_certificate(base64.b64decode(b64, validate=True))
            pk = cert.public_key()
            not_after = _utc(getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after)
            sig_name = getattr(cert.signature_algorithm_oid, "_name", None) or cert.signature_algorithm_oid.dotted_string
            subject, issuer = cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()
            try:
                sig_hash = cert.signature_hash_algorithm
            except Exception:  # unsupported / hash-less signature algorithms (e.g. Ed25519)
                sig_hash = None
        except (binascii.Error, ValueError, TypeError, Exception):
            bad = True
            continue
        if isinstance(pk, rsa.RSAPublicKey):
            alg, bits, desc = "RSA", pk.key_size, f"RSA-{pk.key_size}"
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            alg, bits, desc = "ECDSA", pk.curve.key_size, f"EC-{pk.curve.name}"
        elif isinstance(pk, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            alg, bits, desc = "EdDSA", None, "Ed25519" if isinstance(pk, ed25519.Ed25519PublicKey) else "Ed448"
        elif isinstance(pk, dsa.DSAPublicKey):
            alg, bits, desc = "DSA", pk.key_size, f"DSA-{pk.key_size}"
        else:
            continue
        evidence = (f"-----BEGIN CERTIFICATE----- (X.509 subject={subject}; "
                    f"{'self-signed' if cert.subject == cert.issuer else 'issuer=' + issuer}; key={desc}; "
                    f"signature={sig_name}; notAfter={not_after.date().isoformat()}; "
                    f"{'expired' if not_after < as_of else 'not expired'})")
        r = prules.get("public_key")
        if r:
            m = _make(r, {"algorithm": alg}, first, last, evidence)
            m.key_size = bits
            out.append(m)
        r = prules.get("sha1_signature")
        if r and isinstance(sig_hash, hashes.SHA1):
            out.append(_make(r, None, first, last, evidence))
    return out, ("cert_parse_error" if bad else None)
