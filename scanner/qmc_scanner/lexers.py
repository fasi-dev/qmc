"""Comment/string-aware lexers for Java and JS/TS (05 section 3: 'strip comments first').

Output keeps the SAME LENGTH and newlines as the input so offsets/line numbers stay valid:
  code    - source with comments (and JS regex literals) blanked to spaces; string literals preserved
  mask    - per-char: 0 code, 1 string literal, 2 comment, 3 regex literal
  comments- [(line_no, comment_text)]
A rule match must START in mask==0 (so API names inside strings/comments never count); the
string literal ARGUMENT of a call (e.g. getInstance("ECDH")) is allowed because it is inside the match.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass

# Unterminated strings consume to end of line (a syntax error anyway) so scanning stays linear.
_DQ = r'"(?:\\[\s\S]|[^"\\\n])*(?:"|(?=\n)|\\?\Z)'
_SQ = r"'(?:\\[\s\S]|[^'\\\n])*(?:'|(?=\n)|\\?\Z)"
_COMMENTS = r'//[^\n]*|/\*[\s\S]*?\*/|/\*[\s\S]*\Z'
_JAVA = re.compile(_COMMENTS + r'|"""[\s\S]*?"""|' + _DQ + "|" + _SQ)
_JS = re.compile(_COMMENTS + "|" + _DQ + "|" + _SQ + r"|`(?:\\[\s\S]|[^`\\])*(?:`|\\?\Z)|/")
# Regex literals are only attempted after an operator-ish token, and the body is length-bounded (DoS guard).
_REGEX_LIT = re.compile(r"/(?![/*])(?:\\.|\[(?:\\.|[^\]\\\n]){0,200}\]|[^/\\\n\[]){1,200}/[A-Za-z]*")
_REGEX_PREV = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_KW = {"return", "typeof", "case", "do", "else", "in", "of", "void", "delete", "throw", "new",
             "instanceof", "yield", "await"}
_NON_NL = re.compile(r"[^\n]")


@dataclass
class Lexed:
    code: str
    mask: bytearray
    comments: list[tuple[int, str]]
    newlines: list[int]

    def line_of(self, offset: int) -> int:
        return bisect_right(self.newlines, offset - 1) + 1  # newlines holds offsets of '\n'


def _regex_allowed(text: str, start: int) -> bool:
    i = start - 1
    while i >= 0 and text[i] in " \t\r\n":
        i -= 1
    if i < 0:
        return True
    c = text[i]
    if c in _REGEX_PREV:
        return True
    if c.isalnum() or c in "_$":
        j = i
        while j >= 0 and (text[j].isalnum() or text[j] in "_$"):
            j -= 1
        return text[j + 1:i + 1] in _REGEX_KW
    return False


def lex(text: str, lang: str) -> Lexed:
    token = _JS if lang == "js" else _JAVA
    newlines = [i for i, ch in enumerate(text) if ch == "\n"]
    out: list[str] = []
    mask = bytearray(len(text))
    comments: list[tuple[int, str]] = []
    pos = cursor = 0
    while True:
        m = token.search(text, pos)
        if not m:
            break
        s, e = m.span()
        tok = m.group(0)
        if tok.startswith(("//", "/*")):
            kind = 2
        elif tok == "/":
            rm = _REGEX_LIT.match(text, s) if _regex_allowed(text, s) else None
            if rm is None:                    # division operator, not a regex literal
                pos = s + 1
                continue
            e = rm.end()
            tok = rm.group(0)
            kind = 3
        else:
            kind = 1
        out.append(text[cursor:s])
        if kind == 1:
            out.append(tok)
        else:
            out.append(_NON_NL.sub(" ", tok))
        mask[s:e] = bytes([kind]) * (e - s)
        if kind == 2:
            line = bisect_right(newlines, s - 1) + 1
            body = tok[2:] if tok.startswith("//") else tok[2:-2] if tok.endswith("*/") else tok[2:]
            for k, part in enumerate(body.split("\n")):
                if part.strip():
                    comments.append((line + k, part.strip()))
        cursor = pos = e
    out.append(text[cursor:])
    return Lexed("".join(out), mask, comments, newlines)
