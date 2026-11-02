"""Parse policy row filters into safe, composed SQL (unit U2).

Grammar (case-insensitive keywords)::

    expr    := term ("OR" term)*
    term    := factor ("AND" factor)*
    factor  := "(" expr ")" | ident op literal | ident "IS" ["NOT"] "NULL"
    op      := = | <> | != | < | <= | > | >=
    literal := 'string' ('' escapes) | integer | decimal | TRUE | FALSE

Identifiers are bare lower-case-safe names; everything is re-emitted with
psycopg.sql.Identifier / Literal, never interpolated.
"""

from __future__ import annotations

import re
from decimal import Decimal

from psycopg import sql

MAX_FILTER_LEN = 1000
MAX_DEPTH = 16
_TOKEN_RE = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>-?\d+(?:\.\d+)?)|(?P<op><=|>=|<>|!=|=|<|>)"
    r"|(?P<paren>[()])|(?P<word>[A-Za-z_][A-Za-z0-9_]*))"
)
_KEYWORDS = {"and", "or", "is", "not", "null", "true", "false"}


class RowFilterError(ValueError):
    """Raised when a row filter is outside the supported grammar."""


def _tokenize(text: str) -> list[tuple[str, str]]:
    if len(text) > MAX_FILTER_LEN:
        raise RowFilterError(f"row filter longer than {MAX_FILTER_LEN} characters")
    tokens: list[tuple[str, str]] = []
    pos = 0
    text = text.rstrip()
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise RowFilterError(f"unsupported syntax at position {pos}")
        kind = m.lastgroup or ""
        tokens.append((kind, m.group(kind)))
        pos = m.end()
    if not tokens:
        raise RowFilterError("row filter is empty")
    return tokens


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.toks = tokens
        self.i = 0
        self.columns: set[str] = set()

    def _peek_word(self) -> str | None:
        if self.i < len(self.toks) and self.toks[self.i][0] == "word":
            return self.toks[self.i][1].lower()
        return None

    def _next(self, what: str) -> tuple[str, str]:
        if self.i >= len(self.toks):
            raise RowFilterError(f"unexpected end of filter, expected {what}")
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def parse(self) -> sql.Composable:
        out = self.expr(0)
        if self.i != len(self.toks):
            raise RowFilterError(f"unexpected token {self.toks[self.i][1]!r}")
        return out

    def expr(self, depth: int) -> sql.Composable:
        parts = [self.term(depth)]
        while self._peek_word() == "or":
            self.i += 1
            parts.append(self.term(depth))
        return parts[0] if len(parts) == 1 else sql.SQL(" OR ").join(parts)

    def term(self, depth: int) -> sql.Composable:
        parts = [self.factor(depth)]
        while self._peek_word() == "and":
            self.i += 1
            parts.append(self.factor(depth))
        return parts[0] if len(parts) == 1 else sql.SQL(" AND ").join(parts)

    def factor(self, depth: int) -> sql.Composable:
        if depth > MAX_DEPTH:
            raise RowFilterError("row filter nested too deeply")
        kind, val = self._next("a condition")
        if kind == "paren" and val == "(":
            inner = self.expr(depth + 1)
            if self._next("')'") != ("paren", ")"):
                raise RowFilterError("expected ')'")
            return sql.SQL("({})").format(inner)
        if kind != "word" or val.lower() in _KEYWORDS:
            raise RowFilterError(f"expected a column name, got {val!r}")
        col = sql.Identifier(val)
        self.columns.add(val)
        if self._peek_word() == "is":
            self.i += 1
            neg = self._peek_word() == "not"
            if neg:
                self.i += 1
            if self._next("NULL")[1].lower() != "null":
                raise RowFilterError("expected NULL after IS")
            return sql.SQL("{} IS NOT NULL" if neg else "{} IS NULL").format(col)
        okind, op = self._next("a comparison operator")
        if okind != "op":
            raise RowFilterError(f"expected a comparison operator, got {op!r}")
        op = "<>" if op == "!=" else op
        return sql.SQL("{} " + op + " {}").format(col, self.literal())

    def literal(self) -> sql.Composable:
        kind, val = self._next("a literal")
        if kind == "str":
            return sql.Literal(val[1:-1].replace("''", "'"))
        if kind == "num":
            return sql.Literal(Decimal(val) if "." in val else int(val))
        if kind == "word" and val.lower() in ("true", "false"):
            return sql.Literal(val.lower() == "true")
        raise RowFilterError(f"expected a literal, got {val!r}")


def parse_row_filter(text: str) -> tuple[sql.Composable, frozenset[str]]:
    """Return (composed SQL condition, referenced column names)."""
    p = _Parser(_tokenize(text))
    return p.parse(), frozenset(p.columns)
