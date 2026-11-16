"""Snowflake catalog inspect, typed masks, and safe row-filter emit."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from datagrant.rowfilter import _KEYWORDS, MAX_DEPTH, RowFilterError, _tokenize

_TYPE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class MaskError(RuntimeError):
    """Raised when a Snowflake column cannot be masked or inspected."""


@dataclass(frozen=True)
class TableCatalog:
    columns: dict[str, str]


def _type_name(raw: object) -> str:
    text = str(raw).strip()
    base = text.split("(", 1)[0].strip()
    if not _TYPE_RE.fullmatch(base):
        raise MaskError(f"unsupported column type {text!r}")
    return base.upper()


def inspect_table(
    conn: Any, table: str, *, database: str, schema: str | None = None
) -> TableCatalog:
    """Read COLUMN_NAME / DATA_TYPE from INFORMATION_SCHEMA (qmark-bound)."""
    from datagrant.sf.grant import GrantError, _split_table, q

    tschema, tname = _split_table(table, schema)
    sql = (
        f"SELECT COLUMN_NAME, DATA_TYPE FROM {q(database)}"  # nosec B608
        f".{q('INFORMATION_SCHEMA')}.{q('COLUMNS')}"
        " WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?"
    )
    cur = conn.cursor() if hasattr(conn, "cursor") else conn
    result = cur.execute(sql, (tschema, tname))
    rows: list[Any] = []
    if result is not None and hasattr(result, "fetchall"):
        rows = list(result.fetchall() or ())
    elif hasattr(conn, "fetchall"):
        rows = list(conn.fetchall() or ())
    if not rows:
        raise GrantError(f"table {table!r} not found or has no columns")
    cols: dict[str, str] = {}
    for row in rows:
        if row is None or len(row) < 2:
            continue
        name = str(row[0])
        try:
            cols[name] = _type_name(row[1])
        except MaskError as exc:
            raise GrantError(str(exc)) from None
    if not cols:
        raise GrantError(f"table {table!r} not found or has no columns")
    return TableCatalog(cols)


class _SfFilter:
    def __init__(self, tokens: list[tuple[str, str]], table_alias: str | None = None) -> None:
        self.toks = tokens
        self.i = 0
        self.columns: set[str] = set()
        self.table_alias = table_alias

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

    def parse(self) -> str:
        out = self.expr(0)
        if self.i != len(self.toks):
            raise RowFilterError(f"unexpected token {self.toks[self.i][1]!r}")
        return out

    def expr(self, depth: int) -> str:
        parts = [self.term(depth)]
        while self._peek_word() == "or":
            self.i += 1
            parts.append(self.term(depth))
        return parts[0] if len(parts) == 1 else " OR ".join(parts)

    def term(self, depth: int) -> str:
        parts = [self.factor(depth)]
        while self._peek_word() == "and":
            self.i += 1
            parts.append(self.factor(depth))
        return parts[0] if len(parts) == 1 else " AND ".join(parts)

    def factor(self, depth: int) -> str:
        from datagrant.sf.grant import q

        if depth > MAX_DEPTH:
            raise RowFilterError("row filter nested too deeply")
        kind, val = self._next("a condition")
        if kind == "paren" and val == "(":
            inner = self.expr(depth + 1)
            if self._next("')'") != ("paren", ")"):
                raise RowFilterError("expected ')'")
            return f"({inner})"
        if kind != "word" or val.lower() in _KEYWORDS:
            raise RowFilterError(f"expected a column name, got {val!r}")
        ident = q(val)
        self.columns.add(val)
        col = f"{q(self.table_alias)}.{ident}" if self.table_alias else ident
        if self._peek_word() == "is":
            self.i += 1
            neg = self._peek_word() == "not"
            if neg:
                self.i += 1
            if self._next("NULL")[1].lower() != "null":
                raise RowFilterError("expected NULL after IS")
            return f"{col} IS NOT NULL" if neg else f"{col} IS NULL"
        okind, op = self._next("a comparison operator")
        if okind != "op":
            raise RowFilterError(f"expected a comparison operator, got {op!r}")
        op = "<>" if op == "!=" else op
        return f"{col} {op} {self.literal()}"

    def literal(self) -> str:
        from datagrant.sf.grant import lit

        kind, val = self._next("a literal")
        if kind == "str":
            return lit(val[1:-1].replace("''", "'"))
        if kind == "num":
            return val
        if kind == "word" and val.lower() in ("true", "false"):
            return val.upper()
        raise RowFilterError(f"expected a literal, got {val!r}")


def render_row_filter(text: str, *, table_alias: str | None = None) -> tuple[str, frozenset[str]]:
    """Re-emit a policy row filter as Snowflake SQL. Never interpolates raw text."""
    p = _SfFilter(_tokenize(text), table_alias=table_alias)
    return p.parse(), frozenset(p.columns)
