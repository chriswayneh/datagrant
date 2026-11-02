"""Column masking expressions for grant views (unit U3).

Every expression is composed with psycopg.sql; types and the pgcrypto schema
come from the catalog. The hash key is never embedded in SQL: the view reads it
via a scalar subquery on datagrant.hash_keys, which only the view owner can read.
"""

from __future__ import annotations

from dataclasses import dataclass

import psycopg
from psycopg import sql

REDACTED = "[REDACTED]"
PARTIAL_KEEP = 4
PARTIAL_MIN_LEN = 8
STATE_SCHEMA = "datagrant"


class MaskError(RuntimeError):
    """Raised when a column cannot be masked safely (fail closed)."""


@dataclass(frozen=True)
class ColumnType:
    schema: str
    name: str


@dataclass(frozen=True)
class TableCatalog:
    columns: dict[str, ColumnType]
    pgcrypto_schema: str | None


_COLUMNS_SQL = sql.SQL(
    "SELECT a.attname, tn.nspname, t.typname FROM pg_attribute a"
    " JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace cn ON cn.oid = c.relnamespace"
    " JOIN pg_type t ON t.oid = a.atttypid JOIN pg_namespace tn ON tn.oid = t.typnamespace"
    " WHERE cn.nspname = %s AND c.relname = %s AND a.attnum > 0 AND NOT a.attisdropped"
)
_PGCRYPTO_SQL = sql.SQL(
    "SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace"
    " WHERE e.extname = 'pgcrypto'"
)


def inspect_table(conn: psycopg.Connection, table: str) -> TableCatalog:
    """Read column types for schema.table and locate pgcrypto."""
    schema, name = table.split(".", 1)
    rows = conn.execute(_COLUMNS_SQL, (schema, name)).fetchall()
    if not rows:
        raise MaskError(f"table {table!r} not found or has no columns")
    ext = conn.execute(_PGCRYPTO_SQL).fetchone()
    return TableCatalog({r[0]: ColumnType(r[1], r[2]) for r in rows}, ext[0] if ext else None)


def column_expr(
    col: str, mask: str, catalog: TableCatalog, *, hash_key_id: str | None = None
) -> sql.Composable:
    """SELECT-list expression for one column under its mask, aliased to the column name."""
    ctype = catalog.columns.get(col)
    if ctype is None:
        raise MaskError(f"column {col!r} does not exist in the table")
    ident = sql.Identifier(col)
    as_text = sql.SQL("CAST({} AS text)").format(ident)
    if mask == "passthrough":
        return ident
    if mask == "null":
        expr: sql.Composable = sql.SQL("CAST(NULL AS {})").format(
            sql.Identifier(ctype.schema, ctype.name)
        )
    elif mask == "redact":
        expr = sql.SQL("CAST({} AS text)").format(sql.Literal(REDACTED))
    elif mask == "partial":
        expr = sql.SQL(
            "CASE WHEN length({v}) >= {min} THEN repeat('*', length({v}) - {keep}) || right({v}, {keep})"
            " ELSE repeat('*', length({v})) END"
        ).format(v=as_text, min=sql.Literal(PARTIAL_MIN_LEN), keep=sql.Literal(PARTIAL_KEEP))
    elif mask == "hash":
        if catalog.pgcrypto_schema is None:
            raise MaskError(
                "hash masking needs the pgcrypto extension in this database"
                " (DBA: CREATE EXTENSION pgcrypto)"
            )
        if hash_key_id is None:
            raise MaskError("hash masking needs a hash key")
        expr = sql.SQL(
            "encode({hmac}(convert_to({v}, 'UTF8'),"
            " (SELECT k.key FROM {keys} k WHERE k.id = {kid}), 'sha256'), 'hex')"
        ).format(
            hmac=sql.Identifier(catalog.pgcrypto_schema, "hmac"),
            v=as_text,
            keys=sql.Identifier(STATE_SCHEMA, "hash_keys"),
            kid=sql.Literal(hash_key_id),
        )
    else:
        raise MaskError(f"unknown mask {mask!r} on column {col!r}")
    return sql.SQL("{} AS {}").format(expr, ident)
