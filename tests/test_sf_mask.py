"""Snowflake catalog inspect and row-filter emit."""

from __future__ import annotations

from typing import Any

import pytest

from datagrant.rowfilter import RowFilterError
from datagrant.sf.grant import GrantError
from datagrant.sf.mask import inspect_table, render_row_filter


class _Conn:
    def __init__(self, rows: list[tuple[Any, ...]] | None = None) -> None:
        self.rows = rows if rows is not None else [("PATIENT_ID", "NUMBER"), ("SSN", "VARCHAR(10)")]
        self.sql = ""
        self.params: Any = None

    def cursor(self) -> _Conn:
        return self

    def execute(self, sql: str, params: Any = None) -> _Conn:
        self.sql = sql
        self.params = params
        return self

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self.rows)


def test_inspect_table_qmark_and_types() -> None:
    conn = _Conn()
    cat = inspect_table(conn, "PUBLIC.PATIENTS", database="CLINIC_DB")
    assert cat.columns == {"PATIENT_ID": "NUMBER", "SSN": "VARCHAR"}
    assert "INFORMATION_SCHEMA" in conn.sql
    assert "COLUMN_NAME" in conn.sql
    assert "?" in conn.sql
    assert conn.params == ("PUBLIC", "PATIENTS")
    where = conn.sql.split("WHERE", 1)[1]
    assert "PUBLIC" not in where and "PATIENTS" not in where


def test_inspect_table_missing_raises() -> None:
    with pytest.raises(GrantError, match="not found"):
        inspect_table(_Conn(rows=[]), "PUBLIC.MISSING", database="CLINIC_DB")


def test_inspect_rejects_unsafe_type() -> None:
    with pytest.raises(GrantError, match="unsupported column type"):
        inspect_table(_Conn(rows=[("X", "VARCHAR); DROP")]), "PUBLIC.T", database="DB")


def test_render_row_filter_quotes_idents_and_lits() -> None:
    sql, cols = render_row_filter("REGION = 'west' AND PATIENT_ID <> 0")
    assert sql == '"REGION" = \'west\' AND "PATIENT_ID" <> 0'
    assert cols == frozenset({"REGION", "PATIENT_ID"})
    sql, _ = render_row_filter("REGION = 'O''Brien'")
    assert sql == "\"REGION\" = 'O''Brien'"
    sql, _ = render_row_filter("FLAG IS NOT NULL OR FLAG = TRUE")
    assert sql == '"FLAG" IS NOT NULL OR "FLAG" = TRUE'


def test_render_row_filter_qualifies_table_alias() -> None:
    sql, cols = render_row_filter("SSN IS NULL AND REGION = 'west'", table_alias="SRC")
    assert sql == '"SRC"."SSN" IS NULL AND "SRC"."REGION" = \'west\''
    assert cols == frozenset({"SSN", "REGION"})


def test_render_row_filter_rejects_injection() -> None:
    with pytest.raises(RowFilterError):
        render_row_filter("REGION = 'west'; DROP TABLE X")
    with pytest.raises(RowFilterError):
        render_row_filter("1 = 1")
