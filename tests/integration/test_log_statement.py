"""SET LOCAL log_statement on a live Postgres. Set DATAGRANT_TEST_DSN."""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest
from psycopg import sql

from datagrant.keys import HashKey
from datagrant.pg.grant import apply_plan, build_plan, can_set_log_statement, ensure_state
from datagrant.pg.mask import inspect_table
from datagrant.policy import Request, evaluate, parse_policy

DSN = os.environ.get("DATAGRANT_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DATAGRANT_TEST_DSN not set")

POLICY = parse_policy(
    {
        "version": 1,
        "max_duration": "8h",
        "groups": {"ml": ["alice"]},
        "datasets": [
            {
                "name": "clinic",
                "database": "postgres",
                "tables": [
                    {
                        "name": "public.dg_logstmt",
                        "allowed_groups": ["ml"],
                        "columns": {"id": "passthrough", "zip": "null"},
                    }
                ],
            }
        ],
    },
    "a" * 64,
)


@pytest.fixture
def admin() -> Iterator[psycopg.Connection]:
    assert DSN
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS public.dg_logstmt")
        conn.execute("CREATE TABLE public.dg_logstmt (id int, zip text)")
        conn.execute("INSERT INTO public.dg_logstmt VALUES (1, '90210')")
        ensure_state(conn)
        yield conn
        rows = conn.execute("SELECT role_name, view_name FROM datagrant.grants").fetchall()
        for role, view in rows:
            conn.execute(sql.SQL("DROP VIEW IF EXISTS {}").format(sql.Identifier(*view.split("."))))
            if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        conn.execute("TRUNCATE datagrant.grants, datagrant.hash_keys")
        conn.execute("DROP TABLE public.dg_logstmt")


def _sql_text(q: Any) -> str:
    if hasattr(q, "as_string"):
        try:
            return str(q.as_string(None))
        except Exception:  # noqa: BLE001 - Composed.as_string needs a connection
            return str(q)
    return str(q)


def test_apply_plan_issues_set_local_log_statement(admin: psycopg.Connection) -> None:
    assert can_set_log_statement(admin)
    seen: list[Any] = []
    orig = admin.execute

    def wrapped(q: Any, params: Any = None) -> Any:
        seen.append(q)
        return orig(q, params)

    admin.execute = wrapped  # type: ignore[method-assign]
    req = Request(
        "alice",
        "clinic",
        "public.dg_logstmt",
        ("id", "zip"),
        timedelta(hours=1),
        "eval",
        None,
    )
    d = evaluate(POLICY, req)
    assert d.allowed, d.reasons
    plan = build_plan(
        d,
        req,
        database="postgres",
        password="Zq9-never-logged-Xk",
        now=datetime.now(UTC),
        catalog=inspect_table(admin, req.table),
        hash_key=HashKey("0123456789abcdef", b"k" * 32),
    )
    apply_plan(admin, plan, receipts=None)
    texts = [_sql_text(q).lower() for q in seen]
    log_i = next(i for i, t in enumerate(texts) if "log_statement" in t and "none" in t)
    key_i = next(i for i, t in enumerate(texts) if "hash_keys" in t)
    role_i = next(i for i, t in enumerate(texts) if "create role" in t)
    assert log_i < key_i < role_i
    assert "set local log_statement" in texts[log_i]
