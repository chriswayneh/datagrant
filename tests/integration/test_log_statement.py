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
from datagrant.pg.requests import create_request
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
                        "columns": {"id": "passthrough", "zip": "hash"},
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
        conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        ensure_state(conn)
        yield conn
        rows = conn.execute("SELECT role_name, view_name FROM datagrant.grants").fetchall()
        for role, view in rows:
            conn.execute(sql.SQL("DROP VIEW IF EXISTS {}").format(sql.Identifier(*view.split("."))))
            if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        conn.execute("TRUNCATE datagrant.grants, datagrant.hash_keys, datagrant.requests")
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

    def _idx(needle: str, *, extra: str | None = None) -> int:
        for i, t in enumerate(texts):
            if needle in t and (extra is None or extra in t):
                return i
        raise AssertionError(f"missing {needle!r} in captured SQL: {texts!r}")

    log_i = _idx("log_statement", extra="none")
    key_i = _idx("hash_keys")
    role_i = _idx("create role")
    assert log_i < key_i < role_i
    assert "set local log_statement" in texts[log_i]


def test_create_request_verifier_absent_from_captured_sql(admin: psycopg.Connection) -> None:
    """Two-person pending INSERT binds the SCRAM verifier after SET LOCAL log_statement."""
    assert can_set_log_statement(admin)
    verifier = "SCRAM-SHA-256$sentinel-not-in-sql-Zq9"
    seen: list[tuple[Any, Any]] = []
    orig = admin.execute

    def wrapped(q: Any, params: Any = None) -> Any:
        seen.append((q, params))
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
    pending = create_request(
        admin,
        req,
        policy_sha256="a" * 64,
        verifier=verifier,
        ttl=timedelta(hours=1),
    )
    assert pending.verifier == verifier
    texts = [_sql_text(q) for q, _p in seen]
    joined = "\n".join(texts)
    assert verifier not in joined
    log_i = next(
        i for i, t in enumerate(texts) if "log_statement" in t.lower() and "none" in t.lower()
    )
    ins_i = next(i for i, t in enumerate(texts) if "insert" in t.lower() and "requests" in t.lower())
    assert log_i < ins_i
    insert_params = seen[ins_i][1]
    assert insert_params is not None and verifier in insert_params
