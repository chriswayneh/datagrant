"""Integration tests against a real Postgres. Set DATAGRANT_TEST_DSN (superuser) to run."""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from psycopg import sql

from datagrant.pg.grant import GrantError, apply_plan, build_plan, ensure_state, new_password
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
                        "name": "public.dg_patients",
                        "allowed_groups": ["ml"],
                        "columns": {"id": "passthrough", "zip": "null", "name": "passthrough"},
                        "row_filters": ["region = 'west'"],
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
        conn.execute("DROP TABLE IF EXISTS public.dg_patients")
        conn.execute(
            "CREATE TABLE public.dg_patients (id int, zip text, name text, ssn text, region text)"
        )
        conn.execute(
            "INSERT INTO public.dg_patients VALUES"
            " (1,'90210','Test One','000-00-0001','west'),"
            " (2,'10001','Test Two','000-00-0002','east')"
        )
        ensure_state(conn)
        ensure_state(conn)  # idempotent
        yield conn
        rows = conn.execute("SELECT role_name, view_name FROM datagrant.grants").fetchall()
        for role, view in rows:
            conn.execute(sql.SQL("DROP VIEW IF EXISTS {}").format(sql.Identifier(*view.split("."))))
            conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        conn.execute("TRUNCATE datagrant.grants")
        conn.execute("DROP TABLE public.dg_patients")


def _grant(admin: psycopg.Connection, now: datetime | None = None, **kw: object) -> tuple:
    base: dict[str, object] = {
        "requester": "alice",
        "dataset": "clinic",
        "table": "public.dg_patients",
        "columns": ("id", "zip"),
        "duration": timedelta(hours=1),
        "purpose": "test",
        "row_filter": "region = 'west'",
    }
    base.update(kw)
    req = Request(**base)  # type: ignore[arg-type]
    d = evaluate(POLICY, req)
    assert d.allowed, d.reasons
    pw = new_password()
    plan = build_plan(d, req, password=pw, now=now)
    apply_plan(admin, plan)
    return plan, pw


def _login(role: str, pw: str) -> psycopg.Connection:
    info = psycopg.conninfo.conninfo_to_dict(DSN)
    info.update(user=role, password=pw, host=info.get("host") or "localhost")
    return psycopg.connect(**info, autocommit=True)


def test_grant_role_sees_only_view(admin: psycopg.Connection) -> None:
    plan, pw = _grant(admin)
    with _login(plan.role, pw) as c:
        rows = c.execute(f"SELECT * FROM {plan.view}").fetchall()
        assert rows == [(1, None)]  # row filter applied, zip nulled, other columns absent
        for q in ("SELECT * FROM public.dg_patients", "SELECT * FROM datagrant.grants"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(q)
    row = admin.execute(
        "SELECT role_name, view_name, policy_sha256, status, expires_at FROM datagrant.grants"
    ).fetchone()
    assert row is not None
    assert row[:4] == (plan.role, plan.view, "a" * 64, "active") and row[4] == plan.expires_at
    until = admin.execute("SELECT rolvaliduntil FROM pg_roles WHERE rolname = %s", (plan.role,))
    assert until.fetchone() == (plan.expires_at,)


def test_wrong_password_rejected(admin: psycopg.Connection) -> None:
    plan, _ = _grant(admin)
    with pytest.raises(psycopg.OperationalError):
        _login(plan.role, "wrong")


def test_expired_role_cannot_login(admin: psycopg.Connection) -> None:
    plan, pw = _grant(admin, now=datetime.now(UTC) - timedelta(hours=2))
    with pytest.raises(psycopg.OperationalError):
        _login(plan.role, pw)


def test_failure_rolls_back(admin: psycopg.Connection) -> None:
    admin.execute("ALTER TABLE public.dg_patients DROP COLUMN id")
    with pytest.raises(GrantError, match="rolled back"):
        _grant(admin)
    assert admin.execute("SELECT count(*) FROM datagrant.grants").fetchone() == (0,)
    roles = admin.execute("SELECT count(*) FROM pg_roles WHERE rolname LIKE 'dg\\_%'")
    assert roles.fetchone() == (0,)
