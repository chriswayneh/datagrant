"""Integration tests against a real Postgres. Set DATAGRANT_TEST_DSN (superuser) to run."""

from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from psycopg import sql

from datagrant.keys import HashKey
from datagrant.pg.grant import (
    GrantError,
    apply_plan,
    build_plan,
    ensure_state,
    new_password,
    preflight,
)
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
                        "name": "public.dg_patients",
                        "allowed_groups": ["ml"],
                        "columns": {
                            "id": "passthrough",
                            "zip": "null",
                            "name": "passthrough",
                            "region": "passthrough",
                            "ssn": "hash",
                            "dob": "null",
                            "phone": "partial",
                            "notes": "redact",
                        },
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
            "CREATE TABLE public.dg_patients (id int, zip text, name text, ssn text,"
            " region text, dob date, phone text, notes text)"
        )
        conn.execute(
            "INSERT INTO public.dg_patients VALUES"
            " (1,'90210','Test One','000-00-0001','west','1990-01-01','555-0100-1234','n1'),"
            " (2,'10001','Test Two','000-00-0002','east','1980-01-01','555-0199','n2'),"
            " (3,'10002','Test Three',NULL,'west',NULL,'12',NULL)"
        )
        conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        ensure_state(conn)
        ensure_state(conn)  # idempotent
        yield conn
        rows = conn.execute("SELECT role_name, view_name FROM datagrant.grants").fetchall()
        for role, view in rows:
            conn.execute(sql.SQL("DROP VIEW IF EXISTS {}").format(sql.Identifier(*view.split("."))))
            conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        conn.execute("TRUNCATE datagrant.grants, datagrant.hash_keys")
        conn.execute("DROP TABLE public.dg_patients")


def _grant(
    admin: psycopg.Connection,
    now: datetime | None = None,
    database: str = "postgres",
    hash_key: HashKey | None = None,
    before_apply: str | None = None,
    **kw: object,
) -> tuple:
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
    plan = build_plan(
        d,
        req,
        database=database,
        password=pw,
        now=now,
        catalog=inspect_table(admin, req.table),
        hash_key=hash_key,
    )
    if before_apply:
        admin.execute(before_apply)  # simulate the table changing between plan and apply
    apply_plan(admin, plan)
    return plan, pw


def _login(role: str, pw: str, dbname: str | None = None) -> psycopg.Connection:
    info = psycopg.conninfo.conninfo_to_dict(DSN)
    info.update(user=role, password=pw, host=info.get("host") or "localhost")
    if dbname:
        info["dbname"] = dbname
    return psycopg.connect(**info, autocommit=True)


def test_grant_role_sees_only_view(admin: psycopg.Connection) -> None:
    plan, pw = _grant(admin)
    with _login(plan.role, pw) as c:
        rows = c.execute(f"SELECT * FROM {plan.view}").fetchall()
        assert sorted(rows) == [
            (1, None),
            (3, None),
        ]  # row filter applied, zip nulled, other columns absent
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
    with pytest.raises(GrantError, match="rolled back"):
        _grant(admin, before_apply="ALTER TABLE public.dg_patients DROP COLUMN id")
    assert admin.execute("SELECT count(*) FROM datagrant.grants").fetchone() == (0,)
    roles = admin.execute("SELECT count(*) FROM pg_roles WHERE rolname LIKE 'dg\\_%'")
    assert roles.fetchone() == (0,)


def test_database_mismatch_refused(admin: psycopg.Connection) -> None:
    with pytest.raises(GrantError, match="dataset is in 'clinicdb'"):
        _grant(admin, database="clinicdb")
    assert admin.execute("SELECT count(*) FROM datagrant.grants").fetchone() == (0,)
    roles = admin.execute("SELECT count(*) FROM pg_roles WHERE rolname LIKE 'dg\\_%'")
    assert roles.fetchone() == (0,)


@pytest.fixture
def other_db(admin: psycopg.Connection) -> Iterator[str]:
    admin.execute("DROP DATABASE IF EXISTS dg_other")
    admin.execute("CREATE DATABASE dg_other")
    yield "dg_other"
    admin.execute("DROP DATABASE IF EXISTS dg_other WITH (FORCE)")


def test_preflight_and_hardening(admin: psycopg.Connection, other_db: str) -> None:
    warnings = preflight(admin)
    assert "PUBLIC can CONNECT to database dg_other" in warnings
    assert any("TEMP" in w for w in warnings)
    plan, pw = _grant(admin)
    _login(plan.role, pw, other_db).close()  # default PUBLIC CONNECT: reachable
    admin.execute("REVOKE CONNECT, TEMP ON DATABASE dg_other FROM PUBLIC")
    assert "PUBLIC can CONNECT to database dg_other" not in preflight(admin)
    with pytest.raises(psycopg.OperationalError):
        _login(plan.role, pw, other_db)


KEY_A = HashKey("aaaaaaaaaaaaaaaa", b"A" * 32)
KEY_B = HashKey("bbbbbbbbbbbbbbbb", b"B" * 32)
MASKED = ("id", "ssn", "dob", "phone", "notes")


def _hmac(key: HashKey, value: str) -> str:
    return hmac.new(key.derived, value.encode(), hashlib.sha256).hexdigest()


def test_grantee_sees_masked_values_only(admin: psycopg.Connection) -> None:
    plan, pw = _grant(admin, hash_key=KEY_A, columns=MASKED)
    with _login(plan.role, pw) as c:
        rows = sorted(c.execute(f"SELECT {', '.join(MASKED)} FROM {plan.view}").fetchall())
        types = c.execute(
            "SELECT format_type(atttypid, atttypmod) FROM pg_attribute"
            " WHERE attrelid = %s::regclass AND attname = 'dob'",
            (plan.view,),
        ).fetchone()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT key FROM datagrant.hash_keys")
        viewdef = c.execute("SELECT pg_get_viewdef(%s::regclass)", (plan.view,)).fetchone()
    assert rows == [
        (1, _hmac(KEY_A, "000-00-0001"), None, "*********1234", "[REDACTED]"),
        (3, None, None, "**", "[REDACTED]"),
    ]
    assert types == ("date",)  # typed NULL keeps the column type
    assert viewdef is not None
    for secret in (KEY_A.derived.hex(), KEY_A.derived.decode()):
        assert secret not in viewdef[0]


def test_hash_stable_per_key(admin: psycopg.Connection) -> None:
    def ssn_hash(key: HashKey) -> str:
        plan, pw = _grant(admin, hash_key=key, columns=("id", "ssn"))
        with _login(plan.role, pw) as c:
            row = c.execute(f"SELECT ssn FROM {plan.view} WHERE id = 1").fetchone()
        assert row is not None
        return str(row[0])

    a1, a2, b = ssn_hash(KEY_A), ssn_hash(KEY_A), ssn_hash(KEY_B)
    assert a1 == a2 != b
    assert admin.execute("SELECT count(*) FROM datagrant.hash_keys").fetchone() == (2,)


def test_hash_without_pgcrypto_fails_closed(admin: psycopg.Connection) -> None:
    admin.execute("DROP EXTENSION pgcrypto")
    try:
        with pytest.raises(GrantError, match="pgcrypto"):
            _grant(admin, hash_key=KEY_A, columns=("id", "ssn"))
    finally:
        admin.execute("CREATE EXTENSION pgcrypto")
    assert admin.execute("SELECT count(*) FROM datagrant.grants").fetchone() == (0,)


def test_view_ignores_shadow_functions_on_search_path(admin: psycopg.Connection) -> None:
    # CVE-2018-1058 class: a lookalike in a schema on the admin's path must not be bound.
    admin.execute("CREATE SCHEMA IF NOT EXISTS dg_evil")
    admin.execute(
        "CREATE OR REPLACE FUNCTION dg_evil.length(text) RETURNS integer"
        " LANGUAGE sql AS 'SELECT 99'"
    )
    admin.execute("SET search_path = dg_evil, public, pg_catalog")
    try:
        plan, pw = _grant(admin, hash_key=KEY_A, columns=MASKED)
    finally:
        admin.execute("RESET search_path")
        admin.execute("DROP SCHEMA dg_evil CASCADE")
    with _login(plan.role, pw) as c:
        rows = sorted(c.execute(f"SELECT {', '.join(MASKED)} FROM {plan.view}").fetchall())
    assert [r[3] for r in rows] == ["*********1234", "**"]
