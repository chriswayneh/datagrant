from __future__ import annotations

import base64
import re
from datetime import UTC, datetime, timedelta

import pytest

from datagrant.keys import HashKey
from datagrant.pg.grant import GrantError, build_plan, new_password
from datagrant.pg.mask import ColumnType, TableCatalog
from datagrant.pg.scram import scram_verifier
from datagrant.policy import Decision, Request

NOW = datetime(2026, 11, 2, 23, 0, tzinfo=UTC)
CAT = TableCatalog(
    {"id": ColumnType("pg_catalog", "int4"), "zip": ColumnType("pg_catalog", "text")}, "public"
)
KEY = HashKey("0123456789abcdef", b"k" * 32)


def req(**kw: object) -> Request:
    base: dict[str, object] = {
        "requester": "alice",
        "dataset": "clinic",
        "table": "public.patients",
        "columns": ("id", "zip"),
        "duration": timedelta(hours=2),
        "purpose": "eval",
        "row_filter": "region = 'west'",
    }
    base.update(kw)
    return Request(**base)  # type: ignore[arg-type]


def dec(masks: dict[str, str] | None = None, **kw: object) -> Decision:
    base: dict[str, object] = {
        "allowed": True,
        "reasons": ("ok",),
        "approval": "auto",
        "policy_sha256": "f" * 64,
        "masks": masks or {"id": "passthrough", "zip": "null"},
    }
    base.update(kw)
    return Decision(**base)  # type: ignore[arg-type]


def test_plan_sql() -> None:
    plan = build_plan(
        dec(),
        req(),
        database="clinicdb",
        password="Zq9-never-in-sql-Xk",
        catalog=CAT,
        grant_id="abcdef012345",
        now=NOW,
    )
    assert plan.role == "dg_abcdef012345" and plan.view == "datagrant_views.g_abcdef012345"
    assert plan.database == "clinicdb"
    assert plan.expires_at == NOW + timedelta(hours=2)
    text = [s.as_string(None) for s in plan.statements]
    assert text[0].startswith('CREATE ROLE "dg_abcdef012345" LOGIN NOINHERIT')
    assert "'2026-11-03T01:00:00+00:00'" in text[0]
    assert "Zq9-never-in-sql-Xk" not in text[0] and "SCRAM-SHA-256$4096:" in text[0]
    assert text[1] == (
        'CREATE VIEW "datagrant_views"."g_abcdef012345" WITH (security_barrier = true) AS '
        'SELECT "id", CAST(NULL AS "pg_catalog"."text") AS "zip" FROM "public"."patients" WHERE "region" = \'west\''
    )
    assert text[4] == 'GRANT SELECT ON "datagrant_views"."g_abcdef012345" TO "dg_abcdef012345"'
    # The SCRAM verifier is random base64, so a short password can appear in it by
    # chance; use a distinctive password that cannot.
    assert all("Zq9-never-in-sql-Xk" not in t for t in text)


def test_plan_without_filter_and_random_id() -> None:
    plan = build_plan(
        dec(), req(row_filter=None), database="db", password="x", catalog=CAT, now=NOW
    )
    assert re.fullmatch(r"dg_[0-9a-f]{12}", plan.role)
    assert "WHERE" not in plan.statements[1].as_string(None)


@pytest.mark.parametrize(
    ("kwargs", "msg"),
    [
        ({"decision": dec(allowed=False)}, "denied"),
        ({"decision": dec(approval="two-person")}, "two-person"),
        ({"decision": dec({"id": "hash", "zip": "null"})}, "requires a hash key"),
        (
            {
                "decision": dec({"id": "hash", "zip": "null"}),
                "hash_key": KEY,
                "catalog": TableCatalog(CAT.columns, None),
            },
            "pgcrypto",
        ),
        ({"catalog": TableCatalog({"id": CAT.columns["id"]}, None)}, "does not exist"),
        ({"grant_id": "DROP"}, "12 lowercase hex"),
        ({"now": datetime(2026, 1, 1)}, "timezone-aware"),
    ],
)
def test_plan_errors(kwargs: dict[str, object], msg: str) -> None:
    args: dict[str, object] = {
        "decision": dec(),
        "database": "db",
        "catalog": CAT,
        "password": "x",
        "now": NOW,
    }
    args.update(kwargs)
    d = args.pop("decision")
    with pytest.raises(GrantError, match=msg):
        build_plan(d, req(), **args)  # type: ignore[arg-type]


def test_password_random_and_long() -> None:
    a, b = new_password(), new_password()
    assert a != b and len(a) >= 40


def test_scram_format_and_known_vector() -> None:
    v = scram_verifier("pencil", salt=b"\x00" * 16)
    head, keys = v.split("$", 1)[1].split("$")
    iters, salt = head.split(":")
    assert iters == "4096" and base64.b64decode(salt) == b"\x00" * 16
    assert all(len(base64.b64decode(k)) == 32 for k in keys.split(":"))
    assert scram_verifier("pencil", salt=b"\x00" * 16) == v != scram_verifier("pencil")


def test_hash_plan_carries_key_but_sql_does_not() -> None:
    plan = build_plan(
        dec({"id": "hash", "zip": "passthrough"}),
        req(),
        database="db",
        password="x",
        catalog=CAT,
        hash_key=KEY,
        now=NOW,
    )
    scoped = KEY.scoped("clinic")
    assert plan.hash_key == scoped and "k" * 32 not in repr(plan)
    view = plan.statements[1].as_string(None)
    assert f"'{scoped.key_id}'" in view and "kkkk" not in view
    assert "'0123456789abcdef'" not in view
    no_hash = build_plan(dec(), req(), database="db", password="x", catalog=CAT, hash_key=KEY)
    assert no_hash.hash_key is None


def test_hash_scope_changes_key_per_dataset() -> None:
    def key_for(**kw: object) -> str:
        p = build_plan(
            dec({"id": "hash", "zip": "passthrough"}, **kw),
            req(),
            database="db",
            password="x",
            catalog=CAT,
            hash_key=KEY,
            now=NOW,
        )
        assert p.hash_key is not None
        return p.hash_key.key_id

    default = key_for()
    assert default == key_for(hash_scope="clinic") == KEY.scoped("clinic").key_id
    assert key_for(hash_scope="other") != default
