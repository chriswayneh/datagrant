"""Integration tests against a real Postgres. Set DATAGRANT_TEST_DSN (superuser) to run."""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from psycopg import sql

from datagrant.keys import HashKey, init_keys, load_signing_key
from datagrant.pg.grant import (
    GrantError,
    ReceiptSink,
    apply_plan,
    build_plan,
    ensure_state,
    new_password,
    preflight,
)
from datagrant.pg.mask import inspect_table
from datagrant.pg.revoke import revoke, sweep
from datagrant.policy import Request, evaluate, parse_policy
from datagrant.receipt import verify

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
            if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        conn.execute("TRUNCATE datagrant.grants, datagrant.hash_keys")
        conn.execute("DROP TABLE public.dg_patients")


def _grant(
    admin: psycopg.Connection,
    now: datetime | None = None,
    database: str = "postgres",
    hash_key: HashKey | None = None,
    before_apply: str | None = None,
    receipts: ReceiptSink | None = None,
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
    apply_plan(admin, plan, receipts)
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


# --- U4: revoke and sweep ---


def _role_exists(c: psycopg.Connection, role: str) -> bool:
    return c.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone() is not None


def _view_exists(c: psycopg.Connection, view: str) -> bool:
    return c.execute("SELECT to_regclass(%s)", (view,)).fetchone() != (None,)


def _state(c: psycopg.Connection, gid: str) -> tuple:
    row = c.execute(
        "SELECT status, revoke_reason, revoked_at IS NOT NULL, last_error FROM datagrant.grants"
        " WHERE id = %s",
        (gid,),
    ).fetchone()
    assert row is not None
    return row


def test_revoke_kills_session_and_drops_everything(admin: psycopg.Connection) -> None:
    plan, pw = _grant(admin)
    session = _login(plan.role, pw)
    session.execute(f"SELECT * FROM {plan.view}")
    res = revoke(admin, plan.grant_id)
    assert res.outcome == "revoked" and res.sessions_terminated == 1
    with pytest.raises(psycopg.OperationalError):
        session.execute("SELECT 1")
    session.close()
    assert not _role_exists(admin, plan.role)
    assert not _view_exists(admin, plan.view)
    assert _state(admin, plan.grant_id) == ("revoked", "manual", True, None)
    assert revoke(admin, plan.grant_id).outcome == "noop"  # idempotent


def test_sweep_only_expired(admin: psycopg.Connection) -> None:
    old, _ = _grant(admin, now=datetime.now(UTC) - timedelta(hours=2))
    live, live_pw = _grant(admin)
    results = sweep(admin)
    assert [(r.grant_id, r.outcome) for r in results] == [(old.grant_id, "revoked")]
    assert _state(admin, old.grant_id) == ("expired", "expired", True, None)
    assert not _role_exists(admin, old.role) and not _view_exists(admin, old.view)
    assert _state(admin, live.grant_id)[0] == "active"
    with _login(live.role, live_pw) as c:
        assert c.execute(f"SELECT count(*) FROM {live.view}").fetchone() == (2,)
    assert sweep(admin) == []  # re-run is a no-op


def test_failure_is_recorded_not_marked_revoked(admin: psycopg.Connection) -> None:
    plan, pw = _grant(admin)
    admin.execute(f"CREATE VIEW public.dg_dependent AS SELECT * FROM {plan.view}")
    try:
        res = revoke(admin, plan.grant_id)
        assert res.outcome == "failed" and res.error
        status, reason, revoked, err = _state(admin, plan.grant_id)
        assert (status, reason, revoked) == ("active", None, False) and err
        assert _role_exists(admin, plan.role) and _view_exists(admin, plan.view)
        with pytest.raises(psycopg.OperationalError):
            _login(plan.role, pw)  # best effort NOLOGIN after failure
    finally:
        admin.execute("DROP VIEW public.dg_dependent")
    assert revoke(admin, plan.grant_id).outcome == "revoked"  # retried successfully
    assert _state(admin, plan.grant_id)[3] is None


def test_revoke_unknown_grant(admin: psycopg.Connection) -> None:
    with pytest.raises(GrantError, match="unknown grant"):
        revoke(admin, "000000000000")


def test_revoke_wins_against_reconnect_loop(admin: psycopg.Connection) -> None:
    plan, pw = _grant(admin)  # not expired: manual revoke
    stop = threading.Event()
    stats = {"ok": 0, "fail": 0}

    def loop() -> None:
        while not stop.is_set():
            try:
                with _login(plan.role, pw) as c:
                    stats["ok"] += 1
                    c.execute("SELECT pg_sleep(0.01)")
            except psycopg.Error:
                stats["fail"] += 1

    threads = [threading.Thread(target=loop) for _ in range(3)]
    for t in threads:
        t.start()
    try:
        deadline = time.monotonic() + 5
        while stats["ok"] == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert stats["ok"] > 0  # the loop really was logged in
        res = revoke(admin, plan.grant_id)
        assert res.outcome == "revoked", res.error
        fails_before = stats["fail"]
        time.sleep(0.3)
        assert stats["fail"] > fails_before  # reconnects keep failing
    finally:
        stop.set()
        for t in threads:
            t.join()
    left = admin.execute(
        "SELECT count(*) FROM pg_stat_activity WHERE usename = %s", (plan.role,)
    ).fetchone()
    assert left == (0,)
    assert not _role_exists(admin, plan.role)
    with pytest.raises(psycopg.OperationalError):
        _login(plan.role, pw)


# --- U5: receipts ---


@pytest.fixture
def sink(tmp_path):  # type: ignore[no-untyped-def]
    _, sp, _ = init_keys(tmp_path / "keys")
    return ReceiptSink(tmp_path / "receipts.jsonl", load_signing_key(sp), host="test-host")


def _events(sink: ReceiptSink) -> list[dict]:
    import json

    return [json.loads(x)["receipt"] for x in sink.log.read_text().splitlines()]


def test_receipts_for_issue_revoke_sweep_and_failure(admin: psycopg.Connection, sink) -> None:  # type: ignore[no-untyped-def]
    plan, pw = _grant(admin, hash_key=KEY_A, columns=MASKED, receipts=sink)
    old, _ = _grant(admin, now=datetime.now(UTC) - timedelta(hours=2), receipts=sink)
    stuck, _ = _grant(admin, receipts=sink)
    assert revoke(admin, plan.grant_id, receipts=sink).receipt_error is None
    assert [r.outcome for r in sweep(admin, receipts=sink)] == ["revoked"]
    admin.execute(f"CREATE VIEW public.dg_dependent AS SELECT * FROM {stuck.view}")
    try:
        assert revoke(admin, stuck.grant_id, receipts=sink).outcome == "failed"
    finally:
        admin.execute("DROP VIEW public.dg_dependent")
    assert revoke(admin, plan.grant_id, receipts=sink).outcome == "noop"  # no receipt
    ev = _events(sink)
    assert [(e["event"], e["grant_id"]) for e in ev] == [
        ("issued", plan.grant_id),
        ("issued", old.grant_id),
        ("issued", stuck.grant_id),
        ("revoked", plan.grant_id),
        ("expired", old.grant_id),
        ("revoke_failed", stuck.grant_id),
    ]
    issued = ev[0]
    assert {c["name"]: c["mask"] for c in issued["columns"]}["ssn"] == "hash"
    assert issued["row_filter"] == "region = 'west'" and issued["host"] == "test-host"
    assert issued["policy_sha256"] == "a" * 64 and issued["policy_version"] == 1
    assert ev[3]["columns"] == issued["columns"]  # revoke receipt rebuilt from the state row
    assert ev[3]["details"]["reason"] == "manual" and ev[4]["details"]["reason"] == "expired"
    assert ev[5]["details"]["error"]
    text = sink.log.read_text()
    assert pw not in text and KEY_A.derived.hex() not in text
    res = verify(sink.log, sink.key.private.public_key())
    assert res.ok and res.count == 6


def test_receipt_write_failure_revokes_grant(admin: psycopg.Connection, sink) -> None:  # type: ignore[no-untyped-def]
    sink.log.mkdir()  # unwritable as a file
    with pytest.raises(GrantError, match="receipt not written.*grant revoked: revoked"):
        _grant(admin, receipts=sink)
    row = admin.execute("SELECT id, role_name, status FROM datagrant.grants").fetchone()
    assert row is not None and row[2] == "revoked"
    assert not _role_exists(admin, row[1])


def test_revoke_receipt_failure_still_revokes(admin: psycopg.Connection, sink) -> None:  # type: ignore[no-untyped-def]
    plan, _ = _grant(admin, receipts=sink)
    sink.log.write_bytes(sink.log.read_bytes() + b"partial")
    res = revoke(admin, plan.grant_id, receipts=sink)
    assert res.outcome == "revoked" and "newline" in (res.receipt_error or "")
    assert not _role_exists(admin, plan.role)


def test_receipt_parent_unusable_revokes_grant(admin: psycopg.Connection, sink, tmp_path) -> None:  # type: ignore[no-untyped-def]
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    bad = ReceiptSink(blocker / "sub" / "r.jsonl", sink.key)
    with pytest.raises(GrantError, match="grant revoked: revoked"):
        _grant(admin, receipts=bad)
    row = admin.execute("SELECT role_name, status FROM datagrant.grants").fetchone()
    assert row is not None and row[1] == "revoked" and not _role_exists(admin, row[0])


@pytest.mark.parametrize("exc", [RuntimeError("signer broke"), KeyboardInterrupt()])
def test_any_receipt_exception_revokes_grant(admin, sink, monkeypatch, exc) -> None:  # type: ignore[no-untyped-def]
    from datagrant import receipt as receipt_mod

    def boom(*a, **k):  # type: ignore[no-untyped-def]
        raise exc

    monkeypatch.setattr(receipt_mod, "append", boom)
    expected = GrantError if isinstance(exc, Exception) else KeyboardInterrupt
    with pytest.raises(expected):
        _grant(admin, receipts=sink)
    row = admin.execute("SELECT role_name, status FROM datagrant.grants").fetchone()
    assert row is not None and row[1] == "revoked" and not _role_exists(admin, row[0])
