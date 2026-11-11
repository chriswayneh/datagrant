"""M3 construction PR 1: session advisory lock on mutating --apply."""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Self

import pytest

from datagrant import cli
from datagrant.pg import grant as g
from datagrant.pg.lock import (
    DATAGRANT_ADVISORY_LOCK_KEY,
    acquire_advisory_lock,
    holding_advisory_lock,
    release_advisory_lock,
)
from datagrant.pg.mask import ColumnType, TableCatalog

POLICY = """\
version: 1
approval: auto
max_duration: 8h
groups: {ml: [alice]}
max_concurrent_grants: 8
datasets:
  - name: clinic
    database: clinicdb
    tables:
      - name: public.p
        allowed_groups: [ml]
        columns: {id: passthrough, ssn: hash}
"""
CAT = TableCatalog(
    {"id": ColumnType("pg_catalog", "int4"), "ssn": ColumnType("pg_catalog", "text")}, "public"
)
REQ = (
    "--dataset",
    "clinic",
    "--table",
    "public.p",
    "--columns",
    "id,ssn",
    "--duration",
    "1h",
    "--purpose",
    "x",
    "--as-user",
    "alice",
)


class RecConn:
    def __init__(self) -> None:
        self.queries: list[tuple[Any, Any]] = []
        self.closed = 0

    def execute(self, q: Any, params: Any = None) -> Any:
        self.queries.append((q, params))

        class C:
            def fetchone(self) -> tuple[Any, ...] | None:
                return (True,)

            def fetchall(self) -> list[tuple[Any, ...]]:
                return [(True,)]

        return C()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        yield

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *a: object) -> None:
        return None


def _sql(call: tuple[Any, Any]) -> str:
    return str(call[0]).lower()


def _kinds(conn: RecConn) -> list[str]:
    return [_sql(c) for c in conn.queries]


def run(*argv: str) -> tuple[int, dict[str, Any]]:
    import json

    out: list[str] = []
    code = cli.main(["--json", *argv], out.append)
    data = json.loads(out[-1]) if out else {}
    return code, data


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("DATAGRANT_DSN", "postgresql://admin:pw9secret@db.example:6543/clinicdb")
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
    assert cli.main(["keys", "init", "--apply"], lambda s: None) == 0
    conn = RecConn()
    state: dict[str, Any] = {"conn": conn, "applied": []}
    monkeypatch.setattr(cli, "_connect", lambda a: conn)
    monkeypatch.setattr(g, "ensure_state", lambda c: [])
    monkeypatch.setattr("datagrant.pg.mask.inspect_table", lambda c, t: CAT)
    monkeypatch.setattr(
        g, "apply_plan", lambda c, plan, sink, **kw: state["applied"].append((plan, sink, kw))
    )
    pol = tmp_path / "auto.yaml"
    pol.write_text(POLICY)
    state["tmp"] = tmp_path
    state["pol"] = str(pol)
    return state


def test_key_is_documented_bigint_not_hashtext() -> None:
    assert DATAGRANT_ADVISORY_LOCK_KEY == 0x64677401
    assert DATAGRANT_ADVISORY_LOCK_KEY == 1684501505


def test_acquire_and_unlock_use_constant_not_hashtext_or_xact() -> None:
    conn = RecConn()
    with holding_advisory_lock(conn):
        pass
    assert len(conn.queries) == 2
    lock_sql, lock_params = conn.queries[0]
    unlock_sql, unlock_params = conn.queries[1]
    for q in (lock_sql, unlock_sql):
        text = str(q).lower()
        assert "hashtext" not in text
        assert "pg_advisory_xact_lock" not in text
        assert "pg_advisory_xact_unlock" not in text
    assert "pg_advisory_lock" in str(lock_sql)
    assert "pg_advisory_unlock" in str(unlock_sql)
    assert lock_params == (DATAGRANT_ADVISORY_LOCK_KEY,)
    assert unlock_params == (DATAGRANT_ADVISORY_LOCK_KEY,)


def test_unlock_runs_in_finally_on_exception() -> None:
    conn = RecConn()
    with pytest.raises(RuntimeError, match="boom"), holding_advisory_lock(conn):
        raise RuntimeError("boom")
    kinds = _kinds(conn)
    assert "pg_advisory_lock" in kinds[0]
    assert "pg_advisory_unlock" in kinds[-1]


def test_release_skips_closed_connection() -> None:
    conn = RecConn()
    acquire_advisory_lock(conn)
    conn.closed = 1
    release_advisory_lock(conn)
    kinds = _kinds(conn)
    assert len(kinds) == 1 and "pg_advisory_lock" in kinds[0]


def test_release_swallows_execute_error() -> None:
    class Boom(RecConn):
        def execute(self, q: Any, params: Any = None) -> Any:
            if self.queries:
                raise RuntimeError("session gone")
            return super().execute(q, params)

    conn = Boom()
    acquire_advisory_lock(conn)
    release_advisory_lock(conn)


def test_dry_run_request_does_not_lock(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def count(conn: Any, requester: str) -> int:
        conn.execute("COUNT_ACTIVE_GRANTS")
        return 0

    monkeypatch.setattr(g, "count_active_grants", count)
    code, d = run("request", "--policy", setup["pol"], *REQ)
    assert code == 0 and d["dry_run"]
    kinds = _kinds(setup["conn"])
    assert not any("pg_advisory_lock" in t for t in kinds)


def test_request_apply_locks_before_cap_count_and_unlocks(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def count(conn: Any, requester: str) -> int:
        conn.execute("COUNT_ACTIVE_GRANTS")
        return 0

    monkeypatch.setattr(g, "count_active_grants", count)
    code, d = run("request", "--apply", "--policy", setup["pol"], *REQ)
    assert code == 0 and d["status"] == "granted"
    kinds = _kinds(setup["conn"])
    lock_at = next(i for i, t in enumerate(kinds) if "pg_advisory_lock" in t)
    count_at = next(i for i, t in enumerate(kinds) if "count_active_grants" in t)
    unlock_at = next(i for i, t in enumerate(kinds) if "pg_advisory_unlock" in t)
    assert lock_at < count_at < unlock_at
    assert all("hashtext" not in t for t in kinds)
    assert setup["conn"].queries[lock_at][1] == (DATAGRANT_ADVISORY_LOCK_KEY,)
    assert setup["conn"].queries[unlock_at][1] == (DATAGRANT_ADVISORY_LOCK_KEY,)


def test_request_apply_unlocks_when_apply_plan_raises(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from datagrant.pg.grant import GrantError

    monkeypatch.setattr(g, "count_active_grants", lambda c, requester: 0)

    def boom(c: Any, plan: Any, sink: Any, **kw: Any) -> None:
        raise GrantError("apply failed")

    monkeypatch.setattr(g, "apply_plan", boom)
    code, _d = run("request", "--apply", "--policy", setup["pol"], *REQ)
    assert code == cli.EXIT_FAILED
    kinds = _kinds(setup["conn"])
    assert any("pg_advisory_lock" in t for t in kinds)
    assert any("pg_advisory_unlock" in t for t in kinds)


def test_preflight_apply_locks_dry_run_does_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATAGRANT_DSN", "postgresql://admin:pw@db/x")
    conn = RecConn()
    monkeypatch.setattr(cli, "_connect", lambda a: conn)
    monkeypatch.setattr(g, "ensure_state", lambda c: [])
    monkeypatch.setattr(g, "preflight", lambda c: [])
    assert cli.main(["preflight", "--json"], lambda s: None) == 0
    assert not any("pg_advisory_lock" in t for t in _kinds(conn))
    conn.queries.clear()
    assert cli.main(["preflight", "--apply", "--json"], lambda s: None) == 0
    kinds = _kinds(conn)
    assert "pg_advisory_lock" in kinds[0]
    assert "pg_advisory_unlock" in kinds[-1]


def test_revoke_and_sweep_apply_lock(setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    from datagrant.pg import requests as rq
    from datagrant.pg import revoke as rv

    def result(gid: str) -> Any:
        return type(
            "R",
            (),
            {
                "grant_id": gid,
                "outcome": "noop",
                "sessions_terminated": 0,
                "error": None,
                "receipt_error": None,
            },
        )()

    monkeypatch.setattr(rv, "revoke", lambda c, gid, reason, sink: result(gid))
    monkeypatch.setattr(rv, "sweep", lambda c, sink: [])
    monkeypatch.setattr(rq, "expire_stale_requests", lambda c: [])
    conn: RecConn = setup["conn"]
    code, _d = run("revoke", "--apply", "aaaaaaaaaaaa")
    assert code == 0
    kinds = _kinds(conn)
    assert "pg_advisory_lock" in kinds[0] and "pg_advisory_unlock" in kinds[-1]
    conn.queries.clear()
    code, _d = run("sweep", "--apply")
    assert code == 0
    kinds = _kinds(conn)
    assert "pg_advisory_lock" in kinds[0] and "pg_advisory_unlock" in kinds[-1]


def test_approve_dry_run_does_not_lock(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import UTC, datetime, timedelta

    from datagrant.pg import requests as rq
    from datagrant.pg.requests import PendingRequest
    from datagrant.policy import Request as PolRequest

    t = datetime(2026, 11, 2, 18, tzinfo=UTC)
    pending = PendingRequest(
        "aaaaaaaaaaaa",
        PolRequest("alice", "clinic", "public.p", ("id", "ssn"), timedelta(hours=1), "x", None),
        "p" * 64,
        "SCRAM-SHA-256$x",
        t,
        t + timedelta(hours=24),
        "pending",
        None,
        None,
        None,
    )
    monkeypatch.setattr(rq, "get_request", lambda c, rid: pending)
    two = setup["tmp"] / "two.yaml"
    two.write_text(
        POLICY.replace("approval: auto", "approval: two-person\napprovers: [sec]").replace(
            "groups: {ml: [alice]}", "groups: {ml: [alice], sec: [carol]}"
        )
    )
    code, d = run("approve", str(pending.id), "--policy", str(two), "--as-user", "carol")
    assert code == 0 and d["dry_run"]
    assert not any("pg_advisory_lock" in t for t in _kinds(setup["conn"]))
