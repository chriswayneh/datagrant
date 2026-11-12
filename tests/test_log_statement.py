"""M3: SET LOCAL log_statement = none on apply_plan; refuse if the role cannot SET it."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Self

import pytest
from test_cli_flows import CAT as CLI_CAT
from test_cli_flows import POLICY, REQ, FakeConn

from datagrant import cli
from datagrant.keys import HashKey
from datagrant.pg.grant import (
    SET_LOCAL_LOG_STATEMENT,
    GrantError,
    apply_plan,
    build_plan,
    can_set_log_statement,
    log_statement_capability,
)
from datagrant.pg.mask import ColumnType, TableCatalog
from datagrant.policy import Decision, Request

NOW = datetime(2026, 11, 2, 23, 0, tzinfo=UTC)
CAT = TableCatalog(
    {"id": ColumnType("pg_catalog", "int4"), "zip": ColumnType("pg_catalog", "text")}, "public"
)
KEY = HashKey("0123456789abcdef", b"k" * 32)


class RecConn:
    def __init__(
        self,
        *,
        superuser: bool = True,
        param_set: bool = True,
        version: int = 160003,
        database: str = "clinicdb",
    ) -> None:
        self.queries: list[Any] = []
        self.superuser = superuser
        self.param_set = param_set
        self.version = version
        self.database = database

    def execute(self, q: Any, params: Any = None) -> Any:
        self.queries.append(q)
        low = _sql_text(q).lower()
        if "has_parameter_privilege" in low:
            row: tuple[Any, ...] | None = (self.param_set,)
        elif "server_version_num" in low:
            row = (self.version,)
        elif "rolsuper" in low:
            row = (self.superuser,)
        elif "current_database" in low:
            row = (self.database,)
        else:
            row = None

        class C:
            def fetchone(self) -> tuple[Any, ...] | None:
                return row

            def fetchall(self) -> list[tuple[Any, ...]]:
                return [row] if row else []

        return C()

    def transaction(self) -> Self:
        return self

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *a: object) -> None:
        return None


def _plan() -> Any:
    req = Request(
        "alice",
        "clinic",
        "public.patients",
        ("id", "zip"),
        timedelta(hours=2),
        "eval",
        "region = 'west'",
    )
    decision = Decision(
        True,
        ("ok",),
        "auto",
        "f" * 64,
        {"id": "passthrough", "zip": "hash"},
    )
    return build_plan(
        decision,
        req,
        database="clinicdb",
        password="Zq9-never-in-sql-Xk",
        catalog=CAT,
        grant_id="abcdef012345",
        now=NOW,
        hash_key=KEY,
    )


def _sql_text(q: Any) -> str:
    if hasattr(q, "as_string"):
        try:
            return str(q.as_string(None))
        except Exception:  # noqa: BLE001 - Composed.as_string needs a connection
            return str(q)
    return str(q)


def _sqls(conn: RecConn) -> list[str]:
    return [_sql_text(q).lower() for q in conn.queries]


def test_capability_superuser_and_grant() -> None:
    ok, detail = log_statement_capability(RecConn(superuser=True))
    assert ok and "superuser" in detail
    ok, detail = log_statement_capability(RecConn(superuser=False, param_set=True))
    assert ok and "privilege" in detail
    ok, detail = log_statement_capability(RecConn(superuser=False, param_set=False))
    assert not ok and "SET log_statement" in detail and "GRANT" in detail
    ok, detail = log_statement_capability(RecConn(superuser=False, version=140000))
    assert not ok and "15+" in detail
    assert can_set_log_statement(RecConn(superuser=True)) is True


def test_apply_plan_sets_log_statement_before_key_or_password() -> None:
    conn = RecConn(superuser=True)
    apply_plan(conn, _plan(), receipts=None)
    texts = _sqls(conn)
    log_i = next(i for i, t in enumerate(texts) if "log_statement" in t and "none" in t)
    key_i = next(i for i, t in enumerate(texts) if "hash_keys" in t)
    role_i = next(i for i, t in enumerate(texts) if "create role" in t)
    assert log_i < key_i < role_i
    assert "set local log_statement" in texts[log_i]
    assert "none" in _sql_text(SET_LOCAL_LOG_STATEMENT)


def test_apply_plan_sets_when_parameter_privilege() -> None:
    conn = RecConn(superuser=False, param_set=True)
    apply_plan(conn, _plan(), receipts=None)
    texts = _sqls(conn)
    assert any("has_parameter_privilege" in t for t in texts)
    assert any("log_statement" in t and "none" in t for t in texts)
    assert any("create role" in t for t in texts)


def test_apply_plan_refuses_without_set_privilege() -> None:
    conn = RecConn(superuser=False, param_set=False)
    with pytest.raises(GrantError, match="SET log_statement"):
        apply_plan(conn, _plan(), receipts=None)
    texts = _sqls(conn)
    assert not any("create role" in t for t in texts)
    assert not any("hash_keys" in t for t in texts)
    assert not any("log_statement" in t and "none" in t for t in texts)


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    monkeypatch.setenv("DATAGRANT_DSN", "postgresql://admin:pw9secret@db.example:6543/clinicdb")
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
    monkeypatch.delenv("DATAGRANT_STRICT_POLICY_PERMISSIONS", raising=False)
    assert cli.main(["keys", "init", "--apply"], lambda s: None) == 0
    conn = FakeConn()
    state: dict[str, Any] = {"conn": conn, "applied": []}
    monkeypatch.setattr(cli, "_connect", lambda a: conn)
    monkeypatch.setattr("datagrant.pg.grant.ensure_state", lambda c: [])
    monkeypatch.setattr("datagrant.pg.mask.inspect_table", lambda c, t: CLI_CAT)
    monkeypatch.setattr(
        "datagrant.pg.grant.apply_plan",
        lambda c, plan, sink, **kw: state["applied"].append((plan, sink, kw)),
    )
    pol = tmp_path / "auto.yaml"
    pol.write_text(POLICY.format(approval="auto"))
    os.chmod(pol, 0o600)
    state["tmp"] = tmp_path
    state["pol"] = str(pol)
    yield state


def run(*argv: str) -> tuple[int, dict[str, Any]]:
    out: list[str] = []
    code = cli.main(["--json", *argv], out.append)
    return code, json.loads(out[-1]) if out else {}


def test_request_apply_refuses_without_set_privilege(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("datagrant.pg.grant.can_set_log_statement", lambda c: False)
    code, d = run("request", "--apply", "--policy", setup["pol"], *REQ)
    assert code == cli.EXIT_FAILED
    assert "SET log_statement" in d.get("error", "")
    assert "GRANT" in d.get("error", "")
    assert not setup["applied"]


def test_request_dry_run_does_not_require_set_privilege(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("datagrant.pg.grant.can_set_log_statement", lambda c: False)
    code, d = run("request", "--policy", setup["pol"], *REQ)
    assert code == 0 and d["dry_run"] is True


def test_revoke_proceeds_without_set_privilege(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from datagrant.pg import revoke as rv

    monkeypatch.setattr("datagrant.pg.grant.can_set_log_statement", lambda c: False)
    monkeypatch.setattr(
        rv, "revoke", lambda c, gid, reason, sink: rv.RevokeResult("abc", "revoked", 0)
    )
    code, d = run("revoke", "--apply", "abc")
    assert code == 0
    assert d["outcome"] == "revoked"


def test_sweep_proceeds_without_set_privilege(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from datagrant.pg import revoke as rv

    monkeypatch.setattr("datagrant.pg.grant.can_set_log_statement", lambda c: False)
    monkeypatch.setattr(rv, "sweep", lambda c, sink: [])
    monkeypatch.setattr("datagrant.pg.requests.expire_stale_requests", lambda c: [])
    code, d = run("sweep", "--apply")
    assert code == 0
    assert d.get("results") == []


def test_approve_apply_refuses_without_set_privilege(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("datagrant.pg.grant.can_set_log_statement", lambda c: False)
    code, d = run(
        "approve",
        "--apply",
        "req1",
        "--policy",
        setup["pol"],
        "--as-user",
        "carol",
    )
    assert code == cli.EXIT_FAILED
    assert "SET log_statement" in d.get("error", "")
    assert not setup["applied"]
