"""CLI command flows with the database layer stubbed (no Postgres needed)."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Self

import pytest

from datagrant import cli
from datagrant.pg import grant as g
from datagrant.pg import requests as rq
from datagrant.pg import revoke as rv
from datagrant.pg.mask import ColumnType, TableCatalog
from datagrant.pg.requests import PendingRequest
from datagrant.policy import Request

T = datetime(2026, 11, 2, 18, tzinfo=UTC)
POLICY = """\
version: 1
approval: {approval}
approvers: [sec]
max_duration: 8h
groups: {{ml: [alice, bob], sec: [carol]}}
datasets:
  - name: clinic
    database: clinicdb
    tables:
      - name: public.p
        allowed_groups: [ml]
        columns: {{id: passthrough, ssn: hash}}
"""
CAT = TableCatalog(
    {"id": ColumnType("pg_catalog", "int4"), "ssn": ColumnType("pg_catalog", "text")}, "public"
)


class FakeConn:
    def __init__(self, rows: list[tuple[Any, ...]] | None = None) -> None:
        self.rows = rows or []
        self.queries: list[Any] = []

    def execute(self, q: Any, params: Any = None) -> Any:
        self.queries.append((q, params))
        rows = self.rows

        class C:
            def fetchall(self) -> list[tuple[Any, ...]]:
                return rows

            def fetchone(self) -> tuple[Any, ...] | None:
                return rows[0] if rows else None

        return C()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        yield

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *a: object) -> None:
        return None


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("DATAGRANT_DSN", "postgresql://admin:pw9secret@db.example:6543/clinicdb")
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
    assert cli.main(["keys", "init", "--apply"], lambda s: None) == 0
    conn = FakeConn()
    state: dict[str, Any] = {"conn": conn, "applied": []}
    monkeypatch.setattr(cli, "_connect", lambda a: conn)
    monkeypatch.setattr(g, "ensure_state", lambda c: ["PUBLIC can CREATE in schema public"])
    monkeypatch.setattr("datagrant.pg.mask.inspect_table", lambda c, t: CAT)
    monkeypatch.setattr(
        g, "apply_plan", lambda c, plan, sink, **kw: state["applied"].append((plan, sink, kw))
    )
    for mode in ("auto", "two-person"):
        (tmp_path / f"{mode}.yaml").write_text(POLICY.format(approval=mode))
    state["tmp"] = tmp_path
    return state


def run(*argv: str) -> tuple[int, dict[str, Any]]:
    out: list[str] = []
    code = cli.main(["--json", *argv], out.append)
    return code, json.loads(out[-1]) if out else {}


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


def test_request_auto_dry_run_and_text(setup: dict[str, Any]) -> None:
    pol = str(setup["tmp"] / "auto.yaml")
    code, d = run("request", "--policy", pol, *REQ)
    assert code == 0 and d["dry_run"] and "<redacted>" in d["sql"][0] and not setup["applied"]
    code, d = run("request", "--apply", "--policy", pol, *REQ)
    assert code == 0 and d["status"] == "granted" and len(d["password"]) > 20
    assert d["connection"] == {
        "host": "db.example",
        "port": 6543,
        "dbname": "clinicdb",
        "user": f"dg_{d['grant_id']}",
    }
    plan, sink, _ = setup["applied"][0]
    assert sink is not None and plan.hash_key is not None
    out: list[str] = []
    assert cli.main(["request", "--apply", "--policy", pol, *REQ], out.append) == 0
    assert "one-time password (shown once, not stored)" in out[0]


def test_request_two_person_and_approve(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = str(setup["tmp"] / "two-person.yaml")
    stored: dict[str, Any] = {}

    def create(conn: Any, req: Request, **kw: Any) -> PendingRequest:
        stored["p"] = PendingRequest(
            "aaaaaaaaaaaa",
            req,
            kw["policy_sha256"],
            kw["verifier"],
            T,
            T + kw["ttl"],
            "pending",
            None,
            None,
            kw.get("requester_identity"),
        )
        return stored["p"]

    monkeypatch.setattr(rq, "create_request", create)
    monkeypatch.setattr(rq, "get_request", lambda c, rid: stored["p"])
    code, d = run("request", "--apply", "--policy", pol, *REQ)
    assert code == 0 and d["status"] == "pending" and d["password"]
    assert stored["p"].verifier.startswith("SCRAM-SHA-256$") and d["password"] not in json.dumps(
        stored["p"].verifier
    )
    code, d = run("approve", "--apply", "aaaaaaaaaaaa", "--policy", pol, "--as-user", "alice")
    assert code == 1 and d["approved"] is False
    code, d = run("approve", "--apply", "aaaaaaaaaaaa", "--policy", pol, "--as-user", "carol")
    assert code == 0 and d["status"] == "granted" and "password" not in d
    plan, _, kw = setup["applied"][0]
    assert kw == {"request_id": "aaaaaaaaaaaa", "approver": "carol"}
    assert plan.facts.approvers == ("carol",)
    assert stored["p"].verifier in plan.statements[0].as_string(None)
    stored["p"] = PendingRequest(
        "aaaaaaaaaaaa", stored["p"].request, "", None, T, T, "approved", "carol", "x"
    )
    assert run("approve", "--apply", "aaaaaaaaaaaa", "--policy", pol, "--as-user", "carol")[0] == 1
    # policy tightened after the request: approval re-checks and refuses
    req = Request("alice", "clinic", "public.p", ("id", "nope"), timedelta(hours=1), "x")
    stored["p"] = PendingRequest(
        "aaaaaaaaaaaa", req, "", "SCRAM-SHA-256$x", T, T, "pending", None, None
    )
    code, d = run("approve", "--apply", "aaaaaaaaaaaa", "--policy", pol, "--as-user", "carol")
    assert code == 1 and any("no longer allowed" in r for r in d["reasons"])


def test_grant_list_status_revoke_sweep_preflight(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    row = (
        "abc",
        "alice",
        "clinic",
        "public.p",
        ["id"],
        None,
        "active",
        T,
        T,
        None,
        None,
        [],
        "boom",
    )
    setup["conn"].rows = [row]
    code, d = run("grant", "list", "--all")
    assert code == 0 and d["grants"][0]["id"] == "abc"
    out: list[str] = []
    assert cli.main(["grant", "list"], out.append) == 0 and "ERROR: boom" in out[0]
    assert run("grant", "status", "abc")[1]["requester"] == "alice"
    out = []
    assert cli.main(["grant", "status", "abc"], out.append) == 0
    assert "revoked_at: -" in out[0] and "None" not in out[0]
    setup["conn"].rows = []
    assert run("grant", "status", "abc")[0] == 1
    out = []
    assert cli.main(["grant", "list"], out.append) == 0 and out == ["no grants"]

    results = {"r": rv.RevokeResult("abc", "revoked", 2)}
    monkeypatch.setattr(rv, "revoke", lambda c, gid, reason, sink: results["r"])
    monkeypatch.setattr(rv, "sweep", lambda c, sink: [results["r"]])
    stale = PendingRequest(
        "req1",
        Request("alice", "clinic", "public.p", ("id",), timedelta(hours=1), "x"),
        "s" * 64,
        None,
        T,
        T,
        "expired",
        None,
        None,
    )
    monkeypatch.setattr(rq, "expire_stale_requests", lambda c: [stale])
    monkeypatch.setattr(rq, "expire_requests", lambda c: ["req1"])
    out = []
    assert cli.main(["revoke", "--apply", "abc"], out.append) == 0 and "2 session(s)" in out[0]
    results["r"] = rv.RevokeResult("abc", "failed", error="nope")
    assert run("revoke", "--apply", "abc")[0] == cli.EXIT_REVOKE_FAILED
    out = []
    assert cli.main(["sweep", "--apply"], out.append) == cli.EXIT_REVOKE_FAILED
    assert "request req1: expired" in out[0]
    results["r"] = rv.RevokeResult("abc", "revoked", receipt_error="disk")
    code, d = run("sweep", "--apply")
    assert code == cli.EXIT_RECEIPT and d["expired_requests"] == ["req1"]
    out = []
    assert cli.main(["revoke", "--apply", "abc"], out.append) == cli.EXIT_RECEIPT
    assert "receipt not written: disk" in out[0]
    out = []
    assert cli.main(["preflight", "--apply"], out.append) == 0 and out[0].startswith("WARNING:")


def test_unexpected_error_is_redacted(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(c: Any) -> list[str]:
        raise RuntimeError("failed for postgresql://admin:pw9secret@db.example/clinicdb")

    monkeypatch.setattr(g, "ensure_state", boom)
    assert cli.main(["preflight", "--apply"]) == 1
    err = capsys.readouterr().err
    assert "pw9secret" not in err and "RuntimeError" in err


def test_dry_run_default_never_makes_password(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_pw() -> str:
        raise AssertionError("dry run must not generate a password")

    monkeypatch.setattr(g, "new_password", no_pw)
    monkeypatch.setattr(
        rq,
        "create_request",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("dry run must not store a request")),
    )
    for mode in ("auto", "two-person"):
        out: list[str] = []
        assert (
            cli.main(["request", "--policy", str(setup["tmp"] / f"{mode}.yaml"), *REQ], out.append)
            == 0
        )
        assert out[0].startswith("dry run:") and "PASSWORD '<redacted>'" in out[0]
        assert "SCRAM" not in out[0] and "password (shown once" not in out[0]
    assert not setup["applied"]


def test_keys_init_dry_run(tmp_path: Path) -> None:
    out: list[str] = []
    assert cli.main(["keys", "init", "--dir", str(tmp_path / "k")], out.append) == 0
    assert "would create" in out[0] and not (tmp_path / "k").exists()


@pytest.mark.parametrize("pos", ["global", "sub"])
def test_keys_init_honours_signing_and_hash_key_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pos: str
) -> None:
    monkeypatch.delenv("DATAGRANT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("DATAGRANT_HASH_KEY", raising=False)
    sk, hk = tmp_path / "x" / "my.sign", tmp_path / "y" / "my.hash"
    flags = ["--signing-key", str(sk), "--hash-key", str(hk), "--json"]
    argv = (
        [*flags, "keys", "init", "--apply"]
        if pos == "global"
        else ["keys", "init", "--apply", *flags]
    )
    out: list[str] = []
    assert cli.main([*argv, "--dir", str(tmp_path / "d")], out.append) == 0
    d = json.loads(out[0])
    assert d["signing_key"] == str(sk) and d["hash_key"] == str(hk)  # explicit beats --dir
    assert sk.exists() and hk.exists() and not (tmp_path / "d").exists()
    exp = (
        ["--signing-key", str(sk), "keys", "export-pubkey"]
        if pos == "global"
        else ["keys", "export-pubkey", "--signing-key", str(sk)]
    )
    out2: list[str] = []
    assert cli.main(exp, out2.append) == 0 and out2 == [d["public_key"]]


def test_key_path_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from datagrant.keys import resolve_key_path

    monkeypatch.delenv("DATAGRANT_SIGNING_KEY", raising=False)
    assert resolve_key_path("signing", None, tmp_path) == tmp_path / "signing.key"
    assert resolve_key_path("signing").name == "signing.key"
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "env.key"))
    assert resolve_key_path("signing", None, tmp_path) == tmp_path / "env.key"  # env > --dir
    assert resolve_key_path("signing", tmp_path / "f.key", tmp_path) == tmp_path / "f.key"
    out: list[str] = []
    assert cli.main(["--json", "keys", "init", "--dir", str(tmp_path / "d")], out.append) == 0
    assert json.loads(out[0])["would_create"][1] == str(tmp_path / "env.key")


def test_request_uses_signing_key_flag(
    setup: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sk, hk = tmp_path / "alt" / "s.key", tmp_path / "alt" / "h.key"
    assert (
        cli.main(
            ["keys", "init", "--apply", "--signing-key", str(sk), "--hash-key", str(hk)],
            lambda s: None,
        )
        == 0
    )
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "nope.key"))
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "nope.hash"))
    pol = str(setup["tmp"] / "auto.yaml")
    assert run("request", "--apply", "--policy", pol, *REQ)[0] == 1  # env keys missing
    code, _ = run(
        "--signing-key", str(sk), "--hash-key", str(hk), "request", "--apply", "--policy", pol, *REQ
    )
    assert code == 0
    _, sink, _ = setup["applied"][-1]
    from datagrant.keys import load_signing_key

    assert sink.key.key_id == load_signing_key(sk).key_id


@pytest.mark.parametrize(
    "argv",
    [
        ["--dsn", "x", "policy", "check", "f"],
        ["--receipt-log", "x", "keys", "init"],
        ["--hash-key", "x", "revoke", "abc"],
        ["--signing-key", "x", "grant", "list"],
        ["--dsn", "x", "receipts", "verify"],
    ],
)
def test_global_flag_that_does_not_apply_is_usage_error(argv: list[str]) -> None:
    assert cli.main(argv, lambda s: None) == cli.EXIT_USAGE


def test_subcommands_do_not_advertise_unused_flags(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["policy", "check", "--dsn", "x", "f"]) == cli.EXIT_USAGE
    assert cli.main(["grant", "list", "--signing-key", "x"]) == cli.EXIT_USAGE


def _write_limits_policy(tmp: Path, extra_top: str = "", extra_table: str = "") -> str:
    text = POLICY.format(approval="two-person")
    if extra_top:
        text = text.replace("max_duration: 8h", "max_duration: 8h\n" + extra_top)
    if extra_table:
        text = text.replace("        columns: {id: passthrough, ssn: hash}", extra_table)
    path = tmp / "limits.yaml"
    path.write_text(text)
    return str(path)


def test_pending_ttl_explicit_too_long_is_usage(setup: dict[str, Any]) -> None:
    pol = _write_limits_policy(setup["tmp"], extra_top="pending_ttl: 4h")
    code, d = run("request", "--policy", pol, *REQ, "--pending-ttl", "8h")
    assert code == cli.EXIT_USAGE and "pending-ttl" in d["error"] and "pending_ttl" in d["error"]
    code, d = run("request", "--apply", "--policy", pol, *REQ, "--pending-ttl", "30d")
    assert code == cli.EXIT_USAGE
    code, d = run("request", "--policy", pol, *REQ, "--pending-ttl", "4h")
    assert code == 0 and d["dry_run"]
    assert not setup["applied"]


def test_pending_ttl_omitted_two_person_uses_policy_cap(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = _write_limits_policy(setup["tmp"], extra_top="pending_ttl: 4h")
    stored: dict[str, Any] = {}

    def create(conn: Any, req: Request, **kw: Any) -> PendingRequest:
        stored["ttl"] = kw["ttl"]
        return PendingRequest(
            "dddddddddddd",
            req,
            kw["policy_sha256"],
            kw["verifier"],
            T,
            T + kw["ttl"],
            "pending",
            None,
            None,
            None,
        )

    monkeypatch.setattr(rq, "create_request", create)
    code, d = run("request", "--apply", "--policy", pol, *REQ)
    assert code == 0 and d["status"] == "pending"
    assert stored["ttl"] == timedelta(hours=4)


def test_pending_ttl_omitted_auto_ignores_short_cap(setup: dict[str, Any]) -> None:
    text = POLICY.format(approval="auto").replace(
        "max_duration: 8h", "max_duration: 8h\npending_ttl: 4h"
    )
    pol = setup["tmp"] / "auto-ttl.yaml"
    pol.write_text(text)
    code, d = run("request", "--policy", str(pol), *REQ)
    assert code == 0 and d["dry_run"]
    code, d = run("request", "--policy", str(pol), *REQ, "--pending-ttl", "8h")
    assert code == 0 and d["dry_run"]
    assert not setup["applied"]


def test_pending_ttl_omitted_allows_long_cli_ttl(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = str(setup["tmp"] / "two-person.yaml")
    stored: dict[str, Any] = {}

    def create(conn: Any, req: Request, **kw: Any) -> PendingRequest:
        stored["ttl"] = kw["ttl"]
        return PendingRequest(
            "bbbbbbbbbbbb",
            req,
            kw["policy_sha256"],
            kw["verifier"],
            T,
            T + kw["ttl"],
            "pending",
            None,
            None,
            None,
        )

    monkeypatch.setattr(rq, "create_request", create)
    code, d = run("request", "--apply", "--policy", pol, *REQ, "--pending-ttl", "30d")
    assert code == 0 and d["status"] == "pending"
    assert stored["ttl"] == timedelta(days=30)


def test_max_columns_denied_exit_1(setup: dict[str, Any]) -> None:
    pol = _write_limits_policy(
        setup["tmp"],
        extra_table="        max_columns: 1\n        columns: {id: passthrough, ssn: hash}",
    )
    code, d = run("request", "--policy", pol, *REQ)
    assert code == cli.EXIT_FAILED and d["allowed"] is False
    assert any("max_columns" in r for r in d["reasons"])
    assert not setup["applied"]
    one_col = (*REQ[:5], "id", *REQ[6:])
    code, d = run("request", "--policy", pol, *one_col)
    assert code == 0 and d["dry_run"]


def test_concurrent_cap_denied_on_request_and_approve(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = _write_limits_policy(setup["tmp"], extra_top="max_concurrent_grants: 2")
    monkeypatch.setattr(g, "count_active_grants", lambda c, requester: 2)
    code, d = run("request", "--policy", pol, *REQ)
    assert code == cli.EXIT_FAILED and d["allowed"] is False
    assert any("max_concurrent_grants" in r for r in d["reasons"])
    assert not setup["applied"]

    stored: dict[str, Any] = {}

    def create(conn: Any, req: Request, **kw: Any) -> PendingRequest:
        stored["p"] = PendingRequest(
            "cccccccccccc",
            req,
            kw["policy_sha256"],
            kw["verifier"],
            T,
            T + kw["ttl"],
            "pending",
            None,
            None,
            None,
        )
        return stored["p"]

    monkeypatch.setattr(g, "count_active_grants", lambda c, requester: 0)
    monkeypatch.setattr(rq, "create_request", create)
    monkeypatch.setattr(rq, "get_request", lambda c, rid: stored["p"])
    code, d = run("request", "--apply", "--policy", pol, *REQ, "--pending-ttl", "1h")
    assert code == 0 and d["status"] == "pending"
    monkeypatch.setattr(g, "count_active_grants", lambda c, requester: 2)
    code, d = run("approve", "--apply", "cccccccccccc", "--policy", pol, "--as-user", "carol")
    assert code == cli.EXIT_FAILED and d["approved"] is False
    assert any("max_concurrent_grants" in r for r in d["reasons"])
    assert not setup["applied"]


def test_concurrent_cap_treats_missing_grants_table_as_zero(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from psycopg.errors import UndefinedTable

    pol = _write_limits_policy(setup["tmp"], extra_top="max_concurrent_grants: 1")

    def missing(conn: Any, requester: str) -> int:
        raise UndefinedTable("grants")

    monkeypatch.setattr(g, "count_active_grants", missing)
    code, d = run("request", "--policy", pol, *REQ)
    assert code == 0 and d["dry_run"]


def test_count_active_grants_sql_only_counts_active() -> None:
    seen: dict[str, Any] = {}

    class Conn:
        def execute(self, q: Any, params: Any = None) -> Any:
            seen["sql"] = q.as_string(None)
            seen["params"] = params

            class R:
                def fetchone(self) -> tuple[int]:
                    return (1,)

            return R()

    assert g.count_active_grants(Conn(), "alice") == 1
    sql = seen["sql"]
    assert "status = 'active'" in sql
    assert "expires_at > pg_catalog.now()" in sql
    assert "revoked" not in sql
    assert seen["params"] == ("alice",)


def test_count_active_grants_excludes_unswept_expired() -> None:
    """status=active but expires_at in the past must not match (sweep may not have run)."""
    seen: dict[str, str] = {}

    class Conn:
        def execute(self, q: Any, params: Any = None) -> Any:
            seen["sql"] = q.as_string(None)

            class R:
                def fetchone(self) -> tuple[int]:
                    return (0,)

            return R()

    assert g.count_active_grants(Conn(), "alice") == 0
    sql = seen["sql"]
    assert "status = 'active'" in sql
    assert "expires_at > pg_catalog.now()" in sql


def _receipts(setup: dict[str, Any]) -> list[dict[str, Any]]:
    path = setup["tmp"] / "r.jsonl"
    if not path.exists() or path.stat().st_size == 0:
        return []
    return [json.loads(line)["receipt"] for line in path.read_text().splitlines() if line]


def _deny_policy(setup: dict[str, Any]) -> str:
    return _write_limits_policy(
        setup["tmp"],
        extra_table="        max_columns: 1\n        columns: {id: passthrough, ssn: hash}",
    )


def test_denied_receipt_apply_only_and_schema(setup: dict[str, Any]) -> None:
    pol = _deny_policy(setup)
    code, d = run("request", "--policy", pol, *REQ)
    assert code == cli.EXIT_FAILED and d["allowed"] is False
    assert _receipts(setup) == []
    code, d = run("request", "--apply", "--policy", pol, *REQ)
    assert code == cli.EXIT_FAILED and d["allowed"] is False
    assert not setup["applied"]
    bodies = _receipts(setup)
    assert len(bodies) == 1
    b = bodies[0]
    assert b["event"] == "denied"
    assert "grant_id" not in b
    assert b["details"]["phase"] == "request"
    assert any("max_columns" in r for r in b["details"]["reasons"])
    assert "password" not in json.dumps(b)
    assert b["requester"] == "alice"
    assert b["dataset"] == "clinic"
    assert b["table"] == "public.p"


def test_denied_receipt_redacts_secrets(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from datagrant.policy import Decision

    pol = str(setup["tmp"] / "auto.yaml")

    def leaky(policy: Any, req: Request, extra_groups: Any = frozenset()) -> Decision:
        return Decision(
            False,
            ("denied for postgresql://admin:pw9secret@db.example/clinicdb",),
            "auto",
            policy.sha256,
            {},
            policy.version,
        )

    monkeypatch.setattr("datagrant.policy.evaluate", leaky)
    code, _d = run("request", "--apply", "--policy", pol, *REQ)
    assert code == cli.EXIT_FAILED
    text = (setup["tmp"] / "r.jsonl").read_text()
    assert "pw9secret" not in text
    bodies = _receipts(setup)
    assert len(bodies) == 1 and bodies[0]["event"] == "denied"
    assert any("***" in r for r in bodies[0]["details"]["reasons"])


def test_denied_missing_signing_key_is_exit_3_no_grant(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = _deny_policy(setup)
    (setup["tmp"] / "k" / "signing.key").unlink()
    created: list[Any] = []
    monkeypatch.setattr(
        rq,
        "create_request",
        lambda *a, **k: created.append((a, k)) or (_ for _ in ()).throw(AssertionError("no")),
    )
    code, _d = run("request", "--apply", "--policy", pol, *REQ)
    assert code == cli.EXIT_RECEIPT
    assert not setup["applied"] and created == []
    assert _receipts(setup) == []


def test_denied_concurrent_cap_apply_writes_receipt(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = _write_limits_policy(setup["tmp"], extra_top="max_concurrent_grants: 1")
    monkeypatch.setattr(g, "count_active_grants", lambda c, requester: 1)
    code, d = run("request", "--apply", "--policy", pol, *REQ)
    assert code == cli.EXIT_FAILED and d["allowed"] is False
    bodies = _receipts(setup)
    assert len(bodies) == 1 and bodies[0]["event"] == "denied"
    assert "grant_id" not in bodies[0]
    assert any("max_concurrent_grants" in r for r in bodies[0]["details"]["reasons"])


def test_not_approved_receipt_on_apply_not_dry_run(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = str(setup["tmp"] / "two-person.yaml")
    stored: dict[str, Any] = {}

    def create(conn: Any, req: Request, **kw: Any) -> PendingRequest:
        stored["p"] = PendingRequest(
            "aaaaaaaaaaaa",
            req,
            kw["policy_sha256"],
            kw["verifier"],
            T,
            T + kw["ttl"],
            "pending",
            None,
            None,
            kw.get("requester_identity"),
        )
        return stored["p"]

    monkeypatch.setattr(rq, "create_request", create)
    monkeypatch.setattr(rq, "get_request", lambda c, rid: stored["p"])
    assert run("request", "--apply", "--policy", pol, *REQ)[0] == 0
    before = _receipts(setup)
    code, d = run("approve", "aaaaaaaaaaaa", "--policy", pol, "--as-user", "alice")
    assert code == cli.EXIT_FAILED and d["approved"] is False
    assert _receipts(setup) == before
    code, d = run("approve", "--apply", "aaaaaaaaaaaa", "--policy", pol, "--as-user", "alice")
    assert code == cli.EXIT_FAILED and d["approved"] is False
    bodies = [b for b in _receipts(setup) if b["event"] == "not_approved"]
    assert len(bodies) == 1
    b = bodies[0]
    assert "grant_id" not in b
    assert b["details"]["phase"] == "approve"
    assert b["details"]["request_id"] == "aaaaaaaaaaaa"
    assert any("different person" in r for r in b["details"]["reasons"])


def test_not_approved_expired_pending_is_exit_1(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = str(setup["tmp"] / "two-person.yaml")
    req = Request("alice", "clinic", "public.p", ("id", "ssn"), timedelta(hours=1), "x")
    pending = PendingRequest(
        "eeeeeeeeeeee", req, "a" * 64, None, T, T, "expired", None, None, {"source": "flag"}
    )
    monkeypatch.setattr(rq, "get_request", lambda c, rid: pending)
    code, _d = run("approve", "--apply", "eeeeeeeeeeee", "--policy", pol, "--as-user", "carol")
    assert code == cli.EXIT_FAILED
    bodies = _receipts(setup)
    assert len(bodies) == 1 and bodies[0]["event"] == "not_approved"
    assert bodies[0]["details"]["request_id"] == "eeeeeeeeeeee"
    assert "grant_id" not in bodies[0]


def test_request_expired_receipt_on_sweep_apply_only(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    req = Request("alice", "clinic", "public.p", ("id", "ssn"), timedelta(hours=1), "x")
    pending = PendingRequest(
        "ffffffffffff", req, "b" * 64, None, T, T, "expired", None, None, {"source": "os"}
    )
    monkeypatch.setattr(rv, "sweep", lambda c, sink: [])
    monkeypatch.setattr(rq, "expire_stale_requests", lambda c: [pending])
    monkeypatch.setattr(rq, "expire_requests", lambda c: [pending.id])
    code, d = run("sweep")
    assert code == 0 and d["dry_run"]
    assert _receipts(setup) == []
    code, d = run("sweep", "--apply")
    assert code == 0 and d["expired_requests"] == ["ffffffffffff"]
    bodies = _receipts(setup)
    assert len(bodies) == 1
    b = bodies[0]
    assert b["event"] == "request_expired"
    assert "grant_id" not in b
    assert b["details"]["request_id"] == "ffffffffffff"
    assert b["requester"] == "alice"


def test_request_expired_idempotent_on_repeated_sweep(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    req = Request("alice", "clinic", "public.p", ("id",), timedelta(hours=1), "x")
    pending = PendingRequest("121212121212", req, "c" * 64, None, T, T, "expired", None, None, None)
    n = {"i": 0}

    def expire(c: Any) -> list[PendingRequest]:
        n["i"] += 1
        return [pending] if n["i"] == 1 else []

    monkeypatch.setattr(rv, "sweep", lambda c, sink: [])
    monkeypatch.setattr(rq, "expire_stale_requests", expire)
    assert run("sweep", "--apply")[0] == 0
    assert run("sweep", "--apply")[0] == 0
    bodies = [b for b in _receipts(setup) if b["event"] == "request_expired"]
    assert len(bodies) == 1
    assert bodies[0]["details"]["request_id"] == "121212121212"


def test_request_expired_receipt_failure_still_expires_exit_3(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from datagrant.receipt import ReceiptError

    req = Request("alice", "clinic", "public.p", ("id",), timedelta(hours=1), "x")
    pending = PendingRequest("343434343434", req, "d" * 64, None, T, T, "expired", None, None, None)
    expired_called = {"n": 0}

    def expire(c: Any) -> list[PendingRequest]:
        expired_called["n"] += 1
        return [pending]

    monkeypatch.setattr(rv, "sweep", lambda c, sink: [])
    monkeypatch.setattr(rq, "expire_stale_requests", expire)
    monkeypatch.setattr(rq, "expire_requests", lambda c: [pending.id])

    def boom(*a: Any, **k: Any) -> dict[str, Any]:
        raise ReceiptError("disk full")

    monkeypatch.setattr("datagrant.receipt.append", boom)
    code, d = run("sweep", "--apply")
    assert code == cli.EXIT_RECEIPT
    assert expired_called["n"] == 1
    assert d["expired_requests"] == ["343434343434"]
