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
