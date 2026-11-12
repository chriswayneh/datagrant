"""M3 construction PR 2: datagrant doctor (read-only checks)."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Self

import pytest

from datagrant import cli
from datagrant.doctor import (
    _PARAM_SQL,
    CHECK_CONNECT,
    CHECK_KEYS,
    CHECK_LOG_STATEMENT,
    CHECK_ORDER,
    CHECK_PG_SIGNAL_BACKEND,
    CHECK_POLICY,
    CHECK_POLICY_PERMISSIONS,
    CHECK_PREFLIGHT,
    CHECK_RECEIPT_CHAIN,
    CHECK_RECEIPT_LOG_PERMISSIONS,
    CHECK_SINK_CURSOR,
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_SKIP,
    STATUS_WARN,
    run_doctor,
)
from datagrant.outbox import cursor_path, write_cursor

POLICY = """\
version: 1
approval: auto
max_duration: 8h
groups: {ml: [alice]}
datasets:
  - name: clinic
    database: clinicdb
    tables:
      - name: public.p
        allowed_groups: [ml]
        columns: {id: passthrough, ssn: hash}
"""


class FakeConn:
    def __init__(
        self,
        *,
        superuser: bool = True,
        signal: bool = True,
        version: int = 160003,
        param_set: bool = True,
        public_warnings: list[str] | None = None,
    ) -> None:
        self.queries: list[str] = []
        self.superuser = superuser
        self.signal = signal
        self.version = version
        self.param_set = param_set
        self.public_warnings = public_warnings or []
        self.closed = 0

    def execute(self, q: Any, params: Any = None) -> Any:
        text = q.as_string(None) if hasattr(q, "as_string") else str(q)
        self.queries.append(text)
        low = text.lower()
        if "has_parameter_privilege" in low:
            row: tuple[Any, ...] | None = (self.param_set,)
            rows: list[tuple[Any, ...]] = [row]
        elif "server_version_num" in low:
            row = (self.version,)
            rows = [row]
        elif "pg_signal_backend" in low:
            row = (self.superuser or self.signal,)
            rows = [row]
        elif "rolsuper" in low or "is_superuser" in low:
            row = (self.superuser,)
            rows = [row]
        else:
            rows = [(w,) for w in self.public_warnings]
            row = rows[0] if rows else None

        class C:
            def fetchone(self) -> tuple[Any, ...] | None:
                return row

            def fetchall(self) -> list[tuple[Any, ...]]:
                return rows

        return C()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *a: object) -> None:
        self.closed = 1

    def close(self) -> None:
        self.closed = 1


def run(*argv: str) -> tuple[int, dict[str, Any]]:
    out: list[str] = []
    code = cli.main(["--json", *argv], out.append)
    data = json.loads(out[-1]) if out else {}
    return code, data


def _by_name(d: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["name"]: c for c in d["checks"]}


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    monkeypatch.setenv("DATAGRANT_DSN", "postgresql://admin:pw9secret@db.example:6543/clinicdb")
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
    monkeypatch.delenv("DATAGRANT_STRICT_POLICY_PERMISSIONS", raising=False)
    monkeypatch.delenv("DATAGRANT_RECEIPT_SINK", raising=False)
    assert cli.main(["keys", "init", "--apply"], lambda s: None) == 0
    pol = tmp_path / "p.yaml"
    pol.write_text(POLICY)
    os.chmod(pol, 0o600)
    held: dict[str, FakeConn] = {}

    def factory(_dsn: str) -> Any:
        def open_conn() -> FakeConn:
            conn = FakeConn()
            held["conn"] = conn
            return conn

        return open_conn

    monkeypatch.setattr("datagrant.doctor._default_connect", factory)
    yield {"tmp": tmp_path, "pol": str(pol), "held": held, "factory": factory}


def test_doctor_clean_temp_dir_exit_0_json_shape(env: dict[str, Any]) -> None:
    code, d = run("doctor", "--policy", env["pol"])
    assert code == cli.EXIT_OK and d["ok"] is True
    names = [c["name"] for c in d["checks"]]
    assert names == list(CHECK_ORDER)
    for c in d["checks"]:
        assert set(c) == {"name", "status", "detail"}
        assert c["status"] in {STATUS_PASS, STATUS_WARN, STATUS_SKIP}
        assert c["status"] != STATUS_FAIL
    by = _by_name(d)
    assert by[CHECK_SINK_CURSOR]["status"] == STATUS_SKIP
    assert by[CHECK_PREFLIGHT]["status"] == STATUS_PASS
    conn: FakeConn = env["held"]["conn"]
    joined = " ".join(conn.queries).lower()
    assert "create schema" not in joined
    assert "create table" not in joined
    assert "set local log_statement" not in joined
    assert "set log_statement" not in joined
    assert "pg_advisory_lock" not in joined
    assert "pw9secret" not in json.dumps(d)


def test_doctor_missing_key_fails(env: dict[str, Any], tmp_path: Path) -> None:
    missing = tmp_path / "gone.key"
    code, d = run("doctor", "--policy", env["pol"], "--signing-key", str(missing))
    assert code == cli.EXIT_FAILED and d["ok"] is False
    assert _by_name(d)[CHECK_KEYS]["status"] == STATUS_FAIL
    assert "signing key" in _by_name(d)[CHECK_KEYS]["detail"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_doctor_group_readable_key_fails(env: dict[str, Any]) -> None:
    sk = Path(os.environ["DATAGRANT_SIGNING_KEY"])
    os.chmod(sk, 0o644)
    code, d = run("doctor", "--policy", env["pol"])
    assert code == cli.EXIT_FAILED
    assert "group/others" in _by_name(d)[CHECK_KEYS]["detail"]


def test_doctor_bad_policy_fails(env: dict[str, Any], tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 2\n")
    os.chmod(bad, 0o600)
    code, d = run("doctor", "--policy", str(bad))
    assert code == cli.EXIT_FAILED
    assert _by_name(d)[CHECK_POLICY]["status"] == STATUS_FAIL


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_doctor_policy_0644_warns_does_not_fail(env: dict[str, Any]) -> None:
    pol = Path(env["pol"])
    os.chmod(pol, 0o644)
    code, d = run("doctor", "--policy", str(pol))
    assert code == cli.EXIT_OK and d["ok"] is True
    assert _by_name(d)[CHECK_POLICY_PERMISSIONS]["status"] == STATUS_WARN
    assert "group/other-accessible" in _by_name(d)[CHECK_POLICY_PERMISSIONS]["detail"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_doctor_force_strict_skips_parse_of_untrusted_file(env: dict[str, Any]) -> None:
    pol = Path(env["pol"])
    pol.write_text("version: 2\n")
    os.chmod(pol, 0o644)
    code, d = run("doctor", "--policy", str(pol), "--strict-policy-permissions")
    assert code == cli.EXIT_FAILED
    names = [c["name"] for c in d["checks"]]
    assert names == list(CHECK_ORDER)
    assert _by_name(d)[CHECK_POLICY]["status"] == STATUS_SKIP
    assert "not parsed" in _by_name(d)[CHECK_POLICY]["detail"]
    assert _by_name(d)[CHECK_POLICY_PERMISSIONS]["status"] == STATUS_FAIL
    assert "group/other-accessible" in _by_name(d)[CHECK_POLICY_PERMISSIONS]["detail"]
    assert "unsupported" not in json.dumps(d).lower()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_doctor_env_force_strict_skips_parse(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = Path(env["pol"])
    pol.write_text("version: 2\n")
    os.chmod(pol, 0o644)
    monkeypatch.setenv("DATAGRANT_STRICT_POLICY_PERMISSIONS", "1")
    code, d = run("doctor", "--policy", str(pol))
    assert code == cli.EXIT_FAILED
    assert _by_name(d)[CHECK_POLICY]["status"] == STATUS_SKIP
    assert _by_name(d)[CHECK_POLICY_PERMISSIONS]["status"] == STATUS_FAIL


def test_doctor_strict_policy_permissions_env_typo_exits_2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATAGRANT_STRICT_POLICY_PERMISSIONS", "ture")
    code, d = run("doctor")
    assert code == cli.EXIT_USAGE
    err = d.get("error", "")
    assert "DATAGRANT_STRICT_POLICY_PERMISSIONS" in err
    assert "1/true/yes/on" in err
    assert "0/false/no/off" in err
    assert "ture" in err


@pytest.mark.parametrize("val", ["true", "YES", "on"])
def test_doctor_strict_policy_permissions_env_on_values_accepted(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, val: str
) -> None:
    monkeypatch.setenv("DATAGRANT_STRICT_POLICY_PERMISSIONS", val)
    os.chmod(Path(env["pol"]), 0o600)
    code, d = run("doctor", "--policy", env["pol"])
    assert code == cli.EXIT_OK and d["ok"] is True


@pytest.mark.parametrize("val", ["0", "false", "no", "off"])
def test_doctor_strict_policy_permissions_env_off_values_accepted(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, val: str
) -> None:
    monkeypatch.setenv("DATAGRANT_STRICT_POLICY_PERMISSIONS", val)
    os.chmod(Path(env["pol"]), 0o600)
    code, d = run("doctor", "--policy", env["pol"])
    assert code == cli.EXIT_OK and d["ok"] is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_doctor_strict_policy_permissions_fails_0644(env: dict[str, Any]) -> None:
    pol = Path(env["pol"])
    pol.write_text(POLICY + "strict_policy_permissions: true\n")
    os.chmod(pol, 0o644)
    code, d = run("doctor", "--policy", str(pol))
    assert code == cli.EXIT_FAILED
    assert _by_name(d)[CHECK_POLICY_PERMISSIONS]["status"] == STATUS_FAIL
    assert "group/other-accessible" in _by_name(d)[CHECK_POLICY_PERMISSIONS]["detail"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_doctor_receipt_log_0644_fails(env: dict[str, Any]) -> None:
    log = Path(os.environ["DATAGRANT_RECEIPT_LOG"])
    log.write_text("")
    os.chmod(log, 0o644)
    code, d = run("doctor", "--policy", env["pol"])
    assert code == cli.EXIT_FAILED
    assert _by_name(d)[CHECK_RECEIPT_LOG_PERMISSIONS]["status"] == STATUS_FAIL


def test_doctor_unreachable_dsn_fails(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    def factory(_dsn: str) -> Any:
        def open_conn() -> FakeConn:
            raise OSError("connection refused")

        return open_conn

    monkeypatch.setattr("datagrant.doctor._default_connect", factory)
    code, d = run("doctor", "--policy", env["pol"])
    assert code == cli.EXIT_FAILED
    by = _by_name(d)
    assert by[CHECK_CONNECT]["status"] == STATUS_FAIL
    assert by[CHECK_PREFLIGHT]["status"] == STATUS_SKIP
    assert by[CHECK_PG_SIGNAL_BACKEND]["status"] == STATUS_SKIP
    assert by[CHECK_LOG_STATEMENT]["status"] == STATUS_SKIP
    assert "pw9secret" not in json.dumps(d)


def test_doctor_missing_dsn_fails_not_usage(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    code, d = run("doctor", "--policy", env["pol"])
    assert code == cli.EXIT_FAILED
    assert _by_name(d)[CHECK_CONNECT]["status"] == STATUS_FAIL
    assert "DATAGRANT_DSN" in _by_name(d)[CHECK_CONNECT]["detail"]


def test_doctor_public_warning_listed_does_not_fail(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def factory(_dsn: str) -> Any:
        def open_conn() -> FakeConn:
            c = FakeConn(public_warnings=["PUBLIC can CREATE in schema public"])
            env["held"]["conn"] = c
            return c

        return open_conn

    monkeypatch.setattr("datagrant.doctor._default_connect", factory)
    code, d = run("doctor", "--policy", env["pol"])
    assert code == cli.EXIT_OK
    pre = _by_name(d)[CHECK_PREFLIGHT]
    assert pre["status"] == STATUS_WARN
    assert "PUBLIC" in pre["detail"]


def test_doctor_missing_pg_signal_backend_fails(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def factory(_dsn: str) -> Any:
        return lambda: FakeConn(superuser=False, signal=False)

    monkeypatch.setattr("datagrant.doctor._default_connect", factory)
    code, d = run("doctor", "--policy", env["pol"])
    assert code == cli.EXIT_FAILED
    assert _by_name(d)[CHECK_PG_SIGNAL_BACKEND]["status"] == STATUS_FAIL
    assert "pg_signal_backend" in _by_name(d)[CHECK_PG_SIGNAL_BACKEND]["detail"]


def test_doctor_missing_log_statement_set_privilege_fails(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def factory(_dsn: str) -> Any:
        return lambda: FakeConn(superuser=False, signal=True, param_set=False)

    monkeypatch.setattr("datagrant.doctor._default_connect", factory)
    code, d = run("doctor", "--policy", env["pol"])
    assert code == cli.EXIT_FAILED
    detail = _by_name(d)[CHECK_LOG_STATEMENT]["detail"]
    assert "SET log_statement" in detail
    assert "GRANT" in detail


def test_doctor_pg_lt_15_non_superuser_fails_without_has_parameter_privilege(
    tmp_path: Path,
) -> None:
    assert cli.main(["keys", "init", "--dir", str(tmp_path / "k"), "--apply"], lambda s: None) == 0
    pol = tmp_path / "p.yaml"
    pol.write_text(POLICY)
    os.chmod(pol, 0o600)
    conn = FakeConn(superuser=False, signal=True, version=140000, param_set=True)
    checks = run_doctor(
        signing_path=tmp_path / "k" / "signing.key",
        hash_path=tmp_path / "k" / "hash.key",
        policy_path=pol,
        receipt_log=tmp_path / "r.jsonl",
        dsn="postgresql://x",
        sink_configured=False,
        connect=lambda: conn,
    )
    by = {c.name: c for c in checks}
    assert by[CHECK_LOG_STATEMENT].status == STATUS_FAIL
    assert "PostgreSQL 15+" in by[CHECK_LOG_STATEMENT].detail
    joined = " ".join(conn.queries).lower()
    assert "has_parameter_privilege" not in joined
    assert "create schema" not in joined
    assert "set log_statement" not in joined


def test_doctor_pg_lt_15_superuser_passes(tmp_path: Path) -> None:
    assert cli.main(["keys", "init", "--dir", str(tmp_path / "k"), "--apply"], lambda s: None) == 0
    pol = tmp_path / "p.yaml"
    pol.write_text(POLICY)
    os.chmod(pol, 0o600)
    conn = FakeConn(superuser=True, version=140000)
    checks = run_doctor(
        signing_path=tmp_path / "k" / "signing.key",
        hash_path=tmp_path / "k" / "hash.key",
        policy_path=pol,
        receipt_log=tmp_path / "r.jsonl",
        dsn="postgresql://x",
        sink_configured=False,
        connect=lambda: conn,
    )
    by = {c.name: c for c in checks}
    assert by[CHECK_LOG_STATEMENT].status == STATUS_PASS
    assert "has_parameter_privilege" not in " ".join(conn.queries).lower()


def test_doctor_unreadable_cursor_fails(env: dict[str, Any]) -> None:
    log = Path(os.environ["DATAGRANT_RECEIPT_LOG"])
    log.write_text("")
    os.chmod(log, 0o600)
    cur = cursor_path(log)
    cur.write_text("{")
    os.chmod(cur, 0o600)
    code, d = run(
        "doctor",
        "--policy",
        env["pol"],
        "--receipt-sink",
        (env["tmp"] / "sink.jsonl").as_uri(),
    )
    assert code == cli.EXIT_FAILED
    assert _by_name(d)[CHECK_SINK_CURSOR]["status"] == STATUS_FAIL
    assert "corrupt" in _by_name(d)[CHECK_SINK_CURSOR]["detail"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_doctor_group_readable_cursor_fails_permissions(env: dict[str, Any]) -> None:
    log = Path(os.environ["DATAGRANT_RECEIPT_LOG"])
    log.write_text("")
    os.chmod(log, 0o600)
    write_cursor(log, 0)
    os.chmod(cursor_path(log), 0o644)
    code, d = run("doctor", "--policy", env["pol"])
    assert code == cli.EXIT_FAILED
    assert _by_name(d)[CHECK_RECEIPT_LOG_PERMISSIONS]["status"] == STATUS_FAIL


def test_doctor_apply_is_usage() -> None:
    assert cli.main(["doctor", "--apply"], lambda s: None) == cli.EXIT_USAGE


def test_doctor_no_mutating_sql_on_param_probe(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = FakeConn(superuser=False, signal=True, param_set=True)

    def factory(_dsn: str) -> Any:
        return lambda: conn

    monkeypatch.setattr("datagrant.doctor._default_connect", factory)
    code, d = run("doctor", "--policy", env["pol"])
    assert code == cli.EXIT_OK
    assert _PARAM_SQL.lower() in " ".join(q.lower() for q in conn.queries)
    assert all(
        "set " not in q.lower() or "has_parameter_privilege" in q.lower() for q in conn.queries
    )
    assert d["ok"] is True


def test_doctor_missing_policy_fails(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATAGRANT_POLICY", raising=False)
    code, d = run("doctor")
    assert code == cli.EXIT_FAILED
    assert _by_name(d)[CHECK_POLICY]["status"] == STATUS_FAIL
    assert _by_name(d)[CHECK_POLICY_PERMISSIONS]["status"] == STATUS_SKIP


def test_doctor_broken_receipt_chain_fails(env: dict[str, Any]) -> None:
    log = Path(os.environ["DATAGRANT_RECEIPT_LOG"])
    log.write_text("{}\n")
    os.chmod(log, 0o600)
    code, d = run("doctor", "--policy", env["pol"])
    assert code == cli.EXIT_FAILED
    assert _by_name(d)[CHECK_RECEIPT_CHAIN]["status"] == STATUS_FAIL


def test_doctor_sink_cursor_readable(env: dict[str, Any]) -> None:
    log = Path(os.environ["DATAGRANT_RECEIPT_LOG"])
    log.write_text("")
    os.chmod(log, 0o600)
    write_cursor(log, 0)
    code, d = run(
        "doctor",
        "--policy",
        env["pol"],
        "--receipt-sink",
        (env["tmp"] / "sink.jsonl").as_uri(),
    )
    assert code == cli.EXIT_OK
    assert _by_name(d)[CHECK_SINK_CURSOR]["status"] == STATUS_PASS
    assert "acked_seq 0" in _by_name(d)[CHECK_SINK_CURSOR]["detail"]


def test_doctor_help_omits_apply(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["doctor", "--help"]) == 0
    out = capsys.readouterr().out
    assert "--apply" not in out
    assert "--policy" in out
    assert "--dsn" in out
