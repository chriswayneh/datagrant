"""Snowflake --apply routing and grant engine: extra + DSN, mocked connector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from datagrant import cli
from datagrant.cli import EXIT_OK, EXIT_USAGE
from datagrant.snowflake_support import (
    EXTRA_HINT,
    MAX_DSN_BYTES,
    SNOWFLAKE_DSN_ENV,
)

MIXED = """\
version: 1
approval: auto
max_duration: 8h
groups:
  ml: [alice]
datasets:
  - name: clinic
    database: clinicdb
    tables:
      - name: public.patients
        allowed_groups: [ml]
        columns: {id: passthrough, region: passthrough}
        row_filters: ["region = 'west'"]
        require_row_filter: true
  - name: snow_clinic
    engine: snowflake
    database: CLINIC_DB
    schema: PUBLIC
    tables:
      - name: PUBLIC.PATIENTS
        allowed_groups: [ml]
        columns: {PATIENT_ID: passthrough, SSN: hash}
"""

SF_REQ = [
    "request",
    "--dataset",
    "snow_clinic",
    "--table",
    "PUBLIC.PATIENTS",
    "--columns",
    "PATIENT_ID",
    "--duration",
    "1h",
    "--purpose",
    "eval",
    "--as-user",
    "alice",
]


def _policy(tmp_path: Path) -> Path:
    p = tmp_path / "mixed.yaml"
    p.write_text(MIXED)
    p.chmod(0o600)
    return p


def test_policy_check_mixed_file(tmp_path: Path) -> None:
    path = _policy(tmp_path)
    out: list[str] = []
    code = cli.main(["policy", "check", str(path), "--json"], out.append)
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["ok"] is True
    assert "clinic" in body["datasets"] and "snow_clinic" in body["datasets"]


def test_snowflake_dry_run_skips_postgres_dsn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.delenv(SNOWFLAKE_DSN_ENV, raising=False)
    path = _policy(tmp_path)
    out: list[str] = []
    code = cli.main([*SF_REQ, "--policy", str(path), "--json"], out.append)
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["dry_run"] is True
    assert body["engine"] == "snowflake"
    assert "sql" in body
    assert any("CREATE USER" in s for s in body["sql"])
    assert all("BEGIN" not in s for s in body["sql"])
    text: list[str] = []
    assert cli.main([*SF_REQ, "--policy", str(path)], text.append) == EXIT_OK
    assert EXTRA_HINT in text[0]
    assert SNOWFLAKE_DSN_ENV in text[0]
    assert "BEGIN PRIVATE KEY" not in text[0]


def test_snowflake_apply_missing_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: False)
    monkeypatch.setenv(SNOWFLAKE_DSN_ENV, "snowflake://svc@xy12345/CLINIC_DB")
    path = _policy(tmp_path)
    code = cli.main([*SF_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "datagrant[snowflake]" in err
    assert "snowflake://svc@xy12345" not in err


def test_snowflake_apply_missing_dsn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    monkeypatch.delenv(SNOWFLAKE_DSN_ENV, raising=False)
    path = _policy(tmp_path)
    code = cli.main([*SF_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "pass --snowflake-dsn or set $DATAGRANT_SNOWFLAKE_DSN" in err
    assert "pass --snowflake-dsn <redacted>" not in err
    assert "datagrant[snowflake]" not in err


class _FakeSf:
    def __init__(self) -> None:
        self.queries: list[tuple[str, Any]] = []

    def cursor(self) -> _FakeSf:
        return self

    def execute(self, sql: str, params: Any = None) -> _FakeSf:
        self.queries.append((sql, params))
        return self

    def fetchone(self) -> None:
        return None

    def close(self) -> None:
        return None


def test_snowflake_apply_issues_service_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    monkeypatch.setattr("datagrant.snowflake_support.connect", lambda dsn: _FakeSf())
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.delenv(SNOWFLAKE_DSN_ENV, raising=False)
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
    assert cli.main(["keys", "init", "--apply"], lambda s: None) == 0
    path = _policy(tmp_path)
    dsn = "snowflake://svc:supersecret@xy12345/CLINIC_DB"
    out: list[str] = []
    code = cli.main(
        [*SF_REQ, "--policy", str(path), "--apply", "--snowflake-dsn", dsn, "--json"],
        out.append,
    )
    err = capsys.readouterr().err
    assert code == EXIT_OK, err or (out[-1] if out else "")
    body = json.loads(out[0])
    assert body["status"] == "granted"
    assert body["engine"] == "snowflake"
    assert "BEGIN" in body["private_key"]
    assert "password" not in body
    assert "supersecret" not in err
    assert "xy12345" not in err
    rec = json.loads((tmp_path / "r.jsonl").read_text().splitlines()[0])["receipt"]
    assert rec["event"] == "issued"
    assert rec["details"]["public_key_fingerprint"] == body["public_key_fingerprint"]
    assert "private_key" not in json.dumps(rec)


def test_snowflake_dsn_too_long(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    path = _policy(tmp_path)
    huge = "s" * (MAX_DSN_BYTES + 1)
    code = cli.main([*SF_REQ, "--policy", str(path), "--apply", "--snowflake-dsn", huge])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "too long" in err
    assert huge not in err


def test_whitespace_dsn_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    monkeypatch.setenv(SNOWFLAKE_DSN_ENV, "   ")
    path = _policy(tmp_path)
    code = cli.main([*SF_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    assert SNOWFLAKE_DSN_ENV in capsys.readouterr().err


def test_denied_snowflake_request_does_not_need_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "datagrant.snowflake_support.driver_present",
        lambda: (_ for _ in ()).throw(AssertionError("driver probed on deny")),
    )
    path = _policy(tmp_path)
    out: list[str] = []
    code = cli.main(
        [
            "request",
            "--dataset",
            "snow_clinic",
            "--table",
            "PUBLIC.PATIENTS",
            "--columns",
            "PATIENT_ID",
            "--duration",
            "1h",
            "--purpose",
            "eval",
            "--as-user",
            "eve",
            "--policy",
            str(path),
            "--json",
        ],
        out.append,
    )
    assert code == 1
    assert json.loads(out[0])["allowed"] is False


def test_dsn_kwargs_and_connect_never_need_network(monkeypatch: pytest.MonkeyPatch) -> None:
    from datagrant.snowflake_support import _dsn_kwargs, connect

    kw = _dsn_kwargs("snowflake://svc@xy12345/CLINIC_DB?warehouse=WH")
    assert kw["account"] == "xy12345"
    assert kw["user"] == "svc"
    assert kw["database"] == "CLINIC_DB"
    assert kw["warehouse"] == "WH"
    kv = _dsn_kwargs("account=xy user=svc warehouse=WH")
    assert kv["account"] == "xy" and kv["user"] == "svc"

    captured: dict[str, Any] = {}

    class _Mod:
        @staticmethod
        def connect(**kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return captured

    monkeypatch.setattr("datagrant.snowflake_support.load_connector", lambda: _Mod())
    got = connect("snowflake://svc@xy12345/DB")
    assert got["account"] == "xy12345"
    assert got["user"] == "svc"


def test_two_person_request_stores_public_key_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _FakeSf()
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    monkeypatch.setattr("datagrant.snowflake_support.connect", lambda dsn: conn)
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
    monkeypatch.setenv(SNOWFLAKE_DSN_ENV, "snowflake://svc@xy12345/CLINIC_DB")
    assert cli.main(["keys", "init", "--apply"], lambda s: None) == 0
    pol = tmp_path / "two.yaml"
    pol.write_text(
        MIXED.replace("approval: auto", "approval: two-person").replace(
            "groups:\n  ml: [alice]\n",
            "approvers: [sec]\ngroups:\n  ml: [alice]\n  sec: [carol]\n",
        )
    )
    pol.chmod(0o600)
    out: list[str] = []
    code = cli.main([*SF_REQ, "--policy", str(pol), "--apply", "--json"], out.append)
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["status"] == "pending"
    assert "BEGIN" in body["private_key"]
    blob = "\n".join(s for s, _p in conn.queries)
    assert "RSA_PUBLIC_KEY" in blob
    assert "CREATE USER" not in blob
    assert body["private_key"] not in blob
