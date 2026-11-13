"""Snowflake --apply routing: extra + DSN, no live connector, no grant SQL."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from datagrant import cli
from datagrant.cli import EXIT_OK, EXIT_USAGE
from datagrant.snowflake_support import (
    EXTRA_HINT,
    MAX_DSN_BYTES,
    NOT_IMPLEMENTED,
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
    text: list[str] = []
    assert cli.main([*SF_REQ, "--policy", str(path)], text.append) == EXIT_OK
    assert EXTRA_HINT in text[0]
    assert SNOWFLAKE_DSN_ENV in text[0]


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
    assert SNOWFLAKE_DSN_ENV in err
    assert "datagrant[snowflake]" not in err


def test_snowflake_apply_flag_dsn_ready_but_no_grant_sql(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    monkeypatch.delenv(SNOWFLAKE_DSN_ENV, raising=False)
    path = _policy(tmp_path)
    code = cli.main(
        [
            *SF_REQ,
            "--policy",
            str(path),
            "--apply",
            "--snowflake-dsn",
            "snowflake://svc@xy12345/CLINIC_DB",
        ]
    )
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert NOT_IMPLEMENTED in err
    assert "snowflake://svc@xy12345" not in err


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
