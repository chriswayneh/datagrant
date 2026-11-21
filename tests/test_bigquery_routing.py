"""BigQuery --apply routing: extra + ADC + project; dry run never calls GCP."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from datagrant import cli
from datagrant.bigquery_support import (
    ADC_CHECKING_MSG,
    BIGQUERY_CREDENTIALS_ENV,
    BIGQUERY_DSN_ENV,
    BIGQUERY_PROJECT_ENV,
    EXTRA_HINT,
    JSON_KEY_ADC_MSG,
)
from datagrant.cli import EXIT_OK, EXIT_USAGE

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
  - name: bq_clinic
    engine: bigquery
    database: clinic-proj
    schema: clinic_ds
    location: US
    tables:
      - name: clinic_ds.patients
        allowed_groups: [ml]
        columns: {patient_id: passthrough, ssn: hash}
        filter_columns: [region]
        row_filters: ["region = 'west'"]
"""

BQ_REQ = [
    "request",
    "--dataset",
    "bq_clinic",
    "--table",
    "clinic_ds.patients",
    "--columns",
    "patient_id",
    "--duration",
    "1h",
    "--purpose",
    "eval",
    "--as-user",
    "alice",
    "--google-principal",
    "user:alice@example.com",
]


def _policy(tmp_path: Path) -> Path:
    p = tmp_path / "mixed.yaml"
    p.write_text(MIXED)
    p.chmod(0o600)
    return p


def _boom_driver() -> bool:
    raise AssertionError("BigQuery driver probed")


def _boom_adc() -> bool:
    raise AssertionError("BigQuery ADC probed")


def _boom_client() -> Any:
    raise AssertionError("BigQuery client imported")


def test_policy_check_mixed_postgres_snowflake_bigquery(tmp_path: Path) -> None:
    path = _policy(tmp_path)
    out: list[str] = []
    code = cli.main(["policy", "check", str(path), "--json"], out.append)
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["ok"] is True
    assert "clinic" in body["datasets"]
    assert "snow_clinic" in body["datasets"]
    assert "bq_clinic" in body["datasets"]


def test_bigquery_dry_run_shows_google_principal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    path = _policy(tmp_path)
    out: list[str] = []
    code = cli.main([*BQ_REQ, "--policy", str(path), "--json"], out.append)
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["google_principal"] == "user:alice@example.com"
    text: list[str] = []
    assert cli.main([*BQ_REQ, "--policy", str(path)], text.append) == EXIT_OK
    assert "user:alice@example.com" in text[0]


def test_bigquery_request_requires_google_principal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    path = _policy(tmp_path)
    argv = [item for item in BQ_REQ if item != "user:alice@example.com"]
    # drop the flag name too
    cut = argv.index("--google-principal")
    argv = argv[:cut] + argv[cut + 1 :]
    code = cli.main([*argv, "--policy", str(path)])
    assert code == EXIT_USAGE
    assert "google principal" in capsys.readouterr().err


def test_bigquery_request_maps_policy_principal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    yaml = (
        MIXED
        + "\nidentity:\n  mode: local\n  google_principals:\n    alice: user:alice@example.com\n"
    )
    path = tmp_path / "mapped.yaml"
    path.write_text(yaml)
    path.chmod(0o600)
    argv = [item for item in BQ_REQ]
    cut = argv.index("--google-principal")
    argv = argv[:cut] + argv[cut + 2 :]
    out: list[str] = []
    code = cli.main([*argv, "--policy", str(path), "--json"], out.append)
    assert code == EXIT_OK
    assert json.loads(out[0])["google_principal"] == "user:alice@example.com"


def test_bigquery_approve_routes_without_postgres_dsn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.delenv("DATAGRANT_SNOWFLAKE_DSN", raising=False)
    path = _policy(tmp_path)
    out: list[str] = []
    code = cli.main(
        [
            "approve",
            "abcdef012345",
            "--policy",
            str(path),
            "--bigquery-project",
            "clinic-proj",
            "--as-user",
            "carol",
            "--json",
        ],
        out.append,
    )
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["dry_run"] is True
    assert body["engine"] == "bigquery"
    assert body["approver"] == "carol"
    text: list[str] = []
    assert (
        cli.main(
            [
                "approve",
                "abcdef012345",
                "--policy",
                str(path),
                "--bigquery-project",
                "clinic-proj",
                "--as-user",
                "carol",
            ],
            text.append,
        )
        == EXIT_OK
    )
    assert "stored google principal" in text[0]


def test_bigquery_dry_run_does_not_need_adc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.delenv(BIGQUERY_PROJECT_ENV, raising=False)
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", _boom_driver)
    monkeypatch.setattr("datagrant.bigquery_support.adc_available", _boom_adc)
    monkeypatch.setattr("datagrant.bigquery_support.load_client", _boom_client)
    path = _policy(tmp_path)
    out: list[str] = []
    code = cli.main([*BQ_REQ, "--policy", str(path), "--json"], out.append)
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["dry_run"] is True
    assert body["engine"] == "bigquery"
    text: list[str] = []
    assert cli.main([*BQ_REQ, "--policy", str(path)], text.append) == EXIT_OK
    assert EXTRA_HINT in text[0]
    assert BIGQUERY_PROJECT_ENV in text[0]


def test_bigquery_apply_missing_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: False)
    monkeypatch.delenv(BIGQUERY_PROJECT_ENV, raising=False)
    path = _policy(tmp_path)
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "datagrant[bigquery]" in err


def test_bigquery_apply_missing_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: True)
    monkeypatch.setattr("datagrant.bigquery_support.adc_available", lambda: True)
    monkeypatch.delenv(BIGQUERY_PROJECT_ENV, raising=False)
    path = _policy(tmp_path)
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "pass --bigquery-project or set $DATAGRANT_BIGQUERY_PROJECT" in err
    assert "datagrant[bigquery]" not in err


def test_bigquery_apply_missing_adc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: True)
    monkeypatch.setattr("datagrant.bigquery_support.adc_available", lambda: False)
    monkeypatch.setenv(BIGQUERY_PROJECT_ENV, "clinic-proj")
    path = _policy(tmp_path)
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "ADC" in err


def test_bigquery_apply_json_key_locator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: True)
    path = _policy(tmp_path)
    code = cli.main(
        [*BQ_REQ, "--policy", str(path), "--apply", "--bigquery-project", "/tmp/sa.json"]
    )
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "JSON key" in err
    assert "/tmp/sa.json" not in err


def test_bigquery_apply_credentials_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: True)
    path = _policy(tmp_path)
    code = cli.main(
        [*BQ_REQ, "--policy", str(path), "--apply", "--credentials-path", "/secret/key.json"]
    )
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "credentials_path" in err or "JSON key" in err
    assert "/secret/key.json" not in err


def test_bigquery_apply_dsn_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: True)
    monkeypatch.setenv(BIGQUERY_DSN_ENV, "bigquery://secret")
    path = _policy(tmp_path)
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "DSN" in err or "JSON key" in err
    assert "bigquery://secret" not in err


def test_bigquery_apply_credentials_env_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: True)
    monkeypatch.delenv(BIGQUERY_DSN_ENV, raising=False)
    monkeypatch.setenv(BIGQUERY_CREDENTIALS_ENV, "CRED-CANARY-not-a-dsn")
    path = _policy(tmp_path)
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "DSN" in err or "JSON key" in err
    assert "CRED-CANARY-not-a-dsn" not in err


def test_bigquery_apply_ready_is_not_implemented(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: True)
    monkeypatch.setattr("datagrant.bigquery_support.adc_available", lambda: True)
    monkeypatch.setenv(BIGQUERY_PROJECT_ENV, "clinic-proj")
    path = _policy(tmp_path)
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "not implemented" in err


def test_bigquery_apply_refuses_adc_service_account_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class _User:
        pass

    class _SAMod:
        class Credentials:
            pass

    class _Auth:
        @staticmethod
        def default(request: Any = None) -> tuple[object, str]:
            return _User(), "clinic-proj"

    class _Exc:
        class GoogleAuthError(Exception):
            pass

    def load(name: str) -> Any:
        if name == "google.auth":
            return _Auth
        if name == "google.auth.exceptions":
            return _Exc
        if name == "google.oauth2.service_account":
            return _SAMod
        raise ImportError(name)

    key = tmp_path / "sa.json"
    key.write_text(
        '{"type": "service_account", "private_key": "CANARY-SA-KEY"}',
        encoding="utf-8",
    )
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: True)
    monkeypatch.setenv(BIGQUERY_PROJECT_ENV, "clinic-proj")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
    monkeypatch.delenv(BIGQUERY_DSN_ENV, raising=False)
    monkeypatch.delenv(BIGQUERY_CREDENTIALS_ENV, raising=False)
    monkeypatch.setattr(
        "datagrant.bigquery_support._well_known_adc_path",
        lambda: tmp_path / "missing-adc.json",
    )
    monkeypatch.setattr("datagrant.bigquery_support.importlib.import_module", load)
    path = _policy(tmp_path)
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert JSON_KEY_ADC_MSG in err
    assert "CANARY-SA-KEY" not in err


def test_bigquery_apply_prints_adc_checking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class _User:
        pass

    class _SAMod:
        class Credentials:
            pass

    class _Auth:
        @staticmethod
        def default(request: Any = None) -> tuple[object, str]:
            return _User(), "clinic-proj"

    class _Exc:
        class GoogleAuthError(Exception):
            pass

    def load(name: str) -> Any:
        if name == "google.auth":
            return _Auth
        if name == "google.auth.exceptions":
            return _Exc
        if name == "google.oauth2.service_account":
            return _SAMod
        raise ImportError(name)

    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: True)
    monkeypatch.setenv(BIGQUERY_PROJECT_ENV, "clinic-proj")
    monkeypatch.delenv(BIGQUERY_DSN_ENV, raising=False)
    monkeypatch.delenv(BIGQUERY_CREDENTIALS_ENV, raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setattr(
        "datagrant.bigquery_support._well_known_adc_path",
        lambda: tmp_path / "missing-adc.json",
    )
    monkeypatch.setattr("datagrant.bigquery_support.importlib.import_module", load)
    path = _policy(tmp_path)
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert ADC_CHECKING_MSG in err
    assert "not implemented" in err


def test_bigquery_request_canonicalizes_three_part_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.delenv(BIGQUERY_PROJECT_ENV, raising=False)
    path = _policy(tmp_path)
    out: list[str] = []
    code = cli.main(
        [
            "request",
            "--dataset",
            "bq_clinic",
            "--table",
            "clinic-proj.clinic_ds.patients",
            "--columns",
            "patient_id",
            "--duration",
            "1h",
            "--purpose",
            "eval",
            "--as-user",
            "alice",
            "--google-principal",
            "user:alice@example.com",
            "--policy",
            str(path),
            "--json",
        ],
        out.append,
    )
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["dry_run"] is True
    assert body["table"] == "clinic_ds.patients"
    assert body["google_principal"] == "user:alice@example.com"


def test_bigquery_request_rejects_three_part_wrong_project(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _policy(tmp_path)
    code = cli.main(
        [
            "request",
            "--dataset",
            "bq_clinic",
            "--table",
            "other-proj.clinic_ds.patients",
            "--columns",
            "patient_id",
            "--duration",
            "1h",
            "--purpose",
            "eval",
            "--as-user",
            "alice",
            "--policy",
            str(path),
        ]
    )
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "must match dataset.database" in err
    assert "other-proj" in err


def test_revoke_credentials_path_refused(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["revoke", "g1", "--credentials-path", "x"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "credentials_path" in err or "JSON key" in err
    assert "'x'" not in err
    assert '"x"' not in err


def test_revoke_bigquery_dsn_refused(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["revoke", "g1", "--bigquery-dsn", "x"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "DSN" in err or "JSON key" in err
    assert "'x'" not in err
    assert '"x"' not in err


def test_postgres_request_credentials_path_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _policy(tmp_path)
    code = cli.main(
        [
            "request",
            "--dataset",
            "clinic",
            "--table",
            "public.patients",
            "--columns",
            "id",
            "--duration",
            "1h",
            "--purpose",
            "eval",
            "--as-user",
            "alice",
            "--policy",
            str(path),
            "--credentials-path",
            "x",
        ]
    )
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "credentials_path" in err or "JSON key" in err
    assert "'x'" not in err
    assert '"x"' not in err


def test_snowflake_request_credentials_path_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _policy(tmp_path)
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
            "alice",
            "--policy",
            str(path),
            "--credentials-path",
            "x",
        ]
    )
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "credentials_path" in err or "JSON key" in err
    assert "'x'" not in err
    assert '"x"' not in err


def test_snowflake_request_does_not_open_bigquery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", _boom_driver)
    monkeypatch.setattr("datagrant.bigquery_support.adc_available", _boom_adc)
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
            "alice",
            "--policy",
            str(path),
            "--json",
        ],
        out.append,
    )
    assert code == EXIT_OK
    assert json.loads(out[0])["engine"] == "snowflake"
    assert json.loads(out[0])["dry_run"] is True
