"""BigQuery --apply routing: extra + ADC + project; dry run never calls GCP."""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from datagrant import cli
from datagrant.bigquery_support import (
    BIGQUERY_CREDENTIALS_ENV,
    BIGQUERY_DSN_ENV,
    BIGQUERY_PROJECT_ENV,
    EXTRA_HINT,
    JSON_KEY_ADC_MSG,
)
from datagrant.bq.grant import identity_with_principal
from datagrant.bq.revoke import PendingRequest
from datagrant.bq.state import RequestSnapshot
from datagrant.cli import EXIT_FAILED, EXIT_OK, EXIT_USAGE
from datagrant.receipt import GrantFacts

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

TWO_PERSON = """\
version: 1
approval: two-person
approvers: [approvers]
max_duration: 8h
groups:
  ml: [alice]
  approvers: [carol, bob]
datasets:
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

STORED_PRINCIPAL = "user:alice@example.com"


def _two_person(tmp_path: Path, extra: str = "") -> Path:
    p = tmp_path / "two.yaml"
    p.write_text(TWO_PERSON + extra)
    p.chmod(0o600)
    return p


def _pending_snapshot(
    principal: str = STORED_PRINCIPAL, *, identity: dict[str, Any] | None = None
) -> RequestSnapshot:
    now = datetime.now(UTC)
    facts = GrantFacts(
        "abcdef012345",
        "alice",
        "bq_clinic",
        "clinic_ds.patients",
        ("patient_id",),
        {"patient_id": "passthrough"},
        "region = 'west'",
        "eval",
        now,
        now + timedelta(hours=1),
        "f" * 64,
        1,
        "two-person",
        (),
        identity_with_principal(identity or {"source": "os"}, principal) if principal else None,
        None,
    )
    pending = PendingRequest("abcdef012345", now + timedelta(hours=20), facts)
    return RequestSnapshot(pending, principal, ())


@contextmanager
def _fake_bq_client(
    *,
    snapshot: RequestSnapshot | None = None,
    live: int = 0,
    inserted: list | None = None,
) -> Any:
    class Store:
        def count_live_grants(self, requester: str, principal: str | None = None) -> int:
            return live

        class requests:
            @staticmethod
            def get_pending(request_id: str) -> RequestSnapshot | None:
                return snapshot

            @staticmethod
            def insert_pending(row: PendingRequest, principal: str) -> None:
                if inserted is not None:
                    inserted.append((row, principal))

    yield Store()


def _patch_bq_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    snapshot: RequestSnapshot | None = None,
    live: int = 0,
    inserted: list | None = None,
) -> None:
    @contextmanager
    def fake(_args: Any, **_kw: Any) -> Any:
        with _fake_bq_client(snapshot=snapshot, live=live, inserted=inserted) as client:
            yield client

    monkeypatch.setattr("datagrant.cli._bq_grant_client", fake)


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
    _patch_bq_client(monkeypatch, snapshot=_pending_snapshot())
    path = _two_person(tmp_path)
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
    assert body["google_principal"] == STORED_PRINCIPAL
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
    assert STORED_PRINCIPAL in text[0]
    assert "may approve" in text[0]


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


def test_google_principal_flag_mismatch_from_mapping_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    yaml = (
        MIXED
        + "\nidentity:\n  mode: local\n  google_principals:\n    alice: user:alice@example.com\n"
    )
    path = tmp_path / "mapped.yaml"
    path.write_text(yaml)
    path.chmod(0o600)
    argv = list(BQ_REQ)
    argv[argv.index("user:alice@example.com")] = "user:other@example.com"
    code = cli.main([*argv, "--policy", str(path)])
    assert code == EXIT_USAGE
    assert "does not match identity" in capsys.readouterr().err


def test_google_principal_flag_mismatch_from_oidc_email_is_refused() -> None:
    from datagrant.cli import CliError, _bq_resolve_principal

    policy = SimpleNamespace(
        identity=SimpleNamespace(mode="oidc", google_principals={}),
    )
    args = SimpleNamespace(google_principal="user:other@example.com")
    caller = SimpleNamespace(username="alice@example.com", source="oidc", username_claim="email")
    with pytest.raises(CliError, match="does not match identity") as exc:
        _bq_resolve_principal(args, policy, caller)
    assert exc.value.code == EXIT_USAGE


def test_google_principal_group_and_sa_flags_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    path = _policy(tmp_path)
    for member in (
        "group:eng@example.com",
        "serviceAccount:sa@clinic-proj.iam.gserviceaccount.com",
    ):
        argv = list(BQ_REQ)
        argv[argv.index("user:alice@example.com")] = member
        code = cli.main([*argv, "--policy", str(path)])
        assert code == EXIT_USAGE
        assert "must be user:" in capsys.readouterr().err


def test_google_principal_canonical_match_is_accepted(
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
    out: list[str] = []
    code = cli.main([*BQ_REQ, "--policy", str(path), "--json"], out.append)
    assert code == EXIT_OK
    assert json.loads(out[0])["google_principal"] == "user:alice@example.com"


def test_oidc_sub_claim_with_at_gets_no_principal() -> None:
    from datagrant.cli import CliError, _bq_resolve_principal

    policy = SimpleNamespace(
        identity=SimpleNamespace(mode="oidc", google_principals={}),
    )
    args = SimpleNamespace(google_principal=None)
    caller = SimpleNamespace(username="alice@example.com", source="oidc", username_claim="sub")
    with pytest.raises(CliError, match="google principal is required"):
        _bq_resolve_principal(args, policy, caller)


def test_oidc_group_prefixed_email_is_refused() -> None:
    from datagrant.cli import CliError, _bq_resolve_principal

    policy = SimpleNamespace(
        identity=SimpleNamespace(mode="oidc", google_principals={}),
    )
    args = SimpleNamespace(google_principal=None)
    caller = SimpleNamespace(
        username="group:eng@example.com", source="oidc", username_claim="email"
    )
    with pytest.raises(CliError, match="must not contain ':'"):
        _bq_resolve_principal(args, policy, caller)


def test_request_apply_enforces_concurrent_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: True)
    monkeypatch.setattr("datagrant.bigquery_support.adc_available", lambda: True)
    monkeypatch.setenv(BIGQUERY_PROJECT_ENV, "clinic-proj")
    monkeypatch.setattr("datagrant.cli._write_decision_receipt", lambda *a, **k: None)
    _patch_bq_client(monkeypatch, live=1)
    yaml = MIXED + "\nmax_concurrent_grants: 1\n"
    path = tmp_path / "cap.yaml"
    path.write_text(yaml)
    path.chmod(0o600)
    out: list[str] = []
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"], out.append)
    assert code == EXIT_FAILED
    assert "max_concurrent_grants is 1" in out[0]
    assert "not implemented" not in out[0]


def test_approve_enforces_concurrent_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.delenv("DATAGRANT_SNOWFLAKE_DSN", raising=False)
    _patch_bq_client(monkeypatch, snapshot=_pending_snapshot(), live=1)
    path = _two_person(tmp_path, "\nmax_concurrent_grants: 1\n")
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
        ]
    )
    assert code == EXIT_FAILED
    captured = capsys.readouterr()
    assert "max_concurrent_grants is 1" in captured.err
    assert "may approve" not in captured.out


def test_two_person_request_apply_persists_canonical_principal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: True)
    monkeypatch.setattr("datagrant.bigquery_support.adc_available", lambda: True)
    monkeypatch.setenv(BIGQUERY_PROJECT_ENV, "clinic-proj")
    inserted: list[Any] = []
    _patch_bq_client(monkeypatch, inserted=inserted)
    path = _two_person(tmp_path)
    out: list[str] = []
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply", "--json"], out.append)
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["status"] == "pending"
    assert body["google_principal"] == STORED_PRINCIPAL
    assert len(inserted) == 1
    row, principal = inserted[0]
    assert principal == STORED_PRINCIPAL
    assert row.facts.identity is not None
    assert row.facts.identity["google_principal"] == STORED_PRINCIPAL


def test_approve_shows_stored_principal_not_approver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    stored = "user:stored-alice@example.com"
    _patch_bq_client(monkeypatch, snapshot=_pending_snapshot(stored))
    path = _two_person(tmp_path)
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
    assert body["google_principal"] == stored
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
    assert stored in text[0]
    assert "may approve" in text[0]


def test_approve_rejects_google_principal_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _two_person(tmp_path)
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
            "--google-principal",
            "user:carol@example.com",
        ]
    )
    assert code == EXIT_USAGE
    assert "unrecognized arguments" in capsys.readouterr().err


def test_approve_refuses_missing_stored_principal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    _patch_bq_client(monkeypatch, snapshot=_pending_snapshot(""))
    path = _two_person(tmp_path)
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
        ]
    )
    assert code == EXIT_USAGE
    captured = capsys.readouterr()
    assert "missing a stored google principal" in captured.err
    assert "may approve" not in captured.out


def test_approve_loads_request_before_may_approve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    _patch_bq_client(monkeypatch, snapshot=None)
    path = _two_person(tmp_path)
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
        ]
    )
    assert code == EXIT_FAILED
    captured = capsys.readouterr()
    assert "is not pending" in captured.err
    assert "may approve" not in captured.out


def test_approve_checks_policy_before_may_approve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    snapshot = _pending_snapshot()
    snapshot = RequestSnapshot(
        PendingRequest(
            snapshot.pending.request_id,
            snapshot.pending.expires_at,
            GrantFacts(
                snapshot.pending.facts.grant_id,
                snapshot.pending.facts.requester,
                "missing_dataset",
                snapshot.pending.facts.table,
                snapshot.pending.facts.columns,
                snapshot.pending.facts.masks,
                snapshot.pending.facts.row_filter,
                snapshot.pending.facts.purpose,
                snapshot.pending.facts.starts_at,
                snapshot.pending.facts.expires_at,
                snapshot.pending.facts.policy_sha256,
                snapshot.pending.facts.policy_version,
                snapshot.pending.facts.approval,
                snapshot.pending.facts.approvers,
                snapshot.pending.facts.identity,
                snapshot.pending.facts.approver_identities,
            ),
        ),
        snapshot.principal,
        (),
    )
    _patch_bq_client(monkeypatch, snapshot=snapshot)
    path = _two_person(tmp_path)
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
        ]
    )
    assert code == EXIT_FAILED
    captured = capsys.readouterr()
    assert "no longer names a BigQuery policy table" in captured.err
    assert "may approve" not in captured.out


def test_approve_checks_sod_before_may_approve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    _patch_bq_client(monkeypatch, snapshot=_pending_snapshot())
    yaml = TWO_PERSON.replace("ml: [alice]", "ml: [alice, carol]")
    yaml += "\nseparation_of_duties: distinct-groups\n"
    path = tmp_path / "sod.yaml"
    path.write_text(yaml)
    path.chmod(0o600)
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
        ]
    )
    assert code == EXIT_FAILED
    captured = capsys.readouterr()
    assert "not eligible" in captured.err
    assert "may approve" not in captured.out


def test_approve_ineligible_caller_is_not_may_approve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    _patch_bq_client(monkeypatch, snapshot=_pending_snapshot())
    path = _two_person(tmp_path)
    code = cli.main(
        [
            "approve",
            "abcdef012345",
            "--policy",
            str(path),
            "--bigquery-project",
            "clinic-proj",
            "--as-user",
            "dave",
        ]
    )
    assert code == EXIT_FAILED
    captured = capsys.readouterr()
    assert "not eligible" in captured.err
    assert "may approve" not in captured.out


def test_approve_checks_quorum_before_may_approve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    _patch_bq_client(monkeypatch, snapshot=_pending_snapshot())
    path = _two_person(tmp_path, "\napprovals_required: 2\n")
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
    assert body["google_principal"] == STORED_PRINCIPAL
    assert body["approvals_required"] == 2
    assert body["approvals_recorded"] == 1
