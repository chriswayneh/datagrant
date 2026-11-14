"""BigQuery extra probe, project locator, ADC, and JSON-key refusal."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

from datagrant.bigquery_support import (
    ADC_CHECKING_MSG,
    ADC_SCOPES,
    BIGQUERY_CREDENTIALS_ENV,
    BIGQUERY_DSN_ENV,
    BIGQUERY_PROJECT_ENV,
    JSON_KEY_ADC_MSG,
    BigQuerySetupError,
    adc_available,
    driver_present,
    load_client,
    refuse_secret_locator,
    require_adc,
    require_driver,
    resolve_location,
    resolve_project,
)


def test_driver_present_does_not_raise() -> None:
    assert driver_present() in (True, False)


def test_driver_present_true_when_importable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        lambda name: object(),
    )
    assert driver_present() is True


def test_driver_present_false_on_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_name: str) -> Any:
        raise ImportError("no bigquery")

    monkeypatch.setattr("datagrant.bigquery_support.importlib.import_module", boom)
    assert driver_present() is False


def test_require_driver_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: False)
    with pytest.raises(BigQuerySetupError, match="datagrant\\[bigquery\\]"):
        require_driver()


def test_require_driver_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: True)
    require_driver()


def test_load_client_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = object()
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        lambda name: mod,
    )
    assert load_client() is mod


def test_load_client_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_name: str) -> Any:
        raise ImportError("no bigquery")

    monkeypatch.setattr("datagrant.bigquery_support.importlib.import_module", boom)
    with pytest.raises(BigQuerySetupError, match="datagrant\\[bigquery\\]"):
        load_client()


def test_resolve_project_flag_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(BIGQUERY_PROJECT_ENV, "env-proj")
    assert resolve_project("flag-proj") == "flag-proj"
    assert resolve_project(None) == "env-proj"


def test_resolve_project_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BIGQUERY_PROJECT_ENV, raising=False)
    with pytest.raises(BigQuerySetupError, match="pass --bigquery-project"):
        resolve_project(None)


def test_resolve_project_rejects_json_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BIGQUERY_PROJECT_ENV, raising=False)
    with pytest.raises(BigQuerySetupError, match="JSON key"):
        resolve_project("/tmp/sa.json")


def test_resolve_project_rejects_credentials_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BIGQUERY_PROJECT_ENV, raising=False)
    with pytest.raises(BigQuerySetupError, match="credentials_path"):
        resolve_project("credentials_path=/tmp/sa.json")


def test_refuse_secret_locator_dsn_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(BIGQUERY_DSN_ENV, "bigquery://x")
    with pytest.raises(BigQuerySetupError, match="DSN"):
        refuse_secret_locator(None)


def test_refuse_secret_locator_credentials_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BIGQUERY_DSN_ENV, raising=False)
    monkeypatch.setenv(BIGQUERY_CREDENTIALS_ENV, "CRED-CANARY-not-a-dsn")
    with pytest.raises(BigQuerySetupError, match="DSN") as excinfo:
        refuse_secret_locator(None)
    assert "CRED-CANARY-not-a-dsn" not in str(excinfo.value)


def test_refuse_secret_locator_credentials_flag() -> None:
    with pytest.raises(BigQuerySetupError, match="credentials_path"):
        refuse_secret_locator(None, credentials_path="/tmp/key")


def test_refuse_secret_locator_ok_project(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BIGQUERY_DSN_ENV, raising=False)
    monkeypatch.delenv(BIGQUERY_CREDENTIALS_ENV, raising=False)
    refuse_secret_locator("clinic-proj")


def test_resolve_location_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATAGRANT_BIGQUERY_LOCATION", raising=False)
    assert resolve_location(None) is None


def test_resolve_location_flag() -> None:
    assert resolve_location("US") == "US"


def test_adc_available_false_without_google(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_name: str) -> Any:
        raise ImportError("no google")

    monkeypatch.setattr("datagrant.bigquery_support.importlib.import_module", boom)
    assert adc_available() is False


def test_require_adc_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.adc_available", lambda: False)
    with pytest.raises(BigQuerySetupError, match="ADC"):
        require_adc()


def test_require_adc_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("datagrant.bigquery_support.adc_available", lambda: True)
    require_adc()


class _SACreds:
    pass


class _UserCreds:
    pass


class _ComputeCreds:
    pass


class _SAMod:
    Credentials = _SACreds


class _AuthMod:
    def __init__(self, creds: Any, *, boom: BaseException | None = None) -> None:
        self._creds = creds
        self._boom = boom

    def default(self, request: Any = None, scopes: Any = None) -> tuple[Any, str]:
        if self._boom is not None:
            raise self._boom
        assert os.environ.get("GCE_METADATA_TIMEOUT") == "1"
        assert scopes == ADC_SCOPES
        return self._creds, "clinic-proj"


class _GoogleAuthError(Exception):
    pass


class _AuthExc:
    GoogleAuthError = _GoogleAuthError


def _no_adc_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    missing = tmp_path / "missing-adc.json"
    monkeypatch.setattr(
        "datagrant.bigquery_support._well_known_adc_path",
        lambda: missing,
    )


def _auth_loader(creds: Any, *, boom: BaseException | None = None) -> Any:
    auth = _AuthMod(creds, boom=boom)

    def load(name: str) -> Any:
        if name == "google.auth":
            return auth
        if name == "google.auth.exceptions":
            return _AuthExc
        if name == "google.oauth2.service_account":
            return _SAMod
        raise ImportError(name)

    return load


def test_adc_available_true(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _no_adc_files(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        _auth_loader(_UserCreds()),
    )
    assert adc_available() is True


def test_adc_available_google_auth_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _no_adc_files(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        _auth_loader(_UserCreds(), boom=_GoogleAuthError("no adc")),
    )
    assert adc_available() is False


def test_adc_available_prints_checking(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_adc_files(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        _auth_loader(_UserCreds()),
    )
    assert adc_available() is True
    assert ADC_CHECKING_MSG in capsys.readouterr().err


def test_adc_refuses_service_account_credentials_class(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _no_adc_files(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        _auth_loader(_SACreds()),
    )
    with pytest.raises(BigQuerySetupError, match=re.escape(JSON_KEY_ADC_MSG)):
        adc_available()


def test_adc_refuses_gac_service_account_type(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key = tmp_path / "sa.json"
    key.write_text(
        json.dumps({"type": "service_account", "private_key": "CANARY-SA-KEY"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
    monkeypatch.setattr(
        "datagrant.bigquery_support._well_known_adc_path",
        lambda: tmp_path / "missing-adc.json",
    )
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        _auth_loader(_UserCreds()),
    )
    with pytest.raises(BigQuerySetupError, match=re.escape(JSON_KEY_ADC_MSG)) as excinfo:
        adc_available()
    assert "CANARY-SA-KEY" not in str(excinfo.value)


def test_adc_refuses_gcloud_adc_service_account_type(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    adc = tmp_path / "application_default_credentials.json"
    adc.write_text(json.dumps({"type": "service_account"}), encoding="utf-8")
    monkeypatch.setattr(
        "datagrant.bigquery_support._well_known_adc_path",
        lambda: adc,
    )
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        _auth_loader(_UserCreds()),
    )
    with pytest.raises(BigQuerySetupError, match=re.escape(JSON_KEY_ADC_MSG)):
        adc_available()


@pytest.mark.parametrize(
    "kind",
    (
        "authorized_user",
        "impersonated_service_account",
        "external_account",
    ),
)
def test_adc_allows_file_type(kind: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    adc = tmp_path / "adc.json"
    adc.write_text(json.dumps({"type": kind}), encoding="utf-8")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(adc))
    monkeypatch.setattr(
        "datagrant.bigquery_support._well_known_adc_path",
        lambda: tmp_path / "missing-adc.json",
    )
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        _auth_loader(_UserCreds()),
    )
    assert adc_available() is True


def test_adc_allows_compute_engine(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _no_adc_files(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        _auth_loader(_ComputeCreds()),
    )
    assert adc_available() is True


def test_adc_refuses_cloudsdk_config_service_account(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(tmp_path))
    (tmp_path / "application_default_credentials.json").write_text(
        json.dumps({"type": "service_account"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        _auth_loader(_UserCreds()),
    )
    with pytest.raises(BigQuerySetupError, match=re.escape(JSON_KEY_ADC_MSG)):
        adc_available()


def test_adc_refuses_cloud_sdk_helper_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    adc = tmp_path / "from-sdk.json"
    adc.write_text(json.dumps({"type": "service_account"}), encoding="utf-8")

    class _Sdk:
        @staticmethod
        def get_application_default_credentials_path() -> str:
            return str(adc)

    base = _auth_loader(_UserCreds())

    def load(name: str) -> Any:
        if name == "google.auth._cloud_sdk":
            return _Sdk
        return base(name)

    monkeypatch.setattr("datagrant.bigquery_support.importlib.import_module", load)
    with pytest.raises(BigQuerySetupError, match=re.escape(JSON_KEY_ADC_MSG)):
        adc_available()


def test_adc_gac_unreadable_json_is_not_a_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key = tmp_path / "adc.json"
    key.write_text("not-json {", encoding="utf-8")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
    monkeypatch.setattr(
        "datagrant.bigquery_support._well_known_adc_path",
        lambda: tmp_path / "missing-adc.json",
    )
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        _auth_loader(_UserCreds()),
    )
    assert adc_available() is True


def test_adc_gac_non_object_json_is_not_a_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key = tmp_path / "adc.json"
    key.write_text("[1, 2]", encoding="utf-8")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
    monkeypatch.setattr(
        "datagrant.bigquery_support._well_known_adc_path",
        lambda: tmp_path / "missing-adc.json",
    )
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        _auth_loader(_UserCreds()),
    )
    assert adc_available() is True


def test_adc_gac_missing_type_is_not_a_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    key = tmp_path / "adc.json"
    key.write_text(json.dumps({"client_id": "x"}), encoding="utf-8")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
    monkeypatch.setattr(
        "datagrant.bigquery_support._well_known_adc_path",
        lambda: tmp_path / "missing-adc.json",
    )
    monkeypatch.setattr(
        "datagrant.bigquery_support.importlib.import_module",
        _auth_loader(_UserCreds()),
    )
    assert adc_available() is True


def test_adc_allows_when_service_account_module_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _no_adc_files(monkeypatch, tmp_path)
    base = _auth_loader(_SACreds())

    def load(name: str) -> Any:
        if name == "google.oauth2.service_account":
            raise ImportError(name)
        return base(name)

    monkeypatch.setattr("datagrant.bigquery_support.importlib.import_module", load)
    assert adc_available() is True


def test_adc_transport_request_typeerror_retries_and_restores_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class _Transport:
        class Request:
            pass

    class _Auth:
        def default(self) -> tuple[Any, str]:
            assert os.environ.get("GCE_METADATA_TIMEOUT") == "1"
            return _UserCreds(), "clinic-proj"

    def load(name: str) -> Any:
        if name == "google.auth":
            return _Auth()
        if name == "google.auth.exceptions":
            return _AuthExc
        if name == "google.oauth2.service_account":
            return _SAMod
        if name == "google.auth.transport.requests":
            return _Transport
        raise ImportError(name)

    _no_adc_files(monkeypatch, tmp_path)
    monkeypatch.setenv("GCE_METADATA_TIMEOUT", "9")
    monkeypatch.setattr("datagrant.bigquery_support.importlib.import_module", load)
    assert adc_available() is True
    assert os.environ.get("GCE_METADATA_TIMEOUT") == "9"


def test_adc_metadata_request_init_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class _Transport:
        class Request:
            def __init__(self) -> None:
                raise TypeError("no session")

    base = _auth_loader(_UserCreds())

    def load(name: str) -> Any:
        if name == "google.auth.transport.requests":
            return _Transport
        return base(name)

    _no_adc_files(monkeypatch, tmp_path)
    monkeypatch.setattr("datagrant.bigquery_support.importlib.import_module", load)
    assert adc_available() is True


def test_resolve_project_too_long(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BIGQUERY_PROJECT_ENV, raising=False)
    with pytest.raises(BigQuerySetupError, match="too long"):
        resolve_project("a" * 9000)


def test_resolve_project_invalid_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BIGQUERY_PROJECT_ENV, raising=False)
    with pytest.raises(BigQuerySetupError, match="invalid GCP project id"):
        resolve_project("NOPE")


def test_resolve_location_invalid() -> None:
    with pytest.raises(BigQuerySetupError, match="invalid BigQuery location"):
        resolve_location("us central")
