"""BigQuery extra probe, project locator, ADC, and JSON-key refusal."""

from __future__ import annotations

from typing import Any

import pytest

from datagrant.bigquery_support import (
    BIGQUERY_DSN_ENV,
    BIGQUERY_PROJECT_ENV,
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


def test_refuse_secret_locator_credentials_flag() -> None:
    with pytest.raises(BigQuerySetupError, match="credentials_path"):
        refuse_secret_locator(None, credentials_path="/tmp/key")


def test_refuse_secret_locator_ok_project(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BIGQUERY_DSN_ENV, raising=False)
    monkeypatch.delenv("DATAGRANT_BIGQUERY_CREDENTIALS", raising=False)
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


class _AuthOk:
    @staticmethod
    def default() -> tuple[object, str]:
        return object(), "clinic-proj"


class _GoogleAuthError(Exception):
    pass


class _AuthFail:
    @staticmethod
    def default() -> None:
        raise _GoogleAuthError("no adc")


class _AuthExc:
    GoogleAuthError = _GoogleAuthError


def test_adc_available_true(monkeypatch: pytest.MonkeyPatch) -> None:
    def load(name: str) -> Any:
        if name == "google.auth":
            return _AuthOk
        if name == "google.auth.exceptions":
            return _AuthExc
        raise ImportError(name)

    monkeypatch.setattr("datagrant.bigquery_support.importlib.import_module", load)
    assert adc_available() is True


def test_adc_available_google_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def load(name: str) -> Any:
        if name == "google.auth":
            return _AuthFail
        if name == "google.auth.exceptions":
            return _AuthExc
        raise ImportError(name)

    monkeypatch.setattr("datagrant.bigquery_support.importlib.import_module", load)
    assert adc_available() is False


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
