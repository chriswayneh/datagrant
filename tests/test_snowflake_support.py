from __future__ import annotations

import pytest

from datagrant.snowflake_support import (
    SNOWFLAKE_DSN_ENV,
    SnowflakeSetupError,
    driver_present,
    require_driver,
    resolve_dsn,
)


def test_driver_present_does_not_raise() -> None:
    assert driver_present() in (True, False)


def test_require_driver_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: False)
    with pytest.raises(SnowflakeSetupError, match="datagrant\\[snowflake\\]"):
        require_driver()


def test_require_driver_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    require_driver()


def test_resolve_dsn_flag_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(SNOWFLAKE_DSN_ENV, "env-dsn")
    assert resolve_dsn("flag-dsn") == "flag-dsn"
    assert resolve_dsn(None) == "env-dsn"


def test_resolve_dsn_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(SNOWFLAKE_DSN_ENV, raising=False)
    with pytest.raises(SnowflakeSetupError, match=SNOWFLAKE_DSN_ENV):
        resolve_dsn(None)
    with pytest.raises(SnowflakeSetupError, match=SNOWFLAKE_DSN_ENV):
        resolve_dsn("  ", environ={})
