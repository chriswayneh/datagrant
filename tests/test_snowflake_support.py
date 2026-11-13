from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from datagrant.snowflake_support import (
    SNOWFLAKE_DSN_ENV,
    SnowflakeSetupError,
    _dsn_kwargs,
    _load_private_key,
    connect,
    driver_present,
    load_connector,
    require_driver,
    resolve_dsn,
)


def test_driver_present_does_not_raise() -> None:
    assert driver_present() in (True, False)


def test_driver_present_true_when_importable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "datagrant.snowflake_support.importlib.import_module",
        lambda name: object(),
    )
    assert driver_present() is True


def test_driver_present_false_on_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_name: str) -> Any:
        raise ImportError("no snowflake")

    monkeypatch.setattr("datagrant.snowflake_support.importlib.import_module", boom)
    assert driver_present() is False


def test_require_driver_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: False)
    with pytest.raises(SnowflakeSetupError, match="datagrant\\[snowflake\\]"):
        require_driver()


def test_require_driver_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    require_driver()


def test_load_connector_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_name: str) -> Any:
        raise ImportError("no snowflake")

    monkeypatch.setattr("datagrant.snowflake_support.importlib.import_module", boom)
    with pytest.raises(SnowflakeSetupError, match="datagrant\\[snowflake\\]"):
        load_connector()


def test_load_connector_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = object()
    monkeypatch.setattr(
        "datagrant.snowflake_support.importlib.import_module",
        lambda name: mod,
    )
    assert load_connector() is mod


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


def test_dsn_kwargs_unsupported_port_and_password_aliases() -> None:
    with pytest.raises(SnowflakeSetupError, match="unsupported Snowflake DSN"):
        _dsn_kwargs("account=xy user=svc foo=bar client_session_keep_alive=true")
    kw = _dsn_kwargs("account=xy user=svc warehouse=WH port=443 private_key_file=/k.p8")
    assert kw["port"] == 443
    assert kw["private_key_file"] == "/k.p8"
    with pytest.raises(SnowflakeSetupError, match="port must be an integer"):
        _dsn_kwargs("account=xy user=svc port=abc")
    for raw in (
        "account=xy user=svc passwd=secret",
        "account=xy user=svc pwd=secret",
        "account=xy user=svc passcode=secret",
        "account=xy user=svc passphrase=secret",
        "snowflake://svc:supersecret@xy12345/CLINIC_DB",
    ):
        with pytest.raises(SnowflakeSetupError, match="password auth is not supported"):
            _dsn_kwargs(raw)


def _write_pem(tmp_path: Path, pem: bytes, name: str = "sf.p8") -> Path:
    path = tmp_path / name
    path.write_bytes(pem)
    path.chmod(0o600)
    return path


def _rsa_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def test_load_private_key_missing_and_not_regular(tmp_path: Path) -> None:
    with pytest.raises(SnowflakeSetupError, match="missing"):
        _load_private_key(str(tmp_path / "gone.p8"))
    with pytest.raises(SnowflakeSetupError, match="regular file"):
        _load_private_key(str(tmp_path))


def test_load_private_key_invalid_pem(tmp_path: Path) -> None:
    path = _write_pem(tmp_path, b"not-a-key")
    with pytest.raises(SnowflakeSetupError, match="cannot load Snowflake private key"):
        _load_private_key(str(path))


def test_load_private_key_valid_pem(tmp_path: Path) -> None:
    path = _write_pem(tmp_path, _rsa_pem())
    loaded = _load_private_key(str(path))
    assert loaded is not None
    assert loaded.private_numbers().public_numbers.e == 65537


def test_load_private_key_inspect_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_pem(tmp_path, b"x")
    monkeypatch.setattr("datagrant.hostfs.posix_mode_problem", lambda p, w: None)
    monkeypatch.setattr("datagrant.hostfs.inspect_existing", lambda p, w: "cannot open")
    with pytest.raises(SnowflakeSetupError, match="cannot load Snowflake private key"):
        _load_private_key(str(path))

    class _Owned:
        owner_mismatch = True

    monkeypatch.setattr("datagrant.hostfs.inspect_existing", lambda p, w: _Owned())
    with pytest.raises(SnowflakeSetupError, match="not owned by the current user"):
        _load_private_key(str(path))

    monkeypatch.setattr("datagrant.hostfs.posix_mode_problem", lambda p, w: "chmod 600")
    with pytest.raises(SnowflakeSetupError, match="chmod 600"):
        _load_private_key(str(path))


def test_load_private_key_open_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_pem(tmp_path, _rsa_pem())

    class _Ok:
        owner_mismatch = False

    monkeypatch.setattr("datagrant.hostfs.posix_mode_problem", lambda p, w: None)
    monkeypatch.setattr("datagrant.hostfs.inspect_existing", lambda p, w: _Ok())

    def setup_err(_p: Path) -> int:
        raise SnowflakeSetupError("cannot load Snowflake private key")

    monkeypatch.setattr("datagrant.hostfs.open_existing_fd", setup_err)
    with pytest.raises(SnowflakeSetupError, match="cannot load Snowflake private key"):
        _load_private_key(str(path))

    def os_err(_p: Path) -> int:
        raise OSError("no fd")

    monkeypatch.setattr("datagrant.hostfs.open_existing_fd", os_err)
    with pytest.raises(SnowflakeSetupError, match="cannot load Snowflake private key"):
        _load_private_key(str(path))


def test_connect_loads_pem_and_strips_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_pem(tmp_path, _rsa_pem())
    captured: dict[str, Any] = {}

    class _Mod:
        @staticmethod
        def connect(**kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return captured

    monkeypatch.setattr("datagrant.snowflake_support.load_connector", lambda: _Mod())
    dsn = f"snowflake://svc@xy12345/DB?private_key_file={quote(str(path), safe='')}"
    got = connect(dsn)
    assert got is captured
    assert "private_key" in got and "private_key_file" not in got
    assert got["paramstyle"] == "qmark"
    assert got["account"] == "xy12345"
