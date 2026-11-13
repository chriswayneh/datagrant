"""Snowflake extra and admin DSN (M4 construction).

Does not import the Snowflake driver except to probe the extra or open a
session. Postgres paths must not call these helpers. Never log a DSN.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

SNOWFLAKE_DSN_ENV = "DATAGRANT_SNOWFLAKE_DSN"
EXTRA_HINT = "pip install 'datagrant[snowflake]'"
MAX_DSN_BYTES = 8192
PARAMSTYLE = "qmark"
APPLY_UNAVAILABLE = "Snowflake --apply for grant issue and approve is not enabled yet"
GRANT_APPLY_ENABLED = False
_DSN_ALLOWED = frozenset(
    {
        "account",
        "user",
        "role",
        "warehouse",
        "database",
        "authenticator",
        "private_key_file",
        "host",
        "port",
    }
)
_DSN_REFUSED = frozenset({"insecure_mode", "ocsp_fail_open"})
_BOOL_TRUE = frozenset({"1", "true", "yes", "on"})
_BOOL_FALSE = frozenset({"0", "false", "no", "off"})


class SnowflakeSetupError(ValueError):
    """Missing extra or missing/invalid Snowflake admin DSN."""


def driver_present() -> bool:
    """True when the optional Snowflake connector extra is importable."""
    try:
        importlib.import_module("snowflake.connector")
    except ImportError:
        return False
    return True


def require_driver() -> None:
    if not driver_present():
        raise SnowflakeSetupError(f"Snowflake extra is not installed: {EXTRA_HINT}")


def resolve_dsn(flag: str | None, environ: Mapping[str, str] | None = None) -> str:
    """Return the Snowflake admin DSN. Never log or return it from CLI errors."""
    env = os.environ if environ is None else environ
    raw = flag if flag is not None else env.get(SNOWFLAKE_DSN_ENV)
    if raw is None or not str(raw).strip():
        raise SnowflakeSetupError(f"no Snowflake: pass --snowflake-dsn or set ${SNOWFLAKE_DSN_ENV}")
    dsn = str(raw).strip()
    if len(dsn.encode("utf-8")) > MAX_DSN_BYTES:
        raise SnowflakeSetupError("Snowflake DSN is too long")
    return dsn


def load_connector() -> Any:
    try:
        return importlib.import_module("snowflake.connector")
    except ImportError as exc:
        raise SnowflakeSetupError(f"Snowflake extra is not installed: {EXTRA_HINT}") from exc


def _parse_bool(raw: str, key: str) -> bool:
    v = str(raw).strip().lower()
    if v in _BOOL_TRUE:
        return True
    if v in _BOOL_FALSE:
        return False
    raise SnowflakeSetupError(f"Snowflake DSN {key} must be true or false")


def _raw_dsn_fields(dsn: str) -> dict[str, str]:
    """Parse a Snowflake DSN into string fields. Never log the result."""
    if "://" in dsn:
        u = urlparse(dsn)
        scheme = (u.scheme or "").lower()
        if scheme in {"http", "https"} and scheme != "https":
            raise SnowflakeSetupError("Snowflake DSN protocol must be https")
        kwargs: dict[str, str] = {}
        if u.hostname:
            kwargs["account"] = u.hostname
        if u.username:
            kwargs["user"] = unquote(u.username)
        if u.password:
            kwargs["password"] = unquote(u.password)
        path = (u.path or "").strip("/")
        if path:
            kwargs["database"] = path.split("/")[0]
        for key, vals in parse_qs(u.query).items():
            if vals:
                kwargs[key] = vals[0]
        return kwargs
    kwargs = {}
    for part in dsn.split():
        if "=" in part:
            k, _, v = part.partition("=")
            kwargs[k.strip()] = v.strip()
    return kwargs


def _dsn_kwargs(dsn: str) -> dict[str, Any]:
    """Allowlisted Snowflake connect kwargs. Never log the result."""
    raw = _raw_dsn_fields(dsn)
    if any(k in raw for k in ("password", "passwd", "pwd", "passcode", "passphrase")):
        raise SnowflakeSetupError(
            "Snowflake DSN password auth is not supported; use private_key_file (key-pair only)"
        )
    proto = raw.pop("protocol", None)
    if proto is not None and str(proto).strip().lower() != "https":
        raise SnowflakeSetupError("Snowflake DSN protocol must be https")
    for bad in _DSN_REFUSED:
        if bad in raw:
            _parse_bool(raw[bad], bad)
            raise SnowflakeSetupError(f"Snowflake DSN must not set {bad}")
    extra = set(raw) - _DSN_ALLOWED
    if extra:
        raise SnowflakeSetupError(
            "unsupported Snowflake DSN setting(s): " + ", ".join(sorted(extra))
        )
    out: dict[str, Any] = dict(raw)
    if "port" in out:
        try:
            out["port"] = int(str(out["port"]))
        except (TypeError, ValueError):
            raise SnowflakeSetupError("Snowflake DSN port must be an integer") from None
    return out


def _load_private_key(path: str) -> Any:
    from cryptography.hazmat.primitives import serialization

    from datagrant.hostfs import inspect_existing, open_existing_fd, posix_mode_problem

    p = Path(path)
    problem = posix_mode_problem(p, "Snowflake private key")
    if problem:
        raise SnowflakeSetupError(problem)
    inspected = inspect_existing(p, "Snowflake private key")
    if inspected is None:
        raise SnowflakeSetupError("Snowflake private key file is missing")
    if isinstance(inspected, str):
        raise SnowflakeSetupError("cannot load Snowflake private key")
    if inspected.owner_mismatch:
        raise SnowflakeSetupError("Snowflake private key file is not owned by the current user")
    try:
        fd = open_existing_fd(p)
        try:
            raw = os.read(fd, 16 * 1024)
        finally:
            os.close(fd)
        return serialization.load_pem_private_key(raw, password=None)
    except SnowflakeSetupError:
        raise
    except Exception as exc:
        raise SnowflakeSetupError("cannot load Snowflake private key") from exc


def connect(dsn: str) -> Any:
    """Open a Snowflake session with qmark (server-side) binds. Never log ``dsn``."""
    mod = load_connector()
    mod.paramstyle = PARAMSTYLE
    kwargs = _dsn_kwargs(dsn)
    path = kwargs.pop("private_key_file", None)
    if not path:
        raise SnowflakeSetupError(
            "Snowflake DSN requires private_key_file (key-pair only; password is not supported)"
        )
    kwargs["private_key"] = _load_private_key(str(path))
    kwargs["paramstyle"] = PARAMSTYLE
    conn = mod.connect(**kwargs)
    try:
        conn.paramstyle = PARAMSTYLE
    except (AttributeError, TypeError):
        pass
    style = str(getattr(conn, "paramstyle", None) or getattr(mod, "paramstyle", "")).lower()
    if style in {"pyformat", "format"}:
        raise SnowflakeSetupError("Snowflake connector paramstyle must be qmark, not pyformat")
    return conn
