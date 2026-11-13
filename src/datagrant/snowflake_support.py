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


def resolve_dsn(
    flag: str | None, environ: Mapping[str, str] | None = None
) -> str:
    """Return the Snowflake admin DSN. Never log or return it from CLI errors."""
    env = os.environ if environ is None else environ
    raw = flag if flag is not None else env.get(SNOWFLAKE_DSN_ENV)
    if raw is None or not str(raw).strip():
        raise SnowflakeSetupError(
            f"no Snowflake: pass --snowflake-dsn or set ${SNOWFLAKE_DSN_ENV}"
        )
    dsn = str(raw).strip()
    if len(dsn.encode("utf-8")) > MAX_DSN_BYTES:
        raise SnowflakeSetupError("Snowflake DSN is too long")
    return dsn


def load_connector() -> Any:
    try:
        return importlib.import_module("snowflake.connector")
    except ImportError as exc:
        raise SnowflakeSetupError(f"Snowflake extra is not installed: {EXTRA_HINT}") from exc


def _dsn_kwargs(dsn: str) -> dict[str, Any]:
    """Parse a Snowflake DSN. Never log the result."""
    if "://" in dsn:
        u = urlparse(dsn)
        kwargs: dict[str, Any] = {}
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


def connect(dsn: str) -> Any:
    """Open a Snowflake session with qmark (server-side) binds. Never log ``dsn``."""
    mod = load_connector()
    mod.paramstyle = PARAMSTYLE
    kwargs = _dsn_kwargs(dsn)
    path = kwargs.pop("private_key_file", None)
    if path:
        from cryptography.hazmat.primitives import serialization

        from datagrant.hostfs import open_existing_fd

        try:
            fd = open_existing_fd(Path(path))
            try:
                raw = os.read(fd, 16 * 1024)
            finally:
                os.close(fd)
            kwargs["private_key"] = serialization.load_pem_private_key(raw, password=None)
        except Exception as exc:
            raise SnowflakeSetupError("cannot load Snowflake private key") from exc
    kwargs["paramstyle"] = PARAMSTYLE
    conn = mod.connect(**kwargs)
    try:
        conn.paramstyle = PARAMSTYLE
    except (AttributeError, TypeError):
        pass
    return conn
