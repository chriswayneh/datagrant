"""Snowflake extra and admin DSN (M4 construction PR 1).

No grant SQL. Does not import the Snowflake driver except to probe the extra.
Postgres paths must not call these helpers.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Mapping

SNOWFLAKE_DSN_ENV = "DATAGRANT_SNOWFLAKE_DSN"
EXTRA_HINT = "pip install 'datagrant[snowflake]'"
NOT_IMPLEMENTED = "Snowflake grant SQL is not implemented yet"
MAX_DSN_BYTES = 8192


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
