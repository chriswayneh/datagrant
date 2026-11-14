"""BigQuery extra, secret-free locator, and ADC (M5 construction PR 2).

Does not import the GCP client except to probe the extra or ADC on ``--apply``.
Postgres and Snowflake paths must not call these helpers. Never log a JSON key.
"""

from __future__ import annotations

import importlib
import os
import re
from collections.abc import Mapping
from typing import Any

BIGQUERY_PROJECT_ENV = "DATAGRANT_BIGQUERY_PROJECT"
BIGQUERY_LOCATION_ENV = "DATAGRANT_BIGQUERY_LOCATION"
BIGQUERY_DSN_ENV = "DATAGRANT_BIGQUERY_DSN"
EXTRA_HINT = "pip install 'datagrant[bigquery]'"
MAX_LOCATOR_BYTES = 8192
_REFUSED_KEYS = (
    "credentials_path",
    "credentials-path",
    "private_key",
    "private-key",
)
# Same 6-30 character GCP project id rule as policy.py.
_PROJECT_RE_OK = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_LOCATION_RE_OK = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")


class BigQuerySetupError(ValueError):
    """Missing extra, missing/invalid project locator, missing ADC, or a JSON key."""


def driver_present() -> bool:
    """True when the optional BigQuery client extra is importable."""
    try:
        importlib.import_module("google.cloud.bigquery")
    except ImportError:
        return False
    return True


def require_driver() -> None:
    if not driver_present():
        raise BigQuerySetupError(f"BigQuery extra is not installed: {EXTRA_HINT}")


def adc_available() -> bool:
    """True when Application Default Credentials can be loaded.

    May contact the GCP metadata server. Call only on ``--apply``.
    """
    try:
        google_auth = importlib.import_module("google.auth")
        auth_exceptions = importlib.import_module("google.auth.exceptions")
    except ImportError:
        return False
    try:
        google_auth.default()
    except (auth_exceptions.GoogleAuthError, OSError, AttributeError):
        return False
    return True


def require_adc() -> None:
    if not adc_available():
        raise BigQuerySetupError(
            "no BigQuery ADC: application-default credentials are not available"
        )


def _refused_reason(raw: str) -> str | None:
    """Return an error if ``raw`` looks like a JSON key or credentials_path locator."""
    compact = raw.strip()
    lower = compact.lower().replace("\\", "/")
    folded = lower.replace("-", "_")
    for key in _REFUSED_KEYS:
        token = key.replace("-", "_")
        if token in folded:
            return (
                "BigQuery locator must not set credentials_path or private_key "
                "(use ADC, not a JSON key)"
            )
    if ".json" in lower:
        return "BigQuery locator must not be a JSON key path (use ADC, not a JSON key)"
    return None


def refuse_secret_locator(
    flag: str | None = None,
    *,
    dsn_flag: str | None = None,
    credentials_path: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Refuse a JSON key, credentials_path, private_key, or BigQuery DSN. Never log the value."""
    env = os.environ if environ is None else environ
    chunks: list[str] = []
    for raw in (
        flag,
        dsn_flag,
        credentials_path,
        env.get(BIGQUERY_PROJECT_ENV),
        env.get(BIGQUERY_DSN_ENV),
        env.get("DATAGRANT_BIGQUERY_CREDENTIALS"),
    ):
        if isinstance(raw, str) and raw.strip():
            chunks.append(raw)
    for raw in chunks:
        reason = _refused_reason(raw)
        if reason:
            raise BigQuerySetupError(reason)
    if (isinstance(dsn_flag, str) and dsn_flag.strip()) or (
        isinstance(env.get(BIGQUERY_DSN_ENV), str) and str(env.get(BIGQUERY_DSN_ENV)).strip()
    ):
        raise BigQuerySetupError(
            "BigQuery DSN / JSON key is not supported; use ADC and "
            f"--bigquery-project / ${BIGQUERY_PROJECT_ENV}"
        )
    if isinstance(credentials_path, str) and credentials_path.strip():
        raise BigQuerySetupError("credentials_path is not supported; use ADC, not a JSON key")


def resolve_project(flag: str | None, environ: Mapping[str, str] | None = None) -> str:
    """Return the GCP project id. Never log it as a secret; it is not a key."""
    env = os.environ if environ is None else environ
    raw = flag if flag is not None else env.get(BIGQUERY_PROJECT_ENV)
    if raw is None or not str(raw).strip():
        raise BigQuerySetupError(
            f"no BigQuery project: pass --bigquery-project or set ${BIGQUERY_PROJECT_ENV}"
        )
    project = str(raw).strip()
    if len(project.encode("utf-8")) > MAX_LOCATOR_BYTES:
        raise BigQuerySetupError("BigQuery project locator is too long")
    reason = _refused_reason(project)
    if reason:
        raise BigQuerySetupError(reason)
    if not _PROJECT_RE_OK.fullmatch(project):
        raise BigQuerySetupError("invalid GCP project id")
    return project


def resolve_location(flag: str | None, environ: Mapping[str, str] | None = None) -> str | None:
    """Optional BigQuery location from flag or env. None means read it at --apply later."""
    env = os.environ if environ is None else environ
    raw = flag if flag is not None else env.get(BIGQUERY_LOCATION_ENV)
    if raw is None or not str(raw).strip():
        return None
    loc = str(raw).strip()
    if not _LOCATION_RE_OK.fullmatch(loc):
        raise BigQuerySetupError("invalid BigQuery location")
    return loc


def load_client() -> Any:
    try:
        return importlib.import_module("google.cloud.bigquery")
    except ImportError as exc:
        raise BigQuerySetupError(f"BigQuery extra is not installed: {EXTRA_HINT}") from exc
