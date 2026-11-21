"""BigQuery extra, secret-free locator, and ADC (M5 construction PR 2).

Does not import the GCP client except to probe the extra or ADC on ``--apply``.
Postgres and Snowflake paths must not call these helpers. Never log a JSON key.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

BIGQUERY_PROJECT_ENV = "DATAGRANT_BIGQUERY_PROJECT"
BIGQUERY_LOCATION_ENV = "DATAGRANT_BIGQUERY_LOCATION"
BIGQUERY_DSN_ENV = "DATAGRANT_BIGQUERY_DSN"
BIGQUERY_CREDENTIALS_ENV = "DATAGRANT_BIGQUERY_CREDENTIALS"
EXTRA_HINT = "pip install 'datagrant[bigquery]'"
MAX_LOCATOR_BYTES = 8192
MAX_ADC_FILE_BYTES = 65536
ADC_CHECKING_MSG = "checking Application Default Credentials..."
JSON_KEY_ADC_MSG = (
    "service-account JSON key is not supported; use ADC user login, "
    "workload identity, or impersonation"
)
ADC_FILE_SHAPE_MSG = "ADC credentials file must be a regular file of at most 64 KiB"
_GCE_METADATA_TIMEOUT_ENV = "GCE_METADATA_TIMEOUT"
_ADC_METADATA_TIMEOUT_SEC = "1"
_SERVICE_ACCOUNT_TYPE = "service_account"
_GDCH_SERVICE_ACCOUNT_TYPE = "gdch_service_account"
_IMPERSONATED_TYPE = "impersonated_service_account"
_REFUSED_ADC_TYPES = frozenset({_SERVICE_ACCOUNT_TYPE, _GDCH_SERVICE_ACCOUNT_TYPE})
_ADC_UNWRAP_LIMIT = 8
ADC_SCOPES = ["https://www.googleapis.com/auth/bigquery"]
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


def _well_known_adc_path() -> Path:
    """gcloud application_default_credentials.json (CLOUDSDK_CONFIG or default)."""
    try:
        sdk = importlib.import_module("google.auth._cloud_sdk")
        getter = getattr(sdk, "get_application_default_credentials_path", None)
        if callable(getter):
            raw = getter()
            if isinstance(raw, str) and raw.strip():
                return Path(raw.strip())
    except (ImportError, OSError, AttributeError, TypeError, ValueError):
        pass
    cloudsdk = os.environ.get("CLOUDSDK_CONFIG")
    if isinstance(cloudsdk, str) and cloudsdk.strip():
        return Path(cloudsdk.strip()) / "application_default_credentials.json"
    return Path.home() / ".config" / "gcloud" / "application_default_credentials.json"


def _json_type(body: Mapping[str, Any]) -> str | None:
    raw = body.get("type")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return None


def _adc_body_is_json_key(body: object, *, depth: int = 0) -> bool:
    """True for a service-account JSON key, including nested impersonation sources."""
    if depth > _ADC_UNWRAP_LIMIT or not isinstance(body, dict):
        return False
    kind = _json_type(body)
    if kind in _REFUSED_ADC_TYPES:
        return True
    if kind == _IMPERSONATED_TYPE:
        source = body.get("source_credentials")
        if isinstance(source, dict):
            src_kind = _json_type(source)
            if src_kind in _REFUSED_ADC_TYPES:
                return True
            return _adc_body_is_json_key(source, depth=depth + 1)
    return False


def _adc_file_shape_error(path: Path) -> BigQuerySetupError:
    """Exit-2 error for a FIFO, device, or oversized ADC file. Path only, never contents."""
    return BigQuerySetupError(f"{ADC_FILE_SHAPE_MSG}: {path}")


def _load_adc_json(path: Path) -> dict[str, Any] | None:
    """Load ADC JSON. Refuse a FIFO, device, or oversized file. Never log contents."""
    try:
        info = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ADC_FILE_BYTES:
        raise _adc_file_shape_error(path)
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_ADC_FILE_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_ADC_FILE_BYTES:
        raise _adc_file_shape_error(path)
    try:
        body = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(body, dict):
        return None
    return body


def _adc_file_is_json_key(path: Path) -> bool:
    body = _load_adc_json(path)
    if body is None:
        return False
    return _adc_body_is_json_key(body)


def _refuse_adc_file_json_key() -> None:
    """Refuse a JSON key in GAC or gcloud ADC. Call before google.auth.default()."""
    gac = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if isinstance(gac, str) and gac.strip():
        if _adc_file_is_json_key(Path(gac.strip())):
            raise BigQuerySetupError(JSON_KEY_ADC_MSG)
        return
    if _adc_file_is_json_key(_well_known_adc_path()):
        raise BigQuerySetupError(JSON_KEY_ADC_MSG)


def _isinstance_mod(creds: Any, module: str, attr: str) -> bool:
    try:
        mod = importlib.import_module(module)
    except ImportError:
        return False
    cls = getattr(mod, attr, None)
    return isinstance(cls, type) and isinstance(creds, cls)


def _is_service_account_credentials(creds: Any) -> bool:
    current = creds
    seen: set[int] = set()
    for _ in range(_ADC_UNWRAP_LIMIT):
        if current is None:
            return False
        ident = id(current)
        if ident in seen:
            return False
        seen.add(ident)
        if _isinstance_mod(current, "google.oauth2.service_account", "Credentials"):
            return True
        if _isinstance_mod(current, "google.oauth2.gdch_credentials", "ServiceAccountCredentials"):
            return True
        if _isinstance_mod(current, "google.auth.impersonated_credentials", "Credentials"):
            current = getattr(current, "_source_credentials", None)
            continue
        return False
    return False


def _refuse_service_account_json_key(creds: Any) -> None:
    """Refuse a service-account JSON key loaded via ADC. Allowed: user, WIF, impersonation, GCE."""
    if _is_service_account_credentials(creds):
        raise BigQuerySetupError(JSON_KEY_ADC_MSG)


def _metadata_request() -> Any:
    try:
        transport = importlib.import_module("google.auth.transport.requests")
    except ImportError:
        return None
    request_cls = getattr(transport, "Request", None)
    if not callable(request_cls):
        return None
    try:
        return request_cls()
    except (TypeError, OSError):
        return None


def _call_google_auth_default(google_auth: Any, request: Any, scopes: list[str]) -> Any:
    default = google_auth.default
    try:
        if request is None:
            return default(scopes=scopes)
        return default(scopes=scopes, request=request)
    except TypeError:
        if request is None:
            return default()
        try:
            return default(request=request)
        except TypeError:
            return default()


def load_adc(scopes: list[str] | None = None) -> Any:
    """Load ADC, or return None when it is unavailable.

    May contact the GCP metadata server. Call only on ``--apply``.
    Refuses a service-account JSON key loaded via ADC (exit 2 at the CLI).
    """
    print(ADC_CHECKING_MSG, file=sys.stderr)
    _refuse_adc_file_json_key()
    try:
        google_auth = importlib.import_module("google.auth")
        auth_exceptions = importlib.import_module("google.auth.exceptions")
    except ImportError:
        return None
    request = _metadata_request()
    previous_timeout = os.environ.get(_GCE_METADATA_TIMEOUT_ENV)
    os.environ[_GCE_METADATA_TIMEOUT_ENV] = _ADC_METADATA_TIMEOUT_SEC
    try:
        creds, _project = _call_google_auth_default(
            google_auth, request, ADC_SCOPES if scopes is None else scopes
        )
    except (auth_exceptions.GoogleAuthError, OSError, AttributeError):
        return None
    finally:
        if previous_timeout is None:
            os.environ.pop(_GCE_METADATA_TIMEOUT_ENV, None)
        else:
            os.environ[_GCE_METADATA_TIMEOUT_ENV] = previous_timeout
    _refuse_service_account_json_key(creds)
    return creds


def adc_available() -> bool:
    """True when permitted Application Default Credentials can be loaded."""
    return load_adc() is not None


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
    ):
        if isinstance(raw, str) and raw.strip():
            chunks.append(raw)
    for raw in chunks:
        reason = _refused_reason(raw)
        if reason:
            raise BigQuerySetupError(reason)
    creds_env = env.get(BIGQUERY_CREDENTIALS_ENV)
    if (
        (isinstance(dsn_flag, str) and dsn_flag.strip())
        or (isinstance(env.get(BIGQUERY_DSN_ENV), str) and str(env.get(BIGQUERY_DSN_ENV)).strip())
        or (isinstance(creds_env, str) and creds_env.strip())
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
