"""BigQuery catalog inspect and typed null masks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from datagrant.bq.rest import TIMEOUT

_JOB_TIMEOUT = 60
_SIMPLE_TYPES = frozenset(
    {
        "STRING",
        "BYTES",
        "INT64",
        "FLOAT64",
        "BOOL",
        "DATE",
        "DATETIME",
        "TIME",
        "TIMESTAMP",
        "NUMERIC",
        "BIGNUMERIC",
        "GEOGRAPHY",
        "JSON",
        "INTERVAL",
    }
)
_ARRAY_RE = re.compile(r"^ARRAY<([A-Z][A-Z0-9_]*)>$")


@dataclass(frozen=True)
class TableCatalog:
    columns: dict[str, str]


def sql_type(raw: object) -> str:
    """Return a safe GoogleSQL type name, or raise. Never interpolates unchecked text."""
    from datagrant.bq.grant import GrantError

    text = str(raw).strip().upper()
    if text in _SIMPLE_TYPES:
        return text
    match = _ARRAY_RE.fullmatch(text)
    if match is not None and match.group(1) in _SIMPLE_TYPES:
        return f"ARRAY<{match.group(1)}>"
    raise GrantError(f"unsupported column type {text!r}")


def inspect_table(
    client: Any,
    sdk: Any,
    *,
    project: str,
    dataset: str,
    table: str,
    location: str | None,
) -> TableCatalog:
    """Read COLUMN_NAME / DATA_TYPE from INFORMATION_SCHEMA (query parameters)."""
    from datagrant.bq.grant import GrantError, q, q_project

    q_project(project)
    q(dataset)
    q(table)
    sql = (
        f"SELECT column_name, data_type FROM {q_project(project)}.{q(dataset)}"  # nosec B608
        f".{q('INFORMATION_SCHEMA')}.{q('COLUMNS')}"
        " WHERE table_name = @table_name"
    )
    try:
        config = sdk.QueryJobConfig(
            query_parameters=[sdk.ScalarQueryParameter("table_name", "STRING", table)]
        )
        job = client.query(
            sql,
            job_config=config,
            project=project,
            location=location,
            timeout=TIMEOUT,
            job_retry=None,
        )
        rows = list(job.result(timeout=_JOB_TIMEOUT, job_retry=None))
    except GrantError:
        raise
    except Exception:  # noqa: BLE001 - provider errors may include identifiers
        raise GrantError("BigQuery catalog inspect failed") from None
    cols: dict[str, str] = {}
    for row in rows:
        name = row["column_name"] if not isinstance(row, tuple) else row[0]
        dtype = row["data_type"] if not isinstance(row, tuple) else row[1]
        if not isinstance(name, str) or not name:
            raise GrantError("BigQuery catalog inspect returned an invalid column name")
        q(name)
        cols[name] = sql_type(dtype)
    if not cols:
        raise GrantError(f"table {table!r} not found or has no columns")
    return TableCatalog(cols)
