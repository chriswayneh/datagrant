"""Restricted hash-master table, SQL HMAC UDF, and load-job key writes."""

from __future__ import annotations

import base64
import hashlib
import io
import json
from typing import Any

from datagrant.bq.grant import HASH_UDF, STATE_DATASET, GrantError, GrantPlan, lit, q, q_project
from datagrant.bq.rest import TIMEOUT
from datagrant.keys import HashKey

HASH_TABLE = "_hash_master"
HASH_MASTER_ID = "master"
HMAC_UDF = "_hmac_sha256"
HMAC_KEY_BLOCK = "_hmac_key_block"
HMAC_XOR_PAD = "_hmac_xor_pad"
SCOPE_LABEL = "datagrant/hash-scope/v1:"
_JOB_TIMEOUT = 60
_IPAD = 54  # 0x36
_OPAD = 92  # 0x5c


def _qual(project: str, dataset: str, name: str) -> str:
    return f"{q_project(project)}.{q(dataset)}.{q(name)}"


def hash_routine_entry(project: str) -> dict[str, str]:
    q_project(project)
    return {"projectId": project, "datasetId": STATE_DATASET, "routineId": HASH_UDF}


def uses_hash_mask(plan: GrantPlan) -> bool:
    """True when the grant view will call hash_hmac."""
    facts = plan.facts
    if facts is not None:
        return any(mask == "hash" for mask in facts.masks.values())
    return HASH_UDF in plan.view_sql


def key_fingerprint(key: HashKey) -> str:
    """SHA-256 hex of the derived key. Matches TO_HEX(SHA256(key)) in GoogleSQL."""
    return hashlib.sha256(key.derived).hexdigest()


def create_hash_table_sql(project: str) -> str:
    table = _qual(project, STATE_DATASET, HASH_TABLE)
    return f"CREATE TABLE IF NOT EXISTS {table} (id STRING NOT NULL, key BYTES NOT NULL)"


def create_hmac_helpers_sql(project: str) -> tuple[str, str, str]:
    """SQL HMAC-SHA256 helpers. The key is never a literal."""
    block = _qual(project, STATE_DATASET, HMAC_KEY_BLOCK)
    xor_pad = _qual(project, STATE_DATASET, HMAC_XOR_PAD)
    hmac_fn = _qual(project, STATE_DATASET, HMAC_UDF)
    key_block = (
        f"CREATE OR REPLACE FUNCTION {block}(key BYTES) RETURNS BYTES AS (( "  # nosec B608
        "SELECT IF(BYTE_LENGTH(k) > 64, SHA256(k), k) || FROM_HEX("
        "REPEAT('00', GREATEST(0, 64 - BYTE_LENGTH(IF(BYTE_LENGTH(k) > 64, SHA256(k), k))))) "
        "FROM (SELECT key AS k) ))"
    )
    xor = (
        f"CREATE OR REPLACE FUNCTION {xor_pad}(block BYTES, pad INT64) "  # nosec B608
        "RETURNS BYTES AS (( "
        "SELECT CODE_POINTS_TO_BYTES(ARRAY_AGG(BIT_XOR(c, pad) ORDER BY off)) "
        "FROM UNNEST(TO_CODE_POINTS(block)) AS c WITH OFFSET off WHERE off < 64 ))"
    )
    hmac = (
        f"CREATE OR REPLACE FUNCTION {hmac_fn}(key BYTES, val STRING) "  # nosec B608
        "RETURNS BYTES AS (( "
        "SELECT IF(key IS NULL, ERROR('datagrant hash key is unavailable'), "
        f"SHA256({xor_pad}({block}(key), {_OPAD}) || "
        f"SHA256({xor_pad}({block}(key), {_IPAD}) || CAST(val AS BYTES)))) ))"
    )
    return key_block, xor, hmac


def create_hash_hmac_sql(project: str) -> str:
    """SQL UDF that reads _hash_master. Key bytes never appear in the body."""
    table = _qual(project, STATE_DATASET, HASH_TABLE)
    hmac_fn = _qual(project, STATE_DATASET, HMAC_UDF)
    fn = _qual(project, STATE_DATASET, HASH_UDF)
    return (
        f"CREATE OR REPLACE FUNCTION {fn}(hash_scope STRING, val STRING) "  # nosec B608
        "RETURNS STRING AS (( "
        "SELECT CASE WHEN val IS NULL THEN CAST(NULL AS STRING) ELSE TO_HEX("
        f"{hmac_fn}({hmac_fn}((SELECT key FROM {table} WHERE id = {lit(HASH_MASTER_ID)} LIMIT 1), "
        f"CONCAT({lit(SCOPE_LABEL)}, COALESCE(hash_scope, ''))), val)) END ))"
    )


def fingerprint_sql(project: str) -> str:
    table = _qual(project, STATE_DATASET, HASH_TABLE)
    return (
        f"SELECT COUNT(*) AS n, COUNTIF(TO_HEX(SHA256(key)) = @fp) AS matched "  # nosec B608
        f"FROM {table}"
    )


def _cell(row: Any, name: str, index: int) -> Any:
    if isinstance(row, dict):
        return row[name]
    getter = getattr(row, "get", None)
    if callable(getter):
        return getter(name)
    try:
        return row[name]
    except (KeyError, TypeError, IndexError):
        return row[index]


class HashStore:
    """Idempotent hash-master DDL, fingerprint checks, and load-job key writes."""

    def __init__(self, client: Any, sdk: Any, project: str, location: str) -> None:
        q_project(project)
        self._client = client
        self._sdk = sdk
        self._project = project
        self._location = location

    def _run(self, sql: str, values: dict[str, tuple[str, Any]] | None = None) -> Any:
        params = values or {}
        blob = sql
        for _kind, value in params.values():
            if isinstance(value, (bytes, bytearray)):
                raise GrantError("hash key must not be a query parameter")
            if isinstance(value, str) and len(value) >= 16 and value in blob:
                raise GrantError("hash key leaked into SQL text")
        try:
            config = self._sdk.QueryJobConfig(
                query_parameters=[
                    self._sdk.ScalarQueryParameter(name, kind, value)
                    for name, (kind, value) in params.items()
                ]
            )
            job = self._client.query(
                sql,
                job_config=config,
                project=self._project,
                location=self._location,
                timeout=TIMEOUT,
                job_retry=None,
            )
            return job.result(timeout=_JOB_TIMEOUT, job_retry=None)
        except GrantError:
            raise
        except Exception:  # noqa: BLE001 - provider errors may include query parameters
            raise GrantError("BigQuery hash-master query failed") from None

    def ensure_table(self) -> str:
        sql = create_hash_table_sql(self._project)
        self._run(sql)
        return sql

    def ensure_udf(self) -> tuple[str, ...]:
        helpers = create_hmac_helpers_sql(self._project)
        for stmt in helpers:
            self._run(stmt)
        hmac_sql = create_hash_hmac_sql(self._project)
        self._run(hmac_sql)
        return (*helpers, hmac_sql)

    def master_state(self, key: HashKey) -> tuple[int, int]:
        """Return (row count, fingerprint match count). Sends only SHA-256 hex."""
        fp = key_fingerprint(key)
        sql = fingerprint_sql(self._project)
        if key.derived.hex() in sql:
            raise GrantError("hash key leaked into SQL text")
        rows = list(self._run(sql, {"fp": ("STRING", fp)}) or ())
        if not rows:
            return 0, 0
        if len(rows) != 1:
            raise GrantError("BigQuery hash-master fingerprint query returned an invalid result")
        n = _cell(rows[0], "n", 0)
        matched = _cell(rows[0], "matched", 1)
        if type(n) is not int or n < 0 or type(matched) is not int or matched < 0:
            raise GrantError("BigQuery hash-master fingerprint query returned an invalid result")
        return n, matched

    def require_fingerprint(self, key: HashKey) -> None:
        n, matched = self.master_state(key)
        if n == 0:
            raise GrantError("BigQuery hash-master table is unavailable")
        if n != 1:
            raise GrantError("BigQuery hash-master has duplicate rows")
        if matched != 1:
            raise GrantError("BigQuery hash-master key does not match; rotate explicitly")

    def load_key(self, key: HashKey) -> None:
        """Write the master row with a load job. Never a query parameter."""
        payload = {
            "id": HASH_MASTER_ID,
            "key": base64.b64encode(key.derived).decode("ascii"),
        }
        blob = (json.dumps(payload) + "\n").encode("ascii")
        buf = io.BytesIO(blob)
        table = f"{self._project}.{STATE_DATASET}.{HASH_TABLE}"
        try:
            config = self._sdk.LoadJobConfig(
                schema=[
                    self._sdk.SchemaField("id", "STRING"),
                    self._sdk.SchemaField("key", "BYTES"),
                ],
                source_format=self._sdk.SourceFormat.NEWLINE_DELIMITED_JSON,
                write_disposition=self._sdk.WriteDisposition.WRITE_TRUNCATE,
            )
            job = self._client.load_table_from_file(
                buf,
                table,
                job_config=config,
                project=self._project,
                location=self._location,
            )
            job.result(timeout=_JOB_TIMEOUT)
        except GrantError:
            raise
        except Exception:  # noqa: BLE001 - provider errors may include the load body
            raise GrantError("BigQuery hash-master load failed") from None
