"""Restricted hash-master table, SQL HMAC UDF, and key bind via query parameters."""

from __future__ import annotations

from typing import Any

from datagrant.bq.grant import HASH_UDF, STATE_DATASET, GrantError, lit, q, q_project
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


def bind_hash_key_sql(project: str) -> str:
    table = _qual(project, STATE_DATASET, HASH_TABLE)
    return (
        f"MERGE {table} T USING (SELECT @id AS id, @key AS key) S ON T.id = S.id "  # nosec B608
        "WHEN MATCHED THEN UPDATE SET key = S.key "
        "WHEN NOT MATCHED THEN INSERT (id, key) VALUES (S.id, S.key)"
    )


class HashStore:
    """Idempotent hash-master DDL and parameterized key bind."""

    def __init__(self, client: Any, sdk: Any, project: str, location: str) -> None:
        q_project(project)
        self._client = client
        self._sdk = sdk
        self._project = project
        self._location = location

    def _run(self, sql: str, values: dict[str, tuple[str, Any]] | None = None) -> str:
        params = values or {}
        blob = sql
        for _kind, value in params.values():
            if isinstance(value, (bytes, bytearray)) and value.hex() in blob:
                raise GrantError("hash key leaked into SQL text")
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
            job.result(timeout=_JOB_TIMEOUT, job_retry=None)
        except GrantError:
            raise
        except Exception:  # noqa: BLE001 - provider errors may include query parameters
            raise GrantError("BigQuery hash-master query failed") from None
        return sql

    def ensure_table(self) -> str:
        return self._run(create_hash_table_sql(self._project))

    def ensure_udf(self) -> tuple[str, ...]:
        helpers = create_hmac_helpers_sql(self._project)
        for stmt in helpers:
            self._run(stmt)
        hmac_sql = create_hash_hmac_sql(self._project)
        self._run(hmac_sql)
        return (*helpers, hmac_sql)

    def bind_key(self, key: HashKey) -> str:
        sql = bind_hash_key_sql(self._project)
        if key.derived.hex() in sql:
            raise GrantError("hash key leaked into SQL text")
        self._run(sql, {"id": ("STRING", HASH_MASTER_ID), "key": ("BYTES", key.derived)})
        return sql
