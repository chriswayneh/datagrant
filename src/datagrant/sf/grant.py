"""Snowflake per-grant engine: SERVICE user, secure view, issuing-row fail-safe.

DDL autocommits. Order: issuing row, DISABLED user, view, role, row update,
issued receipt, ENABLE, then active. Reverse-drop on failure. The hash key is
bound into ``datagrant._hash_master`` and read by a SQL secure UDF; it is never
in view SQL or CREATE USER SQL. Revoke/sweep are a later construction PR.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from datagrant import receipt
from datagrant.keys import HashKey
from datagrant.pg.grant import ReceiptSink
from datagrant.policy import Decision, Request
from datagrant.receipt import GrantFacts, ReceiptError
from datagrant.rowfilter import parse_row_filter

STATE_SCHEMA = "DATAGRANT"
VIEW_SCHEMA = "DATAGRANT_VIEWS"
HASH_TABLE = "_HASH_MASTER"
HASH_UDF = "HASH_HMAC"
HASH_MASTER_ID = "master"
_GRANT_ID_RE = re.compile(r"^[0-9a-f]{12}$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SCOPE_LABEL = "datagrant/hash-scope/v1:"
RSA_BITS = 2048
REDACTED = "<redacted>"


class GrantError(RuntimeError):
    """Raised when a Snowflake grant cannot be planned or applied."""


@dataclass(frozen=True)
class KeyPair:
    private_pem: str = field(repr=False)
    public_body: str
    fingerprint: str


@dataclass(frozen=True)
class GrantPlan:
    grant_id: str
    role: str
    view: str
    user: str
    expires_at: datetime
    database: str
    statements: tuple[str, ...]
    hash_key: HashKey | None = field(default=None, repr=False)
    facts: GrantFacts | None = None
    public_body: str = ""
    fingerprint: str = ""
    private_pem: str | None = field(default=None, repr=False)


def q(name: str) -> str:
    """Quote a Snowflake identifier. Rejects names outside the policy ident grammar."""
    if not _IDENT_RE.fullmatch(name):
        raise GrantError(f"unsafe identifier {name!r}")
    return '"' + name.replace('"', '""') + '"'


def lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def new_keypair() -> KeyPair:
    """RSA key pair. Private key is never sent to Snowflake."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    pub = key.public_key()
    der = pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem = pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    body = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
    return KeyPair(private_pem, body, hashlib.sha256(der).hexdigest())


def _split_table(table: str, default_schema: str | None) -> tuple[str, str]:
    if "." in table:
        schema, name = table.split(".", 1)
        return schema, name
    if default_schema:
        return default_schema, table
    raise GrantError(f"table {table!r} needs a schema")


def _col_expr(col: str, mask: str, hash_scope: str) -> str:
    ident = q(col)
    if mask == "passthrough":
        return ident
    if mask == "null":
        return f"NULL AS {ident}"
    if mask == "redact":
        return f"{lit('[REDACTED]')} AS {ident}"
    if mask == "partial":
        return (
            f"CASE WHEN LENGTH(TO_VARCHAR({ident})) >= 8 THEN "
            f"REPEAT('*', LENGTH(TO_VARCHAR({ident})) - 4) || RIGHT(TO_VARCHAR({ident}), 4) "
            f"ELSE REPEAT('*', LENGTH(TO_VARCHAR({ident}))) END AS {ident}"
        )
    if mask == "hash":
        fn = f"{q(STATE_SCHEMA)}.{q(HASH_UDF)}"
        return f"{fn}({lit(hash_scope)}, TO_VARCHAR({ident})) AS {ident}"
    raise GrantError(f"unknown mask {mask!r}")


def _where_sql(row_filter: str | None) -> str:
    if row_filter is None:
        return ""
    cond, _ = parse_row_filter(row_filter)
    return " WHERE " + cond.as_string(None)


def _hash_udf_sql() -> str:
    """SQL secure UDF: reads the master table; no key literal in the body."""
    table = f"{q(STATE_SCHEMA)}.{q(HASH_TABLE)}"
    fn = f"{q(STATE_SCHEMA)}.{q(HASH_UDF)}"
    body = (
        f"SELECT HEX_ENCODE(SHA2_HMAC(COALESCE(VAL, ''), SHA2_HMAC("  # nosec B608
        f"CONCAT({lit(_SCOPE_LABEL)}, COALESCE(HASH_SCOPE, '')),"
        f"(SELECT KEY FROM {table} WHERE ID = {lit(HASH_MASTER_ID)} LIMIT 1), 256), 256))"
    )
    return (
        f"CREATE OR REPLACE SECURE FUNCTION {fn}"
        f"(HASH_SCOPE VARCHAR, VAL VARCHAR) RETURNS VARCHAR LANGUAGE SQL AS $$ {body} $$"
    )


def ensure_state_sql() -> tuple[str, ...]:
    grants = f"{q(STATE_SCHEMA)}.{q('GRANTS')}"
    master = f"{q(STATE_SCHEMA)}.{q(HASH_TABLE)}"
    reqs = f"{q(STATE_SCHEMA)}.{q('REQUESTS')}"
    return (
        f"CREATE SCHEMA IF NOT EXISTS {q(STATE_SCHEMA)}",
        f"CREATE SCHEMA IF NOT EXISTS {q(VIEW_SCHEMA)}",
        (
            f"CREATE TABLE IF NOT EXISTS {grants} ("
            "ID VARCHAR PRIMARY KEY, ROLE_NAME VARCHAR, VIEW_NAME VARCHAR, USER_NAME VARCHAR,"
            " DATASET VARCHAR, TABLE_NAME VARCHAR, REQUESTER VARCHAR, PURPOSE VARCHAR,"
            " COLUMNS VARCHAR, ROW_FILTER VARCHAR, APPROVAL VARCHAR, POLICY_SHA256 VARCHAR,"
            " CREATED_AT TIMESTAMP_TZ, EXPIRES_AT TIMESTAMP_TZ, STARTED_AT TIMESTAMP_TZ,"
            " STATUS VARCHAR, PUBLIC_KEY_FINGERPRINT VARCHAR, LAST_ERROR VARCHAR)"
        ),
        (
            f"CREATE TABLE IF NOT EXISTS {master} ("
            "ID VARCHAR PRIMARY KEY, KEY BINARY)"
        ),
        (
            f"CREATE TABLE IF NOT EXISTS {reqs} ("
            "ID VARCHAR PRIMARY KEY, REQUESTER VARCHAR, DATASET VARCHAR, TABLE_NAME VARCHAR,"
            " COLUMNS VARCHAR, ROW_FILTER VARCHAR, DURATION_SECONDS NUMBER, PURPOSE VARCHAR,"
            " POLICY_SHA256 VARCHAR, RSA_PUBLIC_KEY VARCHAR, PUBLIC_KEY_FINGERPRINT VARCHAR,"
            " CREATED_AT TIMESTAMP_TZ, EXPIRES_AT TIMESTAMP_TZ, STATUS VARCHAR,"
            " APPROVER VARCHAR, GRANT_ID VARCHAR, REQUESTER_IDENTITY VARCHAR)"
        ),
        _hash_udf_sql(),
    )


def build_plan(
    decision: Decision,
    req: Request,
    *,
    database: str,
    public_body: str,
    fingerprint: str,
    schema: str | None = None,
    grant_id: str | None = None,
    now: datetime | None = None,
    approvers: Sequence[str] = (),
    hash_key: HashKey | None = None,
    requester_identity: Mapping[str, Any] | None = None,
    approver_identities: Sequence[Mapping[str, Any]] | None = None,
    private_pem: str | None = None,
) -> GrantPlan:
    """Pure SQL plan. ``public_body`` is the RSA public key (no private key)."""
    if not decision.allowed:
        raise GrantError("cannot build a grant for a denied decision")
    if decision.approval == "two-person" and not approvers:
        raise GrantError("two-person approval: the grant needs an approver")
    gid = grant_id or secrets.token_hex(6)
    if not _GRANT_ID_RE.fullmatch(gid):
        raise GrantError("grant id must be 12 lowercase hex characters")
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise GrantError("now must be timezone-aware")
    expires = now + req.duration
    tschema, tname = _split_table(req.table, schema)
    user = f"DG_{gid}"
    role = f"DG_R_{gid}"
    view = f"G_{gid}"
    needs_hash = any(decision.masks[c] == "hash" for c in req.columns)
    if needs_hash and hash_key is None:
        raise GrantError("hash masking requires a hash key file (see keys.hash_key_path)")
    scope = decision.hash_scope or req.dataset
    cols = ", ".join(_col_expr(c, decision.masks[c], scope) for c in req.columns)
    from_tbl = f"{q(database)}.{q(tschema)}.{q(tname)}"
    view_id = f"{q(VIEW_SCHEMA)}.{q(view)}"
    select = f"SELECT {cols} FROM {from_tbl}" + _where_sql(req.row_filter)  # nosec B608
    comment = f"datagrant:{gid}"
    stmts = (
        (
            f"INSERT INTO {q(STATE_SCHEMA)}.{q('GRANTS')} "  # nosec B608
            "(ID, ROLE_NAME, VIEW_NAME, USER_NAME, DATASET, TABLE_NAME, REQUESTER, PURPOSE,"
            " COLUMNS, ROW_FILTER, APPROVAL, POLICY_SHA256, CREATED_AT, EXPIRES_AT,"
            " STARTED_AT, STATUS, PUBLIC_KEY_FINGERPRINT) VALUES ("
            f"{lit(gid)}, {lit(role)}, {lit(f'{VIEW_SCHEMA}.{view}')}, {lit(user)},"
            f" {lit(req.dataset)}, {lit(req.table)}, {lit(req.requester)}, {lit(req.purpose)},"
            f" {lit(json.dumps(list(req.columns)))}, "
            f"{'NULL' if req.row_filter is None else lit(req.row_filter)},"
            f" {lit(decision.approval)}, {lit(decision.policy_sha256)},"
            f" {lit(now.isoformat())}, {lit(expires.isoformat())},"
            f" {lit(now.isoformat())}, {lit('issuing')}, {lit(fingerprint)})"
        ),
        (
            f"CREATE USER {q(user)} TYPE = SERVICE RSA_PUBLIC_KEY = {lit(public_body)}"
            f" DISABLED DAYS_TO_EXPIRY = 1 COMMENT = {lit(comment)}"
        ),
        f"CREATE SECURE VIEW {view_id} AS {select}",
        f"CREATE ROLE {q(role)}",
        f"GRANT SELECT ON {view_id} TO ROLE {q(role)}",
        f"GRANT ROLE {q(role)} TO USER {q(user)}",
        (
            f"GRANT USAGE ON FUNCTION {q(STATE_SCHEMA)}.{q(HASH_UDF)}(VARCHAR, VARCHAR)"
            f" TO ROLE {q(role)}"
        ),
        (
            f"UPDATE {q(STATE_SCHEMA)}.{q('GRANTS')} SET ROLE_NAME = {lit(role)},"  # nosec B608
            f" VIEW_NAME = {lit(f'{VIEW_SCHEMA}.{view}')}, USER_NAME = {lit(user)},"
            f" PUBLIC_KEY_FINGERPRINT = {lit(fingerprint)} WHERE ID = {lit(gid)}"
        ),
        f"ALTER USER {q(user)} SET DISABLED = FALSE",
        (
            f"UPDATE {q(STATE_SCHEMA)}.{q('GRANTS')} SET STATUS = {lit('active')}"  # nosec B608
            f" WHERE ID = {lit(gid)}"
        ),
    )
    facts = GrantFacts(
        gid,
        req.requester,
        req.dataset,
        req.table,
        tuple(req.columns),
        {c: decision.masks[c] for c in req.columns},
        req.row_filter,
        req.purpose,
        now,
        expires,
        decision.policy_sha256,
        decision.policy_version,
        decision.approval,
        tuple(approvers),
        dict(requester_identity) if requester_identity is not None else None,
        tuple(dict(x) for x in approver_identities) if approver_identities is not None else None,
    )
    return GrantPlan(
        gid,
        role,
        f"{VIEW_SCHEMA}.{view}",
        user,
        expires,
        database,
        stmts,
        hash_key if needs_hash else None,
        facts,
        public_body,
        fingerprint,
        private_pem,
    )


def _exec(conn: Any, sql: str, params: tuple[Any, ...] | None = None) -> Any:
    cur = conn.cursor() if hasattr(conn, "cursor") else conn
    if params is None:
        return cur.execute(sql)
    return cur.execute(sql, params)


def _sql_blob(conn: Any) -> str:
    queries = getattr(conn, "queries", ())
    parts = []
    for item in queries:
        if isinstance(item, tuple):
            parts.append(str(item[0]))
        else:
            parts.append(str(item))
    return "\n".join(parts)


def reverse_drop(conn: Any, plan: GrantPlan, *, enabled: bool) -> None:
    """Drop created objects in reverse order. DISABLE first if ENABLE ran."""
    view_id = f"{q(VIEW_SCHEMA)}.{q('G_' + plan.grant_id)}"
    if enabled:
        _exec(conn, f"ALTER USER {q(plan.user)} SET DISABLED = TRUE")
    _exec(conn, f"DROP VIEW IF EXISTS {view_id}")
    _exec(conn, f"DROP ROLE IF EXISTS {q(plan.role)}")
    _exec(conn, f"DROP USER IF EXISTS {q(plan.user)}")
    _exec(
        conn,
        f"UPDATE {q(STATE_SCHEMA)}.{q('GRANTS')} SET STATUS = {lit('failed')}"  # nosec B608
        f" WHERE ID = {lit(plan.grant_id)}",
    )


def _bind_hash_key(conn: Any, key: HashKey) -> None:
    sql = (
        f"MERGE INTO {q(STATE_SCHEMA)}.{q(HASH_TABLE)} T USING "  # nosec B608
        f"(SELECT %s AS ID, %s AS KEY) S ON T.ID = S.ID "
        f"WHEN MATCHED THEN UPDATE SET KEY = S.KEY "
        f"WHEN NOT MATCHED THEN INSERT (ID, KEY) VALUES (S.ID, S.KEY)"
    )
    _exec(conn, sql, (HASH_MASTER_ID, key.derived))
    text = _sql_blob(conn)
    if key.derived.hex() in text:
        raise GrantError("hash key leaked into SQL text")


def apply_plan(
    conn: Any,
    plan: GrantPlan,
    receipts: ReceiptSink | None = None,
) -> None:
    """Run the fail-safe sequence. No ENABLE without an issued receipt."""
    enabled = False
    created = False
    try:
        for stmt in ensure_state_sql():
            _exec(conn, stmt)
        if plan.hash_key is not None:
            _bind_hash_key(conn, plan.hash_key)
        insert_sql, create_user, *middle, enable_sql, active_sql = plan.statements
        _exec(conn, insert_sql)
        created = True
        _exec(conn, create_user)
        if plan.private_pem and plan.private_pem in create_user:
            raise GrantError("private key must not appear in CREATE USER SQL")
        for stmt in middle:
            _exec(conn, stmt)
        if receipts is None:
            raise GrantError(f"grant {plan.grant_id}: issued receipt is required before ENABLE")
        if plan.facts is None:
            raise ReceiptError("plan has no receipt facts")
        try:
            receipt.append(
                receipts.log,
                "issued",
                plan.facts,
                receipts.key,
                host=receipts.host,
                details={
                    "engine": "snowflake",
                    "public_key_fingerprint": plan.fingerprint,
                },
            )
        except BaseException as exc:
            reverse_drop(conn, plan, enabled=False)
            if not isinstance(exc, Exception):
                raise
            raise GrantError(
                f"grant {plan.grant_id}: receipt not written ({exc}); objects dropped"
            ) from exc
        try:
            _exec(conn, enable_sql)
            enabled = True
        except BaseException as exc:
            reverse_drop(conn, plan, enabled=True)
            try:
                receipt.append(
                    receipts.log,
                    "revoked",
                    plan.facts,
                    receipts.key,
                    host=receipts.host,
                    details={
                        "engine": "snowflake",
                        "reason": "enable_failed",
                        "public_key_fingerprint": plan.fingerprint,
                    },
                )
            except Exception:  # noqa: BLE001, S110  # nosec B110
                pass
            if not isinstance(exc, Exception):
                raise
            raise GrantError(
                f"grant {plan.grant_id}: ENABLE failed ({exc}); objects dropped"
            ) from exc
        _exec(conn, active_sql)
    except GrantError:
        raise
    except Exception as exc:
        if created:
            reverse_drop(conn, plan, enabled=enabled)
        raise GrantError(f"grant {plan.grant_id} failed: {exc}") from exc


def create_pending(
    conn: Any,
    req: Request,
    *,
    policy_sha256: str,
    public_body: str,
    fingerprint: str,
    ttl: timedelta,
    now: datetime | None = None,
    requester_identity: Mapping[str, Any] | None = None,
) -> str:
    """Store a two-person pending request. Public key plus fingerprint only."""
    now = now or datetime.now(UTC)
    rid = secrets.token_hex(6)
    ident = json.dumps(dict(requester_identity), sort_keys=True) if requester_identity else None
    for stmt in ensure_state_sql():
        _exec(conn, stmt)
    _exec(
        conn,
        f"INSERT INTO {q(STATE_SCHEMA)}.{q('REQUESTS')} ("  # nosec B608
        "ID, REQUESTER, DATASET, TABLE_NAME, COLUMNS, ROW_FILTER, DURATION_SECONDS,"
        " PURPOSE, POLICY_SHA256, RSA_PUBLIC_KEY, PUBLIC_KEY_FINGERPRINT,"
        " CREATED_AT, EXPIRES_AT, STATUS, REQUESTER_IDENTITY) VALUES ("
        f"{lit(rid)}, {lit(req.requester)}, {lit(req.dataset)}, {lit(req.table)},"
        f" {lit(json.dumps(list(req.columns)))},"
        f" {'NULL' if req.row_filter is None else lit(req.row_filter)},"
        f" {int(req.duration.total_seconds())}, {lit(req.purpose)}, {lit(policy_sha256)},"
        f" {lit(public_body)}, {lit(fingerprint)}, {lit(now.isoformat())},"
        f" {lit((now + ttl).isoformat())}, {lit('pending')},"
        f" {'NULL' if ident is None else lit(ident)})",
    )
    return rid


def get_pending(conn: Any, request_id: str) -> dict[str, Any] | None:
    result = _exec(
        conn,
        f"SELECT ID, REQUESTER, DATASET, TABLE_NAME, COLUMNS, ROW_FILTER,"  # nosec B608
        f" DURATION_SECONDS, PURPOSE, POLICY_SHA256, RSA_PUBLIC_KEY,"
        f" PUBLIC_KEY_FINGERPRINT, CREATED_AT, EXPIRES_AT, STATUS,"
        f" REQUESTER_IDENTITY FROM {q(STATE_SCHEMA)}.{q('REQUESTS')}"
        f" WHERE ID = {lit(request_id)}",
    )
    row = None
    if result is not None and hasattr(result, "fetchone"):
        row = result.fetchone()
    elif hasattr(conn, "fetchone"):
        row = conn.fetchone()
    if row is None:
        return None
    keys = (
        "id",
        "requester",
        "dataset",
        "table_name",
        "columns",
        "row_filter",
        "duration_seconds",
        "purpose",
        "policy_sha256",
        "rsa_public_key",
        "public_key_fingerprint",
        "created_at",
        "expires_at",
        "status",
        "requester_identity",
    )
    return dict(zip(keys, row, strict=False))
