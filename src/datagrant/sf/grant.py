"""Snowflake per-grant engine: SERVICE user, secure view, issuing-row fail-safe.

DDL autocommits. Order: issuing row, DISABLED user, view, role, row update,
issued receipt, claim issuing to enabling, ENABLE, then active from enabling.
Reverse-drop on failure. The hash key is bound into ``datagrant._hash_master``
and read by a SQL secure UDF; it is never in view SQL or CREATE USER SQL.
Revoke and sweep live in ``datagrant.sf.revoke``.
"""

from __future__ import annotations

import hashlib
import json
import math
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
ROW_FILTER_UNAVAILABLE = "Snowflake row filters are not implemented yet"
SECONDS_PER_DAY = 86400.0
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class GrantError(RuntimeError):
    """Raised when a Snowflake grant cannot be planned or applied."""


@dataclass(frozen=True)
class KeyPair:
    private_pem: str = field(repr=False)
    public_body: str
    fingerprint: str


@dataclass(frozen=True)
class Bound:
    """DML with qmark (``?``) server-side binds. Params never go in SQL text."""

    sql: str
    params: tuple[Any, ...]


Stmt = str | Bound


@dataclass(frozen=True)
class GrantPlan:
    grant_id: str
    role: str
    view: str
    user: str
    expires_at: datetime
    database: str
    statements: tuple[Stmt, ...]
    hash_key: HashKey | None = field(default=None, repr=False)
    facts: GrantFacts | None = None
    public_body: str = ""
    fingerprint: str = ""
    private_pem: str | None = field(default=None, repr=False)
    days_to_expiry: int = 1


def q(name: str) -> str:
    """Quote a Snowflake identifier. Rejects names outside the policy ident grammar."""
    if not _IDENT_RE.fullmatch(name):
        raise GrantError(f"unsafe identifier {name!r}")
    return '"' + name.replace('"', '""') + '"'


def lit(value: str) -> str:
    """Snowflake string literal for DDL only. Escape backslash before quote.

    Snowflake treats ``\\'`` as a closing quote, so a backslash must be doubled
    first or a value like ``\\'`` can break out of CREATE USER / COMMENT.
    """
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def stmt_sql(stmt: Stmt) -> str:
    return stmt.sql if isinstance(stmt, Bound) else stmt


def _placeholders(n: int) -> str:
    return ", ".join("?" for _ in range(n))


def days_to_expiry(duration: timedelta) -> int:
    """Snowflake DAYS_TO_EXPIRY is day-granular; ceil the grant duration."""
    seconds = duration.total_seconds()
    if seconds <= 0:
        raise GrantError("duration must be positive")
    return max(1, math.ceil(seconds / SECONDS_PER_DAY))


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


def _reject_row_filter(req: Request) -> None:
    if req.row_filter is not None:
        raise GrantError(ROW_FILTER_UNAVAILABLE)


def _reject_controls(label: str, value: str) -> None:
    if _CTRL.search(value):
        raise GrantError(f"{label} contains NUL or control characters")


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
        (f"CREATE TABLE IF NOT EXISTS {master} (ID VARCHAR PRIMARY KEY, KEY BINARY)"),
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
    warehouse: str | None = None,
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
    _reject_row_filter(req)
    _reject_controls("purpose", req.purpose)
    gid = grant_id or secrets.token_hex(6)
    if not _GRANT_ID_RE.fullmatch(gid):
        raise GrantError("grant id must be 12 lowercase hex characters")
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise GrantError("now must be timezone-aware")
    expires = now + req.duration
    days = days_to_expiry(req.duration)
    tschema, tname = _split_table(req.table, schema)
    user = f"DG_{gid}"
    role = f"DG_R_{gid}"
    view = f"G_{gid}"
    view_name = f"{VIEW_SCHEMA}.{view}"
    needs_hash = any(decision.masks[c] == "hash" for c in req.columns)
    if needs_hash and hash_key is None:
        raise GrantError("hash masking requires a hash key file (see keys.hash_key_path)")
    scope = decision.hash_scope or req.dataset
    cols = ", ".join(_col_expr(c, decision.masks[c], scope) for c in req.columns)
    from_tbl = f"{q(database)}.{q(tschema)}.{q(tname)}"
    view_id = f"{q(VIEW_SCHEMA)}.{q(view)}"
    select = f"SELECT {cols} FROM {from_tbl}"  # nosec B608
    comment = f"datagrant:{gid}"
    insert = Bound(
        (
            f"INSERT INTO {q(STATE_SCHEMA)}.{q('GRANTS')} "  # nosec B608
            "(ID, ROLE_NAME, VIEW_NAME, USER_NAME, DATASET, TABLE_NAME, REQUESTER, PURPOSE,"
            " COLUMNS, ROW_FILTER, APPROVAL, POLICY_SHA256, CREATED_AT, EXPIRES_AT,"
            " STARTED_AT, STATUS, PUBLIC_KEY_FINGERPRINT) VALUES ("
            f"{_placeholders(17)})"
        ),
        (
            gid,
            role,
            view_name,
            user,
            req.dataset,
            req.table,
            req.requester,
            req.purpose,
            json.dumps(list(req.columns)),
            req.row_filter,
            decision.approval,
            decision.policy_sha256,
            now.isoformat(),
            expires.isoformat(),
            now.isoformat(),
            "issuing",
            fingerprint,
        ),
    )
    update_row = Bound(
        (
            f"UPDATE {q(STATE_SCHEMA)}.{q('GRANTS')} SET ROLE_NAME = ?, VIEW_NAME = ?,"  # nosec B608
            " USER_NAME = ?, PUBLIC_KEY_FINGERPRINT = ? WHERE ID = ? AND STATUS = ?"
        ),
        (role, view_name, user, fingerprint, gid, "issuing"),
    )
    enabling = Bound(
        (
            f"UPDATE {q(STATE_SCHEMA)}.{q('GRANTS')} SET STATUS = ?"  # nosec B608
            " WHERE ID = ? AND STATUS = ?"
        ),
        ("enabling", gid, "issuing"),
    )
    active = Bound(
        (
            f"UPDATE {q(STATE_SCHEMA)}.{q('GRANTS')} SET STATUS = ?"  # nosec B608
            " WHERE ID = ? AND STATUS = ?"
        ),
        ("active", gid, "enabling"),
    )
    stmts: tuple[Stmt, ...] = (
        insert,
        (
            f"CREATE USER {q(user)} TYPE = SERVICE RSA_PUBLIC_KEY = {lit(public_body)}"
            f" DISABLED DAYS_TO_EXPIRY = {days} COMMENT = {lit(comment)}"
        ),
        f"CREATE SECURE VIEW {view_id} AS {select}",
        f"CREATE ROLE {q(role)}",
        f"GRANT SELECT ON {view_id} TO ROLE {q(role)}",
        f"GRANT ROLE {q(role)} TO USER {q(user)}",
        f"GRANT USAGE ON DATABASE {q(database)} TO ROLE {q(role)}",
        f"GRANT USAGE ON SCHEMA {q(VIEW_SCHEMA)} TO ROLE {q(role)}",
        *((f"GRANT USAGE ON WAREHOUSE {q(warehouse)} TO ROLE {q(role)}",) if warehouse else ()),
        update_row,
        enabling,
        f"ALTER USER {q(user)} SET DISABLED = FALSE",
        active,
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
        days,
    )


def _exec(conn: Any, sql: str, params: tuple[Any, ...] | None = None) -> Any:
    cur = conn.cursor() if hasattr(conn, "cursor") else conn
    if params is None:
        return cur.execute(sql)
    return cur.execute(sql, params)


def _run(conn: Any, stmt: Stmt) -> Any:
    if isinstance(stmt, Bound):
        return _exec(conn, stmt.sql, stmt.params)
    return _exec(conn, stmt)


def _sql_blob(conn: Any) -> str:
    queries = getattr(conn, "queries", ())
    parts = []
    for item in queries:
        if isinstance(item, tuple):
            parts.append(str(item[0]))
        else:
            parts.append(str(item))
    return "\n".join(parts)


def _rowcount(result: Any, conn: Any) -> int:
    for obj in (result, conn):
        n = getattr(obj, "rowcount", None)
        if isinstance(n, int) and n >= 0:
            return n
    return 0


def _fetchone(result: Any, conn: Any) -> tuple[Any, ...] | None:
    if result is not None and hasattr(result, "fetchone"):
        row = result.fetchone()
        if row is not None:
            return tuple(row)
    if hasattr(conn, "fetchone"):
        row = conn.fetchone()
        if row is not None:
            return tuple(row)
    return None


def ensure_state(conn: Any) -> None:
    """Create datagrant Snowflake schemas, grant tables, and hash UDF if missing."""
    for stmt in ensure_state_sql():
        _exec(conn, stmt)


def count_live_grants(conn: Any, requester: str, dataset: str) -> int:
    """Live grants for this requester and dataset.

    Count is ``STATUS IN ('issuing','enabling','active')`` and
    ``EXPIRES_AT > CURRENT_TIMESTAMP()``. In-flight issue rows count because
    Snowflake has no advisory lock. Qmark-bound; requester and dataset never
    go in SQL text.
    """
    result = _exec(
        conn,
        (
            f"SELECT COUNT(*) FROM {q(STATE_SCHEMA)}.{q('GRANTS')}"  # nosec B608
            " WHERE REQUESTER = ? AND DATASET = ? AND STATUS IN (?, ?, ?)"
            " AND EXPIRES_AT > CURRENT_TIMESTAMP()"
        ),
        (requester, dataset, "issuing", "enabling", "active"),
    )
    row = _fetchone(result, conn)
    if row is None or row[0] is None:
        return 0
    return int(row[0])


def append_revoked(
    plan: GrantPlan,
    receipts: ReceiptSink | None,
    *,
    reason: str,
) -> None:
    """Best-effort revoked receipt after a post-issued reverse-drop."""
    if receipts is None or plan.facts is None:
        return
    try:
        receipt.append(
            receipts.log,
            "revoked",
            plan.facts,
            receipts.key,
            host=receipts.host,
            details={
                "engine": "snowflake",
                "reason": reason,
                "public_key_fingerprint": plan.fingerprint,
            },
        )
    except Exception:  # noqa: BLE001, S110  # nosec B110
        pass


def reverse_drop(conn: Any, plan: GrantPlan, *, enabled: bool) -> None:
    """Drop created objects in reverse order. DISABLE first if ENABLE ran."""
    view_id = f"{q(VIEW_SCHEMA)}.{q('G_' + plan.grant_id)}"
    if enabled:
        _exec(conn, f"ALTER USER IF EXISTS {q(plan.user)} SET DISABLED = TRUE")
    _exec(conn, f"DROP VIEW IF EXISTS {view_id}")
    _exec(conn, f"DROP ROLE IF EXISTS {q(plan.role)}")
    _exec(conn, f"DROP USER IF EXISTS {q(plan.user)}")
    _run(
        conn,
        Bound(
            f"UPDATE {q(STATE_SCHEMA)}.{q('GRANTS')} SET STATUS = ? WHERE ID = ?",  # nosec B608
            ("failed", plan.grant_id),
        ),
    )


def _bind_hash_key(conn: Any, key: HashKey) -> None:
    sql = (
        f"MERGE INTO {q(STATE_SCHEMA)}.{q(HASH_TABLE)} T USING "  # nosec B608
        f"(SELECT ? AS ID, ? AS KEY) S ON T.ID = S.ID "
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
    *,
    max_concurrent: int | None = None,
) -> None:
    """Run the fail-safe sequence. No ENABLE without an issued receipt and an issuing row."""
    enabled = False
    created = False
    issued = False
    try:
        ensure_state(conn)
        if plan.hash_key is not None:
            _bind_hash_key(conn, plan.hash_key)
        insert_sql, create_user, *middle, update_sql, enabling_sql, enable_sql, active_sql = (
            plan.statements
        )
        _run(conn, insert_sql)
        created = True
        if max_concurrent is not None:
            facts = plan.facts
            if facts is None:
                reverse_drop(conn, plan, enabled=False)
                raise GrantError(f"grant {plan.grant_id}: concurrent cap check needs grant facts")
            n = count_live_grants(conn, facts.requester, facts.dataset)
            if n > max_concurrent:
                reverse_drop(conn, plan, enabled=False)
                raise GrantError(
                    f"grant {plan.grant_id}: concurrent grant cap exceeded "
                    f"({n} live, max_concurrent_grants is {max_concurrent}); objects dropped"
                )
        _run(conn, create_user)
        create_sql = stmt_sql(create_user)
        if plan.private_pem and plan.private_pem in create_sql:
            raise GrantError("private key must not appear in CREATE USER SQL")
        for item in middle:
            _run(conn, item)
        updated = _run(conn, update_sql)
        if _rowcount(updated, conn) != 1:
            reverse_drop(conn, plan, enabled=False)
            raise GrantError(f"grant {plan.grant_id}: not issuing at row update; objects dropped")
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
            issued = True
        except BaseException as exc:
            reverse_drop(conn, plan, enabled=False)
            if not isinstance(exc, Exception):
                raise
            raise GrantError(
                f"grant {plan.grant_id}: receipt not written ({exc}); objects dropped"
            ) from exc
        enabling = _run(conn, enabling_sql)
        if _rowcount(enabling, conn) != 1:
            reverse_drop(conn, plan, enabled=False)
            append_revoked(plan, receipts, reason="lost_issuing")
            raise GrantError(f"grant {plan.grant_id}: not issuing at ENABLE; objects dropped")
        try:
            _run(conn, enable_sql)
            enabled = True
        except BaseException as exc:
            reverse_drop(conn, plan, enabled=True)
            append_revoked(plan, receipts, reason="enable_failed")
            if not isinstance(exc, Exception):
                raise
            raise GrantError(
                f"grant {plan.grant_id}: ENABLE failed ({exc}); objects dropped"
            ) from exc
        active = _run(conn, active_sql)
        if _rowcount(active, conn) != 1:
            _exec(conn, f"ALTER USER IF EXISTS {q(plan.user)} SET DISABLED = TRUE")
            reverse_drop(conn, plan, enabled=True)
            append_revoked(plan, receipts, reason="lost_enabling")
            raise GrantError(f"grant {plan.grant_id}: not enabling after ENABLE; objects dropped")
    except GrantError:
        raise
    except Exception as exc:
        if created:
            reverse_drop(conn, plan, enabled=enabled)
            if issued:
                append_revoked(plan, receipts, reason="apply_failed")
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
    _reject_row_filter(req)
    _reject_controls("purpose", req.purpose)
    now = now or datetime.now(UTC)
    rid = secrets.token_hex(6)
    ident = json.dumps(dict(requester_identity), sort_keys=True) if requester_identity else None
    ensure_state(conn)
    _run(
        conn,
        Bound(
            (
                f"INSERT INTO {q(STATE_SCHEMA)}.{q('REQUESTS')} ("  # nosec B608
                "ID, REQUESTER, DATASET, TABLE_NAME, COLUMNS, ROW_FILTER, DURATION_SECONDS,"
                " PURPOSE, POLICY_SHA256, RSA_PUBLIC_KEY, PUBLIC_KEY_FINGERPRINT,"
                " CREATED_AT, EXPIRES_AT, STATUS, REQUESTER_IDENTITY) VALUES ("
                f"{_placeholders(15)})"
            ),
            (
                rid,
                req.requester,
                req.dataset,
                req.table,
                json.dumps(list(req.columns)),
                req.row_filter,
                int(req.duration.total_seconds()),
                req.purpose,
                policy_sha256,
                public_body,
                fingerprint,
                now.isoformat(),
                (now + ttl).isoformat(),
                "pending",
                ident,
            ),
        ),
    )
    return rid


def get_pending(conn: Any, request_id: str) -> dict[str, Any] | None:
    result = _exec(
        conn,
        (
            f"SELECT ID, REQUESTER, DATASET, TABLE_NAME, COLUMNS, ROW_FILTER,"  # nosec B608
            f" DURATION_SECONDS, PURPOSE, POLICY_SHA256, RSA_PUBLIC_KEY,"
            f" PUBLIC_KEY_FINGERPRINT, CREATED_AT, EXPIRES_AT, STATUS,"
            f" REQUESTER_IDENTITY FROM {q(STATE_SCHEMA)}.{q('REQUESTS')}"
            " WHERE ID = ?"
        ),
        (request_id,),
    )
    row = _fetchone(result, conn)
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


def claim_pending(conn: Any, request_id: str, *, approver: str) -> None:
    """Atomically claim a pending, unexpired request. Fail closed on 0 rows."""
    result = _exec(
        conn,
        (
            f"UPDATE {q(STATE_SCHEMA)}.{q('REQUESTS')} SET STATUS = ?, APPROVER = ?"  # nosec B608
            " WHERE ID = ? AND STATUS = ? AND EXPIRES_AT > CURRENT_TIMESTAMP()"
        ),
        ("approved", approver, request_id, "pending"),
    )
    if _rowcount(result, conn) != 1:
        raise GrantError(f"cannot claim request {request_id}: not pending or expired")


def mark_request_failed(conn: Any, request_id: str) -> None:
    _exec(
        conn,
        f"UPDATE {q(STATE_SCHEMA)}.{q('REQUESTS')} SET STATUS = ? WHERE ID = ?",  # nosec B608
        ("failed", request_id),
    )


def issue_approved(
    conn: Any,
    plan: GrantPlan,
    request_id: str,
    *,
    approver: str,
    receipts: ReceiptSink | None = None,
    max_concurrent: int | None = None,
) -> None:
    """Claim a pending request, then apply. Mark the request failed if apply fails."""
    claim_pending(conn, request_id, approver=approver)
    try:
        apply_plan(conn, plan, receipts, max_concurrent=max_concurrent)
    except BaseException:
        mark_request_failed(conn, request_id)
        raise
