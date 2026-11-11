"""Create per-grant views and expiring login roles (unit U2).

All SQL is composed with psycopg.sql (Identifier/Literal); nothing is
string-interpolated. Grant creation runs in one transaction (fail closed).
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
from psycopg import sql

from datagrant import receipt
from datagrant.keys import HashKey, SigningKey
from datagrant.pg.mask import MaskError, TableCatalog, column_expr
from datagrant.pg.scram import scram_verifier
from datagrant.policy import Decision, Request
from datagrant.receipt import GrantFacts, ReceiptError
from datagrant.rowfilter import parse_row_filter

STATE_SCHEMA = "datagrant"
VIEW_SCHEMA = "datagrant_views"
_GRANT_ID_RE = re.compile(r"^[0-9a-f]{12}$")


class GrantError(RuntimeError):
    """Raised when a grant cannot be planned or applied."""


@dataclass(frozen=True)
class GrantPlan:
    grant_id: str
    role: str
    view: str
    expires_at: datetime
    database: str
    statements: tuple[sql.Composed, ...]
    hash_key: HashKey | None = field(default=None, repr=False)
    facts: GrantFacts | None = None


@dataclass(frozen=True)
class ReceiptSink:
    """Where and with which key grant/revoke events are receipted (U5)."""

    log: Path
    key: SigningKey
    host: str | None = None


STATE_DDL: tuple[sql.Composed, ...] = (
    sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(STATE_SCHEMA)),
    sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(STATE_SCHEMA)),
    sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(VIEW_SCHEMA)),
    sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(VIEW_SCHEMA)),
    sql.SQL(
        "CREATE TABLE IF NOT EXISTS {}.grants ("
        " id text PRIMARY KEY, role_name text NOT NULL UNIQUE, view_name text NOT NULL UNIQUE,"
        " dataset text NOT NULL, table_name text NOT NULL, requester text NOT NULL,"
        " purpose text NOT NULL, columns text[] NOT NULL, row_filter text,"
        " approval text NOT NULL, policy_sha256 text NOT NULL,"
        " created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,"
        " status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','expired')))"
    ).format(sql.Identifier(STATE_SCHEMA)),
    sql.SQL(
        "CREATE TABLE IF NOT EXISTS {}.hash_keys (id text PRIMARY KEY, key bytea NOT NULL,"
        " created_at timestamptz NOT NULL DEFAULT now())"
    ).format(sql.Identifier(STATE_SCHEMA)),
    # U4: revocation bookkeeping (additive, safe to re-run on U2/U3 databases).
    sql.SQL(
        "ALTER TABLE {}.grants ADD COLUMN IF NOT EXISTS revoked_at timestamptz,"
        " ADD COLUMN IF NOT EXISTS revoke_reason text"
        " CHECK (revoke_reason IN ('expired','manual')),"
        " ADD COLUMN IF NOT EXISTS last_error text, ADD COLUMN IF NOT EXISTS last_error_at timestamptz"
    ).format(sql.Identifier(STATE_SCHEMA)),
    # U5: facts needed to receipt revoke/expire events.
    sql.SQL(
        "ALTER TABLE {}.grants ADD COLUMN IF NOT EXISTS masks text,"
        " ADD COLUMN IF NOT EXISTS policy_version integer,"
        " ADD COLUMN IF NOT EXISTS approvers text[] NOT NULL DEFAULT '{{}}'"
    ).format(sql.Identifier(STATE_SCHEMA)),
    # U6: pending two-person requests. Holds only the SCRAM verifier (never a password);
    # it is cleared once the request is approved or expires.
    sql.SQL(
        "CREATE TABLE IF NOT EXISTS {}.requests ("
        " id text PRIMARY KEY, requester text NOT NULL, dataset text NOT NULL,"
        " table_name text NOT NULL, columns text[] NOT NULL, row_filter text,"
        " duration_seconds integer NOT NULL, purpose text NOT NULL,"
        " policy_sha256 text NOT NULL, verifier text,"
        " created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,"
        " status text NOT NULL DEFAULT 'pending'"
        " CHECK (status IN ('pending','approved','expired')),"
        " approver text, grant_id text)"
    ).format(sql.Identifier(STATE_SCHEMA)),
    # v0.3.0: requester and approver identity provenance (local vs OIDC iss/sub/token_sha256).
    sql.SQL("ALTER TABLE {}.requests ADD COLUMN IF NOT EXISTS requester_identity jsonb").format(
        sql.Identifier(STATE_SCHEMA)
    ),
    sql.SQL(
        "ALTER TABLE {}.grants ADD COLUMN IF NOT EXISTS requester_identity jsonb,"
        " ADD COLUMN IF NOT EXISTS approver_identities jsonb"
    ).format(sql.Identifier(STATE_SCHEMA)),
    # M2 quorum: durable votes on a pending request (additive, default empty).
    sql.SQL(
        "ALTER TABLE {}.requests ADD COLUMN IF NOT EXISTS approvals jsonb NOT NULL DEFAULT '[]'::jsonb"
    ).format(sql.Identifier(STATE_SCHEMA)),
)


_PREFLIGHT = sql.SQL(
    "SELECT 'PUBLIC can CONNECT to database ' || quote_ident(datname)"
    " FROM pg_database WHERE datallowconn AND datname <> current_database()"
    " AND has_database_privilege('public', datname, 'CONNECT')"
    " UNION ALL SELECT 'PUBLIC can create TEMP tables in ' || quote_ident(current_database())"
    " WHERE has_database_privilege('public', current_database(), 'TEMP')"
    " UNION ALL SELECT 'PUBLIC can CREATE in schema public'"
    " WHERE has_schema_privilege('public', 'public', 'CREATE')"
)


def preflight(conn: psycopg.Connection) -> list[str]:
    """Return warnings about PUBLIC defaults that every grant role inherits."""
    return sorted(row[0] for row in conn.execute(_PREFLIGHT).fetchall())


def ensure_state(conn: psycopg.Connection) -> list[str]:
    """Create datagrant's schemas and grant-state table if missing; return preflight warnings."""
    with conn.transaction():
        for stmt in STATE_DDL:
            conn.execute(stmt)
    return preflight(conn)


def count_active_grants(conn: psycopg.Connection, requester: str) -> int:
    """How many live grants this principal holds.

    Count is ``status = 'active' AND expires_at > now()``. Revoked grants and
    grants past ``expires_at`` (swept or not) do not count.
    """
    row = conn.execute(
        sql.SQL(
            "SELECT count(*) FROM {}.grants WHERE requester = %s AND status = 'active'"
            " AND expires_at > pg_catalog.now()"
        ).format(sql.Identifier(STATE_SCHEMA)),
        (requester,),
    ).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def build_plan(
    decision: Decision,
    req: Request,
    *,
    database: str,
    password: str,
    catalog: TableCatalog,
    hash_key: HashKey | None = None,
    grant_id: str | None = None,
    now: datetime | None = None,
    approvers: Sequence[str] = (),
    verifier: str | None = None,
    requester_identity: Mapping[str, Any] | None = None,
    approver_identities: Sequence[Mapping[str, Any]] | None = None,
) -> GrantPlan:
    """Build the SQL for an allowed decision. Pure: no database access."""
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
    schema, table = req.table.split(".", 1)
    role, view = f"dg_{gid}", f"g_{gid}"
    role_id, view_id = sql.Identifier(role), sql.Identifier(VIEW_SCHEMA, view)
    needs_key = any(decision.masks[c] == "hash" for c in req.columns)
    if needs_key and hash_key is None:
        raise GrantError("hash masking requires a hash key file (see keys.hash_key_path)")
    if hash_key is not None:
        # Per-dataset scope: equal values hash differently unless datasets share a hash_scope.
        hash_key = hash_key.scoped(decision.hash_scope or req.dataset)
    key_id = hash_key.key_id if hash_key is not None else None
    try:
        cols = sql.SQL(", ").join(
            column_expr(c, decision.masks[c], catalog, hash_key_id=key_id) for c in req.columns
        )
    except MaskError as exc:
        raise GrantError(str(exc)) from None
    select = sql.SQL("SELECT {} FROM {}").format(cols, sql.Identifier(schema, table))
    if req.row_filter is not None:
        cond, _ = parse_row_filter(req.row_filter)
        select = sql.SQL("{} WHERE {}").format(select, cond)
    stmts = (
        sql.SQL(
            "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE"
            " NOREPLICATION PASSWORD {} VALID UNTIL {}"
        ).format(
            role_id,
            sql.Literal(verifier or scram_verifier(password)),
            sql.Literal(expires.isoformat()),
        ),
        sql.SQL("CREATE VIEW {} WITH (security_barrier = true) AS {}").format(view_id, select),
        sql.SQL("REVOKE ALL ON {} FROM PUBLIC").format(view_id),
        sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(VIEW_SCHEMA), role_id),
        sql.SQL("GRANT SELECT ON {} TO {}").format(view_id, role_id),
        sql.SQL(
            "INSERT INTO {}.grants (id, role_name, view_name, dataset, table_name, requester,"
            " purpose, columns, row_filter, approval, policy_sha256, created_at, expires_at,"
            " masks, policy_version, approvers, requester_identity, approver_identities)"
            " VALUES ({})"
        ).format(
            sql.Identifier(STATE_SCHEMA),
            sql.SQL(", ").join(
                sql.Literal(v)
                for v in (
                    gid,
                    role,
                    f"{VIEW_SCHEMA}.{view}",
                    req.dataset,
                    req.table,
                    req.requester,
                    req.purpose,
                    list(req.columns),
                    req.row_filter,
                    decision.approval,
                    decision.policy_sha256,
                    now,
                    expires,
                    json.dumps({c: decision.masks[c] for c in req.columns}, sort_keys=True),
                    decision.policy_version,
                    list(approvers),
                    (
                        json.dumps(dict(requester_identity), sort_keys=True)
                        if requester_identity is not None
                        else None
                    ),
                    (
                        json.dumps([dict(x) for x in approver_identities], sort_keys=True)
                        if approver_identities is not None
                        else None
                    ),
                )
            ),
        ),
    )
    return GrantPlan(
        gid,
        role,
        f"{VIEW_SCHEMA}.{view}",
        expires,
        database,
        stmts,
        hash_key if needs_key else None,
        GrantFacts(
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
            tuple(dict(x) for x in approver_identities)
            if approver_identities is not None
            else None,
        ),
    )


def new_password() -> str:
    """One-time password: shown to the requester once, never stored."""
    return secrets.token_urlsafe(32)


def _require_counted_matches_plan(
    plan: GrantPlan, counted: Sequence[Mapping[str, Any]]
) -> None:
    """Fail closed when the locked counted set is not the plan's approvers."""
    if plan.facts is None:
        raise GrantError(
            f"grant {plan.grant_id}: counted approvers changed during claim; retry approve"
        )
    locked = tuple(str(v.get("approver")) for v in counted)
    planned = tuple(plan.facts.approvers)
    if locked != planned:
        raise GrantError(
            f"grant {plan.grant_id}: counted approvers changed during claim "
            f"({list(locked)} vs plan {list(planned)}); retry approve"
        )


def apply_plan(
    conn: psycopg.Connection,
    plan: GrantPlan,
    receipts: ReceiptSink | None = None,
    *,
    request_id: str | None = None,
    approver: str | None = None,
    approvals: Sequence[Mapping[str, Any]] | None = None,
    required: int | None = None,
    policy_sha256: str = "",
    issuer: str | None = None,
    can_approve: Callable[[Mapping[str, Any]], bool] | None = None,
) -> None:
    """Execute a plan atomically; any failure rolls everything back.

    With ``receipts``, an ``issued`` receipt is written after commit. If that
    write fails the grant is revoked at once (no receipt, no access) and
    GrantError is raised. Quorum's Nth vote is claimed inside this same
    transaction (``FOR UPDATE``, merge the caller's new vote with the locked
    row, re-check eligible votes, write approvals). Plan facts are fixed
    before that lock, so the counted names must match ``plan.facts.approvers``
    or the transaction rolls back (request stays pending; retry approve).
    """
    try:
        with conn.transaction():
            # Resolve every unqualified name to built-ins only (CVE-2018-1058 class).
            conn.execute(sql.SQL("SET LOCAL search_path = pg_catalog, pg_temp"))
            current = conn.execute(sql.SQL("SELECT current_database()")).fetchone()
            if current != (plan.database,):
                raise GrantError(
                    f"connected to database {current!r} but dataset is in {plan.database!r}"
                )
            if plan.hash_key is not None:
                # Bound parameters: the key is not part of any statement text or view definition.
                conn.execute(
                    sql.SQL(
                        "INSERT INTO {}.hash_keys (id, key) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING"
                    ).format(sql.Identifier(STATE_SCHEMA)),
                    (plan.hash_key.key_id, plan.hash_key.derived),
                )
            if request_id is not None:
                # Claim the pending request in the same transaction: exactly one approval wins.
                # The Nth quorum vote is written here too so a failed apply rolls it back.
                if approvals is not None:
                    from datagrant.pg.requests import claim_request

                    counted = claim_request(
                        conn,
                        request_id,
                        grant_id=plan.grant_id,
                        approver=approver,
                        votes=approvals,
                        required=required if required is not None else 1,
                        policy_sha256=policy_sha256,
                        issuer=issuer,
                        can_approve=can_approve,
                    )
                    _require_counted_matches_plan(plan, counted)
                else:
                    claimed = conn.execute(
                        sql.SQL(
                            "UPDATE {}.requests SET status = 'approved', approver = %s, grant_id = %s,"
                            " verifier = NULL WHERE id = %s AND status = 'pending'"
                            " AND expires_at > pg_catalog.now() RETURNING id"
                        ).format(sql.Identifier(STATE_SCHEMA)),
                        (approver, plan.grant_id, request_id),
                    ).fetchone()
                    if claimed is None:
                        raise GrantError(f"request {request_id} is not pending (or has expired)")
            for stmt in plan.statements:
                conn.execute(stmt)
    except psycopg.Error as exc:
        raise GrantError(
            f"grant {plan.grant_id} failed and was rolled back: {exc.sqlstate}"
        ) from exc
    if receipts is None:
        return
    try:
        if plan.facts is None:
            raise ReceiptError("plan has no receipt facts")
        receipt.append(receipts.log, "issued", plan.facts, receipts.key, host=receipts.host)
    except BaseException as exc:  # no receipt, no access - whatever went wrong
        from datagrant.pg.revoke import revoke  # local: revoke imports this module

        res = revoke(conn, plan.grant_id, "manual")
        if not isinstance(exc, Exception):
            raise  # KeyboardInterrupt/SystemExit: re-raise as is, after revoking
        raise GrantError(
            f"grant {plan.grant_id}: receipt not written ({exc}); grant revoked: {res.outcome}"
        ) from exc
