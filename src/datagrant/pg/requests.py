"""Pending two-person requests (unit U6).

A request stores what was asked for plus the SCRAM verifier of the password
shown once to the requester. The approver never sees a password. Approval
re-evaluates the request against the *current* policy, then creates the grant
and claims the request in one transaction.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from psycopg import sql

from datagrant.pg.grant import STATE_SCHEMA, GrantError
from datagrant.policy import Request

_SAFE_PATH = sql.SQL("SET LOCAL search_path = pg_catalog, pg_temp")
DEFAULT_PENDING_TTL = timedelta(hours=24)


@dataclass(frozen=True)
class PendingRequest:
    id: str
    request: Request
    policy_sha256: str
    verifier: str | None
    created_at: datetime
    expires_at: datetime
    status: str
    approver: str | None
    grant_id: str | None
    requester_identity: dict[str, Any] | None = None


def create_request(
    conn: psycopg.Connection,
    req: Request,
    *,
    policy_sha256: str,
    verifier: str,
    ttl: timedelta = DEFAULT_PENDING_TTL,
    now: datetime | None = None,
    requester_identity: Mapping[str, Any] | None = None,
) -> PendingRequest:
    if ttl <= timedelta(0):
        raise GrantError("pending request ttl must be positive")
    now = now or datetime.now(UTC)
    rid = secrets.token_hex(6)
    with conn.transaction():
        conn.execute(_SAFE_PATH)
        ident_dict = dict(requester_identity) if requester_identity is not None else None
        conn.execute(
            sql.SQL(
                "INSERT INTO {}.requests (id, requester, dataset, table_name, columns, row_filter,"
                " duration_seconds, purpose, policy_sha256, verifier, created_at, expires_at,"
                " requester_identity)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            ).format(sql.Identifier(STATE_SCHEMA)),
            (
                rid,
                req.requester,
                req.dataset,
                req.table,
                list(req.columns),
                req.row_filter,
                int(req.duration.total_seconds()),
                req.purpose,
                policy_sha256,
                verifier,
                now,
                now + ttl,
                json.dumps(ident_dict, sort_keys=True) if ident_dict is not None else None,
            ),
        )
    return PendingRequest(
        rid, req, policy_sha256, verifier, now, now + ttl, "pending", None, None, ident_dict
    )


def get_request(conn: psycopg.Connection, request_id: str) -> PendingRequest:
    with conn.transaction():
        conn.execute(_SAFE_PATH)
        r = conn.execute(
            sql.SQL(
                "SELECT id, requester, dataset, table_name, columns, row_filter, duration_seconds,"
                " purpose, policy_sha256, verifier, created_at, expires_at, status, approver,"
                " grant_id, requester_identity FROM {}.requests WHERE id = %s"
            ).format(sql.Identifier(STATE_SCHEMA)),
            (request_id,),
        ).fetchone()
    if r is None:
        raise GrantError(f"unknown request {request_id}")
    req = Request(r[1], r[2], r[3], tuple(r[4]), timedelta(seconds=r[6]), r[7], r[5])
    raw_ident = r[15] if len(r) > 15 else None
    if isinstance(raw_ident, str):
        raw_ident = json.loads(raw_ident)
    ident_out = dict(raw_ident) if isinstance(raw_ident, dict) else None
    return PendingRequest(r[0], req, r[8], r[9], r[10], r[11], r[12], r[13], r[14], ident_out)


def expire_requests(conn: psycopg.Connection) -> list[str]:
    """Mark pending requests past their expiry as expired and drop their verifiers."""
    with conn.transaction():
        conn.execute(_SAFE_PATH)
        rows = conn.execute(
            sql.SQL(
                "UPDATE {}.requests SET status = 'expired', verifier = NULL"
                " WHERE status = 'pending' AND expires_at <= pg_catalog.now() RETURNING id"
            ).format(sql.Identifier(STATE_SCHEMA))
        ).fetchall()
    return sorted(r[0] for r in rows)


def expire_stale_requests(conn: psycopg.Connection) -> list[PendingRequest]:
    """Expire stale pending rows and return them (for request_expired receipts).

    Idempotent: a second call finds no ``pending`` rows and returns nothing.
    """
    return [get_request(conn, rid) for rid in expire_requests(conn)]
