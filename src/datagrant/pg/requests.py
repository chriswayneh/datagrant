"""Pending two-person requests (unit U6).

A request stores what was asked for plus the SCRAM verifier of the password
shown once to the requester. The approver never sees a password. Approval
re-evaluates the request against the *current* policy, then creates the grant
and claims the request in one transaction.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from psycopg import sql

from datagrant.pg.grant import STATE_SCHEMA, GrantError
from datagrant.policy import Request

_SAFE_PATH = sql.SQL("SET LOCAL search_path = pg_catalog, pg_temp")
DEFAULT_PENDING_TTL = timedelta(hours=24)


_SAFE_IDENT = ("approver", "source", "iss", "sub", "token_sha256")


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
    approvals: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class ApprovalRecord:
    pending: PendingRequest
    recorded: int
    required: int
    already: bool
    is_final: bool
    added: bool


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


_REQUEST_COLS = (
    "id, requester, dataset, table_name, columns, row_filter, duration_seconds,"
    " purpose, policy_sha256, verifier, created_at, expires_at, status, approver,"
    " grant_id, requester_identity, approvals"
)


def _parse_json_obj(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, str):
        raw = json.loads(raw)
    return dict(raw) if isinstance(raw, dict) else None


def _parse_approvals(raw: Any) -> tuple[dict[str, Any], ...]:
    if isinstance(raw, str):
        raw = json.loads(raw)
    if not isinstance(raw, list):
        return ()
    out: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict) and isinstance(item.get("approver"), str):
            out.append(dict(item))
    return tuple(out)


def _pending_from_row(r: tuple[Any, ...]) -> PendingRequest:
    req = Request(r[1], r[2], r[3], tuple(r[4]), timedelta(seconds=r[6]), r[7], r[5])
    ident_out = _parse_json_obj(r[15] if len(r) > 15 else None)
    approvals = _parse_approvals(r[16] if len(r) > 16 else ())
    return PendingRequest(
        r[0], req, r[8], r[9], r[10], r[11], r[12], r[13], r[14], ident_out, approvals
    )


def _safe_identity(raw: Mapping[str, Any] | None) -> dict[str, str]:
    if not raw:
        return {}
    return {k: v for k, v in raw.items() if k in _SAFE_IDENT and isinstance(v, str)}


def already_voted(
    votes: Sequence[Mapping[str, Any]], approver: str, identity: Mapping[str, Any] | None
) -> bool:
    """True if this person already recorded a vote (name or OIDC iss/sub)."""
    name = approver.casefold()
    ident = _safe_identity(identity)
    iss, sub = ident.get("iss"), ident.get("sub")
    for v in votes:
        if str(v.get("approver", "")).casefold() == name:
            return True
        raw_id = v.get("identity")
        vid: Mapping[str, Any] = raw_id if isinstance(raw_id, dict) else {}
        if iss and sub and vid.get("iss") == iss and vid.get("sub") == sub:
            return True
    return False


def get_request(conn: psycopg.Connection, request_id: str) -> PendingRequest:
    with conn.transaction():
        conn.execute(_SAFE_PATH)
        r = conn.execute(
            sql.SQL("SELECT {} FROM {}.requests WHERE id = %s").format(
                sql.SQL(_REQUEST_COLS), sql.Identifier(STATE_SCHEMA)
            ),
            (request_id,),
        ).fetchone()
    if r is None:
        raise GrantError(f"unknown request {request_id}")
    return _pending_from_row(r)


def record_approval(
    conn: psycopg.Connection,
    request_id: str,
    *,
    approver: str,
    identity: Mapping[str, Any] | None,
    required: int,
    now: datetime | None = None,
) -> ApprovalRecord:
    """Append a distinct vote under ``SELECT ... FOR UPDATE``. Idempotent per person."""
    now = now or datetime.now(UTC)
    required = max(required, 1)
    ident = _safe_identity(identity)
    with conn.transaction():
        conn.execute(_SAFE_PATH)
        r = conn.execute(
            sql.SQL("SELECT {} FROM {}.requests WHERE id = %s FOR UPDATE").format(
                sql.SQL(_REQUEST_COLS), sql.Identifier(STATE_SCHEMA)
            ),
            (request_id,),
        ).fetchone()
        if r is None:
            raise GrantError(f"unknown request {request_id}")
        pending = _pending_from_row(r)
        if pending.status != "pending" or pending.verifier is None:
            raise GrantError(f"request {request_id} is not pending (or has expired)")
        votes = [dict(v) for v in pending.approvals]
        if already_voted(votes, approver, ident):
            n = len(votes)
            return ApprovalRecord(pending, n, required, True, n >= required, False)
        if len(votes) >= required:
            n = len(votes)
            return ApprovalRecord(pending, n, required, False, True, False)
        vote = {
            "approver": approver,
            "at": now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "identity": ident,
        }
        votes.append(vote)
        conn.execute(
            sql.SQL("UPDATE {}.requests SET approvals = %s::jsonb WHERE id = %s").format(
                sql.Identifier(STATE_SCHEMA)
            ),
            (json.dumps(votes, sort_keys=True), request_id),
        )
        updated = PendingRequest(
            pending.id,
            pending.request,
            pending.policy_sha256,
            pending.verifier,
            pending.created_at,
            pending.expires_at,
            pending.status,
            pending.approver,
            pending.grant_id,
            pending.requester_identity,
            tuple(votes),
        )
        n = len(votes)
        return ApprovalRecord(updated, n, required, False, n >= required, True)


def drop_last_approval(conn: psycopg.Connection, request_id: str) -> None:
    """Remove the newest vote (receipt for a partial approval could not be written)."""
    with conn.transaction():
        conn.execute(_SAFE_PATH)
        r = conn.execute(
            sql.SQL("SELECT {} FROM {}.requests WHERE id = %s FOR UPDATE").format(
                sql.SQL(_REQUEST_COLS), sql.Identifier(STATE_SCHEMA)
            ),
            (request_id,),
        ).fetchone()
        if r is None:
            return
        pending = _pending_from_row(r)
        if pending.status != "pending" or not pending.approvals:
            return
        votes = [dict(v) for v in pending.approvals[:-1]]
        conn.execute(
            sql.SQL("UPDATE {}.requests SET approvals = %s::jsonb WHERE id = %s").format(
                sql.Identifier(STATE_SCHEMA)
            ),
            (json.dumps(votes, sort_keys=True), request_id),
        )


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
