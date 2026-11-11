"""Pending two-person requests (unit U6).

A request stores what was asked for plus the SCRAM verifier of the password
shown once to the requester. The approver never sees a password. Approval
re-evaluates the request against the *current* policy, then creates the grant
and claims the request in one transaction.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable, Mapping, Sequence
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
    ignored: tuple[str, ...] = ()


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


def mapped_groups_of(vote: Mapping[str, Any]) -> frozenset[str]:
    """Policy groups stored on a vote from the caller's verified token."""
    raw = vote.get("mapped_groups", ())
    if isinstance(raw, (list, tuple, set, frozenset)):
        return frozenset(g for g in raw if isinstance(g, str))
    return frozenset()


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


def eligible_votes(
    votes: Sequence[Mapping[str, Any]],
    *,
    policy_sha256: str,
    issuer: str | None = None,
    can_approve: Callable[[Mapping[str, Any]], bool] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split stored votes into those that still count and those that do not.

    A vote counts only when it carries ``policy_sha256`` equal to the current
    policy, an OIDC ``iss`` that matches when ``issuer`` is set, and
    ``can_approve(vote)`` is true (current policy, using the vote's stored
    ``mapped_groups``). Unstamped votes do not count.
    """
    ok = can_approve or (lambda _vote: True)
    counted: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    for raw in votes:
        v = dict(raw)
        if v.get("policy_sha256") != policy_sha256:
            ignored.append(v)
            continue
        if issuer is not None:
            stamp_iss = v.get("iss")
            ident_raw = v.get("identity")
            if not isinstance(stamp_iss, str) and isinstance(ident_raw, dict):
                inner_iss = ident_raw.get("iss")
                stamp_iss = inner_iss if isinstance(inner_iss, str) else None
            if stamp_iss != issuer:
                ignored.append(v)
                continue
        name = v.get("approver")
        if not isinstance(name, str) or not ok(v):
            ignored.append(v)
            continue
        counted.append(v)
    return counted, ignored


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


def _write_approvals(conn: psycopg.Connection, request_id: str, votes: Sequence[Mapping[str, Any]]) -> None:
    conn.execute(
        sql.SQL("UPDATE {}.requests SET approvals = %s::jsonb WHERE id = %s").format(
            sql.Identifier(STATE_SCHEMA)
        ),
        (json.dumps([dict(v) for v in votes], sort_keys=True), request_id),
    )


def record_approval(
    conn: psycopg.Connection,
    request_id: str,
    *,
    approver: str,
    identity: Mapping[str, Any] | None,
    required: int,
    now: datetime | None = None,
    policy_sha256: str = "",
    issuer: str | None = None,
    can_approve: Callable[[Mapping[str, Any]], bool] | None = None,
    persist_if_final: bool = True,
    mapped_groups: Sequence[str] = (),
) -> ApprovalRecord:
    """Append or replace a distinct vote under ``SELECT ... FOR UPDATE``.

    Idempotent per person for a vote that already counts. If the caller already
    has any stored vote that does not count (stale policy stamp), that row is
    replaced instead of appending. When ``persist_if_final`` is false, a vote
    that would issue is returned in memory but not written, so ``apply_plan``
    can store it in the grant-creation transaction.
    """
    now = now or datetime.now(UTC)
    required = max(required, 1)
    ident = _safe_identity(identity)
    extra = sorted({g for g in mapped_groups if isinstance(g, str)})
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
        counted, ignored = eligible_votes(
            votes, policy_sha256=policy_sha256, issuer=issuer, can_approve=can_approve
        )
        ignored_names = tuple(
            str(v.get("approver")) for v in ignored if isinstance(v.get("approver"), str)
        )
        if already_voted(counted, approver, ident):
            n = len(counted)
            return ApprovalRecord(
                pending, n, required, True, n >= required, False, ignored_names
            )
        if len(counted) >= required:
            n = len(counted)
            return ApprovalRecord(
                pending, n, required, False, True, False, ignored_names
            )
        had_any = already_voted(votes, approver, ident)
        votes = [v for v in votes if not already_voted([v], approver, ident)]
        vote: dict[str, Any] = {
            "approver": approver,
            "at": now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "identity": ident,
            "policy_sha256": policy_sha256,
            "mapped_groups": extra,
        }
        if issuer is not None:
            vote["iss"] = issuer
        votes.append(vote)
        counted2, ignored2 = eligible_votes(
            votes, policy_sha256=policy_sha256, issuer=issuer, can_approve=can_approve
        )
        ignored_names = tuple(
            str(v.get("approver")) for v in ignored2 if isinstance(v.get("approver"), str)
        )
        n = len(counted2)
        is_final = n >= required
        now_counts = already_voted(counted2, approver, ident)
        if not (is_final and not persist_if_final):
            _write_approvals(conn, request_id, votes)
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
        already = had_any and not now_counts
        return ApprovalRecord(updated, n, required, already, is_final, True, ignored_names)


def claim_request(
    conn: psycopg.Connection,
    request_id: str,
    *,
    grant_id: str,
    approver: str | None,
    votes: Sequence[Mapping[str, Any]],
    required: int,
    policy_sha256: str = "",
    issuer: str | None = None,
    can_approve: Callable[[Mapping[str, Any]], bool] | None = None,
) -> None:
    """Lock the pending row, merge the caller's new vote, re-check, claim.

    ``votes`` is only the caller's new vote (empty if they already counted),
    not a snapshot of every approval. Stored votes that were dropped after
    the in-memory snapshot stay dropped. Must run in the caller's transaction.
    """
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
    incoming = [dict(v) for v in votes]
    keep: list[dict[str, Any]] = []
    for stored in pending.approvals:
        name = stored.get("approver")
        raw_id = stored.get("identity")
        ident = raw_id if isinstance(raw_id, dict) else {}
        if isinstance(name, str) and not already_voted(incoming, name, ident):
            keep.append(dict(stored))
    merged = keep + incoming
    counted, _ignored = eligible_votes(
        merged, policy_sha256=policy_sha256, issuer=issuer, can_approve=can_approve
    )
    need = max(required, 1)
    if len(counted) < need:
        raise GrantError(f"request {request_id} does not have {need} eligible approvals")
    claimed = conn.execute(
        sql.SQL(
            "UPDATE {}.requests SET status = 'approved', approver = %s, grant_id = %s,"
            " verifier = NULL, approvals = %s::jsonb WHERE id = %s AND status = 'pending'"
            " AND expires_at > pg_catalog.now() RETURNING id"
        ).format(sql.Identifier(STATE_SCHEMA)),
        (approver, grant_id, json.dumps(merged, sort_keys=True), request_id),
    ).fetchone()
    if claimed is None:
        raise GrantError(f"request {request_id} is not pending (or has expired)")


def drop_approval(
    conn: psycopg.Connection,
    request_id: str,
    *,
    approver: str,
    identity: Mapping[str, Any] | None,
) -> None:
    """Remove the caller's vote under ``FOR UPDATE`` (failed ``approval_recorded``)."""
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
        kept = [
            dict(v)
            for v in pending.approvals
            if not already_voted([v], approver, identity)
        ]
        _write_approvals(conn, request_id, kept)


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
