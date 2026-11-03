"""Revoke grants and sweep expired ones (unit U4).

Each grant is revoked in short transactions under a pinned search_path:
first commit a lockout (NOLOGIN, VALID UNTIL 'epoch', PASSWORD NULL) so the
postmaster refuses new logins, then terminate the role's sessions (waiting
until they are gone), then in a final transaction re-terminate stragglers,
revoke privileges, drop the view, drop anything the role owns, drop the role,
then mark the state row. Any failure rolls the cleanup back, the error is
recorded on the row (status stays 'active', the role stays locked out), and the grant is retried by the
next sweep. A grant is never marked revoked unless the role and view are gone.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, replace
from typing import Literal

import psycopg
from psycopg import sql

from datagrant import receipt
from datagrant.pg.grant import STATE_SCHEMA, GrantError, ReceiptSink
from datagrant.receipt import GrantFacts

Reason = Literal["expired", "manual"]
Outcome = Literal["revoked", "noop", "failed"]
SESSION_WAIT_SECONDS = 5.0

_SAFE_PATH = sql.SQL("SET LOCAL search_path = pg_catalog, pg_temp")
_LOCK_ROW = sql.SQL(
    "SELECT role_name, view_name, status FROM {}.grants WHERE id = %s FOR UPDATE"
).format(sql.Identifier(STATE_SCHEMA))
_TERMINATE = sql.SQL(
    "SELECT pid, pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity"
    " WHERE usename = %s AND pid <> pg_catalog.pg_backend_pid()"
)
_COUNT_SESSIONS = sql.SQL(
    "SELECT pg_catalog.count(*) FROM pg_catalog.pg_stat_activity WHERE usename = %s"
)
_ROLE_EXISTS = sql.SQL("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s")
_DUE = sql.SQL(
    "SELECT id FROM {}.grants WHERE status = 'active' AND expires_at <= pg_catalog.now()"
    " ORDER BY expires_at, id"
).format(sql.Identifier(STATE_SCHEMA))


@dataclass(frozen=True)
class RevokeResult:
    grant_id: str
    outcome: Outcome
    sessions_terminated: int = 0
    error: str | None = None
    receipt_error: str | None = None


def _terminate_sessions(conn: psycopg.Connection, role: str) -> int:
    rows = conn.execute(_TERMINATE, (role,)).fetchall()
    if any(ok is not True for _, ok in rows):
        raise GrantError(f"could not terminate sessions of {role} (admin needs pg_signal_backend)")
    deadline = time.monotonic() + SESSION_WAIT_SECONDS
    while True:
        row = conn.execute(_COUNT_SESSIONS, (role,)).fetchone()
        if row is None or row[0] == 0:
            return len(rows)
        if time.monotonic() > deadline:
            raise GrantError(f"sessions of {role} still open after termination")
        time.sleep(0.05)
        conn.execute(sql.SQL("SELECT pg_catalog.pg_stat_clear_snapshot()"))


def _lockout(conn: psycopg.Connection, grant_id: str) -> tuple[str, str, bool] | None:
    """Commit a lockout first so the postmaster refuses new logins before we kill sessions.

    Returns (role, view, role_exists), or None if the grant is no longer active.
    """
    with conn.transaction():
        conn.execute(_SAFE_PATH)
        row = conn.execute(_LOCK_ROW, (grant_id,)).fetchone()
        if row is None:
            raise GrantError(f"unknown grant {grant_id}")
        role, view, status = row
        if status != "active":
            return None
        exists = conn.execute(_ROLE_EXISTS, (role,)).fetchone() is not None
        if exists:
            conn.execute(
                sql.SQL("ALTER ROLE {} NOLOGIN VALID UNTIL 'epoch' PASSWORD NULL").format(
                    sql.Identifier(role)
                )
            )
    return role, view, exists


def _cleanup(conn: psycopg.Connection, grant_id: str, reason: Reason) -> RevokeResult:
    locked = _lockout(conn, grant_id)  # committed: logins now refused
    if locked is None:
        return RevokeResult(grant_id, "noop")
    role, view, exists = locked
    role_id = sql.Identifier(role)
    view_id = sql.Identifier(*view.split(".", 1))
    n = 0
    if exists:
        with conn.transaction():
            conn.execute(_SAFE_PATH)
            n = _terminate_sessions(conn, role)
    with conn.transaction():
        conn.execute(_SAFE_PATH)
        row = conn.execute(_LOCK_ROW, (grant_id,)).fetchone()
        if row is None or row[2] != "active":
            return RevokeResult(grant_id, "noop", n)  # a concurrent revoke finished it
        if exists:
            n += _terminate_sessions(conn, role)  # stragglers that slipped in before lockout
        conn.execute(sql.SQL("DROP VIEW IF EXISTS {}").format(view_id))
        if exists:
            # Objects the role may own (it should own none) go back to the admin, then
            # DROP OWNED removes its remaining privileges in this database.
            conn.execute(sql.SQL("REASSIGN OWNED BY {} TO CURRENT_USER").format(role_id))
            conn.execute(sql.SQL("DROP OWNED BY {}").format(role_id))
            conn.execute(sql.SQL("DROP ROLE {}").format(role_id))
        conn.execute(
            sql.SQL(
                "UPDATE {}.grants SET status = %s, revoked_at = pg_catalog.now(),"
                " revoke_reason = %s, last_error = NULL, last_error_at = NULL WHERE id = %s"
            ).format(sql.Identifier(STATE_SCHEMA)),
            ("expired" if reason == "expired" else "revoked", reason, grant_id),
        )
    return RevokeResult(grant_id, "revoked", n)


def _record_failure(conn: psycopg.Connection, grant_id: str, error: str) -> None:
    try:
        with conn.transaction():
            conn.execute(_SAFE_PATH)
            conn.execute(
                sql.SQL(
                    "UPDATE {}.grants SET last_error = %s, last_error_at = pg_catalog.now()"
                    " WHERE id = %s AND status = 'active'"
                ).format(sql.Identifier(STATE_SCHEMA)),
                (error[:500], grant_id),
            )
            row = conn.execute(
                sql.SQL("SELECT role_name FROM {}.grants WHERE id = %s").format(
                    sql.Identifier(STATE_SCHEMA)
                ),
                (grant_id,),
            ).fetchone()
            if row and conn.execute(_ROLE_EXISTS, (row[0],)).fetchone():
                # Best effort: at least stop new logins until the next sweep succeeds.
                conn.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(row[0])))
    except psycopg.Error:
        pass  # the original failure is still reported to the caller


_FACTS = sql.SQL(
    "SELECT requester, dataset, table_name, columns, masks, row_filter, purpose, created_at,"
    " expires_at, policy_sha256, policy_version, approval, approvers"
    " FROM {}.grants WHERE id = %s AND status = 'active'"
).format(sql.Identifier(STATE_SCHEMA))


def _load_facts(conn: psycopg.Connection, grant_id: str) -> GrantFacts | None:
    with conn.transaction():
        conn.execute(_SAFE_PATH)
        r = conn.execute(_FACTS, (grant_id,)).fetchone()
    if r is None:
        return None
    try:
        masks = json.loads(r[4]) if r[4] else {}
    except ValueError:
        masks = {}
    return GrantFacts(
        grant_id,
        r[0],
        r[1],
        r[2],
        tuple(r[3]),
        masks,
        r[5],
        r[6],
        r[7],
        r[8],
        r[9],
        r[10] or 1,
        r[11],
        tuple(r[12] or ()),
    )


def _attempt(conn: psycopg.Connection, grant_id: str, reason: Reason) -> RevokeResult:
    try:
        return _cleanup(conn, grant_id, reason)
    except (psycopg.Error, GrantError) as exc:
        if isinstance(exc, GrantError) and str(exc).startswith("unknown grant"):
            raise
        msg = str(exc) if isinstance(exc, GrantError) else f"database error {exc.sqlstate}"
        _record_failure(conn, grant_id, msg)
        return RevokeResult(grant_id, "failed", error=msg)


def revoke(
    conn: psycopg.Connection,
    grant_id: str,
    reason: Reason = "manual",
    receipts: ReceiptSink | None = None,
) -> RevokeResult:
    """Revoke one grant. Idempotent: an already revoked/expired grant is a no-op.

    With ``receipts``, a ``revoked``/``expired`` (or ``revoke_failed``) receipt is
    written. Access removal never depends on the receipt: a receipt write
    failure is returned in ``receipt_error`` after the revoke itself.
    """
    facts = _load_facts(conn, grant_id) if receipts is not None else None
    res = _attempt(conn, grant_id, reason)
    if receipts is None or facts is None or res.outcome == "noop":
        return res
    if res.outcome == "revoked":
        event: receipt.Event = "expired" if reason == "expired" else "revoked"
        details: dict[str, object] = {
            "reason": reason,
            "sessions_terminated": res.sessions_terminated,
        }
    else:
        event, details = "revoke_failed", {"reason": reason, "error": res.error or ""}
    try:
        receipt.append(
            receipts.log, event, facts, receipts.key, host=receipts.host, details=details
        )
    except receipt.ReceiptError as exc:
        return replace(res, receipt_error=str(exc))
    return res


def sweep(conn: psycopg.Connection, receipts: ReceiptSink | None = None) -> list[RevokeResult]:
    """Revoke every active grant past expiry, one transaction per grant."""
    with conn.transaction():
        conn.execute(_SAFE_PATH)
        due = [r[0] for r in conn.execute(_DUE).fetchall()]
    return [revoke(conn, gid, "expired", receipts) for gid in due]
