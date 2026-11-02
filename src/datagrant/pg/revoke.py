"""Revoke grants and sweep expired ones (unit U4).

Each grant is revoked in its own transaction under a pinned search_path:
block new logins, terminate the role's sessions (waiting until they are gone),
revoke privileges, drop the view, drop anything the role owns, drop the role,
then mark the state row. Any failure rolls the cleanup back, the error is
recorded on the row (status stays 'active'), and the grant is retried by the
next sweep. A grant is never marked revoked unless the role and view are gone.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal

import psycopg
from psycopg import sql

from datagrant.pg.grant import STATE_SCHEMA, GrantError

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


def _cleanup(conn: psycopg.Connection, grant_id: str, reason: Reason) -> RevokeResult:
    with conn.transaction():
        conn.execute(_SAFE_PATH)
        row = conn.execute(_LOCK_ROW, (grant_id,)).fetchone()
        if row is None:
            raise GrantError(f"unknown grant {grant_id}")
        role, view, status = row
        if status != "active":
            return RevokeResult(grant_id, "noop")
        role_id = sql.Identifier(role)
        view_id = sql.Identifier(*view.split(".", 1))
        exists = conn.execute(_ROLE_EXISTS, (role,)).fetchone() is not None
        n = 0
        if exists:
            conn.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(role_id))
            n = _terminate_sessions(conn, role)
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


def revoke(conn: psycopg.Connection, grant_id: str, reason: Reason = "manual") -> RevokeResult:
    """Revoke one grant. Idempotent: an already revoked/expired grant is a no-op."""
    try:
        return _cleanup(conn, grant_id, reason)
    except (psycopg.Error, GrantError) as exc:
        if isinstance(exc, GrantError) and str(exc).startswith("unknown grant"):
            raise
        msg = str(exc) if isinstance(exc, GrantError) else f"database error {exc.sqlstate}"
        _record_failure(conn, grant_id, msg)
        return RevokeResult(grant_id, "failed", error=msg)


def sweep(conn: psycopg.Connection) -> list[RevokeResult]:
    """Revoke every active grant past expiry, one transaction per grant."""
    with conn.transaction():
        conn.execute(_SAFE_PATH)
        due = [r[0] for r in conn.execute(_DUE).fetchall()]
    return [revoke(conn, gid, "expired") for gid in due]
