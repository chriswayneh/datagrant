"""Create per-grant views and expiring login roles (unit U2).

All SQL is composed with psycopg.sql (Identifier/Literal); nothing is
string-interpolated. Grant creation runs in one transaction (fail closed).
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

import psycopg
from psycopg import sql

from datagrant.pg.scram import scram_verifier
from datagrant.policy import Decision, Request
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
    statements: tuple[sql.Composed, ...]


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
)


def ensure_state(conn: psycopg.Connection) -> None:
    """Create datagrant's schemas and grant-state table if missing."""
    with conn.transaction():
        for stmt in STATE_DDL:
            conn.execute(stmt)


def _column_expr(col: str, mask: str) -> sql.Composable:
    # U3 replaces this hook with real masking; until then fail closed.
    if mask == "passthrough":
        return sql.Identifier(col)
    if mask == "null":
        return sql.SQL("NULL::text AS {}").format(sql.Identifier(col))
    raise GrantError(f"mask {mask!r} on column {col!r} is not implemented yet (U3)")


def build_plan(
    decision: Decision,
    req: Request,
    *,
    password: str,
    grant_id: str | None = None,
    now: datetime | None = None,
) -> GrantPlan:
    """Build the SQL for an allowed decision. Pure: no database access."""
    if not decision.allowed:
        raise GrantError("cannot build a grant for a denied decision")
    if decision.approval != "auto":
        raise GrantError("two-person approval is not supported yet (U6)")
    gid = grant_id or secrets.token_hex(6)
    if not _GRANT_ID_RE.match(gid):
        raise GrantError("grant id must be 12 lowercase hex characters")
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise GrantError("now must be timezone-aware")
    expires = now + req.duration
    schema, table = req.table.split(".", 1)
    role, view = f"dg_{gid}", f"g_{gid}"
    role_id, view_id = sql.Identifier(role), sql.Identifier(VIEW_SCHEMA, view)
    cols = sql.SQL(", ").join(_column_expr(c, decision.masks[c]) for c in req.columns)
    select = sql.SQL("SELECT {} FROM {}").format(cols, sql.Identifier(schema, table))
    if req.row_filter is not None:
        cond, _ = parse_row_filter(req.row_filter)
        select = sql.SQL("{} WHERE {}").format(select, cond)
    stmts = (
        sql.SQL(
            "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE"
            " NOREPLICATION PASSWORD {} VALID UNTIL {}"
        ).format(role_id, sql.Literal(scram_verifier(password)), sql.Literal(expires.isoformat())),
        sql.SQL("CREATE VIEW {} WITH (security_barrier = true) AS {}").format(view_id, select),
        sql.SQL("REVOKE ALL ON {} FROM PUBLIC").format(view_id),
        sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(VIEW_SCHEMA), role_id),
        sql.SQL("GRANT SELECT ON {} TO {}").format(view_id, role_id),
        sql.SQL(
            "INSERT INTO {}.grants (id, role_name, view_name, dataset, table_name, requester,"
            " purpose, columns, row_filter, approval, policy_sha256, created_at, expires_at)"
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
                )
            ),
        ),
    )
    return GrantPlan(gid, role, f"{VIEW_SCHEMA}.{view}", expires, stmts)


def new_password() -> str:
    """One-time password: shown to the requester once, never stored."""
    return secrets.token_urlsafe(32)


def apply_plan(conn: psycopg.Connection, plan: GrantPlan) -> None:
    """Execute a plan atomically; any failure rolls everything back."""
    try:
        with conn.transaction():
            for stmt in plan.statements:
                conn.execute(stmt)
    except psycopg.Error as exc:
        raise GrantError(
            f"grant {plan.grant_id} failed and was rolled back: {exc.sqlstate}"
        ) from exc
