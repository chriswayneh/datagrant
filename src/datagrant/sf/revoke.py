"""Snowflake revoke and sweep (M4 construction PR 3).

DISABLE the grant user first (`ALTER USER IF EXISTS ... SET DISABLED = TRUE`;
that aborts the user's queries), then DROP VIEW / ROLE / USER IF EXISTS so a
partial issuing or enabling row is safe. A DISABLE error fails closed
(`revoke_failed`, exit 4). Claim the grants row with qmark binds and a rowcount
check so two sweeps cannot double-revoke. Issuing and enabling rows younger
than 10 minutes are skipped; older ones are dropped and marked failed. Pending
request TTL expiry does not drop Snowflake objects.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from datagrant import receipt
from datagrant.pg.grant import ReceiptSink
from datagrant.receipt import GrantFacts, ReceiptError
from datagrant.sf.grant import (
    STATE_SCHEMA,
    VIEW_SCHEMA,
    Bound,
    GrantError,
    _exec,
    _rowcount,
    _run,
    q,
)

Reason = Literal["expired", "manual", "stale_issuing"]
Outcome = Literal["revoked", "noop", "failed"]
ISSUING_GRACE_MINUTES = 10
_GRANT_SELECT = (
    "ID, ROLE_NAME, VIEW_NAME, USER_NAME, DATASET, TABLE_NAME, REQUESTER, PURPOSE,"
    " COLUMNS, ROW_FILTER, APPROVAL, POLICY_SHA256, CREATED_AT, EXPIRES_AT,"
    " STARTED_AT, STATUS, PUBLIC_KEY_FINGERPRINT, LAST_ERROR"
)


@dataclass(frozen=True)
class RevokeResult:
    grant_id: str
    outcome: Outcome
    sessions_terminated: int = 0
    error: str | None = None
    receipt_error: str | None = None
    reason: Reason | None = None


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


def _fetchall(result: Any, conn: Any) -> list[tuple[Any, ...]]:
    if result is not None and hasattr(result, "fetchall"):
        rows = result.fetchall()
        if rows:
            return [tuple(r) for r in rows]
    if hasattr(conn, "fetchall"):
        rows = conn.fetchall()
        if rows:
            return [tuple(r) for r in rows]
    return []


def _parse_dt(raw: Any) -> datetime:
    if isinstance(raw, datetime):
        return raw
    return datetime.fromisoformat(str(raw))


def _row_dict(row: tuple[Any, ...]) -> dict[str, Any]:
    keys = (
        "id",
        "role_name",
        "view_name",
        "user_name",
        "dataset",
        "table_name",
        "requester",
        "purpose",
        "columns",
        "row_filter",
        "approval",
        "policy_sha256",
        "created_at",
        "expires_at",
        "started_at",
        "status",
        "public_key_fingerprint",
        "last_error",
    )
    return dict(zip(keys, row, strict=False))


def _names(row: dict[str, Any]) -> tuple[str, str, str]:
    gid = str(row["id"])
    user = str(row["user_name"] or f"DG_{gid}")
    role = str(row["role_name"] or f"DG_R_{gid}")
    view = str(row["view_name"] or f"{VIEW_SCHEMA}.G_{gid}")
    return user, role, view


def _facts(row: dict[str, Any]) -> GrantFacts:
    raw_cols = row.get("columns")
    if isinstance(raw_cols, str):
        try:
            cols = tuple(json.loads(raw_cols))
        except ValueError:
            cols = ()
    elif isinstance(raw_cols, (list, tuple)):
        cols = tuple(raw_cols)
    else:
        cols = ()
    return GrantFacts(
        str(row["id"]),
        str(row.get("requester") or ""),
        str(row.get("dataset") or ""),
        str(row.get("table_name") or ""),
        cols,
        {},
        row.get("row_filter"),
        str(row.get("purpose") or ""),
        _parse_dt(row["created_at"]),
        _parse_dt(row["expires_at"]),
        str(row.get("policy_sha256") or ""),
        1,
        str(row.get("approval") or "auto"),
        (),
        None,
        None,
    )


def get_grant(conn: Any, grant_id: str) -> dict[str, Any] | None:
    result = _exec(
        conn,
        (
            f"SELECT {_GRANT_SELECT} FROM {q(STATE_SCHEMA)}.{q('GRANTS')}"  # nosec B608
            " WHERE ID = ?"
        ),
        (grant_id,),
    )
    row = _fetchone(result, conn)
    return _row_dict(row) if row is not None else None


def list_grants(conn: Any, *, active_only: bool = True) -> list[dict[str, Any]]:
    if active_only:
        result = _exec(
            conn,
            (
                f"SELECT {_GRANT_SELECT} FROM {q(STATE_SCHEMA)}.{q('GRANTS')}"  # nosec B608
                " WHERE STATUS = ? ORDER BY CREATED_AT, ID"
            ),
            ("active",),
        )
    else:
        result = _exec(
            conn,
            (
                f"SELECT {_GRANT_SELECT} FROM {q(STATE_SCHEMA)}.{q('GRANTS')}"  # nosec B608
                " ORDER BY CREATED_AT, ID"
            ),
        )
    return [_row_dict(r) for r in _fetchall(result, conn)]


def _claim(
    conn: Any,
    grant_id: str,
    *,
    from_status: str,
    to_status: str,
    extra_sql: str = "",
    extra_params: tuple[Any, ...] = (),
) -> bool:
    result = _exec(
        conn,
        (
            f"UPDATE {q(STATE_SCHEMA)}.{q('GRANTS')} SET STATUS = ?"  # nosec B608
            f" WHERE ID = ? AND STATUS = ?{extra_sql}"
        ),
        (to_status, grant_id, from_status, *extra_params),
    )
    return _rowcount(result, conn) == 1


def _set_status(
    conn: Any,
    grant_id: str,
    status: str,
    *,
    last_error: str | None = None,
) -> None:
    _run(
        conn,
        Bound(
            (
                f"UPDATE {q(STATE_SCHEMA)}.{q('GRANTS')}"  # nosec B608
                " SET STATUS = ?, LAST_ERROR = ? WHERE ID = ?"
            ),
            (status, last_error, grant_id),
        ),
    )


def drop_grant_objects(conn: Any, row: dict[str, Any]) -> int:
    """DISABLE IF EXISTS (aborts queries), then DROP VIEW / ROLE / USER IF EXISTS."""
    user, role, view = _names(row)
    schema, view_name = (view.split(".", 1) + [view])[:2] if "." in view else (VIEW_SCHEMA, view)
    _exec(conn, f"ALTER USER IF EXISTS {q(user)} SET DISABLED = TRUE")
    _exec(conn, f"DROP VIEW IF EXISTS {q(schema)}.{q(view_name)}")
    _exec(conn, f"DROP ROLE IF EXISTS {q(role)}")
    _exec(conn, f"DROP USER IF EXISTS {q(user)}")
    return 0


def _write_receipt(
    receipts: ReceiptSink | None,
    facts: GrantFacts | None,
    event: receipt.Event,
    details: dict[str, Any],
) -> str | None:
    if receipts is None or facts is None:
        return None
    try:
        receipt.append(
            receipts.log,
            event,
            facts,
            receipts.key,
            host=receipts.host,
            details=details,
        )
    except ReceiptError as exc:
        return str(exc)
    except Exception as exc:  # noqa: BLE001
        return str(exc)
    return None


def _cleanup(
    conn: Any,
    row: dict[str, Any],
    reason: Reason,
    receipts: ReceiptSink | None,
) -> RevokeResult:
    gid = str(row["id"])
    facts = _facts(row)
    cancelled = 0
    try:
        cancelled = drop_grant_objects(conn, row)
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)[:500]
        _set_status(conn, gid, row["status"], last_error=msg)
        err = _write_receipt(
            receipts,
            facts,
            "revoke_failed",
            {"engine": "snowflake", "reason": reason, "error": msg},
        )
        return RevokeResult(
            gid,
            "failed",
            sessions_terminated=cancelled,
            error=msg,
            receipt_error=err,
            reason=reason,
        )
    final = (
        "expired" if reason == "expired" else ("failed" if reason == "stale_issuing" else "revoked")
    )
    event: receipt.Event = (
        "expired"
        if reason == "expired"
        else ("revoke_failed" if reason == "stale_issuing" else "revoked")
    )
    _set_status(conn, gid, final, last_error=None)
    err = _write_receipt(
        receipts,
        facts,
        event,
        {
            "engine": "snowflake",
            "reason": reason,
            "public_key_fingerprint": row.get("public_key_fingerprint"),
        },
    )
    return RevokeResult(
        gid, "revoked", sessions_terminated=cancelled, receipt_error=err, reason=reason
    )


def revoke(
    conn: Any,
    grant_id: str,
    reason: Reason = "manual",
    receipts: ReceiptSink | None = None,
) -> RevokeResult:
    """Revoke one grant. Idempotent. Safe when some objects were never created."""
    row = get_grant(conn, grant_id)
    if row is None:
        raise GrantError(f"unknown grant {grant_id}")
    status = str(row["status"])
    if status in {"revoked", "expired", "failed"}:
        return RevokeResult(grant_id, "noop", reason=reason)
    if status == "active":
        extra = " AND EXPIRES_AT <= CURRENT_TIMESTAMP()" if reason == "expired" else ""
        claimed = _claim(
            conn,
            grant_id,
            from_status="active",
            to_status="expiring" if reason == "expired" else "revoking",
            extra_sql=extra,
        )
        if not claimed:
            return RevokeResult(grant_id, "noop", reason=reason)
        row = get_grant(conn, grant_id) or {**row, "status": "revoking"}
        return _cleanup(conn, row, reason, receipts)
    if status in {"revoking", "expiring", "sweeping"}:
        retry_reason: Reason = (
            "expired"
            if status == "expiring"
            else ("stale_issuing" if status == "sweeping" else "manual")
        )
        return _cleanup(conn, row, retry_reason, receipts)
    if status in {"issuing", "enabling"}:
        claimed = _claim(
            conn,
            grant_id,
            from_status=status,
            to_status="sweeping",
        )
        if not claimed:
            return RevokeResult(grant_id, "noop", reason=reason)
        row = get_grant(conn, grant_id) or {**row, "status": "sweeping"}
        return _cleanup(conn, row, "stale_issuing" if reason != "manual" else "manual", receipts)
    return RevokeResult(grant_id, "noop", reason=reason)


def _list_ids(conn: Any, sql: str, params: tuple[Any, ...]) -> list[str]:
    result = _exec(conn, sql, params)
    return [str(r[0]) for r in _fetchall(result, conn)]


def sweep(conn: Any, receipts: ReceiptSink | None = None) -> list[RevokeResult]:
    """Expire due active grants and clean stale issuing/enabling rows. Atomic per row."""
    due = _list_ids(
        conn,
        (
            f"SELECT ID FROM {q(STATE_SCHEMA)}.{q('GRANTS')}"  # nosec B608
            " WHERE STATUS = ? AND EXPIRES_AT <= CURRENT_TIMESTAMP() ORDER BY EXPIRES_AT, ID"
        ),
        ("active",),
    )
    stale = _list_ids(
        conn,
        (
            f"SELECT ID FROM {q(STATE_SCHEMA)}.{q('GRANTS')}"  # nosec B608
            " WHERE STATUS IN (?, ?) AND STARTED_AT <= DATEADD(MINUTE, ?, CURRENT_TIMESTAMP())"
            " ORDER BY STARTED_AT, ID"
        ),
        ("issuing", "enabling", -ISSUING_GRACE_MINUTES),
    )
    inflight = _list_ids(
        conn,
        (
            f"SELECT ID FROM {q(STATE_SCHEMA)}.{q('GRANTS')}"  # nosec B608
            " WHERE STATUS IN (?, ?, ?) ORDER BY ID"
        ),
        ("revoking", "expiring", "sweeping"),
    )
    seen: set[str] = set()
    out: list[RevokeResult] = []
    for gid in due:
        if gid in seen:
            continue
        seen.add(gid)
        out.append(revoke(conn, gid, "expired", receipts))
    for gid in stale:
        if gid in seen:
            continue
        seen.add(gid)
        out.append(revoke(conn, gid, "stale_issuing", receipts))
    for gid in inflight:
        if gid in seen:
            continue
        seen.add(gid)
        out.append(revoke(conn, gid, "manual", receipts))
    return out


def due_grant_ids(conn: Any) -> list[str]:
    """Expired active grants plus issuing/enabling rows past the 10-minute grace."""
    due = _list_ids(
        conn,
        (
            f"SELECT ID FROM {q(STATE_SCHEMA)}.{q('GRANTS')}"  # nosec B608
            " WHERE STATUS = ? AND EXPIRES_AT <= CURRENT_TIMESTAMP() ORDER BY EXPIRES_AT, ID"
        ),
        ("active",),
    )
    stale = _list_ids(
        conn,
        (
            f"SELECT ID FROM {q(STATE_SCHEMA)}.{q('GRANTS')}"  # nosec B608
            " WHERE STATUS IN (?, ?) AND STARTED_AT <= DATEADD(MINUTE, ?, CURRENT_TIMESTAMP())"
            " ORDER BY STARTED_AT, ID"
        ),
        ("issuing", "enabling", -ISSUING_GRACE_MINUTES),
    )
    return due + [g for g in stale if g not in due]


def pending_expired_ids(conn: Any) -> list[str]:
    result = _exec(
        conn,
        (
            f"SELECT ID FROM {q(STATE_SCHEMA)}.{q('REQUESTS')}"  # nosec B608
            " WHERE STATUS = ? AND EXPIRES_AT <= CURRENT_TIMESTAMP() ORDER BY ID"
        ),
        ("pending",),
    )
    return [str(r[0]) for r in _fetchall(result, conn)]


def expire_stale_requests(conn: Any) -> list[dict[str, Any]]:
    """Mark expired pending requests. Does not drop Snowflake objects."""
    result = _exec(
        conn,
        (
            f"SELECT ID, REQUESTER, DATASET, TABLE_NAME, COLUMNS, ROW_FILTER,"  # nosec B608
            " DURATION_SECONDS, PURPOSE, POLICY_SHA256, CREATED_AT, EXPIRES_AT,"
            " REQUESTER_IDENTITY FROM"
            f" {q(STATE_SCHEMA)}.{q('REQUESTS')} WHERE STATUS = ?"
            " AND EXPIRES_AT <= CURRENT_TIMESTAMP() ORDER BY ID"
        ),
        ("pending",),
    )
    rows = _fetchall(result, conn)
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
        "created_at",
        "expires_at",
        "requester_identity",
    )
    expired: list[dict[str, Any]] = []
    for raw in rows:
        item = dict(zip(keys, raw, strict=False))
        claimed = _exec(
            conn,
            (
                f"UPDATE {q(STATE_SCHEMA)}.{q('REQUESTS')} SET STATUS = ?"  # nosec B608
                " WHERE ID = ? AND STATUS = ? AND EXPIRES_AT <= CURRENT_TIMESTAMP()"
            ),
            ("expired", item["id"], "pending"),
        )
        if _rowcount(claimed, conn) == 1:
            expired.append(item)
    return expired
