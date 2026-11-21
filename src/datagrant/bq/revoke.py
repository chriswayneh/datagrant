"""BigQuery revoke/sweep orchestration; mocked store/client until M5 PR 5.

The store must atomically claim the exact row revision before cleanup, and
conditionally finalize/release that claim. No source dataset ACL is removed.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol

from datagrant import receipt
from datagrant.bq.grant import GrantClient, GrantError, GrantPlan, apply_unbind
from datagrant.pg.grant import ReceiptSink
from datagrant.receipt import GrantFacts

Reason = Literal["manual", "expired", "stale_issuing", "failed_cleanup"]
GRACE = timedelta(minutes=10)


@dataclass(frozen=True)
class GrantRecord:
    plan: GrantPlan
    status: str
    started_at: datetime
    revision: int = 0
    cleanup_reason: Reason | None = None
    claimed_at: datetime | None = None
    cleanup_complete: bool = False


@dataclass(frozen=True)
class PendingRequest:
    request_id: str
    expires_at: datetime
    facts: GrantFacts
    revision: int = 0


class PendingExpiryStore(Protocol):
    def list_due_requests(self, now: datetime) -> Sequence[PendingRequest]: ...

    def claim_expired_request(self, row: PendingRequest, now: datetime) -> int:
        """Claim a pending request only if its stored expiry matches and is due."""
        ...


class RevokeClient(GrantClient, PendingExpiryStore, Protocol):
    def get_grant(self, grant_id: str) -> GrantRecord | None: ...

    def list_grants(self) -> Sequence[GrantRecord]: ...

    def claim_revoke(self, row: GrantRecord, reason: Reason, now: datetime) -> int:
        """CAS row revision/status to revoking; increment revision, save reason/time.

        Return 1 only for the winner, 0 for a lost claim. The updated revision
        is row.revision + 1. Issuance claims cannot advance a revoking row.
        """
        ...

    def finish_revoke(self, grant_id: str, revision: int, status: str) -> int:
        """CAS the claimed revision to final status and cleanup_complete=True."""
        ...

    def release_revoke(self, grant_id: str, revision: int, error: str) -> None:
        """CAS failure details; clear claimed_at and advance revision for retry.

        Preserve revoking status and cleanup_reason. Never change a row owned
        by another revision. A crash instead leaves the claim for GRACE.
        """
        ...

    def cancel_jobs(self, plan: GrantPlan) -> int:
        """Best-effort cancellation for this principal in this grant project."""
        ...


@dataclass(frozen=True)
class RevokeResult:
    grant_id: str
    outcome: Literal["revoked", "noop", "failed"]
    reason: Reason
    jobs_cancelled: int = 0
    error: str | None = None
    receipt_error: str | None = None
    cancel_error: str | None = None


@dataclass(frozen=True)
class RequestExpiryResult:
    request_id: str
    receipt_error: str | None = None


def _now(now: datetime | None) -> datetime:
    value = now or datetime.now(UTC)
    if value.tzinfo is None or value.utcoffset() is None:
        raise GrantError("now must be timezone-aware")
    return value


def _write_receipt(
    sink: ReceiptSink | None,
    plan: GrantPlan,
    event: receipt.Event,
    reason: Reason,
    *,
    error: str | None = None,
) -> str | None:
    if sink is None or plan.facts is None:
        return "receipt sink or grant facts unavailable"
    details: dict[str, object] = {
        "engine": "bigquery",
        "principal": plan.principal,
        "reason": reason,
    }
    if error:
        details["error"] = error
    try:
        receipt.append(
            sink.log,
            event,
            plan.facts,
            sink.key,
            host=sink.host,
            details=details,
        )
    except Exception as exc:  # noqa: BLE001 - access removal must survive a receipt outage
        return str(exc)
    return None


def get_grant(client: RevokeClient, grant_id: str) -> GrantRecord | None:
    return client.get_grant(grant_id)


def list_grants(client: RevokeClient, *, active_only: bool = True) -> list[GrantRecord]:
    rows = client.list_grants()
    return sorted(
        (r for r in rows if not active_only or r.status == "active"),
        key=lambda r: (r.started_at, r.plan.grant_id),
    )


def revoke(
    client: RevokeClient,
    grant_id: str,
    reason: Reason = "manual",
    receipts: ReceiptSink | None = None,
    *,
    now: datetime | None = None,
) -> RevokeResult:
    current = _now(now)
    row = client.get_grant(grant_id)
    if row is None:
        raise GrantError(f"unknown grant {grant_id}")
    if row.plan.grant_id != grant_id:
        raise GrantError("grant store returned a mismatched grant id")
    if row.status in {"revoked", "expired"} or row.cleanup_complete:
        return RevokeResult(grant_id, "noop", reason)
    if row.status not in {"active", "issuing", "enabling", "failed", "revoking"}:
        raise GrantError(f"grant {grant_id}: unsupported status {row.status!r}")
    if row.claimed_at is not None and current - row.claimed_at < GRACE:
        return RevokeResult(grant_id, "noop", reason)
    if row.cleanup_reason is not None:
        reason = row.cleanup_reason
    elif (
        reason == "expired"
        and row.plan.expires_at > current
        or reason == "stale_issuing"
        and (row.status not in {"issuing", "enabling"} or current - row.started_at < GRACE)
        or reason == "failed_cleanup"
        and row.status != "failed"
    ):
        return RevokeResult(grant_id, "noop", reason)
    if client.claim_revoke(row, reason, current) != 1:
        return RevokeResult(grant_id, "noop", reason)
    plan = row.plan
    claimed_revision = row.revision + 1
    try:
        # A missing view is success; the adapter must implement idempotent DROP.
        # Unbind still runs if drop_view raises so leftover IAM is not stranded.
        parts: list[str] = []
        try:
            try:
                client.drop_view(plan)
            except Exception as exc:  # noqa: BLE001 - unbind still runs
                parts.append(f"drop_view failed ({exc})")
        finally:
            try:
                apply_unbind(client, plan)
            except Exception as exc:  # noqa: BLE001 - still report drop_view
                parts.append(f"unbind failed ({exc})")
        if parts:
            raise GrantError("; ".join(parts))
        cancelled = 0
        cancel_error = None
        try:
            cancelled = client.cancel_jobs(plan)
        except Exception as exc:  # noqa: BLE001 - cancellation cannot reopen a missing view
            cancel_error = str(exc)
        final = (
            "expired"
            if reason == "expired"
            else ("failed" if reason in {"stale_issuing", "failed_cleanup"} else "revoked")
        )
        if client.finish_revoke(grant_id, claimed_revision, final) != 1:
            raise GrantError(f"grant {grant_id}: lost revoke claim before final state")
    except Exception as exc:  # noqa: BLE001 - record and retry partial cleanup
        error = str(exc)
        try:
            client.release_revoke(grant_id, claimed_revision, error)
        except Exception as state_exc:  # noqa: BLE001 - report both failures
            error += f"; recording failure failed ({state_exc})"
        receipt_error = _write_receipt(receipts, plan, "revoke_failed", reason, error=error)
        return RevokeResult(grant_id, "failed", reason, error=error, receipt_error=receipt_error)
    event: receipt.Event = (
        "expired" if reason == "expired" else ("revoke_failed" if final == "failed" else "revoked")
    )
    receipt_error = _write_receipt(receipts, plan, event, reason)
    return RevokeResult(
        grant_id,
        "revoked",
        reason,
        cancelled,
        receipt_error=receipt_error,
        cancel_error=cancel_error,
    )


def sweep(
    client: RevokeClient, receipts: ReceiptSink | None = None, *, now: datetime | None = None
) -> list[RevokeResult]:
    current = _now(now)
    results = []
    for row in list_grants(client, active_only=False):
        if row.cleanup_complete or row.status in {"revoked", "expired"}:
            continue
        reason: Reason
        if row.status == "active" and row.plan.expires_at <= current:
            reason = "expired"
        elif row.status in {"issuing", "enabling"} and current - row.started_at >= GRACE:
            reason = "stale_issuing"
        elif row.status == "failed":
            reason = "failed_cleanup"
        elif row.status == "revoking":
            reason = row.cleanup_reason or "manual"
        else:
            continue
        # Re-read and CAS each record so a stale list cannot take another writer's claim.
        results.append(revoke(client, row.plan.grant_id, reason, receipts, now=current))
    return results


def expire_pending(
    client: PendingExpiryStore, receipts: ReceiptSink | None = None, *, now: datetime | None = None
) -> list[RequestExpiryResult]:
    """Expire pending requests without any view, IAM, or job operations."""
    current = _now(now)
    results = []
    for row in client.list_due_requests(current):
        if row.expires_at > current or client.claim_expired_request(row, current) != 1:
            continue
        error = None
        if receipts is None:
            error = "receipt sink unavailable"
        else:
            try:
                receipt.append(
                    receipts.log,
                    "request_expired",
                    row.facts,
                    receipts.key,
                    host=receipts.host,
                    details={"engine": "bigquery", "request_id": row.request_id},
                )
            except Exception as exc:  # noqa: BLE001 - expiry survives receipt outages
                error = str(exc)
        results.append(RequestExpiryResult(row.request_id, error))
    return results
