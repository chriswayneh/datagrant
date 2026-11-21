"""BigQuery grant state writes. All row values are query parameters."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from datagrant.bq.approval import Approval, Vote, evaluate_approval
from datagrant.bq.grant import (
    _GRANT_ID_RE,
    STATE_DATASET,
    GrantError,
    GrantPlan,
    _parse_principal,
    q_project,
)
from datagrant.bq.rest import TIMEOUT
from datagrant.bq.revoke import GRACE, GrantRecord, PendingRequest, Reason
from datagrant.oidc import VerifiedIdentity
from datagrant.policy import Policy
from datagrant.receipt import GrantFacts

_JOB_TIMEOUT = 60


class _Store:
    def __init__(self, client: Any, sdk: Any, project: str, location: str) -> None:
        q_project(project)
        self._client = client
        self._sdk = sdk
        self._project = project
        self._location = location

    def _query(self, sql: str, values: dict[str, tuple[str, Any]]) -> tuple[Any, Any]:
        try:
            config = self._sdk.QueryJobConfig(
                query_parameters=[
                    self._sdk.ScalarQueryParameter(name, kind, value)
                    for name, (kind, value) in values.items()
                ]
            )
            job = self._client.query(
                sql,
                job_config=config,
                project=self._project,
                location=self._location,
                timeout=TIMEOUT,
                job_retry=None,
            )
            rows = list(job.result(timeout=_JOB_TIMEOUT, job_retry=None))
        except Exception:  # noqa: BLE001 - provider errors may contain query parameters
            raise GrantError("BigQuery state query failed") from None
        return job, rows

    def _affected(self, sql: str, values: dict[str, tuple[str, Any]]) -> int:
        job, _ = self._query(sql, values)
        count = job.num_dml_affected_rows
        if type(count) is not int or count not in (0, 1):
            raise GrantError("BigQuery state write returned an unexpected row count")
        return count


class GrantStore(_Store):
    """Conditional writes to a preprovisioned grants table in the grant project."""

    def __init__(self, client: Any, sdk: Any, project: str, location: str) -> None:
        super().__init__(client, sdk, project, location)
        self._table = f"`{project}.{STATE_DATASET}.grants`"

    def _id(self, plan: GrantPlan) -> tuple[str, str]:
        if plan.project != self._project:
            raise GrantError("invalid BigQuery grant state target")
        return _grant_id(plan.grant_id)

    def insert_issuing(self, plan: GrantPlan) -> None:
        grant_id = self._id(plan)
        facts = None
        if plan.facts is not None:
            if plan.facts.grant_id != plan.grant_id:
                raise GrantError("BigQuery grant receipt id does not match the plan")
            facts = _encode_facts(plan.facts)
        sql = f"""
BEGIN TRANSACTION;
DELETE FROM {self._table} WHERE FALSE;
ASSERT NOT EXISTS (SELECT 1 FROM {self._table} WHERE grant_id = @grant_id)
  AS 'grant id already reserved';
INSERT INTO {self._table}
  (grant_id, status, started_at, revision, cleanup_complete, principal, expires_at,
   source_dataset, source_table, view_id, location, facts_json, request_id)
VALUES
  (@grant_id, 'issuing', CURRENT_TIMESTAMP(), 0, FALSE, @principal, @expires_at,
   @source_dataset, @source_table, @view_id, @location, @facts_json, @request_id);
COMMIT TRANSACTION;
"""  # nosec B608
        self._query(
            sql,
            {
                "grant_id": grant_id,
                "principal": ("STRING", plan.principal),
                "expires_at": ("TIMESTAMP", plan.expires_at),
                "source_dataset": ("STRING", plan.source_dataset),
                "source_table": ("STRING", plan.source_table),
                "view_id": ("STRING", plan.view_id),
                "location": ("STRING", plan.location),
                "facts_json": ("STRING", facts),
                "request_id": _grant_id(plan.request_id) if plan.request_id else ("STRING", None),
            },
        )

    def _update(self, assignments: str, predicate: str, **values: tuple[str, Any]) -> int:
        sql = f"""
UPDATE {self._table}
SET revision = revision + 1, {assignments}
WHERE grant_id = @grant_id AND {predicate}
"""  # nosec B608
        return self._affected(sql, values)

    def update_names(self, plan: GrantPlan) -> int:
        return self._update(
            "view_id = @view_id",
            "status = 'issuing'",
            grant_id=self._id(plan),
            view_id=("STRING", plan.view_id),
        )

    def _advance(self, plan: GrantPlan, current: str, target: str) -> int:
        return self._update(
            "status = @target",
            "status = @current AND expires_at > CURRENT_TIMESTAMP()",
            grant_id=self._id(plan),
            current=("STRING", current),
            target=("STRING", target),
        )

    def claim_enabling(self, plan: GrantPlan) -> int:
        return self._advance(plan, "issuing", "enabling")

    def claim_active(self, plan: GrantPlan) -> int:
        return self._advance(plan, "enabling", "active")

    def mark_failed(self, plan: GrantPlan) -> None:
        self._update(
            "status = 'failed'",
            "status IN ('issuing', 'enabling')",
            grant_id=self._id(plan),
        )

    def count_live_grants(self, requester: str, principal: str | None = None) -> int:
        """Count issuing/enabling/active rows for this requester.

        Optional ``principal`` further restricts the count. Postgres and
        Snowflake stores are not included. The cap is per engine.
        """
        if not isinstance(requester, str) or not requester.strip():
            raise GrantError("requester is required")
        values: dict[str, tuple[str, Any]] = {"requester": ("STRING", requester)}
        extra = ""
        if principal is not None:
            extra = " AND principal = @principal"
            values["principal"] = ("STRING", _parse_principal(principal))
        _, rows = self._query(
            f"SELECT COUNT(*) AS n FROM {self._table} "  # nosec B608
            "WHERE JSON_VALUE(facts_json, '$.requester') = @requester "
            "AND status IN ('issuing', 'enabling', 'active') "
            "AND expires_at > CURRENT_TIMESTAMP()"
            f"{extra}",
            values,
        )
        if len(rows) != 1:
            raise GrantError("BigQuery concurrent-grant count failed")
        n = rows[0]["n"]
        if type(n) is not int or n < 0:
            raise GrantError("BigQuery concurrent-grant count failed")
        return n

    def claim_revoke(self, row: GrantRecord, reason: Reason, now: datetime) -> int:
        if row.status not in {"issuing", "enabling", "active", "failed", "revoking"}:
            return 0
        return self._update(
            "status = 'revoking', cleanup_reason = @reason, claimed_at = @now",
            """status = @status AND revision = @revision AND NOT cleanup_complete
               AND (claimed_at IS NULL OR claimed_at <= @stale_before)""",
            grant_id=self._id(row.plan),
            status=("STRING", row.status),
            revision=("INT64", row.revision),
            reason=("STRING", reason),
            now=("TIMESTAMP", now),
            stale_before=("TIMESTAMP", now - GRACE),
        )

    def _complete(
        self, grant_id: str, revision: int, assignments: str, **values: tuple[str, Any]
    ) -> int:
        return self._update(
            assignments,
            "status = 'revoking' AND revision = @revision AND claimed_at IS NOT NULL",
            grant_id=_grant_id(grant_id),
            revision=("INT64", revision),
            **values,
        )

    def finish_revoke(self, grant_id: str, revision: int, status: str) -> int:
        if status not in {"revoked", "expired", "failed"}:
            raise GrantError("invalid BigQuery cleanup status")
        return self._complete(
            grant_id,
            revision,
            "status = @status, cleanup_complete = TRUE, claimed_at = NULL",
            status=("STRING", status),
        )

    def release_revoke(self, grant_id: str, revision: int, error: str) -> None:
        self._complete(grant_id, revision, "claimed_at = NULL")

    def _read(self, sql: str, **values: tuple[str, Any]) -> list[GrantRecord]:
        _, rows = self._query(sql, values)
        try:
            return [self._decode(row) for row in rows]
        except (KeyError, TypeError, ValueError):
            raise GrantError("BigQuery returned an invalid grant record") from None

    def _decode(self, row: Any) -> GrantRecord:
        facts = None
        if row["facts_json"] is not None:
            facts = _decode_facts(row["facts_json"])
            if facts.grant_id != row["grant_id"]:
                raise ValueError("mismatched grant facts")
        return GrantRecord(
            plan=GrantPlan(
                grant_id=_grant_id(row["grant_id"])[1],
                view_id=row["view_id"],
                view_sql="",
                project=self._project,
                source_dataset=row["source_dataset"],
                source_table=row["source_table"],
                principal=row["principal"],
                expires_at=row["expires_at"],
                location=row["location"],
                facts=facts,
                request_id=row["request_id"],
            ),
            status=row["status"],
            started_at=row["started_at"],
            revision=row["revision"],
            cleanup_reason=row["cleanup_reason"],
            claimed_at=row["claimed_at"],
            cleanup_complete=row["cleanup_complete"],
        )

    def get_grant(self, grant_id: str) -> GrantRecord | None:
        rows = self._read(
            f"SELECT * FROM {self._table} WHERE grant_id = @grant_id LIMIT 2",  # nosec B608
            grant_id=_grant_id(grant_id),
        )
        if len(rows) > 1:
            raise GrantError("BigQuery grant state contains duplicate ids")
        return rows[0] if rows else None

    def list_grants(self) -> list[GrantRecord]:
        return self._read(f"SELECT * FROM {self._table}")  # nosec B608


def _grant_id(grant_id: str) -> tuple[str, str]:
    if not isinstance(grant_id, str) or not _GRANT_ID_RE.fullmatch(grant_id):
        raise GrantError("invalid BigQuery grant state id")
    return ("STRING", grant_id)


def _encode_facts(facts: GrantFacts) -> str:
    payload = asdict(facts)
    payload["starts_at"] = facts.starts_at.isoformat()
    payload["expires_at"] = facts.expires_at.isoformat()
    return json.dumps(payload, allow_nan=False)


def _decode_facts(raw: str) -> GrantFacts:
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise TypeError("invalid receipt facts")
    for key in ("starts_at", "expires_at"):
        payload[key] = datetime.fromisoformat(payload[key])
    return GrantFacts(**payload)


@dataclass(frozen=True)
class RequestSnapshot:
    pending: PendingRequest
    principal: str
    votes: tuple[Vote, ...]


@dataclass(frozen=True)
class ApprovalRef:
    request_id: str
    revision: int
    grant_id: str


@dataclass(frozen=True)
class ApprovalClaim(ApprovalRef):
    snapshot: RequestSnapshot
    approval: Approval


class RequestStore(_Store):
    """Persist pending requests; the caller verifies policy, identity, and quorum."""

    def __init__(self, client: Any, sdk: Any, project: str, location: str) -> None:
        super().__init__(client, sdk, project, location)
        self._table = f"`{project}.{STATE_DATASET}.requests`"

    def insert_pending(self, row: PendingRequest, principal: str) -> None:
        if row.facts.approval != "two-person" or row.facts.approvers:
            raise GrantError("BigQuery pending requests require unapproved two-person facts")
        if row.expires_at.utcoffset() is None:
            raise GrantError("BigQuery pending request expiry must be timezone-aware")
        sql = f"""
BEGIN TRANSACTION;
DELETE FROM {self._table} WHERE FALSE;
ASSERT NOT EXISTS (SELECT 1 FROM {self._table} WHERE request_id = @request_id)
  AS 'request id already reserved';
INSERT INTO {self._table}
  (request_id, principal, expires_at, facts_json, status, revision, votes_json)
VALUES (@request_id, @principal, @expires_at, @facts_json, 'pending', 0, '[]');
COMMIT TRANSACTION;
"""  # nosec B608
        self._query(
            sql,
            {
                "request_id": _grant_id(row.request_id),
                "principal": ("STRING", _parse_principal(principal)),
                "expires_at": ("TIMESTAMP", row.expires_at),
                "facts_json": ("STRING", _encode_facts(row.facts)),
            },
        )

    def _read_requests(self, sql: str, **values: tuple[str, Any]) -> list[RequestSnapshot]:
        _, rows = self._query(sql, values)
        try:
            return [
                RequestSnapshot(
                    PendingRequest(
                        _grant_id(row["request_id"])[1],
                        row["expires_at"],
                        _decode_facts(row["facts_json"]),
                        row["revision"],
                    ),
                    _parse_principal(row["principal"]),
                    _decode_votes(row["votes_json"]),
                )
                for row in rows
            ]
        except (KeyError, TypeError, ValueError):
            raise GrantError("BigQuery returned an invalid pending request") from None

    def get_pending(self, request_id: str) -> RequestSnapshot | None:
        rows = self._read_requests(
            f"SELECT * FROM {self._table} WHERE request_id = @request_id "
            "AND status = 'pending' AND expires_at > CURRENT_TIMESTAMP() LIMIT 2",  # nosec B608
            request_id=_grant_id(request_id),
        )
        if len(rows) > 1:
            raise GrantError("BigQuery request state contains duplicate ids")
        if rows and rows[0].pending.request_id != request_id:
            raise GrantError("BigQuery request store returned a mismatched id")
        return rows[0] if rows else None

    def list_due_requests(self, now: datetime) -> list[PendingRequest]:
        rows = self._read_requests(
            f"SELECT * FROM {self._table} WHERE status = 'pending' "  # nosec B608
            "AND expires_at <= @now AND expires_at <= CURRENT_TIMESTAMP()",
            now=("TIMESTAMP", now),
        )
        return [snapshot.pending for snapshot in rows]

    def record_vote(
        self,
        request_id: str,
        policy: Policy,
        caller: VerifiedIdentity,
        *,
        now: datetime,
        grant_id: str,
    ) -> ApprovalClaim | None:
        """Save a vote or claim final approval from the exact evaluated revision."""
        grant_param = _grant_id(grant_id)
        snapshot = self.get_pending(request_id)
        if snapshot is None:
            raise GrantError("BigQuery request is no longer pending")
        row = snapshot.pending
        approval = evaluate_approval(policy, row, caller, snapshot.votes, now=now)
        if not approval.added and not approval.is_final:
            return None
        sql = f"""
UPDATE {self._table}
SET votes_json = @votes, status = @status, grant_id = @grant_id, revision = revision + 1
WHERE request_id = @request_id AND status = 'pending' AND revision = @revision
  AND expires_at = @expires_at AND expires_at > CURRENT_TIMESTAMP()
  AND principal = @principal
"""  # nosec B608
        count = self._affected(
            sql,
            {
                "request_id": _grant_id(request_id),
                "expires_at": ("TIMESTAMP", row.expires_at),
                "revision": ("INT64", row.revision),
                "principal": ("STRING", snapshot.principal),
                "votes": ("STRING", _encode_votes(approval.votes)),
                "status": ("STRING", "approving" if approval.is_final else "pending"),
                "grant_id": grant_param if approval.is_final else ("STRING", None),
            },
        )
        if count != 1:
            raise GrantError("BigQuery pending request changed; reload before approving")
        if approval.is_final:
            return ApprovalClaim(request_id, row.revision + 1, grant_id, snapshot, approval)
        return None

    def claim_expired_request(self, row: PendingRequest, now: datetime) -> int:
        sql = f"""
UPDATE {self._table}
SET status = 'expired', revision = revision + 1
WHERE request_id = @request_id AND status = 'pending' AND revision = @revision
  AND expires_at = @expires_at AND expires_at <= @now AND expires_at <= CURRENT_TIMESTAMP()
"""  # nosec B608
        return self._affected(
            sql,
            {
                "request_id": _grant_id(row.request_id),
                "expires_at": ("TIMESTAMP", row.expires_at),
                "now": ("TIMESTAMP", now),
                "revision": ("INT64", row.revision),
            },
        )

    def get_approving(self, request_id: str) -> ApprovalRef | None:
        _, rows = self._query(
            f"SELECT request_id, revision, grant_id FROM {self._table} "  # nosec B608
            "WHERE request_id = @request_id AND status = 'approving' LIMIT 2",
            {"request_id": _grant_id(request_id)},
        )
        matches = list(rows)
        if not matches:
            return None
        row = matches[0]
        if len(matches) != 1 or row["request_id"] != request_id:
            raise GrantError("BigQuery approval recovery returned inconsistent state")
        return ApprovalRef(request_id, row["revision"], _grant_id(row["grant_id"])[1])

    def _finish(self, claim: ApprovalRef, status: str) -> int:
        sql = f"""
UPDATE {self._table}
SET status = @status, revision = revision + 1
WHERE request_id = @request_id AND status = 'approving' AND revision = @revision
  AND grant_id = @grant_id
"""  # nosec B608
        return self._affected(
            sql,
            {
                "request_id": _grant_id(claim.request_id),
                "grant_id": _grant_id(claim.grant_id),
                "revision": ("INT64", claim.revision),
                "status": ("STRING", status),
            },
        )

    def finish_approval(self, claim: ApprovalRef) -> int:
        return self._finish(claim, "approved")

    def mark_request_failed(self, claim: ApprovalRef) -> int:
        return self._finish(claim, "failed")


def _encode_votes(votes: tuple[Vote, ...]) -> str:
    payload = []
    for vote in votes:
        identity = asdict(vote.identity)
        identity["mapped_groups"] = sorted(vote.identity.mapped_groups)
        payload.append({"identity": identity, "policy_sha256": vote.policy_sha256})
    return json.dumps(payload, allow_nan=False)


def _decode_votes(raw: str) -> tuple[Vote, ...]:
    payload = json.loads(raw)
    if not isinstance(payload, list) or len(payload) > 8:
        raise ValueError("invalid approval votes")
    votes = []
    for item in payload:
        identity = dict(item["identity"])
        identity["mapped_groups"] = frozenset(identity["mapped_groups"])
        identity["idp_groups"] = tuple(identity["idp_groups"])
        votes.append(Vote(VerifiedIdentity(**identity), item["policy_sha256"]))
    return tuple(votes)
