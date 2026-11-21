"""Issue a claimed approval and reconcile its state without replaying issuance."""

from dataclasses import replace
from datetime import datetime
from typing import Literal, Protocol

from datagrant.bq.grant import GrantClient, GrantError, GrantPlan, apply_plan, build_plan
from datagrant.bq.revoke import GrantRecord
from datagrant.bq.state import ApprovalClaim, ApprovalRef
from datagrant.keys import HashKey
from datagrant.pg.grant import ReceiptSink
from datagrant.policy import Dataset


class _ApprovalState(Protocol):
    def finish_approval(self, claim: ApprovalRef) -> int: ...

    def mark_request_failed(self, claim: ApprovalRef) -> int: ...


class ApprovalClient(GrantClient, Protocol):
    @property
    def requests(self) -> _ApprovalState: ...

    def get_grant(self, grant_id: str) -> GrantRecord | None: ...


def issue_approved(
    client: ApprovalClient,
    claim: ApprovalClaim,
    *,
    project: str,
    dataset: Dataset,
    receipts: ReceiptSink,
    now: datetime,
    hash_key: HashKey | None = None,
    max_concurrent: int | None = None,
) -> GrantPlan:
    """Consume a freshly won claim. On ambiguity, leave it for reconciliation."""
    approval = claim.approval
    pending = claim.snapshot.pending
    if (
        not approval.is_final
        or claim.request_id != pending.request_id
        or dataset.name != approval.request.dataset
        or dataset.engine != "bigquery"
    ):
        raise GrantError("BigQuery approval claim does not match the request")
    if not claim.snapshot.principal:
        raise GrantError("BigQuery pending request is missing a google principal")
    plan = build_plan(
        approval.decision,
        approval.request,
        project=project,
        principal=claim.snapshot.principal,
        source_project=dataset.database,
        source_dataset=dataset.schema,
        location=dataset.location,
        grant_id=claim.grant_id,
        now=now,
        approvers=tuple(vote.identity.username for vote in approval.votes),
        requester_identity=pending.facts.identity,
        approver_identities=tuple(vote.identity.approver_receipt_dict() for vote in approval.votes),
        hash_key=hash_key,
    )
    plan = replace(plan, request_id=claim.request_id)
    apply_plan(client, plan, receipts, max_concurrent=max_concurrent)
    if client.requests.finish_approval(claim) != 1:
        raise GrantError("BigQuery grant issued but approval finalization needs reconciliation")
    return plan


def reconcile_approval(
    client: ApprovalClient, claim: ApprovalRef
) -> Literal["approved", "failed", "pending", "changed"]:
    """Settle an interrupted approval from linked grant state; never issue access."""
    row = client.get_grant(claim.grant_id)
    if row is None:
        return "pending"
    if row.plan.grant_id != claim.grant_id or row.plan.request_id != claim.request_id:
        raise GrantError("BigQuery approval recovery found an unrelated grant")
    if row.status == "active":
        return "approved" if client.requests.finish_approval(claim) == 1 else "changed"
    if row.status == "failed" and row.cleanup_complete:
        return "failed" if client.requests.mark_request_failed(claim) == 1 else "changed"
    return "pending"
