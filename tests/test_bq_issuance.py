"""Approved issuance never replays access changes during recovery."""

from dataclasses import replace
from pathlib import Path

import pytest
from test_bq_approval import BOB, CAROL, approval_case  # noqa: F401 - pytest fixture
from test_bq_grant import NOW, PRINCIPAL, PROJECT, FakeClient, _sink

from datagrant.bq.approval import Vote, evaluate_approval
from datagrant.bq.grant import GrantError, GrantPlan
from datagrant.bq.issuance import issue_approved, reconcile_approval
from datagrant.bq.revoke import GrantRecord, PendingRequest
from datagrant.bq.state import ApprovalClaim, ApprovalRef, RequestSnapshot
from datagrant.policy import Policy


class Requests:
    def __init__(self) -> None:
        self.result = 1
        self.calls: list[tuple[str, ApprovalRef]] = []

    def finish_approval(self, claim: ApprovalRef) -> int:
        self.calls.append(("approved", claim))
        return self.result

    def mark_request_failed(self, claim: ApprovalRef) -> int:
        self.calls.append(("failed", claim))
        return self.result


class Client(FakeClient):
    def __init__(self) -> None:
        super().__init__()
        self.requests = Requests()
        self.plan: GrantPlan | None = None
        self.row: GrantRecord | None = None

    def insert_issuing(self, plan: GrantPlan) -> None:
        self.plan = plan
        super().insert_issuing(plan)

    def get_grant(self, grant_id: str) -> GrantRecord | None:
        return self.row


def test_interrupted_finalization_reconciles_without_issuing_again(
    case: tuple[Policy, PendingRequest], tmp_path: Path
) -> None:
    policy, row = case
    snapshot = RequestSnapshot(row, PRINCIPAL, (Vote(BOB, policy.sha256),))
    approval = evaluate_approval(policy, row, CAROL, snapshot.votes, now=NOW)
    claim = ApprovalClaim(row.request_id, 2, "abcdef012346", snapshot, approval)
    ref = ApprovalRef(claim.request_id, claim.revision, claim.grant_id)
    client = Client()
    client.requests.result = 0
    with pytest.raises(GrantError, match="finalization needs reconciliation"):
        issue_approved(
            client,
            claim,
            project=PROJECT,
            dataset=policy.datasets[row.facts.dataset],
            receipts=_sink(tmp_path),
            now=NOW,
        )
    plan = client.plan
    assert plan is not None and plan.request_id == row.request_id and plan.principal == PRINCIPAL
    assert plan.facts is not None and plan.facts.approvers == ("bob", "carol")
    calls = list(client.calls)
    client.requests.result = 1
    assert reconcile_approval(client, ref) == "pending"
    client.row = GrantRecord(replace(plan, request_id=None), "active", NOW)
    with pytest.raises(GrantError, match="unrelated grant"):
        reconcile_approval(client, ref)
    client.row = GrantRecord(plan, "enabling", NOW)
    assert reconcile_approval(client, ref) == "pending"
    client.row = replace(client.row, status="active")
    assert reconcile_approval(client, ref) == "approved"
    assert client.requests.calls[-1] == ("approved", ref)
    assert client.calls == calls


def test_failed_grant_only_settles_after_cleanup(
    case: tuple[Policy, PendingRequest], tmp_path: Path
) -> None:
    policy, row = case
    snapshot = RequestSnapshot(row, PRINCIPAL, (Vote(BOB, policy.sha256),))
    approval = evaluate_approval(policy, row, CAROL, snapshot.votes, now=NOW)
    claim = ApprovalClaim(row.request_id, 2, "abcdef012346", snapshot, approval)
    client = Client()
    plan = issue_approved(
        client,
        claim,
        project=PROJECT,
        dataset=policy.datasets[row.facts.dataset],
        receipts=_sink(tmp_path),
        now=NOW,
    )
    client.row = GrantRecord(plan, "failed", NOW)
    assert reconcile_approval(client, claim) == "pending"
    client.row = replace(client.row, cleanup_complete=True)
    assert reconcile_approval(client, claim) == "failed"
