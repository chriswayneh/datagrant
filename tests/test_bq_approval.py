"""Approval eligibility and quorum before live BigQuery activation."""

from dataclasses import replace
from datetime import timedelta

import pytest
from test_bq_grant import GID, NOW, PRINCIPAL, PROJECT, dec, req

from datagrant.bq.approval import Vote, evaluate_approval
from datagrant.bq.grant import GrantError, build_plan
from datagrant.bq.revoke import PendingRequest
from datagrant.oidc import IdentityConfig, VerifiedIdentity
from datagrant.policy import Dataset, Policy, TableRule

ISSUER = "https://identity.example.com"
BOB = VerifiedIdentity("bob", "os")
CAROL = VerifiedIdentity("carol", "os")


@pytest.fixture(name="case")
def approval_case() -> tuple[Policy, PendingRequest]:
    request = req()
    duration = timedelta(hours=4)
    rule = TableRule(
        request.table, frozenset({"readers"}), {"patient_id": "passthrough", "ssn": "redact"},
        (), False, duration,
    )
    dataset = Dataset(request.dataset, PROJECT, {request.table: rule}, engine="bigquery")
    policy = Policy(
        1, "two-person", duration,
        {"readers": frozenset({"alice"}), "approvers": frozenset({"alice", "bob", "carol"})},
        {dataset.name: dataset}, "current", approver_groups=frozenset({"approvers"}),
        approvals_required=2,
    )
    plan = build_plan(
        dec(rule.columns), request, project=PROJECT, principal=PRINCIPAL, grant_id=GID, now=NOW,
    )
    assert plan.facts is not None
    pending = PendingRequest(GID, NOW + timedelta(minutes=20), replace(
        plan.facts, approval="two-person", identity={"source": "os"},
    ))
    return policy, pending


def test_only_distinct_current_votes_count(case: tuple[Policy, PendingRequest]) -> None:
    policy, pending = case
    first = evaluate_approval(policy, pending, BOB, (Vote(CAROL, "old"),), now=NOW)
    assert first.added and not first.is_final
    duplicate = evaluate_approval(policy, pending, BOB, first.votes, now=NOW)
    assert not duplicate.added and not duplicate.is_final
    final = evaluate_approval(policy, pending, CAROL, duplicate.votes, now=NOW)
    assert final.is_final
    assert [vote.identity.username for vote in final.votes] == ["bob", "carol"]


def test_rechecks_request_and_separation_of_duties(case: tuple[Policy, PendingRequest]) -> None:
    policy, pending = case
    with pytest.raises(GrantError, match="not eligible"):
        evaluate_approval(policy, pending, VerifiedIdentity("Alice", "os"), (), now=NOW)
    changed = replace(
        policy, separation_of_duties="distinct-groups",
        groups={**policy.groups, "readers": frozenset({"alice", "bob"})},
    )
    with pytest.raises(GrantError, match="not eligible"):
        evaluate_approval(changed, pending, BOB, (), now=NOW)
    with pytest.raises(GrantError, match="no longer allowed"):
        evaluate_approval(replace(policy, groups={}), pending, BOB, (), now=NOW)
    with pytest.raises(GrantError, match="has expired"):
        evaluate_approval(policy, pending, BOB, (), now=pending.expires_at)


def test_oidc_aliases_cannot_add_another_vote_or_self_approve(
    case: tuple[Policy, PendingRequest],
) -> None:
    policy, pending = case
    policy = replace(policy, identity=IdentityConfig(mode="oidc", issuer=ISSUER))
    pending = replace(pending, facts=replace(pending.facts, identity={
        "source": "oidc", "iss": ISSUER, "sub": "requester", "username_claim": "sub",
    }))
    bob = VerifiedIdentity("bob", "oidc", ISSUER, "approver", username_claim="sub")
    alias = VerifiedIdentity("carol", "oidc", ISSUER, "approver", username_claim="sub")
    result = evaluate_approval(policy, pending, alias, (Vote(bob, policy.sha256),), now=NOW)
    assert not result.added and not result.is_final
    with pytest.raises(GrantError, match="not eligible"):
        evaluate_approval(policy, pending, replace(alias, sub="requester"), (), now=NOW)
