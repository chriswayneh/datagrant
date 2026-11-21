"""Evaluate a BigQuery approval before attempting any state or access change."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from datagrant.bq.grant import GrantError
from datagrant.bq.revoke import PendingRequest
from datagrant.oidc import VerifiedIdentity
from datagrant.policy import Decision, Policy, Request, evaluate


@dataclass(frozen=True)
class Vote:
    identity: VerifiedIdentity
    policy_sha256: str


@dataclass(frozen=True)
class Approval:
    request: Request
    decision: Decision
    votes: tuple[Vote, ...]
    required: int
    added: bool

    @property
    def is_final(self) -> bool:
        return len(self.votes) >= self.required


def evaluate_approval(
    policy: Policy,
    pending: PendingRequest,
    caller: VerifiedIdentity,
    previous: Sequence[Vote],
    *,
    now: datetime,
) -> Approval:
    """Recheck current policy and deduplicate authenticated approvers."""
    facts = pending.facts
    if now.utcoffset() is None or pending.expires_at.utcoffset() is None:
        raise GrantError("BigQuery approval timestamps must be timezone-aware")
    if now >= pending.expires_at:
        raise GrantError("BigQuery request has expired")
    if facts.approval != "two-person" or policy.approval != "two-person":
        raise GrantError("BigQuery approval requires two-person policy")
    dataset = policy.datasets.get(facts.dataset)
    rule = dataset.tables.get(facts.table) if dataset is not None else None
    if dataset is None or dataset.engine != "bigquery" or rule is None:
        raise GrantError("BigQuery request no longer names a BigQuery policy table")
    req = Request(
        facts.requester,
        facts.dataset,
        facts.table,
        tuple(facts.columns),
        facts.expires_at - facts.starts_at,
        facts.purpose,
        facts.row_filter,
    )
    meta = facts.identity or {}
    request_groups: frozenset[str] = frozenset()
    oidc = policy.identity.mode == "oidc"
    if oidc:
        if (
            meta.get("source") != "oidc"
            or meta.get("iss") != policy.identity.issuer
            or not isinstance(meta.get("sub"), str)
            or not meta["sub"]
            or meta.get("username_claim") != policy.identity.username_claim
        ):
            raise GrantError("BigQuery requester identity no longer matches policy")
        same_claim = meta.get("groups_claim") == policy.identity.groups_claim
        raw = meta.get("idp_groups", ()) if same_claim else ()
        groups = (
            {item for item in raw if isinstance(item, str)}
            if isinstance(raw, (list, tuple))
            else set()
        )
        if policy.identity.allowed_groups and not groups & policy.identity.allowed_groups:
            raise GrantError("BigQuery requester is outside the allowed identity groups")
        request_groups = frozenset(
            policy.identity.group_map[group]
            for group in groups
            if group in policy.identity.group_map
        )
    elif meta.get("source") not in {None, "os", "flag"}:
        raise GrantError("BigQuery requester identity no longer matches policy")
    decision = evaluate(policy, req, extra_groups=request_groups)
    if not decision.allowed:
        raise GrantError("BigQuery request no longer allowed by policy")

    def eligible(identity: VerifiedIdentity) -> bool:
        if not identity.username.strip():
            return False
        if oidc:
            if (
                identity.source != "oidc"
                or identity.iss != policy.identity.issuer
                or not identity.sub
                or identity.sub == meta.get("sub")
                or identity.username_claim != policy.identity.username_claim
            ):
                return False
        elif identity.source not in {"os", "flag"}:
            return False
        extra = identity.mapped_groups if oidc else frozenset()
        return not policy.can_approve(identity.username, req.requester, extra) and (
            not policy.sod_reasons(
                req.requester,
                identity.username,
                rule.allowed_groups,
                requester_extra=request_groups,
                approver_extra=extra,
            )
        )

    if not eligible(caller):
        raise GrantError("BigQuery caller is not eligible to approve this request")
    votes: list[Vote] = []
    names: set[str] = set()
    subjects: set[tuple[str | None, str | None]] = set()
    added = False
    for index, vote in enumerate((*previous, Vote(caller, policy.sha256))):
        identity = vote.identity
        name = identity.username.casefold()
        subject = (identity.iss, identity.sub)
        if vote.policy_sha256 != policy.sha256 or not eligible(identity):
            continue
        if name in names or (oidc and subject in subjects):
            continue
        votes.append(vote)
        names.add(name)
        subjects.add(subject)
        added = index == len(previous)
    return Approval(req, decision, tuple(votes), policy.approvals_required, added)
