"""Mocked BigQuery revoke, conditional ownership, and sweep regressions."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from test_bq_grant import GID, NOW, FakeClient, _events, _plan, _sink

from datagrant.bq.grant import GrantError, apply_bind
from datagrant.bq.revoke import (
    GRACE,
    GrantRecord,
    PendingRequest,
    expire_pending,
    get_grant,
    list_grants,
    revoke,
    sweep,
)


class Store(FakeClient):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.rows: dict[str, GrantRecord] = {}
        self.lose_claim = False
        self.lose_finish = False
        self.cancel_fails = False
        self.state_fails = False
        self.listed: list[GrantRecord] | None = None

    def add(self, status: str = "active", *, age: timedelta = GRACE, **kw: Any) -> GrantRecord:
        plan = _plan(**kw)
        row = GrantRecord(plan, status, NOW - age)
        self.rows[plan.grant_id] = row
        self.status[plan.grant_id] = status
        self.views.add(plan.view_id)
        apply_bind(self, plan)
        self.calls.clear()
        return row

    def get_grant(self, grant_id: str) -> GrantRecord | None:
        return self.rows.get(grant_id)

    def list_grants(self) -> list[GrantRecord]:
        return self.listed if self.listed is not None else list(self.rows.values())

    def claim_revoke(self, row: GrantRecord, reason: Any, now: Any) -> int:
        self.calls.append("claim")
        current = self.rows[row.plan.grant_id]
        if self.lose_claim or current.revision != row.revision or current.status != row.status:
            return 0
        self.rows[row.plan.grant_id] = replace(
            current,
            status="revoking",
            revision=row.revision + 1,
            cleanup_reason=reason,
            claimed_at=now,
        )
        self.status[row.plan.grant_id] = "revoking"
        return 1

    def finish_revoke(self, grant_id: str, revision: int, status: str) -> int:
        self.calls.append("finish")
        current = self.rows[grant_id]
        if self.lose_finish or current.revision != revision or current.status != "revoking":
            return 0
        self.rows[grant_id] = replace(
            current, status=status, cleanup_complete=True, claimed_at=None, revision=revision + 1
        )
        self.status[grant_id] = status
        return 1

    def release_revoke(self, grant_id: str, revision: int, error: str) -> None:
        self.calls.append("release")
        if self.state_fails:
            raise RuntimeError("store outage")
        row = self.rows[grant_id]
        if row.revision == revision and row.status == "revoking":
            self.rows[grant_id] = replace(row, claimed_at=None, revision=revision + 1)

    def cancel_jobs(self, plan: Any) -> int:
        self.calls.append("cancel")
        if self.cancel_fails:
            raise RuntimeError("jobs unavailable")
        return 2


def test_drop_before_unbind_cancel_finalize_and_receipt(tmp_path: Path) -> None:
    client = Store()
    row = client.add()
    result = revoke(client, GID, receipts=_sink(tmp_path), now=NOW)
    assert result.outcome == "revoked" and result.jobs_cancelled == 2
    assert result.receipt_error is None
    assert client.calls.index("drop_view") < client.calls.index("get_project_iam")
    assert client.calls.index("set_dataset_iam") < client.calls.index("cancel")
    assert client.calls.index("cancel") < client.calls.index("finish")
    assert row.plan.view_id not in client.views
    assert client.rows[GID].status == "revoked"
    assert _events(tmp_path / "r.jsonl") == ["revoked"]
    assert revoke(client, GID, now=NOW).outcome == "noop"


def test_one_principal_two_grants_preserves_other_bindings(tmp_path: Path) -> None:
    client = Store()
    first = client.add()
    # _plan fixes its id, so construct a second immutable plan with a distinct resource.
    other = replace(
        first.plan, grant_id="012345abcdef", view_id=first.plan.view_id.replace(GID, "012345abcdef")
    )
    client.rows[other.grant_id] = GrantRecord(other, "active", NOW)
    client.views.add(other.view_id)
    apply_bind(client, other)
    revoke(client, GID, receipts=_sink(tmp_path), now=NOW)
    for policy in (client.project_policy, client.dataset_policy):
        assert len(policy.bindings) == 1
        assert policy.bindings[0]["condition"]["title"] == "G_" + other.grant_id
    assert other.view_id in client.views


def test_failed_drop_has_failure_receipt_and_can_retry(tmp_path: Path) -> None:
    client = Store(fail_drop=True)
    row = client.add()
    sink = _sink(tmp_path)
    result = revoke(client, GID, receipts=sink, now=NOW)
    assert result.outcome == "failed"
    assert row.plan.view_id in client.views
    assert not client.rows[GID].cleanup_complete
    client.fail_drop = False
    assert sweep(client, sink, now=NOW)[0].outcome == "revoked"
    assert _events(tmp_path / "r.jsonl") == ["revoke_failed", "revoked"]


def test_drop_view_failure_still_unbinds_and_releases_claim(tmp_path: Path) -> None:
    client = Store(fail_drop=True)
    client.add()
    sink = _sink(tmp_path)
    result = revoke(client, GID, receipts=sink, now=NOW)
    assert result.outcome == "failed"
    assert result.error and "drop_view failed" in result.error
    assert "unbind_iam" in client.calls or "get_project_iam" in client.calls
    assert not client.project_policy.bindings
    assert not client.dataset_policy.bindings
    assert client.rows[GID].claimed_at is None
    assert not client.rows[GID].cleanup_complete
    failed = [
        json.loads(line)["receipt"]
        for line in sink.log.read_text().splitlines()
        if json.loads(line)["receipt"]["event"] == "revoke_failed"
    ]
    assert failed and "drop_view" in str(failed[0]["details"].get("error"))


def test_unbind_failure_still_attempts_both_policies_then_retries() -> None:
    client = Store()
    row = client.add()
    client.fail_on = "set_project_iam"
    result = revoke(client, GID, now=NOW)
    assert result.outcome == "failed" and row.plan.view_id not in client.views
    assert "set_dataset_iam" in client.calls
    client.fail_on = None
    assert sweep(client, now=NOW)[0].outcome == "revoked"


def test_cancel_failure_is_best_effort_and_missing_receipt_does_not_reopen_access() -> None:
    client = Store()
    row = client.add()
    client.cancel_fails = True
    result = revoke(client, GID, now=NOW)
    assert result.outcome == "revoked" and result.cancel_error == "jobs unavailable"
    assert result.receipt_error
    assert row.plan.view_id not in client.views
    assert client.rows[GID].cleanup_complete


def test_lost_claim_no_side_effects_and_inflight_claim_lease() -> None:
    client = Store()
    row = client.add()
    client.lose_claim = True
    assert revoke(client, GID, now=NOW).outcome == "noop"
    assert client.calls == ["claim"]
    client.lose_claim = False
    assert client.claim_revoke(row, "expired", NOW) == 1
    client.calls.clear()
    assert revoke(client, GID, now=NOW).outcome == "noop"
    assert client.calls == []
    assert revoke(client, GID, now=NOW + GRACE).outcome == "revoked"
    assert client.rows[GID].status == "expired"


@pytest.mark.parametrize("status", ["issuing", "enabling"])
def test_sweep_grace_and_failed_terminal_idempotence(status: str, tmp_path: Path) -> None:
    client = Store()
    client.add(status, age=GRACE - timedelta(seconds=1))
    sink = _sink(tmp_path)
    assert sweep(client, sink, now=NOW) == []
    assert sweep(client, sink, now=NOW + timedelta(seconds=1))[0].outcome == "revoked"
    assert client.rows[GID].status == "failed" and client.rows[GID].cleanup_complete
    assert sweep(client, sink, now=NOW + GRACE) == []
    assert _events(tmp_path / "r.jsonl") == ["revoke_failed"]


def test_sweep_expiry_and_failed_leftover_iam() -> None:
    client = Store()
    client.add()
    assert sweep(client, now=NOW) == []
    assert revoke(client, GID, "expired", now=NOW).outcome == "noop"
    assert sweep(client, now=NOW + timedelta(hours=2))[0].reason == "expired"
    assert client.rows[GID].status == "expired"
    client = Store()
    client.add("failed")
    assert sweep(client, now=NOW)[0].reason == "failed_cleanup"
    assert not client.project_policy.bindings and not client.dataset_policy.bindings


def test_stale_list_cannot_cleanup_newly_active_or_young_issuance() -> None:
    client = Store()
    old = client.add("issuing")
    client.listed = [old]
    client.rows[GID] = replace(old, status="active", revision=1)
    assert sweep(client, now=NOW)[0].outcome == "noop"
    client.rows[GID] = replace(old, started_at=NOW, revision=1)
    assert sweep(client, now=NOW)[0].outcome == "noop"


def test_finish_failure_and_failure_recording_outage() -> None:
    client = Store()
    client.add()
    client.lose_finish = client.state_fails = True
    result = revoke(client, GID, now=NOW)
    assert result.outcome == "failed"
    assert "lost revoke claim" in str(result.error)
    assert "store outage" in str(result.error)


def test_issue_cannot_reactivate_a_claimed_grant(tmp_path: Path) -> None:
    client = Store()
    row = client.add("enabling")
    assert client.claim_revoke(row, "manual", NOW) == 1
    assert client.claim_active(row.plan) == 0


def test_list_status_and_invalid_inputs() -> None:
    client = Store()
    row = client.add()
    assert get_grant(client, GID) == row
    assert list_grants(client) == [row]
    with pytest.raises(GrantError, match="unknown grant"):
        revoke(client, "missing", now=NOW)
    with pytest.raises(GrantError, match="timezone-aware"):
        revoke(client, GID, now=NOW.replace(tzinfo=None))
    client.rows[GID] = replace(row, status="pending")
    assert list_grants(client) == []
    assert sweep(client, now=NOW) == []
    with pytest.raises(GrantError, match="unsupported status"):
        revoke(client, GID, now=NOW)


def test_receipt_failure_after_removal_keeps_final_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = Store()
    row = client.add()
    sink = _sink(tmp_path)

    def broken(*args: Any, **kwargs: Any) -> None:
        raise OSError("receipt disk unavailable")

    monkeypatch.setattr("datagrant.bq.revoke.receipt.append", broken)
    result = revoke(client, GID, receipts=sink, now=NOW)
    assert result.outcome == "revoked" and result.receipt_error == "receipt disk unavailable"
    assert client.rows[GID].cleanup_complete and row.plan.view_id not in client.views


def test_old_revision_cannot_finish_or_release_a_new_claim() -> None:
    client = Store()
    row = client.add()
    assert client.claim_revoke(row, "manual", NOW) == 1
    claimed = client.rows[GID]
    assert client.claim_revoke(claimed, "manual", NOW + GRACE) == 1
    newer = client.rows[GID]
    assert client.finish_revoke(GID, claimed.revision, "revoked") == 0
    client.release_revoke(GID, claimed.revision, "stale failure")
    assert client.rows[GID] == newer


def test_pending_expiry_never_calls_ddl_or_iam(tmp_path: Path) -> None:
    class PendingStore(Store):
        def __init__(self) -> None:
            super().__init__()
            facts = _plan().facts
            assert facts is not None
            self.requests = [
                PendingRequest("due", NOW, facts),
                PendingRequest("future", NOW + timedelta(seconds=1), facts),
                PendingRequest("approved", NOW, facts),
            ]
            self.expired: set[str] = set()

        def list_due_requests(self, now: Any) -> list[PendingRequest]:
            return self.requests

        def claim_expired_request(self, row: PendingRequest, now: Any) -> int:
            if row.request_id == "approved" or row.request_id in self.expired:
                return 0
            self.expired.add(row.request_id)
            return 1

    client = PendingStore()
    sink = _sink(tmp_path)
    results = expire_pending(client, sink, now=NOW)
    assert [r.request_id for r in results] == ["due"]
    assert results[0].receipt_error is None
    assert client.calls == []
    assert _events(tmp_path / "r.jsonl") == ["request_expired"]
    assert expire_pending(client, sink, now=NOW) == []


def test_pending_expiry_survives_receipt_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Store()
    facts = _plan().facts
    assert facts is not None
    monkeypatch.setattr(
        Store, "list_due_requests", lambda *_: [PendingRequest("due", NOW, facts)], raising=False
    )
    monkeypatch.setattr(Store, "claim_expired_request", lambda *_: 1, raising=False)
    assert expire_pending(client, now=NOW)[0].receipt_error == "receipt sink unavailable"
    assert client.calls == []


def test_interrupted_cleanup_retains_lease_then_recovers(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Store()
    row = client.add()

    def interrupted(*args: Any) -> None:
        raise KeyboardInterrupt

    with monkeypatch.context() as patch:
        patch.setattr(client, "drop_view", interrupted)
        with pytest.raises(KeyboardInterrupt):
            revoke(client, GID, now=NOW)
    assert client.rows[GID].claimed_at == NOW
    assert row.plan.view_id in client.views
    assert revoke(client, GID, now=NOW).outcome == "noop"
    assert sweep(client, now=NOW + GRACE)[0].outcome == "revoked"


def test_store_mismatched_id_never_touches_cloud(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Store()
    row = client.add()
    monkeypatch.setattr(
        client, "get_grant", lambda _: replace(row, plan=replace(row.plan, grant_id="012345abcdef"))
    )
    with pytest.raises(GrantError, match="mismatched grant id"):
        revoke(client, GID, now=NOW)
    assert client.calls == []


def test_claim_loser_cannot_finish_and_does_not_write_a_receipt(tmp_path: Path) -> None:
    client = Store()
    row = client.add()
    assert client.claim_revoke(row, "manual", NOW) == 1
    assert client.claim_revoke(row, "manual", NOW) == 0
    assert client.finish_revoke(GID, row.revision, "revoked") == 0
    sink = _sink(tmp_path)
    assert revoke(client, GID, receipts=sink, now=NOW).outcome == "noop"
    assert not sink.log.exists()


def test_sweep_skips_null_expires_at_and_revokes_valid() -> None:
    client = Store()
    valid = client.add()
    other_id = "012345abcdef"
    other = replace(
        valid.plan,
        grant_id=other_id,
        view_id=valid.plan.view_id.replace(GID, other_id),
        expires_at=None,
    )
    client.rows[other_id] = GrantRecord(other, "active", NOW)
    client.status[other_id] = "active"
    results = sweep(client, now=NOW + timedelta(hours=2))
    by_id = {item.grant_id: item for item in results}
    assert by_id[GID].outcome == "revoked"
    assert client.rows[GID].status == "expired"
    assert valid.plan.view_id not in client.views
    assert by_id[other_id].outcome == "failed"
    assert by_id[other_id].error == "invalid grant record"
    assert client.rows[other_id].status == "active"
