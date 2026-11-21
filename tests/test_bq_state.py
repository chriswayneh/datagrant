"""Grant store contract at the BigQuery SDK boundary."""

from dataclasses import replace
from typing import Any

import pytest
from test_bq_approval import BOB, CAROL, approval_case  # noqa: F401 - pytest fixture
from test_bq_grant import GID, KEY, NOW, PRINCIPAL, PROJECT, dec, req

from datagrant.bq.grant import GrantError, GrantPlan, build_plan
from datagrant.bq.revoke import GRACE, GrantRecord, PendingRequest, expire_pending
from datagrant.bq.state import GrantStore, RequestStore
from datagrant.policy import Policy


class SDK:
    @staticmethod
    def ScalarQueryParameter(name: str, kind: str, value: Any) -> tuple[str, Any]:
        return name, (kind, value)

    @staticmethod
    def QueryJobConfig(*, query_parameters: list) -> dict:
        return dict(query_parameters)


class Client:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.num_dml_affected_rows = 1
        self.rows: list[dict] = []

    def query(self, sql: str, **kwargs: Any) -> "Client":
        assert kwargs["project"] == PROJECT and kwargs["location"] == "US"
        assert kwargs["job_retry"] is None
        self.calls.append((sql, kwargs["job_config"]))
        return self

    def result(self, *, timeout: int, job_retry: None) -> list[dict]:
        assert timeout > 0
        return self.rows


@pytest.fixture
def plan() -> GrantPlan:
    return build_plan(
        dec(),
        req(),
        project=PROJECT,
        principal=PRINCIPAL,
        grant_id=GID,
        hash_key=KEY,
        now=NOW,
        location="US",
    )


def test_reservation_locks_before_check_and_round_trips_cleanup_facts(plan: GrantPlan) -> None:
    client = Client()
    store = GrantStore(client, SDK, PROJECT, "US")
    store.insert_issuing(plan)
    sql, params = client.calls[0]
    terms = ["BEGIN TRANSACTION", "WHERE FALSE", "ASSERT NOT EXISTS", "INSERT INTO", "COMMIT"]
    assert [sql.index(term) for term in terms] == sorted(sql.index(term) for term in terms)
    assert PRINCIPAL not in sql
    assert KEY.derived.hex() not in str(params)
    assert plan.view_sql not in str(params)
    row = {name: value for name, (_, value) in params.items()}
    row.update(
        status="issuing",
        started_at=NOW,
        revision=0,
        cleanup_complete=False,
        claimed_at=None,
        cleanup_reason=None,
    )
    client.rows = [row]
    stored = store.get_grant(GID)
    assert stored is not None
    assert stored.plan.hash_key is None
    assert stored.plan.view_sql == ""
    assert stored.plan.facts is not None and plan.facts is not None
    assert stored.plan.facts.starts_at == plan.facts.starts_at
    assert stored.plan.facts.masks == plan.facts.masks
    assert stored.plan.view_id == plan.view_id
    client.rows = [row, row]
    with pytest.raises(GrantError, match="duplicate ids"):
        store.get_grant(GID)


def test_database_transitions_protect_revoke_claims(plan: GrantPlan) -> None:
    client = Client()
    store = GrantStore(client, SDK, PROJECT, "US")
    assert store.update_names(plan) == 1
    assert store.claim_enabling(plan) == 1
    assert store.claim_active(plan) == 1
    store.mark_failed(plan)
    assert store.claim_revoke(GrantRecord(plan, "active", NOW, revision=8), "manual", NOW) == 1
    assert store.finish_revoke(GID, 9, "revoked") == 1
    store.release_revoke(GID, 9, "details must not be persisted")
    names, enabling, active, failed, claim, finish, release = client.calls
    assert "status = 'issuing'" in names[0]
    assert enabling[1]["current"] == ("STRING", "issuing")
    assert active[1]["current"] == ("STRING", "enabling")
    assert "expires_at > CURRENT_TIMESTAMP()" in active[0]
    assert "status IN ('issuing', 'enabling')" in failed[0]
    assert "status = @status AND revision = @revision AND NOT cleanup_complete" in claim[0]
    assert claim[1]["revision"] == ("INT64", 8)
    assert claim[1]["stale_before"] == ("TIMESTAMP", NOW - GRACE)
    for sql, params in (finish, release):
        assert "status = 'revoking' AND revision = @revision AND claimed_at IS NOT NULL" in sql
        assert params["revision"] == ("INT64", 9)
    assert "cleanup_complete = TRUE" in finish[0]
    assert "details must not be persisted" not in repr(client.calls)


@pytest.mark.parametrize("count", [None, 2])
def test_unexpected_update_count_fails_closed(plan: GrantPlan, count: Any) -> None:
    client = Client()
    client.num_dml_affected_rows = count
    with pytest.raises(GrantError, match="unexpected row count"):
        GrantStore(client, SDK, PROJECT, "US").claim_active(plan)


def test_wrong_project_is_rejected_before_reserving(plan: GrantPlan) -> None:
    client = Client()
    with pytest.raises(GrantError, match="invalid BigQuery grant state target"):
        GrantStore(client, SDK, PROJECT, "US").insert_issuing(replace(plan, project="other-proj"))
    assert not client.calls


def test_pending_round_trip_and_expiry_use_only_request_state(plan: GrantPlan) -> None:
    assert plan.facts is not None
    pending = PendingRequest(
        GID, plan.expires_at, replace(plan.facts, approval="two-person", approvers=())
    )
    client = Client()
    store = RequestStore(client, SDK, PROJECT, "US")
    store.insert_pending(pending, PRINCIPAL)
    insert, params = client.calls[0]
    assert "'pending', 0, '[]'" in insert
    assert PRINCIPAL not in insert and KEY.derived.hex() not in str(params)
    client.rows = [
        {**{name: value for name, (_, value) in params.items()}, "revision": 0, "votes_json": "[]"}
    ]
    snapshot = store.get_pending(GID)
    assert snapshot is not None
    row = snapshot.pending
    assert row.expires_at == pending.expires_at and snapshot.principal == PRINCIPAL
    assert row.facts.approval == "two-person"
    expired = expire_pending(store, now=pending.expires_at)
    assert [result.request_id for result in expired] == [GID]
    for sql, _ in client.calls:
        assert f"`{PROJECT}.datagrant.requests`" in sql
        assert "VIEW" not in sql


def test_quorum_claim_and_expiry_use_the_evaluated_revision(
    case: tuple[Policy, PendingRequest],
) -> None:
    policy, pending = case
    client = Client()
    store = RequestStore(client, SDK, PROJECT, "US")
    grant_id = "abcdef012346"
    store.insert_pending(pending, PRINCIPAL)
    client.rows = [
        {
            **{name: value for name, (_, value) in client.calls[0][1].items()},
            "revision": 0,
            "votes_json": "[]",
        }
    ]
    assert store.record_vote(GID, policy, BOB, now=NOW, grant_id=grant_id) is None
    first_vote = client.calls[-1][1]
    assert first_vote["status"] == ("STRING", "pending")
    assert first_vote["grant_id"] == ("STRING", None)
    client.rows[0].update(revision=1, votes_json=first_vote["votes"][1])
    assert store.record_vote(GID, policy, BOB, now=NOW, grant_id=grant_id) is None
    assert client.calls[-1][0].startswith("SELECT")

    client.num_dml_affected_rows = 0
    with pytest.raises(GrantError, match="changed; reload"):
        store.record_vote(GID, policy, CAROL, now=NOW, grant_id=grant_id)
    client.num_dml_affected_rows = 1
    claim = store.record_vote(GID, policy, CAROL, now=NOW, grant_id=grant_id)
    assert claim is not None and claim.revision == 2 and claim.grant_id == grant_id
    assert [vote.identity.username for vote in claim.approval.votes] == ["bob", "carol"]
    approve = client.calls[-1]
    assert approve[1]["status"] == ("STRING", "approving")
    assert approve[1]["grant_id"] == ("STRING", grant_id)
    client.num_dml_affected_rows = 0
    assert store.claim_expired_request(claim.snapshot.pending, pending.expires_at) == 0
    expire = client.calls[-1]
    for sql, params in (approve, expire):
        assert "status = 'pending' AND revision = @revision" in sql
        assert params["revision"] == ("INT64", 1)
        assert params["expires_at"] == ("TIMESTAMP", pending.expires_at)
    assert "expires_at > CURRENT_TIMESTAMP()" in approve[0]
    assert "expires_at <= CURRENT_TIMESTAMP()" in expire[0]
    assert store.finish_approval(claim) == 0
    assert store.mark_request_failed(claim) == 0
    for sql, params in client.calls[-2:]:
        assert "status = 'approving' AND revision = @revision" in sql
        assert "AND grant_id = @grant_id" in sql
        assert params["revision"] == ("INT64", 2)


def test_query_paging_errors_are_wrapped(plan: GrantPlan) -> None:
    class Paging:
        num_dml_affected_rows = 1

        def query(self, sql: str, **kwargs: Any) -> "Paging":
            return self

        def result(self, *, timeout: int, job_retry: None) -> Any:
            def pages() -> Any:
                yield {"n": 1}
                raise RuntimeError("page two failed")

            return pages()

    with pytest.raises(GrantError, match="state query failed"):
        GrantStore(Paging(), SDK, PROJECT, "US").count_live_grants(PRINCIPAL)


def test_cli_concurrent_reason_uses_store_count(plan: GrantPlan) -> None:
    from types import SimpleNamespace

    from datagrant.cli import _bq_concurrent_reason

    class Store:
        def count_live_grants(self, principal: str) -> int:
            assert principal == PRINCIPAL
            return 2

    policy = SimpleNamespace(concurrent_grant_cap=lambda dataset: 2)
    msg = _bq_concurrent_reason(Store(), policy, PRINCIPAL, "bq_clinic")
    assert msg is not None
    assert "max_concurrent_grants is 2" in msg
    policy = SimpleNamespace(concurrent_grant_cap=lambda dataset: None)
    assert _bq_concurrent_reason(Store(), policy, PRINCIPAL, "bq_clinic") is None


def test_count_live_grants_is_per_principal(plan: GrantPlan) -> None:
    client = Client()
    client.rows = [{"n": 2}]
    n = GrantStore(client, SDK, PROJECT, "US").count_live_grants(PRINCIPAL)
    assert n == 2
    sql, params = client.calls[0]
    assert "status IN ('issuing', 'enabling', 'active')" in sql
    assert "expires_at > CURRENT_TIMESTAMP()" in sql
    assert params["principal"] == ("STRING", PRINCIPAL)
    assert PRINCIPAL not in sql
    client.rows = [{"n": -1}]
    with pytest.raises(GrantError, match="concurrent-grant count failed"):
        GrantStore(client, SDK, PROJECT, "US").count_live_grants(PRINCIPAL)


def test_auto_request_cannot_enter_pending_storage(plan: GrantPlan) -> None:
    assert plan.facts is not None
    pending = PendingRequest(GID, plan.expires_at, plan.facts)
    client = Client()
    with pytest.raises(GrantError, match="unapproved two-person"):
        RequestStore(client, SDK, PROJECT, "US").insert_pending(pending, PRINCIPAL)
    assert not client.calls
