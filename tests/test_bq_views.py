"""Verify view DDL boundaries without a BigQuery connection."""

from dataclasses import replace
from typing import Any

import pytest
from test_bq_grant import GID, KEY, NOW, PRINCIPAL, PROJECT, dec, req

from datagrant.bq.grant import GrantError, GrantPlan, build_plan
from datagrant.bq.views import ViewClient


class QueryClient:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.waits: list[dict[str, Any]] = []
        self.error = error

    def query(self, query: str, **kwargs: Any) -> "QueryClient":
        self.calls.append((query, kwargs))
        return self

    def result(self, **kwargs: Any) -> None:
        self.waits.append(kwargs)
        if self.error is not None:
            raise self.error


@pytest.fixture
def plan() -> GrantPlan:
    return build_plan(
        dec(),
        req(),
        project=PROJECT,
        source_project="source-proj",
        principal=PRINCIPAL,
        grant_id=GID,
        location="US",
        hash_key=KEY,
        now=NOW,
    )


def test_create_and_drop_wait_for_view_only_jobs(plan: GrantPlan) -> None:
    sdk = QueryClient()
    client = ViewClient(sdk, PROJECT)
    client.create_view(plan)
    client.drop_view(plan)
    create, drop = [sql for sql, _ in sdk.calls]
    assert create == (
        f"CREATE VIEW `{plan.view_id}` "
        f"OPTIONS(expiration_timestamp=TIMESTAMP('2026-11-15T01:00:00Z')) AS {plan.view_sql}"
    )
    assert drop == f"DROP VIEW IF EXISTS `{plan.view_id}`"
    assert all(
        kwargs == {"project": PROJECT, "location": "US", "timeout": 15, "job_retry": None}
        for _, kwargs in sdk.calls
    )
    assert sdk.waits == [{"timeout": 60, "job_retry": None}] * 2
    assert KEY.derived.hex() not in create


@pytest.mark.parametrize(
    "change",
    [
        {"project": "other-proj"},
        {"grant_id": "not-a-grant"},
        {"view_id": f"{PROJECT}.datagrant_views.G_abcdef012346"},
        {"view_id": f"{PROJECT}.clinic.patients"},
    ],
)
def test_foreign_or_mismatched_view_target_is_rejected_before_query(
    plan: GrantPlan, change: dict[str, Any]
) -> None:
    sdk = QueryClient()
    client = ViewClient(sdk, PROJECT)
    changed = replace(plan, **change)
    for operation in (client.create_view, client.drop_view):
        with pytest.raises(GrantError, match="view"):
            operation(changed)
    assert not sdk.calls


def test_create_rejects_naive_expiration_before_query(plan: GrantPlan) -> None:
    sdk = QueryClient()
    with pytest.raises(GrantError, match="timezone-aware"):
        ViewClient(sdk, PROJECT).create_view(
            replace(plan, expires_at=plan.expires_at.replace(tzinfo=None))
        )
    assert not sdk.calls


def test_failed_query_is_reported_without_exposing_sql(plan: GrantPlan) -> None:
    sdk = QueryClient(error=RuntimeError(plan.view_sql))
    with pytest.raises(GrantError, match="view creation failed") as error:
        ViewClient(sdk, PROJECT).create_view(plan)
    assert plan.view_sql not in str(error.value)
