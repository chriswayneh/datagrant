"""BigQuery logical view operations scoped to the configured grant project."""

from __future__ import annotations

from typing import Protocol

from datagrant.bq.grant import (
    _GRANT_ID_RE,
    VIEW_DATASET,
    GrantError,
    GrantPlan,
    lit,
    q_project,
    rfc3339,
)
from datagrant.bq.rest import TIMEOUT

_JOB_TIMEOUT = 60


class _QueryJob(Protocol):
    def result(self, *, timeout: int, job_retry: None) -> object: ...


class _QueryClient(Protocol):
    def query(
        self,
        query: str,
        *,
        project: str,
        location: str | None,
        timeout: int,
        job_retry: None,
    ) -> _QueryJob: ...


class ViewClient:
    """Run view DDL using the operator's BigQuery query client."""

    def __init__(self, client: _QueryClient, grant_project: str) -> None:
        q_project(grant_project)
        self._client = client
        self._project = grant_project

    def _target(self, plan: GrantPlan) -> str:
        if plan.project != self._project or not _GRANT_ID_RE.fullmatch(plan.grant_id):
            raise GrantError("invalid BigQuery grant view target")
        target = f"{self._project}.{VIEW_DATASET}.G_{plan.grant_id}"
        if plan.view_id != target:
            raise GrantError("BigQuery grant view does not match its grant id")
        return f"`{target}`"

    def _execute(self, ddl: str, plan: GrantPlan, operation: str) -> None:
        try:
            job = self._client.query(
                ddl,
                project=self._project,
                location=plan.location,
                timeout=TIMEOUT,
                job_retry=None,
            )
            job.result(timeout=_JOB_TIMEOUT, job_retry=None)
        except Exception:  # noqa: BLE001 - SDK errors can include the submitted SQL
            raise GrantError(f"BigQuery grant view {operation} failed") from None

    def create_view(self, plan: GrantPlan) -> None:
        """Create a new view from planner-generated SQL without replacing a view."""
        target = self._target(plan)
        if plan.expires_at.utcoffset() is None:
            raise GrantError("BigQuery grant view expiration must be timezone-aware")
        expiration = lit(rfc3339(plan.expires_at))
        ddl = f"CREATE VIEW {target} OPTIONS(expiration_timestamp=TIMESTAMP({expiration}))"
        self._execute(f"{ddl} AS {plan.view_sql}", plan, "creation")

    def drop_view(self, plan: GrantPlan) -> None:
        """Drop only the grant's view; absence succeeds and tables are never dropped."""
        self._execute(f"DROP VIEW IF EXISTS {self._target(plan)}", plan, "drop")
