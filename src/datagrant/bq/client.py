"""Compose BigQuery grant operations for CLI --apply, revoke, and sweep."""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from typing import Any

from datagrant.bigquery_support import (
    ADC_SCOPES,
    BigQuerySetupError,
    load_adc,
    load_client,
    resolve_location,
    resolve_project,
)
from datagrant.bq.dataset_access import DatasetAccessClient
from datagrant.bq.grant import GrantError, GrantPlan, apply_bind, apply_unbind
from datagrant.bq.hash import HashStore
from datagrant.bq.project_iam import ProjectIamClient
from datagrant.bq.rest import Session
from datagrant.bq.state import GrantStore, RequestStore
from datagrant.bq.views import ViewClient

_PROJECT_SCOPE = "https://www.googleapis.com/auth/cloudplatformprojects"


class BigQueryGrantClient:
    """Share one grant-project context across state, view, and IAM operations."""

    def __init__(
        self, client: Any, sdk: Any, session: Session, *, project: str, state_location: str
    ) -> None:
        grants = GrantStore(client, sdk, project, state_location)
        views = ViewClient(client, project)
        dataset = DatasetAccessClient(session, grant_project=project)
        iam = ProjectIamClient(session, project)
        hashes = HashStore(client, sdk, project, state_location)
        self.requests = RequestStore(client, sdk, project, state_location)
        self._bq = client
        self._sdk = sdk
        self._project = project
        self._state_location = state_location
        self._hashes = hashes
        self._dataset = dataset
        self.insert_issuing = grants.insert_issuing
        self.update_names = grants.update_names
        self.claim_enabling = grants.claim_enabling
        self.claim_active = grants.claim_active
        self.mark_failed = grants.mark_failed
        self._grants = grants
        self.get_grant = grants.get_grant
        self.list_grants = grants.list_grants
        self.claim_revoke = grants.claim_revoke
        self.finish_revoke = grants.finish_revoke
        self.release_revoke = grants.release_revoke
        self.create_view = views.create_view
        self.drop_view = views.drop_view
        self.authorize_views_dataset_if_missing = dataset.authorize_views_dataset_if_missing
        self.get_dataset_iam = dataset.get_dataset_iam
        self.set_dataset_iam = dataset.set_dataset_iam
        self.get_project_iam = iam.get_project_iam
        self.set_project_iam = iam.set_project_iam
        self.list_due_requests = self.requests.list_due_requests
        self.claim_expired_request = self.requests.claim_expired_request
        self.count_live_grants = grants.count_live_grants
        self.count_live_hash_grants = grants.count_live_hash_grants

    def inspect_table(
        self, dataset: str, table: str, *, project: str, location: str | None = None
    ) -> Any:
        from datagrant.bq.mask import inspect_table as inspect

        return inspect(
            self._bq,
            self._sdk,
            project=project,
            dataset=dataset,
            table=table,
            location=location if location is not None else self._state_location,
        )

    def setup_hash(self, key: Any, *, rotate: bool = False) -> None:
        """Provision hash-master and hash_hmac. Writes the key only on insert or rotate."""
        from datagrant.keys import HashKey

        if not isinstance(key, HashKey):
            raise GrantError("BigQuery setup requires a hash key")
        self._dataset.require_hash_dataset_locked(self._project)
        self._hashes.ensure_table()
        self._hashes.ensure_udf()
        self._dataset.require_hash_object_iam_absent(self._project)
        n, matched = self._hashes.master_state(key)
        if n > 1 and not rotate:
            raise GrantError("BigQuery hash-master has duplicate rows")
        if rotate or n == 0:
            self._hashes.load_key(key)
        elif matched != 1:
            raise GrantError("BigQuery hash-master key does not match; rotate explicitly")
        self._dataset.authorize_hash_routine_if_missing(
            project=self._project, location=self._state_location
        )

    def ensure_hash(self, plan: GrantPlan) -> None:
        from datagrant.bq.hash import uses_hash_mask

        if not uses_hash_mask(plan):
            return
        if plan.hash_key is None:
            raise GrantError("hash masking requires a hash key file (see keys.hash_key_path)")
        self._dataset.require_hash_dataset_locked(plan.project)
        self._dataset.require_hash_objects(plan.project)
        self._dataset.require_hash_object_iam_absent(plan.project)
        self._hashes.require_fingerprint(plan.hash_key)

    @property
    def invalid_grant_results(self) -> list:
        return list(getattr(self._grants, "invalid_grant_results", ()))

    def bind_iam(self, plan: GrantPlan) -> None:
        apply_bind(self, plan)

    def unbind_iam(self, plan: GrantPlan) -> None:
        apply_unbind(self, plan)

    def cancel_jobs(self, plan: GrantPlan) -> int:
        raise GrantError("BigQuery grant-specific job cancellation is unavailable")


@contextmanager
def open_grant_client(project: str, state_location: str) -> Iterator[BigQueryGrantClient]:
    """Open the SDK client and REST transport with the same keyless ADC identity."""
    project = resolve_project(project)
    location = resolve_location(state_location)
    if location is None:
        raise BigQuerySetupError("BigQuery state dataset location is required")
    sdk = load_client()
    credentials = load_adc([*ADC_SCOPES, _PROJECT_SCOPE])
    if credentials is None:
        raise BigQuerySetupError(
            "no BigQuery ADC: application-default credentials are not available"
        )
    transport = importlib.import_module("google.auth.transport.requests")
    with ExitStack() as cleanup:
        client = sdk.Client(project=project, credentials=credentials)
        cleanup.callback(client.close)
        session = transport.AuthorizedSession(credentials)
        cleanup.callback(session.close)
        yield BigQueryGrantClient(client, sdk, session, project=project, state_location=location)
