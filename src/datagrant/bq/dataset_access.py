"""Versioned BigQuery dataset access updates for authorized views."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from datagrant.bq.grant import (
    ACCESS_POLICY_VERSION,
    ETAG_MAX_TRIES,
    STATE_DATASET,
    VIEW_DATASET,
    ConflictError,
    GrantError,
    GrantPlan,
    IamPolicy,
    _conditional_cap_hit,
    _parse_principal,
    grantee_role,
    q,
    q_project,
)
from datagrant.bq.rest import TIMEOUT, Response, Session

_ROOT = "https://bigquery.googleapis.com/bigquery/v2/projects"


@dataclass
class _DatasetPolicy(IamPolicy):
    resource: str = ""
    original_etag: str = ""
    access: list[dict[str, Any]] = field(default_factory=list)


def _access_list(body: dict[str, Any]) -> list[dict[str, Any]]:
    access = body.get("access")
    if not isinstance(access, list) or not all(isinstance(entry, dict) for entry in access):
        raise GrantError("BigQuery dataset read did not include a complete access list")
    if any("_withcond_" in str(entry.get("role", "")) for entry in access):
        raise GrantError("BigQuery dataset returned an incomplete conditional policy")
    return access


def _etag(body: dict[str, Any]) -> str:
    etag = body.get("etag")
    if not isinstance(etag, str) or not etag.strip():
        raise GrantError("BigQuery dataset etag missing")
    return etag


def _managed_member(entry: dict[str, Any], role: str) -> str | None:
    if entry.get("role") != role or not isinstance(entry.get("condition"), dict):
        return None
    raw: str | None = None
    if isinstance(email := entry.get("userByEmail"), str):
        prefix = "serviceAccount" if email.lower().endswith(".gserviceaccount.com") else "user"
        raw = f"{prefix}:{email}"
    elif isinstance(email := entry.get("groupByEmail"), str):
        raw = f"group:{email}"
    elif isinstance(member := entry.get("iamMember"), str):
        raw = member
    if raw is None:
        return None
    try:
        return _parse_principal(raw)
    except GrantError:
        return None


def _dataset_url(project: str, dataset: str) -> str:
    q_project(project)
    q(dataset)
    return f"{_ROOT}/{project}/datasets/{dataset}"


def _routine_url(project: str, dataset: str, routine: str) -> str:
    q_project(project)
    q(dataset)
    q(routine)
    return f"{_ROOT}/{project}/datasets/{dataset}/routines/{routine}"


def _table_url(project: str, dataset: str, table: str) -> str:
    q_project(project)
    q(dataset)
    q(table)
    return f"{_ROOT}/{project}/datasets/{dataset}/tables/{table}"


class DatasetAccessClient:
    """Uses an operator-authenticated session supplied by the eventual live client."""

    def __init__(self, session: Session, *, grant_project: str | None = None) -> None:
        if grant_project is not None:
            q_project(grant_project)
        self._session = session
        self._grant_project = grant_project

    def _request(
        self, method: str, url: str, *, metadata_only: bool = False, **kwargs: Any
    ) -> Response:
        params: dict[str, int | str] = {"accessPolicyVersion": ACCESS_POLICY_VERSION}
        if metadata_only:
            params["datasetView"] = "METADATA"
        try:
            return self._session.request(
                method, url, params=params, timeout=TIMEOUT, allow_redirects=False, **kwargs
            )
        except Exception:  # noqa: BLE001 - transport errors can include URLs
            raise GrantError("BigQuery dataset request failed") from None

    def _read(self, url: str, *, metadata_only: bool = False) -> dict[str, Any]:
        response = self._request("GET", url, metadata_only=metadata_only)
        if response.status_code != 200:
            raise GrantError(f"BigQuery dataset read failed (HTTP {response.status_code})")
        try:
            body = response.json()
        except ValueError:
            raise GrantError("BigQuery dataset read returned invalid JSON") from None
        if not isinstance(body, dict):
            raise GrantError("BigQuery dataset read returned an invalid resource")
        return body

    def _write(self, url: str, etag: str, access: list[dict[str, Any]]) -> None:
        response = self._request("PATCH", url, headers={"If-Match": etag}, json={"access": access})
        status = response.status_code
        if status == 200:
            return
        if status in (409, 412):
            raise ConflictError(f"BigQuery dataset etag conflict (HTTP {status})")
        if status in (400, 429):
            try:
                body = response.json()
            except ValueError:
                body = None
            error = body.get("error") if isinstance(body, dict) else None
            if isinstance(error, dict) and _conditional_cap_hit(str(error.get("message", ""))):
                raise GrantError("Google IAM per-principal conditional-binding cap was hit")
        raise GrantError(f"BigQuery dataset update failed (HTTP {status})")

    def _iam_url(self, project: str, dataset: str, version: int) -> str:
        if project != self._grant_project or dataset != VIEW_DATASET:
            raise GrantError(
                "dataset IAM only supports datagrant_views in the configured grant project"
            )
        if version != ACCESS_POLICY_VERSION:
            raise GrantError("dataset IAM requires policy version 3")
        return _dataset_url(project, dataset)

    def get_dataset_iam(
        self, project: str, dataset: str, *, access_policy_version: int
    ) -> IamPolicy:
        url = self._iam_url(project, dataset, access_policy_version)
        body = self._read(url)
        access = _access_list(body)
        etag = _etag(body)
        bindings: list[dict[str, Any]] = []
        role = grantee_role(project)
        for entry in access:
            member = _managed_member(entry, role)
            if member is None:
                continue
            condition = entry["condition"]
            for binding in bindings:
                if binding["condition"] == condition:
                    if member not in binding["members"]:
                        binding["members"].append(member)
                    break
            else:
                bindings.append(
                    {"role": role, "members": [member], "condition": deepcopy(condition)}
                )
        return _DatasetPolicy(
            etag, bindings, resource=url, original_etag=etag, access=deepcopy(access)
        )

    def set_dataset_iam(
        self, project: str, dataset: str, policy: IamPolicy, *, access_policy_version: int
    ) -> None:
        url = self._iam_url(project, dataset, access_policy_version)
        if (
            not isinstance(policy, _DatasetPolicy)
            or policy.resource != url
            or policy.etag != policy.original_etag
            or not policy.etag.strip()
            or policy.version != ACCESS_POLICY_VERSION
        ):
            raise GrantError("dataset IAM update requires a version 3 snapshot of the target")
        role = grantee_role(project)
        edits: list[tuple[dict[str, Any], str]] = []
        for binding in policy.bindings:
            condition = binding.get("condition")
            if (
                binding.get("role") != role
                or not isinstance(condition, dict)
                or not isinstance(condition.get("title"), str)
                or not condition["title"]
                or not isinstance(condition.get("expression"), str)
                or not condition["expression"]
                or not isinstance(binding.get("members"), list)
            ):
                raise GrantError("dataset IAM edits require the conditional grant role")
            for member in binding["members"]:
                if not isinstance(member, str) or _parse_principal(member) != member:
                    raise GrantError("invalid dataset IAM grant principal")
                if (condition, member) not in edits:
                    edits.append((condition, member))
        access = []
        existing = []
        for entry in policy.access:
            member = _managed_member(entry, role)
            if member is None:
                access.append(entry)
            elif (entry["condition"], member) in edits:
                access.append(entry)
                existing.append((entry["condition"], member))
        for condition, member in edits:
            if (condition, member) in existing:
                continue
            kind, email = member.split(":", 1)
            field_name = "groupByEmail" if kind == "group" else "userByEmail"
            entry = {"role": role, field_name: email, "condition": condition}
            if _managed_member(entry, role) != member:
                raise GrantError(
                    "dataset IAM principal does not round-trip through the access list"
                )
            access.append(entry)
        self._write(url, policy.etag, access)

    def authorize_views_dataset_if_missing(self, plan: GrantPlan) -> bool:
        """Add only the operator's shared views dataset to the source access list."""
        source_project, sep, source_dataset = plan.source_dataset.partition(".")
        if self._grant_project is not None and plan.project != self._grant_project:
            raise GrantError("source authorization requires the configured BigQuery grant project")
        if not sep:
            raise GrantError("BigQuery source dataset must be project-qualified")
        source_url = _dataset_url(source_project, source_dataset)
        views_url = _dataset_url(plan.project, VIEW_DATASET)
        if source_project == plan.project and source_dataset.casefold() in {
            STATE_DATASET,
            VIEW_DATASET,
        }:
            raise GrantError("BigQuery source cannot be a datagrant internal dataset")
        target = {
            "dataset": {"projectId": plan.project, "datasetId": VIEW_DATASET},
            "targetTypes": ["VIEWS"],
        }
        views_location = self._read(views_url, metadata_only=True).get("location")
        for _attempt in range(ETAG_MAX_TRIES):
            source = self._read(source_url)
            location = source.get("location")
            if (
                not isinstance(location, str)
                or not location
                or not isinstance(views_location, str)
                or location.casefold() != views_location.casefold()
                or (plan.location is not None and location.casefold() != plan.location.casefold())
            ):
                raise GrantError("BigQuery source, views, and requested locations must match")
            access = _access_list(source)
            if any(
                entry.get("dataset") == target and not entry.get("condition") for entry in access
            ):
                return False
            try:
                self._write(source_url, _etag(source), [*access, {"dataset": target}])
                return True
            except ConflictError:
                continue
        raise GrantError(f"BigQuery dataset etag conflict after {ETAG_MAX_TRIES} attempts")

    def _authorize_routine(self, project: str, dataset: str, entry: dict[str, Any]) -> bool:
        url = _dataset_url(project, dataset)
        for _attempt in range(ETAG_MAX_TRIES):
            body = self._read(url)
            access = _access_list(body)
            if any(item.get("routine") == entry and not item.get("condition") for item in access):
                return False
            try:
                self._write(url, _etag(body), [*access, {"routine": entry}])
                return True
            except ConflictError:
                continue
        raise GrantError(f"BigQuery dataset etag conflict after {ETAG_MAX_TRIES} attempts")

    def _get_object(self, url: str, missing: str) -> dict[str, Any]:
        try:
            response = self._session.request("GET", url, timeout=TIMEOUT, allow_redirects=False)
        except Exception:  # noqa: BLE001 - transport errors can include URLs
            raise GrantError("BigQuery hash preflight request failed") from None
        if response.status_code == 404:
            raise GrantError(missing)
        if response.status_code != 200:
            raise GrantError("BigQuery hash preflight request failed")
        try:
            body = response.json()
        except ValueError:
            raise GrantError("BigQuery hash preflight returned invalid JSON") from None
        if not isinstance(body, dict):
            raise GrantError("BigQuery hash preflight returned an invalid resource")
        return body

    def require_hash_objects(self, project: str) -> None:
        """routines.get hash_hmac and tables.get _hash_master. Fail closed if missing.

        Does not inspect the authorized-routine ACL. A missing ACL can still
        leave an issued grant active but unusable.
        """
        from datagrant.bq.hash import HASH_TABLE, HASH_UDF

        if self._grant_project is not None and project != self._grant_project:
            raise GrantError("hash preflight requires the configured grant project")
        self._get_object(
            _routine_url(project, STATE_DATASET, HASH_UDF),
            "BigQuery hash_hmac routine is unavailable",
        )
        self._get_object(
            _table_url(project, STATE_DATASET, HASH_TABLE),
            "BigQuery hash-master table is unavailable",
        )

    def authorize_hash_routine_if_missing(self, plan: GrantPlan) -> bool:
        """Authorize hash_hmac on datagrant_views. Do not grant the grantee datagrant access.

        Also authorize the routine on the hash-master dataset so the UDF can
        read `_hash_master` without giving invokers table access.
        """
        from datagrant.bq.hash import hash_routine_entry

        if self._grant_project is not None and plan.project != self._grant_project:
            raise GrantError("hash routine authorization requires the configured grant project")
        entry = hash_routine_entry(plan.project)
        views_url = _dataset_url(plan.project, VIEW_DATASET)
        state_url = _dataset_url(plan.project, STATE_DATASET)
        views_location = self._read(views_url, metadata_only=True).get("location")
        state = self._read(state_url, metadata_only=True)
        state_location = state.get("location")
        if (
            not isinstance(views_location, str)
            or not views_location
            or not isinstance(state_location, str)
            or views_location.casefold() != state_location.casefold()
            or (plan.location is not None and views_location.casefold() != plan.location.casefold())
        ):
            raise GrantError("BigQuery hash-master, views, and requested locations must match")
        added_views = self._authorize_routine(plan.project, VIEW_DATASET, entry)
        added_state = self._authorize_routine(plan.project, STATE_DATASET, entry)
        return added_views or added_state
