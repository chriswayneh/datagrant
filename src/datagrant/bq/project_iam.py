"""Cloud Resource Manager transport for BigQuery's project jobUser bindings."""

from __future__ import annotations

from typing import Any

from datagrant.bq.grant import (
    ACCESS_POLICY_VERSION,
    ConflictError,
    GrantError,
    IamPolicy,
    _conditional_cap_hit,
    q_project,
)
from datagrant.bq.rest import TIMEOUT, Response, Session

_ROOT = "https://cloudresourcemanager.googleapis.com/v3/projects"


def _body(response: Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        raise GrantError("project IAM returned invalid JSON") from None
    if not isinstance(body, dict):
        raise GrantError("project IAM returned an invalid resource")
    return body


class ProjectIamClient:
    """Edit allow bindings only on the configured grant project."""

    def __init__(self, session: Session, grant_project: str) -> None:
        q_project(grant_project)
        self._session = session
        self._project = grant_project

    def _request(
        self, project: str, operation: str, access_policy_version: int, payload: dict[str, Any]
    ) -> Response:
        if project != self._project:
            raise GrantError("project IAM only supports the configured BigQuery grant project")
        if access_policy_version != ACCESS_POLICY_VERSION:
            raise GrantError("project IAM requires policy version 3")
        return self._session.request(
            "POST",
            f"{_ROOT}/{self._project}:{operation}",
            json=payload,
            timeout=TIMEOUT,
            allow_redirects=False,
        )

    def get_project_iam(self, project: str, *, access_policy_version: int) -> IamPolicy:
        response = self._request(
            project,
            "getIamPolicy",
            access_policy_version,
            {"options": {"requestedPolicyVersion": access_policy_version}},
        )
        if response.status_code != 200:
            raise GrantError(f"project IAM read failed (HTTP {response.status_code})")
        policy = _body(response)
        etag = policy.get("etag")
        if not isinstance(etag, str) or not etag.strip():
            raise GrantError("project IAM policy etag missing")
        version = policy.get("version", 0)
        bindings = policy.get("bindings", [])
        if version not in (0, 1, ACCESS_POLICY_VERSION) or not isinstance(bindings, list):
            raise GrantError("project IAM returned an invalid policy")
        for binding in bindings:
            if (
                not isinstance(binding, dict)
                or not isinstance(binding.get("role"), str)
                or not isinstance(binding.get("members"), list)
                or not all(isinstance(member, str) for member in binding["members"])
            ):
                raise GrantError("project IAM returned an invalid binding")
            if "_withcond_" in binding["role"] or (
                version != ACCESS_POLICY_VERSION and "condition" in binding
            ):
                raise GrantError("project IAM returned an incomplete conditional policy")
        return IamPolicy(etag, bindings, version)

    def set_project_iam(self, project: str, policy: IamPolicy, *, access_policy_version: int) -> None:
        if not policy.etag.strip():
            raise GrantError("project IAM policy etag missing")
        if policy.version != ACCESS_POLICY_VERSION:
            raise GrantError("project IAM requires policy version 3")
        response = self._request(
            project,
            "setIamPolicy",
            access_policy_version,
            {
                "policy": {
                    "version": policy.version,
                    "etag": policy.etag,
                    "bindings": policy.bindings,
                },
                "updateMask": "bindings,etag",
            },
        )
        status = response.status_code
        if status == 200:
            return
        if status in (409, 412):
            raise ConflictError(f"project IAM etag conflict (HTTP {status})")
        if status in (400, 429):
            try:
                error = _body(response).get("error")
            except GrantError:
                error = None
            if isinstance(error, dict) and _conditional_cap_hit(str(error.get("message", ""))):
                raise GrantError("Google IAM per-principal conditional-binding cap was hit")
        raise GrantError(f"project IAM update failed (HTTP {status})")
