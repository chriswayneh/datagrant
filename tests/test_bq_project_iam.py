"""Project IAM wire contract with the existing grant lifecycle."""

from typing import Any

import pytest
from test_bq_dataset_access import Response, Session
from test_bq_grant import GID, KEY, NOW, PRINCIPAL, PROJECT, FakeClient, dec, req

from datagrant.bq.grant import (
    GrantError,
    IamPolicy,
    apply_bind,
    apply_unbind,
    build_plan,
    job_user_binding,
)
from datagrant.bq.project_iam import ProjectIamClient

BASE = f"https://cloudresourcemanager.googleapis.com/v3/projects/{PROJECT}"
OWNER = {"role": "roles/owner", "members": ["group:owners@example.com"]}
OTHER = {"role": "roles/viewer", "members": ["user:other@example.com"]}


class Client(FakeClient):
    def __init__(self, session: Session) -> None:
        super().__init__()
        self.iam = ProjectIamClient(session, PROJECT)

    def get_project_iam(self, project: str, *, access_policy_version: int) -> IamPolicy:
        return self.iam.get_project_iam(project, access_policy_version=access_policy_version)

    def set_project_iam(
        self, project: str, policy: IamPolicy, *, access_policy_version: int
    ) -> None:
        self.iam.set_project_iam(project, policy, access_policy_version=access_policy_version)


@pytest.mark.parametrize("status", [409, 412])
def test_project_bind_retries_without_erasing_concurrent_change(status: int) -> None:
    plan = build_plan(dec(), req(), project=PROJECT, principal=PRINCIPAL, hash_key=KEY, now=NOW)
    session = Session(
        Response(body={"version": 1, "etag": "first", "bindings": [OWNER]}),
        Response(status),
        Response(body={"version": 1, "etag": "second", "bindings": [OWNER, OTHER]}),
        Response(),
    )
    apply_bind(Client(session), plan)
    assert [(method, url) for method, url, _ in session.calls] == [
        ("POST", f"{BASE}:getIamPolicy"),
        ("POST", f"{BASE}:setIamPolicy"),
        ("POST", f"{BASE}:getIamPolicy"),
        ("POST", f"{BASE}:setIamPolicy"),
    ]
    for _, _, options in session.calls:
        assert options["timeout"] > 0
        assert options["allow_redirects"] is False
    first_read, first_write, second_read, second_write = [
        options["json"] for _, _, options in session.calls
    ]
    assert first_read == second_read == {"options": {"requestedPolicyVersion": 3}}
    assert first_write["policy"]["etag"] == "first"
    assert second_write == {
        "policy": {
            "version": 3,
            "etag": "second",
            "bindings": [OWNER, OTHER, job_user_binding(plan)],
        },
        "updateMask": "bindings,etag",
    }


def test_project_unbind_retains_other_grants_and_leaves_audit_settings_alone() -> None:
    plan = build_plan(
        dec(), req(), project=PROJECT, principal=PRINCIPAL, grant_id=GID, hash_key=KEY, now=NOW
    )
    other_plan = build_plan(
        dec(),
        req(),
        project=PROJECT,
        principal=PRINCIPAL,
        grant_id="abcdef012346",
        hash_key=KEY,
        now=NOW,
    )
    other_grant = job_user_binding(other_plan)
    session = Session(
        Response(
            body={
                "version": 3,
                "etag": "present",
                "bindings": [OWNER, other_grant, job_user_binding(plan)],
                "auditConfigs": [{"service": "bigquery.googleapis.com"}],
            }
        ),
        Response(),
    )
    apply_unbind(Client(session), plan)
    assert session.calls[-1][2]["json"] == {
        "policy": {"version": 3, "etag": "present", "bindings": [OWNER, other_grant]},
        "updateMask": "bindings,etag",
    }


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"version": 3}, "etag missing"),
        ({"etag": "present", "version": 2}, "invalid policy"),
        ({"etag": "present", "bindings": [{}]}, "invalid binding"),
        (
            {
                "etag": "present",
                "bindings": [{"role": "roles/viewer_withcond_hash", "members": []}],
            },
            "incomplete conditional policy",
        ),
    ],
)
def test_invalid_snapshot_cannot_reach_a_write(body: dict[str, Any], message: str) -> None:
    session = Session(Response(body=body))
    client = ProjectIamClient(session, PROJECT)
    with pytest.raises(GrantError, match=message):
        client.get_project_iam(PROJECT, access_policy_version=3)
    assert len(session.calls) == 1


def test_context_and_write_preconditions_prevent_network_calls() -> None:
    session = Session()
    client = ProjectIamClient(session, PROJECT)
    with pytest.raises(GrantError, match="configured BigQuery grant project"):
        client.get_project_iam("other-proj", access_policy_version=3)
    with pytest.raises(GrantError, match="requires policy version 3"):
        client.get_project_iam(PROJECT, access_policy_version=1)
    with pytest.raises(GrantError, match="etag missing"):
        client.set_project_iam(PROJECT, IamPolicy(""), access_policy_version=3)
    assert not session.calls


def test_provider_cap_message_is_reported_without_raw_provider_details() -> None:
    session = Session(
        Response(400, {"error": {"message": "Too many conditional bindings for member example"}})
    )
    client = ProjectIamClient(session, PROJECT)
    with pytest.raises(GrantError, match="conditional-binding cap") as error:
        client.set_project_iam(PROJECT, IamPolicy("present"), access_policy_version=3)
    assert "example" not in str(error.value)
