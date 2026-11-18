"""BigQuery source authorization at the HTTP boundary, without cloud credentials."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

import pytest
from test_bq_grant import GID, KEY, NOW, PRINCIPAL, PROJECT, FakeClient, dec, req

from datagrant.bq.dataset_access import DatasetAccessClient
from datagrant.bq.grant import (
    GrantError,
    GrantPlan,
    IamPolicy,
    apply_bind,
    apply_unbind,
    build_plan,
    dataset_binding,
    job_user_binding,
)

SOURCE_PROJECT = "source-proj"
BASE = "https://bigquery.googleapis.com/bigquery/v2/projects"
SOURCE_URL = f"{BASE}/{SOURCE_PROJECT}/datasets/clinic"
VIEWS_URL = f"{BASE}/{PROJECT}/datasets/datagrant_views"
AUTHORIZATION = {
    "dataset": {
        "dataset": {"projectId": PROJECT, "datasetId": "datagrant_views"},
        "targetTypes": ["VIEWS"],
    }
}
EXISTING = [
    {"role": "OWNER", "specialGroup": "projectOwners"},
    {"view": {"projectId": "other-proj", "datasetId": "reports", "tableId": "report"}},
    {"routine": {"projectId": "other-proj", "datasetId": "reports", "routineId": "mask"}},
    {
        "role": "READER",
        "userByEmail": "reader@example.com",
        "condition": {"title": "keep", "expression": "request.time < timestamp('2027-01-01')"},
    },
]


@dataclass
class Response:
    status_code: int = 200
    body: Any = None

    def json(self) -> Any:
        if isinstance(self.body, ValueError):
            raise self.body
        return self.body


class Session:
    def __init__(self, *responses: Response) -> None:
        self.responses = iter(responses)
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> Response:
        self.calls.append((method, url, kwargs))
        return next(self.responses)


@pytest.fixture
def plan() -> GrantPlan:
    return build_plan(
        dec(),
        req(),
        project=PROJECT,
        source_project=SOURCE_PROJECT,
        principal=PRINCIPAL,
        grant_id=GID,
        location="US",
        hash_key=KEY,
        now=NOW,
    )


def source(access: list[dict[str, Any]], etag: str = 'W/"1"') -> Response:
    return Response(body={"location": "us", "access": access, "etag": etag, "labels": {"keep": "me"}})


def test_plan_separates_source_from_operator_resources(plan: GrantPlan) -> None:
    assert plan.source_dataset == f"{SOURCE_PROJECT}.clinic"
    assert f"`{SOURCE_PROJECT}`.`clinic`.`patients`" in plan.view_sql
    assert f"`{PROJECT}`.`datagrant`.`hash_hmac`" in plan.view_sql
    assert plan.view_id == f"{PROJECT}.datagrant_views.G_{GID}"
    assert f"projects/{PROJECT}/datasets/datagrant_views/" in dataset_binding(plan)["condition"][
        "expression"
    ]
    assert job_user_binding(plan)["role"] == "roles/bigquery.jobUser"


@pytest.mark.parametrize("status", [409, 412])
def test_authorize_retries_from_new_snapshot_without_replacing_other_access(
    plan: GrantPlan, status: int
) -> None:
    concurrent = {"role": "READER", "groupByEmail": "new@example.com"}
    session = Session(
        Response(body={"location": "US"}),
        source(EXISTING),
        Response(status),
        source([*EXISTING, concurrent], 'W/"2"'),
        Response(),
    )
    assert DatasetAccessClient(session).authorize_views_dataset_if_missing(plan)
    assert [(method, url) for method, url, _ in session.calls] == [
        ("GET", VIEWS_URL),
        ("GET", SOURCE_URL),
        ("PATCH", SOURCE_URL),
        ("GET", SOURCE_URL),
        ("PATCH", SOURCE_URL),
    ]
    for _, _, options in session.calls:
        assert options["params"]["accessPolicyVersion"] == 3
        assert options["timeout"] > 0
        assert options["allow_redirects"] is False
    assert session.calls[0][2]["params"]["datasetView"] == "METADATA"
    assert session.calls[2][2]["headers"] == {"If-Match": 'W/"1"'}
    assert session.calls[4][2]["headers"] == {"If-Match": 'W/"2"'}
    assert session.calls[4][2]["json"] == {"access": [*EXISTING, concurrent, AUTHORIZATION]}


def test_concurrent_authorization_needs_no_duplicate_write(plan: GrantPlan) -> None:
    session = Session(
        Response(body={"location": "US"}),
        source(EXISTING),
        Response(412),
        source([*EXISTING, AUTHORIZATION], 'W/"2"'),
    )
    assert not DatasetAccessClient(session).authorize_views_dataset_if_missing(plan)
    assert [method for method, _, _ in session.calls] == ["GET", "GET", "PATCH", "GET"]


@pytest.mark.parametrize(
    ("snapshot", "message"),
    [
        (Response(body={"location": "EU", "access": EXISTING, "etag": "1"}), "locations must match"),
        (Response(body={"location": "US", "etag": "1"}), "complete access list"),
        (source(EXISTING, ""), "etag missing"),
        (Response(403), "read failed"),
        (Response(body=ValueError()), "invalid JSON"),
        (Response(body=[]), "invalid resource"),
    ],
)
def test_rejects_incomplete_or_incompatible_snapshot(
    plan: GrantPlan, snapshot: Response, message: str
) -> None:
    session = Session(Response(body={"location": "US"}), snapshot)
    with pytest.raises(GrantError, match=message):
        DatasetAccessClient(session).authorize_views_dataset_if_missing(plan)
    assert all(method == "GET" for method, _, _ in session.calls)


@pytest.mark.parametrize("dataset", ["clinic", "../clinic", f"{PROJECT}.datagrant_views"])
def test_rejects_invalid_or_internal_source_without_network(plan: GrantPlan, dataset: str) -> None:
    session = Session()
    with pytest.raises(GrantError):
        DatasetAccessClient(session).authorize_views_dataset_if_missing(
            replace(plan, source_dataset=dataset)
        )
    assert not session.calls


def test_conflicts_are_bounded_and_denial_does_not_get_retried(plan: GrantPlan) -> None:
    conflicts = Session(
        Response(body={"location": "US"}),
        source(EXISTING),
        Response(412),
        source(EXISTING, 'W/"2"'),
        Response(409),
    )
    with pytest.raises(GrantError, match="etag conflict after 2 attempts"):
        DatasetAccessClient(conflicts).authorize_views_dataset_if_missing(plan)
    denied = Session(Response(body={"location": "US"}), source(EXISTING), Response(403))
    with pytest.raises(GrantError, match=r"update failed \(HTTP 403\)"):
        DatasetAccessClient(denied).authorize_views_dataset_if_missing(plan)


class IamClient(FakeClient):
    def __init__(self, session: Session) -> None:
        super().__init__()
        self.access = DatasetAccessClient(session, grant_project=PROJECT)

    def get_dataset_iam(
        self, project: str, dataset: str, *, access_policy_version: int
    ) -> IamPolicy:
        return self.access.get_dataset_iam(
            project, dataset, access_policy_version=access_policy_version
        )

    def set_dataset_iam(
        self, project: str, dataset: str, policy: IamPolicy, *, access_policy_version: int
    ) -> None:
        self.access.set_dataset_iam(
            project, dataset, policy, access_policy_version=access_policy_version
        )


@pytest.mark.parametrize(("member", "field"), [
    (PRINCIPAL, "userByEmail"),
    ("serviceAccount:reader@clinic-proj.iam.gserviceaccount.com", "userByEmail"),
    ("group:readers@example.com", "groupByEmail"),
])
def test_dataset_binding_round_trip_keeps_other_access(
    plan: GrantPlan, member: str, field: str
) -> None:
    plan = replace(plan, principal=member)
    binding = dataset_binding(plan)
    kept = [*EXISTING, AUTHORIZATION]
    another = {
        "role": binding["role"],
        "groupByEmail": "other@example.com",
        "condition": binding["condition"],
    }
    entry = {
        "role": binding["role"],
        field: member.split(":", 1)[1],
        "condition": binding["condition"],
    }
    session = Session(
        source(kept), Response(412),
        source([*kept, another], "new"), Response(),
        source([*kept, another, entry], "bound"), Response(),
    )
    client = IamClient(session)
    apply_bind(client, plan)
    assert session.calls[3][2]["headers"] == {"If-Match": "new"}
    assert session.calls[3][2]["json"] == {"access": [*kept, another, entry]}
    apply_unbind(client, plan)
    assert session.calls[-1][2]["json"] == {"access": [*kept, another]}
    assert all(url == VIEWS_URL for _, url, _ in session.calls)
    assert all(options["params"]["accessPolicyVersion"] == 3 for _, _, options in session.calls)


def test_dataset_iam_refuses_unconditional_edits_and_wrong_target() -> None:
    session = Session(source(EXISTING))
    client = DatasetAccessClient(session, grant_project=PROJECT)
    with pytest.raises(GrantError, match="configured grant project"):
        client.get_dataset_iam(SOURCE_PROJECT, "datagrant_views", access_policy_version=3)
    with pytest.raises(GrantError, match="configured grant project"):
        client.get_dataset_iam(PROJECT, "clinic", access_policy_version=3)
    with pytest.raises(GrantError, match="snapshot of the target"):
        client.set_dataset_iam(
            PROJECT, "datagrant_views", IamPolicy("etag"), access_policy_version=3
        )
    assert not session.calls
    policy = client.get_dataset_iam(PROJECT, "datagrant_views", access_policy_version=3)
    policy.bindings.append({"role": "roles/owner", "members": [PRINCIPAL]})
    with pytest.raises(GrantError, match="conditional grant role"):
        client.set_dataset_iam(PROJECT, "datagrant_views", policy, access_policy_version=3)
    assert [method for method, _, _ in session.calls] == ["GET"]
