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
    return Response(
        body={"location": "us", "access": access, "etag": etag, "labels": {"keep": "me"}}
    )


def test_plan_separates_source_from_operator_resources(plan: GrantPlan) -> None:
    assert plan.source_dataset == f"{SOURCE_PROJECT}.clinic"
    assert f"`{SOURCE_PROJECT}`.`clinic`.`patients`" in plan.view_sql
    assert f"`{PROJECT}`.`datagrant`.`hash_hmac`" in plan.view_sql
    assert plan.view_id == f"{PROJECT}.datagrant_views.G_{GID}"
    assert (
        f"projects/{PROJECT}/datasets/datagrant_views/"
        in dataset_binding(plan)["condition"]["expression"]
    )
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
        (
            Response(body={"location": "EU", "access": EXISTING, "etag": "1"}),
            "locations must match",
        ),
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


@pytest.mark.parametrize(
    ("member", "field"),
    [
        (PRINCIPAL, "userByEmail"),
        ("serviceAccount:reader@clinic-proj.iam.gserviceaccount.com", "userByEmail"),
        ("group:readers@example.com", "groupByEmail"),
    ],
)
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
        source(kept),
        Response(412),
        source([*kept, another], "new"),
        Response(),
        source([*kept, another, entry], "bound"),
        Response(),
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


def test_dataset_request_errors_do_not_leak_url() -> None:
    url = f"{VIEWS_URL}?name=clinic-proj"

    class Boom:
        def request(self, *args: Any, **kwargs: Any) -> Response:
            raise RuntimeError(f"GET {url}")

    client = DatasetAccessClient(Boom(), grant_project=PROJECT)  # type: ignore[arg-type]
    with pytest.raises(GrantError, match="dataset request failed") as err:
        client.get_dataset_iam(PROJECT, "datagrant_views", access_policy_version=3)
    text = str(err.value)
    assert url not in text
    assert "https://" not in text
    assert "clinic-proj" not in text
    assert err.value.__cause__ is None


def test_mixed_case_conditional_grantee_bind_and_unbind(plan: GrantPlan) -> None:
    binding = dataset_binding(plan)
    mixed = {
        "role": binding["role"],
        "userByEmail": "Alice@Example.com",
        "condition": binding["condition"],
    }
    kept = [*EXISTING, AUTHORIZATION]
    session = Session(
        source([*kept, mixed]),
        Response(),
        source([*kept, mixed]),
        Response(),
    )
    client = IamClient(session)
    apply_unbind(client, plan)
    assert session.calls[1][2]["json"] == {"access": kept}
    apply_bind(client, plan)
    emails = [
        entry.get("userByEmail")
        for entry in session.calls[-1][2]["json"]["access"]
        if entry.get("condition") == binding["condition"]
    ]
    assert len(emails) == 1
    assert emails[0].lower() == "alice@example.com"


STATE_URL = f"{BASE}/{PROJECT}/datasets/datagrant"
ROUTINE_URL = f"{BASE}/{PROJECT}/datasets/datagrant/routines/hash_hmac"
TABLE_URL = f"{BASE}/{PROJECT}/datasets/datagrant/tables/_hash_master"
ROUTINE = {"projectId": PROJECT, "datasetId": "datagrant", "routineId": "hash_hmac"}
ROUTINE_ACL = {"routine": ROUTINE}


def test_hash_preflight_gets_routine_then_hash_master(plan: GrantPlan) -> None:
    session = Session(
        Response(body={"routineReference": {"routineId": "hash_hmac"}}),
        Response(body={"tableReference": {"tableId": "_hash_master"}}),
    )
    DatasetAccessClient(session, grant_project=PROJECT).require_hash_objects(PROJECT)
    assert [(method, url) for method, url, _ in session.calls] == [
        ("GET", ROUTINE_URL),
        ("GET", TABLE_URL),
    ]
    for _, _, kwargs in session.calls:
        assert kwargs.get("params") is None
        assert kwargs.get("allow_redirects") is False


def test_hash_preflight_fails_closed_when_routine_missing() -> None:
    session = Session(Response(status_code=404, body={}))
    with pytest.raises(GrantError, match="hash_hmac routine is unavailable"):
        DatasetAccessClient(session, grant_project=PROJECT).require_hash_objects(PROJECT)
    assert session.calls[0][1] == ROUTINE_URL


def test_hash_preflight_fails_closed_when_table_missing() -> None:
    session = Session(
        Response(body={"routineReference": {"routineId": "hash_hmac"}}),
        Response(status_code=404, body={}),
    )
    with pytest.raises(GrantError, match="hash-master table is unavailable"):
        DatasetAccessClient(session, grant_project=PROJECT).require_hash_objects(PROJECT)
    assert session.calls[1][1] == TABLE_URL


def test_hash_routine_acl_is_routine_only_and_preserves_access(plan: GrantPlan) -> None:
    session = Session(
        Response(body={"location": "US"}),
        Response(body={"location": "US"}),
        source(EXISTING),
        Response(),
        source(EXISTING),
        Response(),
    )
    client = DatasetAccessClient(session, grant_project=PROJECT)
    assert client.authorize_hash_routine_if_missing(plan)
    urls = [url for _, url, _ in session.calls]
    assert urls == [VIEWS_URL, STATE_URL, VIEWS_URL, VIEWS_URL, STATE_URL, STATE_URL]
    methods = [method for method, _, _ in session.calls]
    assert methods == ["GET", "GET", "GET", "PATCH", "GET", "PATCH"]
    views_patch = session.calls[3][2]["json"]["access"]
    state_patch = session.calls[5][2]["json"]["access"]
    assert views_patch == [*EXISTING, ROUTINE_ACL]
    assert state_patch == [*EXISTING, ROUTINE_ACL]
    for access in (views_patch, state_patch):
        added = access[-1]
        assert list(added) == ["routine"]
        assert added["routine"] == ROUTINE
        assert PRINCIPAL not in repr(added)
        assert "userByEmail" not in added
        assert not any(
            entry.get("userByEmail") == PRINCIPAL.split(":", 1)[1]
            or entry.get("iamMember") == PRINCIPAL
            for entry in access
        )


def test_hash_routine_acl_skips_write_when_present(plan: GrantPlan) -> None:
    session = Session(
        Response(body={"location": "US"}),
        Response(body={"location": "US"}),
        source([*EXISTING, ROUTINE_ACL]),
        source([*EXISTING, ROUTINE_ACL]),
    )
    client = DatasetAccessClient(session, grant_project=PROJECT)
    assert not client.authorize_hash_routine_if_missing(plan)
    assert [method for method, _, _ in session.calls] == ["GET", "GET", "GET", "GET"]
    assert not any(method == "PATCH" for method, _, _ in session.calls)


def test_hash_routine_acl_retries_etag_conflict(plan: GrantPlan) -> None:
    session = Session(
        Response(body={"location": "US"}),
        Response(body={"location": "US"}),
        source(EXISTING),
        Response(412),
        source(EXISTING, 'W/"2"'),
        Response(),
        source(EXISTING),
        Response(),
    )
    client = DatasetAccessClient(session, grant_project=PROJECT)
    assert client.authorize_hash_routine_if_missing(plan)
    assert session.calls[5][2]["headers"] == {"If-Match": 'W/"2"'}
    assert session.calls[5][2]["json"] == {"access": [*EXISTING, ROUTINE_ACL]}


def test_hash_routine_acl_refuses_location_mismatch_and_wrong_project(plan: GrantPlan) -> None:
    mismatched = Session(Response(body={"location": "US"}), Response(body={"location": "EU"}))
    with pytest.raises(GrantError, match="locations must match"):
        DatasetAccessClient(mismatched, grant_project=PROJECT).authorize_hash_routine_if_missing(
            plan
        )
    empty = Session()
    with pytest.raises(GrantError, match="configured grant project"):
        DatasetAccessClient(empty, grant_project=PROJECT).authorize_hash_routine_if_missing(
            replace(plan, project="other-proj")
        )
    assert not empty.calls


def test_hash_routine_acl_does_not_grant_grantee_datagrant_access(plan: GrantPlan) -> None:
    owners = [{"role": "OWNER", "specialGroup": "projectOwners"}]
    session = Session(
        Response(body={"location": "US"}),
        Response(body={"location": "US"}),
        source(owners),
        Response(),
        source(owners),
        Response(),
    )
    DatasetAccessClient(session, grant_project=PROJECT).authorize_hash_routine_if_missing(plan)
    state_access = session.calls[-1][2]["json"]["access"]
    assert session.calls[-1][1] == STATE_URL
    assert state_access == [*owners, ROUTINE_ACL]
    assert PRINCIPAL not in repr(state_access)
    assert all("userByEmail" not in entry for entry in state_access)
    assert all("groupByEmail" not in entry for entry in state_access)
    assert all("iamMember" not in entry for entry in state_access)


TABLE_IAM_URL = f"{TABLE_URL}:getIamPolicy"
ROUTINE_IAM_URL = f"{ROUTINE_URL}:getIamPolicy"
OPERATOR_ACCESS = [
    {"role": "OWNER", "specialGroup": "projectOwners"},
    {"role": "WRITER", "specialGroup": "projectWriters"},
]


def test_hash_acl_refuses_project_readers() -> None:
    session = Session(
        source([*OPERATOR_ACCESS, {"role": "READER", "specialGroup": "projectReaders"}])
    )
    with pytest.raises(GrantError, match="operator-only"):
        DatasetAccessClient(session, grant_project=PROJECT).require_hash_dataset_locked(PROJECT)
    assert session.calls[0][1] == STATE_URL
    assert session.calls[0][0] == "GET"


def test_hash_acl_accepts_operator_only() -> None:
    session = Session(source(OPERATOR_ACCESS))
    DatasetAccessClient(session, grant_project=PROJECT).require_hash_dataset_locked(PROJECT)


def test_hash_object_iam_is_refused() -> None:
    session = Session(
        Response(
            body={"bindings": [{"role": "roles/bigquery.dataViewer", "members": ["projectViewer"]}]}
        ),
        Response(body={"bindings": []}),
    )
    with pytest.raises(GrantError, match="table-level IAM"):
        DatasetAccessClient(session, grant_project=PROJECT).require_hash_object_iam_absent(PROJECT)
    assert session.calls[0][0] == "POST"
    assert session.calls[0][1] == TABLE_IAM_URL


def test_hash_object_iam_absent_when_404() -> None:
    session = Session(Response(status_code=404, body={}), Response(status_code=404, body={}))
    DatasetAccessClient(session, grant_project=PROJECT).require_hash_object_iam_absent(PROJECT)
    assert [url for _, url, _ in session.calls] == [TABLE_IAM_URL, ROUTINE_IAM_URL]
