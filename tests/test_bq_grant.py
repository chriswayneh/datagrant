"""BigQuery grant engine: view SQL, fail-safe apply order, mocked client."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from datagrant.bq.grant import (
    ACCESS_POLICY_VERSION,
    GRANTEE_PERMISSIONS,
    JOB_USER_ROLE,
    VIEW_DATASET,
    ConflictError,
    GrantError,
    GrantPlan,
    IamPolicy,
    _parse_principal,
    _upsert_binding,
    apply_bind,
    apply_plan,
    apply_unbind,
    build_plan,
    dataset_binding,
    identity_with_principal,
    job_user_binding,
    lit,
    q,
    q_project,
    render_row_filter,
    resolve_google_principal,
    reverse_drop,
    view_resource_name,
    view_select_sql,
)
from datagrant.keys import HashKey, init_keys, load_signing_key
from datagrant.pg.grant import ReceiptSink
from datagrant.policy import Decision, Request

NOW = datetime(2026, 11, 14, 23, 0, tzinfo=UTC)
KEY = HashKey("0123456789abcdef", bytes.fromhex("aa" * 32))
GID = "abcdef012345"
PROJECT = "clinic-proj"
PRINCIPAL = "user:alice@example.com"


def req(**kw: object) -> Request:
    base: dict[str, object] = {
        "requester": "alice",
        "dataset": "bq_clinic",
        "table": "clinic.patients",
        "columns": ("patient_id", "ssn"),
        "duration": timedelta(hours=2),
        "purpose": "eval",
        "row_filter": None,
    }
    base.update(kw)
    return Request(**base)  # type: ignore[arg-type]


def dec(masks: dict[str, str] | None = None, **kw: object) -> Decision:
    base: dict[str, object] = {
        "allowed": True,
        "reasons": ("ok",),
        "approval": "auto",
        "policy_sha256": "f" * 64,
        "masks": masks or {"patient_id": "passthrough", "ssn": "hash"},
        "hash_scope": "bq_clinic",
        "policy_version": 1,
    }
    base.update(kw)
    return Decision(**base)  # type: ignore[arg-type]


class FakeClient:
    """Records grant RPCs. bind_iam applies IAM JSON with etag RMW."""

    def __init__(
        self,
        fail_on: str | None = None,
        names_rowcount: int = 1,
        enabling_rowcount: int = 1,
        active_rowcount: int = 1,
        fail_drop: bool = False,
        raise_after_bind: bool = False,
        conflict_dataset: int = 0,
        conflict_project: int = 0,
        extra_live: int = 0,
        missing_hash_objects: bool = False,
    ) -> None:
        self.calls: list[str] = []
        self.fail_on = fail_on
        self.fail_drop = fail_drop
        self.raise_after_bind = raise_after_bind
        self.authorized = False
        self.authorize_added: list[bool] = []
        self.views: set[str] = set()
        self.status: dict[str, str] = {}
        self.names_rowcount = names_rowcount
        self.enabling_rowcount = enabling_rowcount
        self.active_rowcount = active_rowcount
        self.view_sql: str | None = None
        self.dataset_policy = IamPolicy(etag='W/"1"')
        self.project_policy = IamPolicy(etag='W/"1"')
        self.conflict_dataset = conflict_dataset
        self.conflict_project = conflict_project
        self.iam_versions: list[int] = []
        self.iam_etags: list[str] = []
        self.extra_live = extra_live
        self.hash_sqls: list[str] = []
        self.hash_params: list[bytes] = []
        self.views_access: list[dict[str, Any]] = []
        self.state_access: list[dict[str, Any]] = []
        self.missing_hash_objects = missing_hash_objects

    def _step(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_on == name:
            raise RuntimeError(f"stub:{name}")

    def ensure_hash(self, plan: GrantPlan) -> None:
        from datagrant.bq.hash import (
            bind_hash_key_sql,
            create_hash_hmac_sql,
            create_hash_table_sql,
            create_hmac_helpers_sql,
            hash_routine_entry,
            uses_hash_mask,
        )

        self._step("ensure_hash")
        self.hash_sqls.append(create_hash_table_sql(plan.project))
        self.hash_sqls.extend(create_hmac_helpers_sql(plan.project))
        self.hash_sqls.append(create_hash_hmac_sql(plan.project))
        if plan.hash_key is not None:
            sql = bind_hash_key_sql(plan.project)
            self.hash_sqls.append(sql)
            self.hash_params.append(plan.hash_key.derived)
            if plan.hash_key.derived.hex() in "\n".join(self.hash_sqls):
                raise GrantError("hash key leaked into SQL text")
        if uses_hash_mask(plan) and self.missing_hash_objects:
            raise GrantError("BigQuery hash_hmac routine is unavailable")
        entry = {"routine": hash_routine_entry(plan.project)}
        if entry not in self.views_access:
            self.views_access.append(dict(entry))
        if entry not in self.state_access:
            self.state_access.append(dict(entry))

    def insert_issuing(self, plan: GrantPlan) -> None:
        self._step("insert_issuing")
        self.status[plan.grant_id] = "issuing"

    def count_live_grants(self, requester: str, principal: str | None = None) -> int:
        n = sum(1 for st in self.status.values() if st in {"issuing", "enabling", "active"})
        return n + self.extra_live

    def create_view(self, plan: GrantPlan) -> None:
        self._step("create_view")
        self.views.add(plan.view_id)
        self.view_sql = plan.view_sql

    def authorize_views_dataset_if_missing(self, plan: GrantPlan) -> bool:
        self._step("authorize")
        added = not self.authorized
        self.authorized = True
        self.authorize_added.append(added)
        return added

    def update_names(self, plan: GrantPlan) -> int:
        self._step("update_names")
        if self.status.get(plan.grant_id) != "issuing":
            return 0
        return self.names_rowcount

    def claim_enabling(self, plan: GrantPlan) -> int:
        self._step("claim_enabling")
        if self.status.get(plan.grant_id) != "issuing":
            return 0
        if self.enabling_rowcount != 1:
            return self.enabling_rowcount
        self.status[plan.grant_id] = "enabling"
        return 1

    def _iam_get(self, stored: IamPolicy, name: str, access_policy_version: int) -> IamPolicy:
        self.calls.append(name)
        self.iam_versions.append(access_policy_version)
        return IamPolicy(
            etag=stored.etag,
            bindings=copy.deepcopy(stored.bindings),
            version=stored.version,
        )

    def _iam_set(
        self,
        attr: str,
        name: str,
        policy: IamPolicy,
        *,
        access_policy_version: int,
        conflict_attr: str,
    ) -> None:
        self.calls.append(name)
        self.iam_versions.append(access_policy_version)
        self.iam_etags.append(policy.etag)
        if self.fail_on == name:
            raise RuntimeError(f"stub:{name}")
        if not policy.etag:
            raise RuntimeError("etag omitted")
        stored: IamPolicy = getattr(self, attr)
        left = getattr(self, conflict_attr)
        if left > 0:
            setattr(self, conflict_attr, left - 1)
            stored.etag = 'W/"2"'
            raise ConflictError("409")
        if policy.etag != stored.etag:
            raise ConflictError("409")
        setattr(
            self,
            attr,
            IamPolicy(
                etag=policy.etag,
                bindings=copy.deepcopy(policy.bindings),
                version=policy.version,
            ),
        )

    def get_dataset_iam(
        self, project: str, dataset: str, *, access_policy_version: int
    ) -> IamPolicy:
        return self._iam_get(self.dataset_policy, "get_dataset_iam", access_policy_version)

    def set_dataset_iam(
        self, project: str, dataset: str, policy: IamPolicy, *, access_policy_version: int
    ) -> None:
        self._iam_set(
            "dataset_policy",
            "set_dataset_iam",
            policy,
            access_policy_version=access_policy_version,
            conflict_attr="conflict_dataset",
        )

    def get_project_iam(self, project: str, *, access_policy_version: int) -> IamPolicy:
        return self._iam_get(self.project_policy, "get_project_iam", access_policy_version)

    def set_project_iam(
        self, project: str, policy: IamPolicy, *, access_policy_version: int
    ) -> None:
        self._iam_set(
            "project_policy",
            "set_project_iam",
            policy,
            access_policy_version=access_policy_version,
            conflict_attr="conflict_project",
        )

    def bind_iam(self, plan: GrantPlan) -> None:
        self._step("bind_iam")
        apply_bind(self, plan)
        if self.raise_after_bind:
            raise RuntimeError("stub:bind_after")

    def unbind_iam(self, plan: GrantPlan) -> None:
        self.calls.append("unbind_iam")
        if self.fail_on == "unbind_iam":
            raise RuntimeError("stub:unbind_iam")
        apply_unbind(self, plan)

    def claim_active(self, plan: GrantPlan) -> int:
        self._step("claim_active")
        if self.status.get(plan.grant_id) != "enabling":
            return 0
        if self.active_rowcount != 1:
            return self.active_rowcount
        self.status[plan.grant_id] = "active"
        return 1

    def drop_view(self, plan: GrantPlan) -> None:
        self.calls.append("drop_view")
        if self.fail_drop:
            raise RuntimeError("stub:drop_view")
        self.views.discard(plan.view_id)

    def mark_failed(self, plan: GrantPlan) -> None:
        self.calls.append("mark_failed")
        self.status[plan.grant_id] = "failed"


def _sink(tmp_path: Path) -> ReceiptSink:
    _, sp, _ = init_keys(tmp_path / "keys")
    return ReceiptSink(tmp_path / "r.jsonl", load_signing_key(sp), host="test")


def _plan(**kw: Any) -> GrantPlan:
    return build_plan(
        dec(),
        req(),
        project=PROJECT,
        principal=PRINCIPAL,
        source_dataset="clinic",
        grant_id=GID,
        now=NOW,
        hash_key=KEY,
        **kw,
    )


def _assert_cleanup(client: FakeClient, *, unbind: bool) -> None:
    assert "drop_view" in client.calls
    assert "mark_failed" in client.calls
    if unbind:
        assert client.calls.index("unbind_iam") < client.calls.index("drop_view")
    else:
        assert "unbind_iam" not in client.calls
    assert client.calls.index("drop_view") < client.calls.index("mark_failed")


def unlit(sql: str) -> str:
    """Decode a GoogleSQL string literal produced by lit()."""
    if len(sql) < 2 or sql[0] != "'" or sql[-1] != "'":
        raise AssertionError(f"not a literal: {sql!r}")
    body = sql[1:-1]
    out: list[str] = []
    i = 0
    escapes = {
        "\\": "\\",
        "'": "'",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "b": "\b",
        "f": "\f",
        "v": "\v",
    }
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= len(body):
            raise AssertionError("dangling backslash")
        nxt = body[i + 1]
        if nxt == "x":
            out.append(chr(int(body[i + 2 : i + 4], 16)))
            i += 4
            continue
        if nxt == "u":
            out.append(chr(int(body[i + 2 : i + 6], 16)))
            i += 6
            continue
        out.append(escapes[nxt])
        i += 2
    return "".join(out)


def _events(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        json.loads(line)["receipt"]["event"]
        for line in path.read_text().splitlines()
        if line.strip()
    ]


def test_view_sql_src_hash_hmac_no_key_bytes() -> None:
    plan = _plan()
    sql = plan.view_sql
    assert plan.view_id == f"{PROJECT}.{VIEW_DATASET}.G_{GID}"
    assert f"FROM `{PROJECT}`.`clinic`.`patients` AS `SRC`" in sql
    assert f"`{PROJECT}`.`datagrant`.`hash_hmac`(" in sql
    assert f"`{PROJECT}`.`datagrant`.`hash_hmac`('bq_clinic', CAST(`SRC`.`ssn` AS STRING))" in sql
    assert KEY.derived.hex() not in sql
    assert KEY.derived.hex() not in plan.view_id
    assert "google.cloud" not in Path("src/datagrant/bq/grant.py").read_text()


def test_five_masks() -> None:
    columns = ("id", "ssn", "note", "acct", "email")
    masks = {
        "id": "passthrough",
        "ssn": "hash",
        "note": "redact",
        "acct": "partial",
        "email": "null",
    }
    sql = view_select_sql(
        req(columns=columns),
        masks,
        project=PROJECT,
        source_dataset="clinic",
        hash_scope="bq_clinic",
    )
    assert "`SRC`.`id` AS `id`" in sql
    assert f"`{PROJECT}`.`datagrant`.`hash_hmac`(" in sql
    assert "'[REDACTED]' AS `note`" in sql
    assert "REPEAT('*'" in sql and "RIGHT(" in sql
    assert "CAST(NULL AS STRING) AS `email`" in sql
    assert KEY.derived.hex() not in sql


def test_row_filter_uses_src_alias() -> None:
    plan = build_plan(
        dec(),
        req(row_filter="region = 'TX' AND deceased IS NULL"),
        project=PROJECT,
        principal=PRINCIPAL,
        source_dataset="clinic",
        grant_id=GID,
        now=NOW,
        hash_key=KEY,
    )
    assert "WHERE `SRC`.`region` = 'TX' AND `SRC`.`deceased` IS NULL" in plan.view_sql
    apostrophe, _ = render_row_filter("name = 'O''Brien'")
    assert apostrophe == r"`SRC`.`name` = 'O\'Brien'"
    slash_quote, _ = render_row_filter("path = 'a\\''b'")
    assert slash_quote == r"`SRC`.`path` = 'a\\\'b'"
    cond, cols = render_row_filter("flag = true OR n != 1")
    assert cond == "`SRC`.`flag` = TRUE OR `SRC`.`n` <> 1"
    assert cols == frozenset({"flag", "n"})
    notnull, _ = render_row_filter("region IS NOT NULL")
    assert notnull == "`SRC`.`region` IS NOT NULL"
    nested, _ = render_row_filter("(a = 1)")
    assert nested == "(`SRC`.`a` = 1)"
    with pytest.raises(GrantError, match="unsupported|expected"):
        view_select_sql(
            req(row_filter="!!!"),
            {"patient_id": "passthrough", "ssn": "passthrough"},
            project=PROJECT,
            source_dataset="clinic",
            hash_scope="bq_clinic",
        )


def test_denied_cannot_plan() -> None:
    with pytest.raises(GrantError, match="denied"):
        build_plan(dec(allowed=False), req(), project=PROJECT, principal=PRINCIPAL)


@pytest.mark.parametrize("kwargs", [{}, {"approvers": ()}])
def test_two_person_plan_requires_an_approver(kwargs: dict[str, Any]) -> None:
    with pytest.raises(GrantError, match="two-person approval: the grant needs an approver"):
        build_plan(
            dec(approval="two-person"),
            req(),
            project=PROJECT,
            principal=PRINCIPAL,
            hash_key=KEY,
            **kwargs,
        )


def test_two_person_apply_rejects_unapproved_facts_before_any_rpc(tmp_path: Path) -> None:
    plan = _plan()
    assert plan.facts is not None
    unapproved = replace(plan, facts=replace(plan.facts, approval="two-person", approvers=()))
    client = FakeClient()
    sink = _sink(tmp_path)
    with pytest.raises(GrantError, match="two-person approval: the grant needs an approver"):
        apply_plan(client, unapproved, sink)
    assert client.calls == []
    assert client.views == set()
    assert client.status == {}
    assert not sink.log.exists()


def test_two_person_approved_plan_still_activates(tmp_path: Path) -> None:
    plan = build_plan(
        dec(approval="two-person"),
        req(),
        project=PROJECT,
        principal=PRINCIPAL,
        grant_id=GID,
        now=NOW,
        hash_key=KEY,
        approvers=("bob",),
    )
    client = FakeClient()
    apply_plan(client, plan, _sink(tmp_path))
    assert client.status[GID] == "active"
    entry = json.loads((tmp_path / "r.jsonl").read_text().splitlines()[0])
    assert entry["receipt"]["approvers"] == ["bob"]


def test_apply_order_iam_last_before_active(tmp_path: Path) -> None:
    client = FakeClient()
    apply_plan(client, _plan(), _sink(tmp_path))
    assert client.calls == [
        "ensure_hash",
        "insert_issuing",
        "create_view",
        "authorize",
        "update_names",
        "claim_enabling",
        "bind_iam",
        "get_dataset_iam",
        "set_dataset_iam",
        "get_project_iam",
        "set_project_iam",
        "claim_active",
    ]
    assert client.status[GID] == "active"
    assert client.authorize_added == [True]
    assert _events(tmp_path / "r.jsonl") == ["issued"]
    idx_names = client.calls.index("update_names")
    idx_iam = client.calls.index("bind_iam")
    idx_active = client.calls.index("claim_active")
    assert idx_names < idx_iam < idx_active


def test_second_grant_skips_authorize(tmp_path: Path) -> None:
    client = FakeClient()
    sink = _sink(tmp_path)
    apply_plan(client, _plan(), sink)
    other = build_plan(
        dec(),
        req(),
        project=PROJECT,
        principal=PRINCIPAL,
        source_dataset="clinic",
        grant_id="bbbbbb000000",
        now=NOW,
        hash_key=KEY,
    )
    apply_plan(client, other, sink)
    assert client.authorize_added == [True, False]
    assert client.authorized is True
    assert client.status[GID] == "active"
    assert client.status["bbbbbb000000"] == "active"


def test_reverse_drop_on_view_failure_keeps_authorized_dataset(tmp_path: Path) -> None:
    client = FakeClient(fail_on="create_view")
    with pytest.raises(GrantError, match="failed"):
        apply_plan(client, _plan(), _sink(tmp_path))
    assert "drop_view" in client.calls
    assert "mark_failed" in client.calls
    assert "bind_iam" not in client.calls
    assert "deauthorize" not in client.calls
    assert client.authorized is False
    assert GID not in client.views or not client.views
    assert client.status[GID] == "failed"


def test_zero_row_names_update_drops_view_not_dataset(tmp_path: Path) -> None:
    client = FakeClient(names_rowcount=0)
    with pytest.raises(GrantError, match="not issuing at row update"):
        apply_plan(client, _plan(), _sink(tmp_path))
    assert client.calls.index("create_view") < client.calls.index("drop_view")
    assert "bind_iam" not in client.calls
    assert client.authorized is True
    assert "deauthorize" not in client.calls
    assert client.status[GID] == "failed"
    assert _events(tmp_path / "r.jsonl") == []


def test_receipt_failure_drops_view_no_iam(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from datagrant import receipt as rec

    def boom(*_a: Any, **_k: Any) -> None:
        raise rec.ReceiptError("disk full")

    monkeypatch.setattr(rec, "append", boom)
    client = FakeClient()
    with pytest.raises(GrantError, match="receipt not written"):
        apply_plan(client, _plan(), _sink(tmp_path))
    assert "drop_view" in client.calls
    assert "bind_iam" not in client.calls
    assert client.authorized is True
    assert "deauthorize" not in client.calls
    assert client.status[GID] == "failed"


def test_iam_failure_after_issued_drops_view_writes_revoked(tmp_path: Path) -> None:
    client = FakeClient(fail_on="bind_iam")
    with pytest.raises(GrantError, match="IAM failed"):
        apply_plan(client, _plan(), _sink(tmp_path))
    assert "claim_active" not in client.calls
    assert client.authorized is True
    assert "deauthorize" not in client.calls
    _assert_cleanup(client, unbind=True)
    assert client.status[GID] == "failed"
    assert _events(tmp_path / "r.jsonl") == ["issued", "revoked"]


def test_cli_apply_is_wired() -> None:
    src = Path("src/datagrant/cli.py").read_text()
    assert "BigQuery grant --apply is not implemented yet" not in src


def test_plan_guards_and_quoting() -> None:
    with pytest.raises(GrantError, match="google principal"):
        build_plan(dec(), req(), project=PROJECT, principal="  ")
    with pytest.raises(GrantError, match="control"):
        build_plan(dec(), req(purpose="bad\nline"), project=PROJECT, principal=PRINCIPAL)
    with pytest.raises(GrantError, match="12 lowercase"):
        build_plan(
            dec(), req(), project=PROJECT, principal=PRINCIPAL, grant_id="ZZ", now=NOW, hash_key=KEY
        )
    with pytest.raises(GrantError, match="timezone-aware"):
        build_plan(
            dec(),
            req(),
            project=PROJECT,
            principal=PRINCIPAL,
            now=datetime(2026, 1, 1),
            hash_key=KEY,
        )
    with pytest.raises(GrantError, match="hash key"):
        build_plan(dec(), req(), project=PROJECT, principal=PRINCIPAL, now=NOW)
    with pytest.raises(GrantError, match="unsafe identifier"):
        q("clinic-proj")
    assert q_project(PROJECT) == "`clinic-proj`"
    with pytest.raises(GrantError, match="unsafe GCP project"):
        q_project("1bad")
    assert lit("O'Brien") == r"'O\'Brien'"
    assert lit("foo\\'bar") == r"'foo\\\'bar'"
    assert lit("a\nb") == r"'a\nb'"
    assert lit("\r\t\b\f\v\x01\x7f") == r"'\r\t\b\f\v\x01\x7f'"
    assert "''" not in lit("O'Brien")
    with pytest.raises(GrantError, match="needs a dataset"):
        build_plan(
            dec(masks={"id": "passthrough"}),
            req(table="patients", columns=("id",)),
            project=PROJECT,
            principal=PRINCIPAL,
            now=NOW,
        )


def test_missing_receipts_or_facts_drop_view(tmp_path: Path) -> None:
    client = FakeClient()
    with pytest.raises(GrantError, match="issued receipt is required"):
        apply_plan(client, _plan(), receipts=None)
    assert "drop_view" in client.calls
    assert "bind_iam" not in client.calls
    plan = _plan()
    bare = GrantPlan(
        plan.grant_id,
        plan.view_id,
        plan.view_sql,
        plan.project,
        plan.source_dataset,
        plan.source_table,
        plan.principal,
        plan.expires_at,
        plan.location,
        None,
        plan.hash_key,
    )
    client2 = FakeClient()
    with pytest.raises(GrantError, match="no receipt facts"):
        apply_plan(client2, bare, _sink(tmp_path))
    assert "drop_view" in client2.calls


def test_zero_row_enabling_and_active_reverse_drop(tmp_path: Path) -> None:
    sink = _sink(tmp_path)
    client = FakeClient(enabling_rowcount=0)
    with pytest.raises(GrantError, match="not issuing at IAM"):
        apply_plan(client, _plan(), sink)
    assert "bind_iam" not in client.calls
    _assert_cleanup(client, unbind=False)
    assert _events(tmp_path / "r.jsonl") == ["issued", "revoked"]
    sink2 = _sink(tmp_path / "b")
    client2 = FakeClient(active_rowcount=0)
    with pytest.raises(GrantError, match="not enabling after IAM"):
        apply_plan(client2, _plan(), sink2)
    assert "bind_iam" in client2.calls
    _assert_cleanup(client2, unbind=True)
    assert client2.authorized is True
    assert _events(tmp_path / "b" / "r.jsonl") == ["issued", "revoked"]


def test_reverse_drop_helper_does_not_deauthorize() -> None:
    client = FakeClient()
    client.authorized = True
    reverse_drop(client, _plan())
    assert client.calls == ["drop_view", "mark_failed"]
    assert client.authorized is True


def test_reverse_drop_marks_failed_if_drop_view_raises() -> None:
    client = FakeClient(fail_drop=True)
    with pytest.raises(GrantError, match="drop_view failed"):
        reverse_drop(client, _plan())
    assert client.calls == ["drop_view", "mark_failed"]
    assert client.status[GID] == "failed"
    assert client.authorized is False


def test_cleanup_drop_view_failure_keeps_mark_failed_and_revoked(tmp_path: Path) -> None:
    sink = _sink(tmp_path)
    iam = FakeClient(fail_on="bind_iam", fail_drop=True)
    with pytest.raises(GrantError, match=r"IAM failed.*cleanup failed"):
        apply_plan(iam, _plan(), sink)
    assert iam.calls.count("drop_view") == 1
    _assert_cleanup(iam, unbind=True)
    assert iam.status[GID] == "failed"
    assert _events(tmp_path / "r.jsonl") == ["issued", "revoked"]

    view = FakeClient(fail_on="create_view", fail_drop=True)
    with pytest.raises(GrantError, match=r"stub:create_view.*cleanup failed"):
        apply_plan(view, _plan(), sink)
    assert view.calls.count("drop_view") == 1
    _assert_cleanup(view, unbind=False)
    assert view.status[GID] == "failed"
    assert "bind_iam" not in view.calls

    names = FakeClient(names_rowcount=0, fail_drop=True)
    with pytest.raises(GrantError, match=r"not issuing at row update.*cleanup failed"):
        apply_plan(names, _plan(), sink)
    assert names.calls.count("drop_view") == 1
    _assert_cleanup(names, unbind=False)
    assert names.status[GID] == "failed"
    assert "bind_iam" not in names.calls
    assert "deauthorize" not in names.calls


def test_unbind_cleanup_failure_sets_cleanup_failed_on_revoked(tmp_path: Path) -> None:
    sink = _sink(tmp_path)
    client = FakeClient(raise_after_bind=True, fail_on="unbind_iam")
    with pytest.raises(GrantError, match="cleanup failed"):
        apply_plan(client, _plan(), sink)
    revoked = [
        json.loads(line)["receipt"]
        for line in (tmp_path / "r.jsonl").read_text().splitlines()
        if json.loads(line)["receipt"]["event"] == "revoked"
    ]
    assert revoked[0]["details"]["cleanup_failed"] is True
    assert "unbind_iam" in str(revoked[0]["details"]["error"])


def test_insert_and_authorize_failures(tmp_path: Path) -> None:
    sink = _sink(tmp_path)
    client = FakeClient(fail_on="insert_issuing")
    with pytest.raises(GrantError, match="stub:insert_issuing"):
        apply_plan(client, _plan(), sink)
    assert "drop_view" not in client.calls
    client2 = FakeClient(fail_on="authorize")
    with pytest.raises(GrantError, match="stub:authorize"):
        apply_plan(client2, _plan(), sink)
    assert "drop_view" in client2.calls
    assert "bind_iam" not in client2.calls
    assert "deauthorize" not in client2.calls


def test_bind_iam_keyboardinterrupt_still_drops_view(tmp_path: Path) -> None:
    class Boom(FakeClient):
        def bind_iam(self, plan: GrantPlan) -> None:
            self.calls.append("bind_iam")
            raise KeyboardInterrupt

    client = Boom()
    with pytest.raises(KeyboardInterrupt):
        apply_plan(client, _plan(), _sink(tmp_path))
    _assert_cleanup(client, unbind=True)
    assert client.status[GID] == "failed"


def test_keyboardinterrupt_cleanup_failure_reraises(tmp_path: Path) -> None:
    class Boom(FakeClient):
        def bind_iam(self, plan: GrantPlan) -> None:
            self.calls.append("bind_iam")
            apply_bind(self, plan)
            raise KeyboardInterrupt

    client = Boom(fail_drop=True)
    with pytest.raises(KeyboardInterrupt):
        apply_plan(client, _plan(), _sink(tmp_path))
    _assert_cleanup(client, unbind=True)
    assert client.status[GID] == "failed"


def test_unknown_mask_and_passthrough_omits_key() -> None:
    with pytest.raises(GrantError, match="unknown mask"):
        view_select_sql(
            req(columns=("id",)),
            {"id": "rotate"},
            project=PROJECT,
            source_dataset="clinic",
            hash_scope="bq_clinic",
        )
    plan = build_plan(
        dec(masks={"patient_id": "passthrough"}),
        req(columns=("patient_id",)),
        project=PROJECT,
        principal=PRINCIPAL,
        source_dataset="clinic",
        grant_id=GID,
        now=NOW,
        hash_key=KEY,
        location="US",
    )
    assert plan.hash_key is None
    assert plan.location == "US"
    assert "`SRC`.`patient_id`" in plan.view_sql


def test_generated_grant_id_and_dataset_default() -> None:
    plan = build_plan(
        dec(masks={"patient_id": "passthrough"}),
        req(table="patients", columns=("patient_id",)),
        project=PROJECT,
        principal=PRINCIPAL,
        source_dataset="clinic",
        now=NOW,
    )
    assert len(plan.grant_id) == 12
    assert f"`{PROJECT}`.`clinic`.`patients`" in plan.view_sql
    scoped = build_plan(
        dec(hash_scope=None),
        req(),
        project=PROJECT,
        principal=PRINCIPAL,
        source_dataset="clinic",
        grant_id=GID,
        now=NOW,
        hash_key=KEY,
    )
    assert f"`{PROJECT}`.`datagrant`.`hash_hmac`('bq_clinic'" in scoped.view_sql
    timed = build_plan(
        dec(masks={"patient_id": "passthrough"}),
        req(columns=("patient_id",)),
        project=PROJECT,
        principal=PRINCIPAL,
        source_dataset="clinic",
    )
    assert timed.expires_at.tzinfo is not None


def test_row_filter_errors() -> None:
    with pytest.raises(Exception, match="column name"):
        render_row_filter("and = 1")
    with pytest.raises(Exception, match="NULL"):
        render_row_filter("region IS")
    with pytest.raises(Exception, match="NULL"):
        render_row_filter("region IS X")
    with pytest.raises(Exception, match="operator|end of filter"):
        render_row_filter("region")
    with pytest.raises(Exception, match="literal|end of filter"):
        render_row_filter("region =")
    with pytest.raises(Exception, match="literal"):
        render_row_filter("region = foo")
    with pytest.raises(Exception, match="unexpected token"):
        render_row_filter("region = 1 extra")
    with pytest.raises(Exception, match="nested too deeply"):
        render_row_filter("(" * 20 + "a = 1" + ")" * 20)
    with pytest.raises(Exception, match="expected '\\)'"):
        render_row_filter("(a = 1")


def test_hash_key_leak_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("datagrant.bq.grant.view_select_sql", lambda *_a, **_k: KEY.derived.hex())
    with pytest.raises(GrantError, match="leaked"):
        _plan()


def test_identity_on_facts() -> None:
    plan = build_plan(
        dec(masks={"patient_id": "passthrough"}),
        req(columns=("patient_id",)),
        project=PROJECT,
        principal=PRINCIPAL,
        source_dataset="clinic",
        grant_id=GID,
        now=NOW,
        requester_identity={"source": "local"},
        approver_identities=({"source": "local"},),
        approvers=("bob",),
    )
    assert plan.facts is not None
    assert plan.facts.identity == {"source": "local", "google_principal": PRINCIPAL}
    assert plan.facts.approver_identities == ({"source": "local"},)
    assert plan.facts.approvers == ("bob",)


def test_revoked_receipt_failure_is_swallowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datagrant import receipt as rec

    real = rec.append

    def flaky(log: Path, event: str, *a: Any, **k: Any) -> None:
        if event == "revoked":
            raise rec.ReceiptError("sink down")
        real(log, event, *a, **k)

    monkeypatch.setattr(rec, "append", flaky)
    client = FakeClient(fail_on="bind_iam")
    with pytest.raises(GrantError, match="IAM failed"):
        apply_plan(client, _plan(), _sink(tmp_path))
    assert _events(tmp_path / "r.jsonl") == ["issued"]
    _assert_cleanup(client, unbind=True)


def test_lit_round_trip() -> None:
    cases = ["O'Brien", "'x'", "'", "\\", *[n * "'" for n in range(2, 7)], "foo\\'bar"]
    for raw in cases:
        encoded = lit(raw)
        assert encoded.startswith("'") and encoded.endswith("'")
        assert unlit(encoded) == raw
    for raw in ("a\nb", "\rX", "\t", "\x01", "\x7f", "\u2028", "\u2029", "\u0085"):
        assert unlit(lit(raw)) == raw
    assert lit("\u2028") == r"'\u2028'"
    assert lit("\u2029") == r"'\u2029'"
    assert lit("\u0085") == r"'\u0085'"


def test_resolve_google_principal_identity_first() -> None:
    assert resolve_google_principal(mapped="user:map@example.com") == "user:map@example.com"
    assert (
        resolve_google_principal(flag="user:map@example.com", mapped="user:map@example.com")
        == "user:map@example.com"
    )
    with pytest.raises(GrantError, match="does not match identity"):
        resolve_google_principal(flag="user:flag@example.com", mapped="user:map@example.com")
    with pytest.raises(GrantError, match="does not match identity"):
        resolve_google_principal(
            flag="user:other@example.com",
            oidc_email="Alice@Example.com",
            identity_mode="oidc",
        )
    assert resolve_google_principal(oidc_email="Alice@Example.com") == "user:alice@example.com"
    assert (
        resolve_google_principal(
            flag="user:alice@example.com",
            oidc_email="Alice@Example.com",
            identity_mode="oidc",
        )
        == "user:alice@example.com"
    )
    with pytest.raises(GrantError, match="must not contain ':'"):
        resolve_google_principal(oidc_email="group:eng@example.com", identity_mode="oidc")
    with pytest.raises(GrantError, match="google principal is required"):
        resolve_google_principal(identity_mode="oidc")
    with pytest.raises(GrantError, match="google principal is required"):
        resolve_google_principal(flag="user:alice@example.com", identity_mode="oidc")
    with pytest.raises(GrantError, match="must be user:"):
        resolve_google_principal(flag="group:eng@example.com")
    with pytest.raises(GrantError, match="must be user:"):
        resolve_google_principal(flag="serviceAccount:sa@proj.iam.gserviceaccount.com")
    assert resolve_google_principal(flag="user:alice@example.com") == "user:alice@example.com"
    assert (
        resolve_google_principal(flag="group:eng@example.com", mapped="group:eng@example.com")
        == "group:eng@example.com"
    )
    with pytest.raises(GrantError, match="google principal is required"):
        resolve_google_principal()
    with pytest.raises(GrantError, match="unsupported identity mode"):
        resolve_google_principal(flag="user:alice@example.com", identity_mode="ldap")
    with pytest.raises(GrantError, match="unsupported identity mode"):
        resolve_google_principal(mapped="user:map@example.com", identity_mode="saml")


def test_parse_principal_null_fails_closed() -> None:
    with pytest.raises(GrantError, match="google principal is required"):
        _parse_principal(None)
    with pytest.raises(GrantError, match="google principal is required"):
        _parse_principal(123)
    with pytest.raises(GrantError, match="google principal is required"):
        _parse_principal(b"user:alice@example.com")


def test_identity_with_principal_pins_canonical_member() -> None:
    assert identity_with_principal({"source": "os"}, PRINCIPAL) == {
        "source": "os",
        "google_principal": PRINCIPAL,
    }
    assert identity_with_principal(None, PRINCIPAL) == {"google_principal": PRINCIPAL}


def test_principal_allowlist() -> None:
    ok = (
        "user:alice@example.com",
        "serviceAccount:sa@clinic-proj.iam.gserviceaccount.com",
        "group:eng@example.com",
    )
    for principal in ok:
        plan = build_plan(
            dec(masks={"patient_id": "passthrough"}),
            req(columns=("patient_id",)),
            project=PROJECT,
            principal=principal,
            source_dataset="clinic",
            grant_id=GID,
            now=NOW,
        )
        assert plan.principal == principal
    mixed = build_plan(
        dec(masks={"patient_id": "passthrough"}),
        req(columns=("patient_id",)),
        project=PROJECT,
        principal="USER:Alice@Example.com",
        source_dataset="clinic",
        grant_id=GID,
        now=NOW,
    )
    assert mixed.principal == "user:alice@example.com"
    sa = build_plan(
        dec(masks={"patient_id": "passthrough"}),
        req(columns=("patient_id",)),
        project=PROJECT,
        principal="SERVICEACCOUNT:sa@clinic-proj.iam.gserviceaccount.com",
        source_dataset="clinic",
        grant_id=GID,
        now=NOW,
    )
    assert sa.principal == "serviceAccount:sa@clinic-proj.iam.gserviceaccount.com"
    for bad in ("allUsers", "allAuthenticatedUsers", "domain:example.com"):
        with pytest.raises(GrantError, match="refused google principal"):
            build_plan(
                dec(masks={"patient_id": "passthrough"}),
                req(columns=("patient_id",)),
                project=PROJECT,
                principal=bad,
                source_dataset="clinic",
                now=NOW,
            )
    for bad in (
        "user:not-an-email",
        "user:alice@",
        "user:@example.com",
        "user:a@b@c",
        "user:alice!@example.com",
        "user:alice@exam_ple.com",
        "user:a@b..com",
        "user:a@-b.com",
        "user:.a@b.com",
    ):
        with pytest.raises(GrantError, match="email is invalid"):
            build_plan(
                dec(masks={"patient_id": "passthrough"}),
                req(columns=("patient_id",)),
                project=PROJECT,
                principal=bad,
                source_dataset="clinic",
                now=NOW,
            )
    plus = build_plan(
        dec(masks={"patient_id": "passthrough"}),
        req(columns=("patient_id",)),
        project=PROJECT,
        principal="user:alice+ml@example.com",
        source_dataset="clinic",
        grant_id=GID,
        now=NOW,
    )
    assert plus.principal == "user:alice+ml@example.com"
    apostrophe = build_plan(
        dec(masks={"patient_id": "passthrough"}),
        req(columns=("patient_id",)),
        project=PROJECT,
        principal="user:o'brien@example.com",
        source_dataset="clinic",
        grant_id=GID,
        now=NOW,
    )
    assert apostrophe.principal == "user:o'brien@example.com"
    for bad in ("alice@example.com", "principal://x", "user:"):
        with pytest.raises(GrantError, match="principal"):
            build_plan(
                dec(masks={"patient_id": "passthrough"}),
                req(columns=("patient_id",)),
                project=PROJECT,
                principal=bad,
                source_dataset="clinic",
                now=NOW,
            )


def test_principal_rejects_unicode_casefold_homoglyphs() -> None:
    kwargs = {
        "project": PROJECT,
        "source_dataset": "clinic",
        "now": NOW,
    }
    with pytest.raises(GrantError, match="email is invalid"):
        build_plan(
            dec(masks={"patient_id": "passthrough"}),
            req(columns=("patient_id",)),
            principal="user:\u212aelvin@example.com",
            **kwargs,
        )
    plan = build_plan(
        dec(masks={"patient_id": "passthrough"}),
        req(columns=("patient_id",)),
        principal="user:Kelvin@example.com",
        grant_id=GID,
        **kwargs,
    )
    assert plan.principal == "user:kelvin@example.com"


def test_mixed_case_iam_members_bind_and_unbind() -> None:
    plan = _plan()
    client = FakeClient()
    mixed_ds = dict(dataset_binding(plan))
    mixed_ds["members"] = ["user:Alice@Example.com"]
    mixed_job = dict(job_user_binding(plan))
    mixed_job["members"] = ["user:Alice@Example.com"]
    client.dataset_policy = IamPolicy(etag='W/"1"', bindings=[mixed_ds])
    client.project_policy = IamPolicy(etag='W/"1"', bindings=[mixed_job])
    apply_unbind(client, plan)
    assert client.dataset_policy.bindings == []
    assert client.project_policy.bindings == []
    apply_bind(client, plan)
    assert client.dataset_policy.bindings[0]["members"] == [plan.principal]
    assert client.project_policy.bindings[0]["members"] == [plan.principal]


def test_unbind_iam_on_bind_attempt(tmp_path: Path) -> None:
    sink = _sink(tmp_path)
    lost = FakeClient(active_rowcount=0)
    with pytest.raises(GrantError, match="not enabling after IAM"):
        apply_plan(lost, _plan(), sink)
    _assert_cleanup(lost, unbind=True)
    assert lost.calls.count("unbind_iam") == 1

    after = FakeClient(raise_after_bind=True)
    with pytest.raises(GrantError, match="IAM failed"):
        apply_plan(after, _plan(), sink)
    _assert_cleanup(after, unbind=True)
    assert after.calls.index("bind_iam") < after.calls.index("unbind_iam")

    drop = FakeClient(fail_on="bind_iam", fail_drop=True)
    with pytest.raises(GrantError, match=r"IAM failed.*cleanup failed"):
        apply_plan(drop, _plan(), sink)
    _assert_cleanup(drop, unbind=True)
    assert drop.calls.count("drop_view") == 1
    assert drop.status[GID] == "failed"


def test_client_grant_error_still_cleans_up(tmp_path: Path) -> None:
    class Boom(FakeClient):
        def create_view(self, plan: GrantPlan) -> None:
            self.calls.append("create_view")
            raise GrantError("client boom")

    client = Boom()
    with pytest.raises(GrantError, match="client boom"):
        apply_plan(client, _plan(), _sink(tmp_path))
    _assert_cleanup(client, unbind=False)


def test_cleanup_error_does_not_duplicate_grant_prefix(tmp_path: Path) -> None:
    client = FakeClient(fail_on="bind_iam", fail_drop=True)
    with pytest.raises(GrantError, match=r"^grant abcdef012345: IAM failed") as ei:
        apply_plan(client, _plan(), _sink(tmp_path))
    msg = str(ei.value)
    assert msg.count("grant abcdef012345:") == 1
    assert "cleanup failed" in msg


def _titles(policy: IamPolicy) -> list[str]:
    return [str((b.get("condition") or {}).get("title")) for b in policy.bindings]


def test_iam_json_one_view_no_tables_get(tmp_path: Path) -> None:
    client = FakeClient()
    plan = _plan()
    apply_plan(client, plan, _sink(tmp_path))
    assert all(v == ACCESS_POLICY_VERSION for v in client.iam_versions)
    ds = client.dataset_policy.bindings
    ju = client.project_policy.bindings
    assert len(ds) == 1 and len(ju) == 1
    expr = ds[0]["condition"]["expression"]
    resource = view_resource_name(PROJECT, GID)
    assert resource == f"projects/{PROJECT}/datasets/datagrant_views/tables/G_{GID}"
    assert f'resource.name == "{resource}"' in expr
    assert expr.count("/tables/G_") == 1
    assert 'resource.type == "bigquery.googleapis.com/Table"' in expr
    assert "request.time < timestamp(" in expr
    assert "tables.get" not in json.dumps(ds)
    assert "bigquery.tables.get" not in GRANTEE_PERMISSIONS
    assert GRANTEE_PERMISSIONS == ("bigquery.tables.getData",)
    assert ju[0]["role"] == JOB_USER_ROLE
    assert ju[0]["condition"]["title"] == f"G_{GID}"
    assert ds[0]["condition"]["title"] == f"G_{GID}"
    assert "resource.name" not in ju[0]["condition"]["expression"]
    assert ju[0]["condition"]["expression"].startswith("request.time < timestamp(")
    blob = json.dumps(ds) + json.dumps(ju)
    assert KEY.derived.hex() not in blob
    bind = dataset_binding(plan)
    job = job_user_binding(plan)
    assert bind["members"] == [PRINCIPAL]
    assert job["members"] == [PRINCIPAL]
    assert bind["role"] == f"projects/{PROJECT}/roles/datagrantViewGetData"


def test_two_grants_two_jobuser_titles(tmp_path: Path) -> None:
    client = FakeClient()
    sink = _sink(tmp_path)
    apply_plan(client, _plan(), sink)
    other = build_plan(
        dec(),
        req(),
        project=PROJECT,
        principal=PRINCIPAL,
        source_dataset="clinic",
        grant_id="bbbbbb000000",
        now=NOW,
        hash_key=KEY,
    )
    apply_plan(client, other, sink)
    titles = _titles(client.project_policy)
    assert titles == [f"G_{GID}", "G_bbbbbb000000"]
    ds_expr = [b["condition"]["expression"] for b in client.dataset_policy.bindings]
    assert ds_expr[0].count("G_abcdef012345") == 1
    assert "G_bbbbbb000000" not in ds_expr[0]
    assert "G_abcdef012345" not in ds_expr[1]
    apply_unbind(client, _plan())
    assert _titles(client.project_policy) == ["G_bbbbbb000000"]
    assert _titles(client.dataset_policy) == ["G_bbbbbb000000"]
    apply_unbind(client, _plan())
    assert _titles(client.project_policy) == ["G_bbbbbb000000"]


def test_unbind_idempotent_when_no_bindings() -> None:
    client = FakeClient()
    apply_unbind(client, _plan())
    apply_unbind(client, _plan())
    assert client.dataset_policy.bindings == []
    assert client.project_policy.bindings == []
    assert client.calls.count("set_dataset_iam") == 0
    assert client.calls.count("set_project_iam") == 0


def test_unbind_project_failure_still_removes_dataset(tmp_path: Path) -> None:
    client = FakeClient()
    apply_plan(client, _plan(), _sink(tmp_path))
    assert _titles(client.dataset_policy) == [f"G_{GID}"]
    assert _titles(client.project_policy) == [f"G_{GID}"]
    client.fail_on = "set_project_iam"
    with pytest.raises(
        GrantError, match=r"project jobUser unbind failed \(stub:set_project_iam\)"
    ) as ei:
        apply_unbind(client, _plan())
    msg = str(ei.value)
    assert msg.count("grant abcdef012345:") == 1
    assert "dataset unbind failed" not in msg
    assert _titles(client.dataset_policy) == []
    assert _titles(client.project_policy) == [f"G_{GID}"]
    assert "set_dataset_iam" in client.calls


def test_etag_409_retries_once_with_fresh_etag(tmp_path: Path) -> None:
    client = FakeClient(conflict_dataset=1, conflict_project=1)
    apply_plan(client, _plan(), _sink(tmp_path))
    assert client.dataset_policy.bindings
    assert client.project_policy.bindings
    assert client.calls.count("get_dataset_iam") == 2
    assert client.calls.count("set_dataset_iam") == 2
    assert client.calls.count("get_project_iam") == 2
    assert client.calls.count("set_project_iam") == 2
    assert all(v == ACCESS_POLICY_VERSION for v in client.iam_versions)
    assert client.iam_etags == ['W/"1"', 'W/"2"', 'W/"1"', 'W/"2"']
    stuck = FakeClient(conflict_dataset=5)
    with pytest.raises(GrantError, match="etag conflict after 2"):
        apply_plan(stuck, _plan(), _sink(tmp_path / "b"))
    assert stuck.calls.count("set_dataset_iam") == 2
    assert stuck.calls.count("get_dataset_iam") >= 2


def test_upsert_checks_every_duplicate_title() -> None:
    plan = _plan()
    ours = dataset_binding(plan)
    clash = {
        "role": "roles/bigquery.dataViewer",
        "members": ["user:ops@example.com"],
        "condition": {"title": f"G_{GID}", "expression": "true"},
    }
    policy = IamPolicy(etag='W/"1"', bindings=[copy.deepcopy(ours), copy.deepcopy(clash)])
    with pytest.raises(GrantError, match="IAM condition title G_abcdef012345 already in use"):
        _upsert_binding(policy, dataset_binding(plan))
    assert policy.bindings[0]["members"] == [PRINCIPAL]
    assert policy.bindings[1] == clash


def test_clashing_title_bind_refuses_and_leaves_operator_binding(tmp_path: Path) -> None:
    client = FakeClient()
    clash = {
        "role": "roles/bigquery.dataViewer",
        "members": ["user:ops@example.com"],
        "condition": {"title": f"G_{GID}", "expression": "true"},
    }
    client.dataset_policy.bindings.append(copy.deepcopy(clash))
    with pytest.raises(GrantError, match="IAM condition title G_abcdef012345 already in use"):
        apply_plan(client, _plan(), _sink(tmp_path))
    assert client.dataset_policy.bindings == [clash]
    assert client.project_policy.bindings == []


def test_unbind_keeps_matching_binding_with_extra_member(tmp_path: Path) -> None:
    client = FakeClient()
    apply_plan(client, _plan(), _sink(tmp_path))
    extra = "user:ops@example.com"
    client.dataset_policy.bindings[0]["members"].append(extra)
    client.project_policy.bindings[0]["members"].append(extra)
    apply_unbind(client, _plan())
    assert client.dataset_policy.bindings[0]["members"] == [extra]
    assert client.project_policy.bindings[0]["members"] == [extra]
    assert _titles(client.dataset_policy) == [f"G_{GID}"]
    assert _titles(client.project_policy) == [f"G_{GID}"]


def test_conditional_binding_cap_is_named() -> None:
    class Cap(FakeClient):
        def set_dataset_iam(
            self, project: str, dataset: str, policy: IamPolicy, *, access_policy_version: int
        ) -> None:
            self.calls.append("set_dataset_iam")
            raise RuntimeError(
                "The number of IAM Conditions for this principal exceeds the limit of 20"
            )

    client = Cap()
    with pytest.raises(GrantError, match="per-principal conditional-binding cap"):
        apply_bind(client, _plan())


def test_apply_plan_rechecks_concurrent_cap_by_requester(tmp_path: Path) -> None:
    client = FakeClient(extra_live=1)
    with pytest.raises(GrantError, match="concurrent grant cap exceeded"):
        apply_plan(client, _plan(), _sink(tmp_path), max_concurrent=1)
    assert client.calls[:2] == ["ensure_hash", "insert_issuing"]
    assert "drop_view" in client.calls
    assert "bind_iam" not in client.calls
    ok = FakeClient()
    apply_plan(ok, _plan(), _sink(tmp_path / "ok"), max_concurrent=1)
    assert ok.status[GID] == "active"
