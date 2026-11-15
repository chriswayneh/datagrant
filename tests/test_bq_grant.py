"""BigQuery grant engine: view SQL, fail-safe apply order, mocked client."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from datagrant.bq.grant import (
    VIEW_DATASET,
    GrantError,
    GrantPlan,
    apply_plan,
    build_plan,
    lit,
    q,
    q_project,
    render_row_filter,
    reverse_drop,
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
    """Records grant RPCs. bind_iam is a 3a stub (3b fills IAM JSON)."""

    def __init__(
        self,
        fail_on: str | None = None,
        names_rowcount: int = 1,
        enabling_rowcount: int = 1,
        active_rowcount: int = 1,
        fail_drop: bool = False,
    ) -> None:
        self.calls: list[str] = []
        self.fail_on = fail_on
        self.fail_drop = fail_drop
        self.authorized = False
        self.authorize_added: list[bool] = []
        self.views: set[str] = set()
        self.status: dict[str, str] = {}
        self.names_rowcount = names_rowcount
        self.enabling_rowcount = enabling_rowcount
        self.active_rowcount = active_rowcount
        self.view_sql: str | None = None

    def _step(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_on == name:
            raise RuntimeError(f"stub:{name}")

    def insert_issuing(self, plan: GrantPlan) -> None:
        self._step("insert_issuing")
        self.status[plan.grant_id] = "issuing"

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

    def bind_iam(self, plan: GrantPlan) -> None:
        self._step("bind_iam")

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
    assert "`datagrant`.`hash_hmac`('bq_clinic', CAST(`SRC`.`ssn` AS STRING))" in sql
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
    assert "`datagrant`.`hash_hmac`" in sql
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


def test_apply_order_iam_last_before_active(tmp_path: Path) -> None:
    client = FakeClient()
    apply_plan(client, _plan(), _sink(tmp_path))
    assert client.calls == [
        "insert_issuing",
        "create_view",
        "authorize",
        "update_names",
        "claim_enabling",
        "bind_iam",
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
    assert "drop_view" in client.calls
    assert "claim_active" not in client.calls
    assert client.authorized is True
    assert "deauthorize" not in client.calls
    assert client.status[GID] == "failed"
    assert _events(tmp_path / "r.jsonl") == ["issued", "revoked"]


def test_cli_apply_still_not_implemented() -> None:
    src = Path("src/datagrant/cli.py").read_text()
    assert "BigQuery grant --apply is not implemented yet" in src
    assert "from datagrant.bq" not in src


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
    assert "drop_view" in client.calls
    assert _events(tmp_path / "r.jsonl") == ["issued", "revoked"]
    sink2 = _sink(tmp_path / "b")
    client2 = FakeClient(active_rowcount=0)
    with pytest.raises(GrantError, match="not enabling after IAM"):
        apply_plan(client2, _plan(), sink2)
    assert "bind_iam" in client2.calls
    assert "drop_view" in client2.calls
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
    assert "mark_failed" in iam.calls
    assert iam.status[GID] == "failed"
    assert _events(tmp_path / "r.jsonl") == ["issued", "revoked"]

    view = FakeClient(fail_on="create_view", fail_drop=True)
    with pytest.raises(GrantError, match=r"stub:create_view.*cleanup failed"):
        apply_plan(view, _plan(), sink)
    assert view.calls.count("drop_view") == 1
    assert "mark_failed" in view.calls
    assert view.status[GID] == "failed"
    assert "bind_iam" not in view.calls

    names = FakeClient(names_rowcount=0, fail_drop=True)
    with pytest.raises(GrantError, match=r"not issuing at row update.*cleanup failed"):
        apply_plan(names, _plan(), sink)
    assert names.calls.count("drop_view") == 1
    assert "mark_failed" in names.calls
    assert names.status[GID] == "failed"
    assert "bind_iam" not in names.calls
    assert "deauthorize" not in names.calls


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
    assert "drop_view" in client.calls
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
    assert "`datagrant`.`hash_hmac`('bq_clinic'" in scoped.view_sql
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
    assert plan.facts.identity == {"source": "local"}
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
    assert "drop_view" in client.calls
