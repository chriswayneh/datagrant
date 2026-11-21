"""BigQuery CLI --apply: grant issue, approve, revoke, and failure cleanup."""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from test_bigquery_routing import BQ_REQ, MIXED, STORED_PRINCIPAL, _policy, _two_person
from test_bq_grant import FakeClient, _events
from test_bq_revoke import Store

from datagrant import cli
from datagrant.bigquery_support import ADC_CHECKING_MSG, BIGQUERY_PROJECT_ENV
from datagrant.bq.approval import evaluate_approval
from datagrant.bq.grant import GrantError, GrantPlan
from datagrant.bq.revoke import GrantRecord, PendingRequest
from datagrant.bq.state import ApprovalClaim, RequestSnapshot
from datagrant.cli import EXIT_FAILED, EXIT_OK


class ApplyClient(FakeClient):
    """FakeClient plus pending-request methods used by CLI --apply."""

    def __init__(
        self,
        *,
        snapshot: RequestSnapshot | None = None,
        inserted: list[Any] | None = None,
        race_extra: int = 0,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.snapshot = snapshot
        self.inserted = inserted if inserted is not None else []
        self.race_extra = race_extra
        self.grants: dict[str, GrantRecord] = {}
        self.due_requests: list[PendingRequest] = []
        self.requests = self
        self.applied: list[GrantPlan] = []

    def insert_pending(self, row: PendingRequest, principal: str) -> None:
        self.inserted.append((row, principal))
        self.snapshot = RequestSnapshot(row, principal, ())

    def get_pending(self, request_id: str) -> RequestSnapshot | None:
        if self.snapshot and self.snapshot.pending.request_id == request_id:
            return self.snapshot
        return None

    def record_vote(
        self,
        request_id: str,
        policy: Any,
        caller: Any,
        *,
        now: datetime,
        grant_id: str,
    ) -> ApprovalClaim | None:
        snapshot = self.get_pending(request_id)
        if snapshot is None:
            raise GrantError("BigQuery request is no longer pending")
        approval = evaluate_approval(policy, snapshot.pending, caller, snapshot.votes, now=now)
        if not approval.added and not approval.is_final:
            return None
        pending = snapshot.pending
        bumped = PendingRequest(
            pending.request_id, pending.expires_at, pending.facts, pending.revision + 1
        )
        self.snapshot = RequestSnapshot(bumped, snapshot.principal, approval.votes)
        if approval.is_final:
            return ApprovalClaim(request_id, bumped.revision, grant_id, snapshot, approval)
        return None

    def finish_approval(self, claim: Any) -> int:
        self.snapshot = None
        return 1

    def mark_request_failed(self, claim: Any) -> int:
        return 1

    def insert_issuing(self, plan: GrantPlan) -> None:
        super().insert_issuing(plan)
        self.applied.append(plan)
        if self.race_extra:
            self.extra_live += self.race_extra

    def claim_active(self, plan: GrantPlan) -> int:
        n = super().claim_active(plan)
        if n == 1:
            self.grants[plan.grant_id] = GrantRecord(plan, "active", datetime.now(UTC))
        return n

    def mark_failed(self, plan: GrantPlan) -> None:
        super().mark_failed(plan)
        self.grants[plan.grant_id] = GrantRecord(plan, "failed", datetime.now(UTC))

    def get_grant(self, grant_id: str) -> GrantRecord | None:
        return self.grants.get(grant_id)

    def list_grants(self) -> list[GrantRecord]:
        return list(self.grants.values())

    def list_due_requests(self, now: datetime) -> list[PendingRequest]:
        return list(self.due_requests)

    def claim_expired_request(self, row: PendingRequest, now: datetime) -> int:
        self.due_requests = [
            item for item in self.due_requests if item.request_id != row.request_id
        ]
        return 1


class SweepClient(Store):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.due_requests: list[PendingRequest] = []

    def list_due_requests(self, now: datetime) -> list[PendingRequest]:
        return list(self.due_requests)

    def claim_expired_request(self, row: PendingRequest, now: datetime) -> int:
        self.due_requests = [
            item for item in self.due_requests if item.request_id != row.request_id
        ]
        return 1


def _init_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    log = tmp_path / "r.jsonl"
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(log))
    assert cli.main(["keys", "init", "--apply"], lambda s: None) == 0
    return log


def _ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    client: Any,
    *,
    stub_adc: bool = True,
) -> Path:
    monkeypatch.setattr("datagrant.bigquery_support.driver_present", lambda: True)
    if stub_adc:
        monkeypatch.setattr("datagrant.bigquery_support.adc_available", lambda: True)
    monkeypatch.setenv(BIGQUERY_PROJECT_ENV, "clinic-proj")
    monkeypatch.setenv("DATAGRANT_BIGQUERY_LOCATION", "US")
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.delenv("DATAGRANT_SNOWFLAKE_DSN", raising=False)
    log = _init_keys(tmp_path, monkeypatch)

    @contextmanager
    def fake(_args: Any, **_kw: Any) -> Any:
        yield client

    monkeypatch.setattr("datagrant.cli._bq_grant_client", fake)
    return log


def test_request_apply_issues_view_and_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = ApplyClient()
    log = _ready(tmp_path, monkeypatch, client)
    path = _policy(tmp_path)
    out: list[str] = []
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply", "--json"], out.append)
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["status"] == "granted"
    assert body["engine"] == "bigquery"
    assert body["google_principal"] == STORED_PRINCIPAL
    assert body["grant_id"]
    assert body["view"].endswith(f".G_{body['grant_id']}")
    assert client.applied and client.applied[0].principal == STORED_PRINCIPAL
    assert client.applied[0].view_id in client.views
    assert client.status[body["grant_id"]] == "active"
    assert client.dataset_policy.bindings
    assert client.project_policy.bindings
    assert _events(log) == ["issued"]


def test_apply_failure_drops_view_and_unbinds_iam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = ApplyClient(fail_on="bind_iam")
    _ready(tmp_path, monkeypatch, client)
    path = _policy(tmp_path)
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_FAILED
    err = capsys.readouterr().err
    assert "IAM failed" in err or "stub:bind_iam" in err
    assert "drop_view" in client.calls
    assert "unbind_iam" in client.calls
    assert client.calls.index("unbind_iam") < client.calls.index("drop_view")
    assert not client.views
    assert not client.dataset_policy.bindings
    assert not client.project_policy.bindings
    assert all(st == "failed" for st in client.status.values())


def test_two_person_approve_apply_issues_stored_principal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = ApplyClient()
    log = _ready(tmp_path, monkeypatch, client)
    path = _two_person(tmp_path)
    out: list[str] = []
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply", "--json"], out.append)
    assert code == EXIT_OK
    pending = json.loads(out[0])
    assert pending["status"] == "pending"
    assert pending["google_principal"] == STORED_PRINCIPAL
    request_id = pending["request_id"]
    granted: list[str] = []
    code = cli.main(
        [
            "approve",
            request_id,
            "--policy",
            str(path),
            "--as-user",
            "carol",
            "--apply",
            "--json",
        ],
        granted.append,
    )
    assert code == EXIT_OK
    body = json.loads(granted[0])
    assert body["status"] == "granted"
    assert body["google_principal"] == STORED_PRINCIPAL
    assert client.applied and client.applied[0].principal == STORED_PRINCIPAL
    assert "carol@" not in client.applied[0].principal
    assert _events(log) == ["issued"]


def test_apply_cap_race_drops_issuing_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = ApplyClient(race_extra=1)
    _ready(tmp_path, monkeypatch, client)
    yaml = MIXED + "\nmax_concurrent_grants: 1\n"
    path = tmp_path / "cap.yaml"
    path.write_text(yaml)
    path.chmod(0o600)
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_FAILED
    err = capsys.readouterr().err
    assert "concurrent grant cap exceeded" in err
    assert "drop_view" in client.calls
    assert "bind_iam" not in client.calls
    assert "unbind_iam" not in client.calls
    assert not client.views
    assert all(st == "failed" for st in client.status.values())


def test_revoke_apply_covers_issued_grant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = Store()
    row = client.add()
    log = _ready(tmp_path, monkeypatch, client)
    out: list[str] = []
    code = cli.main(
        ["revoke", row.plan.grant_id, "--apply", "--json", "--bigquery-location", "US"],
        out.append,
    )
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["outcome"] == "revoked"
    assert body["engine"] == "bigquery"
    assert row.plan.view_id not in client.views
    assert not client.dataset_policy.bindings
    assert not client.project_policy.bindings
    assert _events(log) == ["revoked"]


def test_sweep_apply_unbinds_failed_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = SweepClient()
    row = client.add(status="failed")
    log = _ready(tmp_path, monkeypatch, client)
    out: list[str] = []
    code = cli.main(
        ["sweep", "--apply", "--json", "--bigquery-location", "US"],
        out.append,
    )
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["engine"] == "bigquery"
    assert body["results"][0]["outcome"] == "revoked"
    assert row.plan.view_id not in client.views
    assert not client.dataset_policy.bindings
    assert not client.project_policy.bindings
    assert _events(log) == ["revoke_failed"]


def test_grant_list_routes_to_bigquery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = ApplyClient()
    _ready(tmp_path, monkeypatch, client)
    path = _policy(tmp_path)
    out: list[str] = []
    assert cli.main([*BQ_REQ, "--policy", str(path), "--apply", "--json"], out.append) == EXIT_OK
    grant_id = json.loads(out[0])["grant_id"]
    listed: list[str] = []
    code = cli.main(["grant", "list", "--json", "--bigquery-location", "US"], listed.append)
    assert code == EXIT_OK
    body = json.loads(listed[0])
    assert body["engine"] == "bigquery"
    assert body["grants"][0]["id"] == grant_id
    assert body["grants"][0]["google_principal"] == STORED_PRINCIPAL


def test_apply_prints_adc_checking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class _User:
        pass

    class _SAMod:
        class Credentials:
            pass

    class _Auth:
        @staticmethod
        def default(request: Any = None) -> tuple[object, str]:
            return _User(), "clinic-proj"

    class _Exc:
        class GoogleAuthError(Exception):
            pass

    def load(name: str) -> Any:
        if name == "google.auth":
            return _Auth
        if name == "google.auth.exceptions":
            return _Exc
        if name == "google.oauth2.service_account":
            return _SAMod
        raise ImportError(name)

    client = ApplyClient()
    _ready(tmp_path, monkeypatch, client, stub_adc=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setattr(
        "datagrant.bigquery_support._well_known_adc_path",
        lambda: tmp_path / "missing-adc.json",
    )
    monkeypatch.setattr("datagrant.bigquery_support.importlib.import_module", load)
    path = _policy(tmp_path)
    out: list[str] = []
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply", "--json"], out.append)
    assert code == EXIT_OK
    err = capsys.readouterr().err
    assert ADC_CHECKING_MSG in err
    assert json.loads(out[0])["status"] == "granted"
    assert "not implemented" not in err
