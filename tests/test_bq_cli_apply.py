"""BigQuery CLI --apply: grant issue, approve, revoke, and failure cleanup."""

from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from test_bigquery_routing import BQ_REQ, MIXED, STORED_PRINCIPAL, _policy, _two_person
from test_bq_grant import GID, FakeClient, _events, _plan
from test_bq_revoke import Store

from datagrant import cli
from datagrant.bigquery_support import ADC_CHECKING_MSG, BIGQUERY_PROJECT_ENV
from datagrant.bq.approval import evaluate_approval
from datagrant.bq.grant import GrantError, GrantPlan, apply_bind
from datagrant.bq.revoke import GRACE, GrantRecord, PendingRequest, RevokeResult
from datagrant.bq.state import ApprovalClaim, RequestSnapshot, VoteResult
from datagrant.cli import EXIT_FAILED, EXIT_OK, EXIT_RECEIPT, EXIT_REVOKE_FAILED
from datagrant.sink import SinkConfig, SinkError


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
        self.lose_claim = False

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
    ) -> VoteResult:
        snapshot = self.get_pending(request_id)
        if snapshot is None:
            raise GrantError("BigQuery request is no longer pending")
        approval = evaluate_approval(policy, snapshot.pending, caller, snapshot.votes, now=now)
        counts = VoteResult(len(approval.votes), approval.required, approval.added)
        if not approval.added and not approval.is_final:
            return counts
        pending = snapshot.pending
        bumped = PendingRequest(
            pending.request_id, pending.expires_at, pending.facts, pending.revision + 1
        )
        self.snapshot = RequestSnapshot(bumped, snapshot.principal, approval.votes)
        if approval.is_final:
            return VoteResult(
                counts.recorded,
                counts.required,
                counts.added,
                ApprovalClaim(request_id, bumped.revision, grant_id, snapshot, approval),
            )
        return counts

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

    def claim_revoke(self, row: GrantRecord, reason: Any, now: datetime) -> int:
        current = self.grants.get(row.plan.grant_id)
        if (
            self.lose_claim
            or current is None
            or current.revision != row.revision
            or current.status != row.status
        ):
            return 0
        self.grants[row.plan.grant_id] = replace(
            current,
            status="revoking",
            revision=row.revision + 1,
            cleanup_reason=reason,
            claimed_at=now,
        )
        self.status[row.plan.grant_id] = "revoking"
        return 1

    def finish_revoke(self, grant_id: str, revision: int, status: str) -> int:
        current = self.grants.get(grant_id)
        if current is None or current.revision != revision or current.status != "revoking":
            return 0
        self.grants[grant_id] = replace(
            current, status=status, cleanup_complete=True, claimed_at=None, revision=revision + 1
        )
        self.status[grant_id] = status
        return 1

    def release_revoke(self, grant_id: str, revision: int, error: str) -> None:
        row = self.grants.get(grant_id)
        if row is not None and row.revision == revision and row.status == "revoking":
            self.grants[grant_id] = replace(row, claimed_at=None, revision=revision + 1)

    def cancel_jobs(self, plan: GrantPlan) -> int:
        return 0

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
    assert body["approvals_recorded"] == 1
    assert body["approvals_required"] == 1
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


_UNSET = object()


def _store_row(
    client: Store,
    grant_id: str,
    status: str,
    *,
    started_at: datetime | None = None,
    expires_at: Any = _UNSET,
) -> GrantRecord:
    base = _plan()
    plan = replace(
        base,
        grant_id=grant_id,
        view_id=base.view_id.replace(GID, grant_id),
        expires_at=base.expires_at if expires_at is _UNSET else expires_at,
    )
    row = GrantRecord(plan, status, started_at or datetime.now(UTC))
    client.rows[grant_id] = row
    client.status[grant_id] = status
    client.views.add(plan.view_id)
    if expires_at is not None:
        apply_bind(client, plan)
    return row


def test_required_sink_failure_after_active_revokes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Boom:
        name = "boom"

        def deliver(self, line: bytes) -> None:
            raise SinkError("down")

        def head(self) -> None:
            return None

    client = ApplyClient()
    _ready(tmp_path, monkeypatch, client)
    monkeypatch.setattr(cli, "_remote", lambda args: SinkConfig(Boom(), "required"))
    path = _policy(tmp_path)
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"])
    err = capsys.readouterr().err
    assert code == EXIT_RECEIPT
    assert "grant revoked" in err
    assert "STILL ACTIVE" not in err
    assert "Traceback" not in err
    assert not client.views
    assert not client.dataset_policy.bindings
    assert not client.project_policy.bindings
    assert client.grants
    row = next(iter(client.grants.values()))
    assert row.status == "revoked"


def test_sweep_dry_run_lists_failed_stale_and_revoking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = SweepClient()
    _store_row(client, "aaaaaaaaaaaa", "failed")
    _store_row(client, "bbbbbbbbbbbb", "issuing", started_at=datetime.now(UTC) - GRACE)
    _store_row(client, "cccccccccccc", "revoking")
    _store_row(
        client,
        "dddddddddddd",
        "active",
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    _store_row(client, "eeeeeeeeeeee", "issuing", started_at=datetime.now(UTC))
    _ready(tmp_path, monkeypatch, client)
    out: list[str] = []
    code = cli.main(["sweep", "--json", "--bigquery-location", "US"], out.append)
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert set(body["would_revoke"]) == {
        "aaaaaaaaaaaa",
        "bbbbbbbbbbbb",
        "cccccccccccc",
        "dddddddddddd",
    }


def test_sweep_null_expiry_skips_and_revokes_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = SweepClient()
    valid = client.add()
    _store_row(client, "012345abcdef", "active", expires_at=None)
    _ready(tmp_path, monkeypatch, client)
    out: list[str] = []
    code = cli.main(
        ["sweep", "--apply", "--json", "--bigquery-location", "US"],
        out.append,
    )
    err = capsys.readouterr().err
    assert "TypeError" not in err
    assert "Traceback" not in err
    assert code == EXIT_REVOKE_FAILED
    body = json.loads(out[0])
    by_id = {item["grant_id"]: item for item in body["results"]}
    assert by_id[GID]["outcome"] == "revoked"
    assert by_id["012345abcdef"]["outcome"] == "failed"
    assert by_id["012345abcdef"]["error"] == "invalid grant record"
    assert client.rows[GID].status == "expired"
    assert valid.plan.view_id not in client.views
    assert client.rows["012345abcdef"].status == "active"


def _bad_row(client: Store, **fields: Any) -> str:
    gid = "012345abcdef"
    valid = next(iter(client.rows.values()))
    plan = replace(valid.plan, grant_id=gid, view_id=valid.plan.view_id.replace(GID, gid))
    row = replace(GrantRecord(plan, "active", datetime.now(UTC)), **fields)
    client.rows[gid] = row
    client.status[gid] = "active"
    return gid


@pytest.mark.parametrize(
    "fields",
    [
        {"claimed_at": datetime.now().replace(tzinfo=None)},
        {"claimed_at": "2026-01-01T00:00:00Z"},
        {"revision": "0"},
    ],
)
def test_sweep_skips_bad_claimed_at_or_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fields: dict[str, Any],
) -> None:
    client = SweepClient()
    valid = client.add()
    bad_id = _bad_row(client, **fields)
    _ready(tmp_path, monkeypatch, client)
    dry: list[str] = []
    dry_code = cli.main(["sweep", "--json", "--bigquery-location", "US"], dry.append)
    dry_err = capsys.readouterr().err
    assert dry_code == EXIT_FAILED
    assert "TypeError" not in dry_err
    assert "Traceback" not in dry_err
    dry_body = json.loads(dry[0])
    assert bad_id in dry_body["invalid_grants"]
    assert GID not in dry_body["invalid_grants"]
    assert GID in dry_body["would_revoke"]

    out: list[str] = []
    code = cli.main(
        ["sweep", "--apply", "--json", "--bigquery-location", "US"],
        out.append,
    )
    err = capsys.readouterr().err
    assert "TypeError" not in err
    assert "Traceback" not in err
    assert code == EXIT_REVOKE_FAILED
    body = json.loads(out[0])
    by_id = {item["grant_id"]: item for item in body["results"]}
    assert by_id[GID]["outcome"] == "revoked"
    assert by_id[bad_id]["outcome"] == "failed"
    assert by_id[bad_id]["error"] == "invalid grant record"
    assert client.rows[GID].status == "expired"
    assert valid.plan.view_id not in client.views
    assert client.rows[bad_id].status == "active"


def test_required_sink_failure_revoke_failed_stays_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Boom:
        name = "boom"

        def deliver(self, line: bytes) -> None:
            raise SinkError("down token=sekrit-token")

        def head(self) -> None:
            return None

    client = ApplyClient()
    client.lose_claim = True
    _ready(tmp_path, monkeypatch, client)
    monkeypatch.setattr(cli, "_remote", lambda args: SinkConfig(Boom(), "required"))
    path = _policy(tmp_path)
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"])
    err = capsys.readouterr().err
    assert code == EXIT_RECEIPT
    assert "STILL ACTIVE" in err
    assert "sekrit-token" not in err
    assert "Traceback" not in err
    assert client.grants
    row = next(iter(client.grants.values()))
    assert row.status == "active"
    assert client.views
    assert client.dataset_policy.bindings
    assert client.project_policy.bindings


def test_grant_list_and_status_warn_invalid_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = SweepClient()
    row = client.add()
    client.invalid_grant_results = [
        RevokeResult("012345abcdef", "failed", "manual", error="invalid grant record")
    ]
    _ready(tmp_path, monkeypatch, client)
    listed: list[str] = []
    code = cli.main(["grant", "list", "--json", "--bigquery-location", "US"], listed.append)
    assert code == EXIT_OK
    list_err = capsys.readouterr().err
    assert "skipped 1 invalid grant record" in list_err
    assert json.loads(listed[0])["grants"][0]["id"] == row.plan.grant_id
    status: list[str] = []
    assert (
        cli.main(
            ["grant", "status", row.plan.grant_id, "--json", "--bigquery-location", "US"],
            status.append,
        )
        == EXIT_OK
    )
    status_err = capsys.readouterr().err
    assert "skipped 1 invalid grant record" in status_err


def test_sweep_revoke_exception_labels_class_on_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = SweepClient()
    client.add()
    _ready(tmp_path, monkeypatch, client)

    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise TypeError("token=sekrit-token")

    monkeypatch.setattr("datagrant.bq.revoke.revoke", boom)
    out: list[str] = []
    code = cli.main(
        ["sweep", "--apply", "--json", "--bigquery-location", "US"],
        out.append,
    )
    err = capsys.readouterr().err
    assert code == EXIT_REVOKE_FAILED
    assert "Traceback" not in err
    assert "sekrit-token" not in err
    body = json.loads(out[0])
    assert body["results"][0]["error"] == "revoke error: TypeError"
    assert client.rows[GID].status == "active"


def test_sweep_non_row_error_says_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Boom(SweepClient):
        def list_grants(self) -> list[GrantRecord]:
            raise RuntimeError("token=sekrit-token")

    client = Boom()
    _ready(tmp_path, monkeypatch, client)
    dry_code = cli.main(["sweep", "--bigquery-location", "US"])
    dry_err = capsys.readouterr().err
    assert dry_code == EXIT_FAILED
    assert "BigQuery sweep failed" in dry_err
    assert "Traceback" not in dry_err
    assert "sekrit-token" not in dry_err
    assert "RuntimeError" not in dry_err

    code = cli.main(["sweep", "--apply", "--bigquery-location", "US"])
    err = capsys.readouterr().err
    assert code == EXIT_FAILED
    assert "BigQuery sweep failed" in err
    assert "Traceback" not in err
    assert "sekrit-token" not in err
    assert "RuntimeError" not in err


def test_setup_bigquery_dry_run_and_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = ApplyClient()
    _ready(tmp_path, monkeypatch, client)
    out: list[str] = []
    dry = cli.main(["setup", "bigquery", "--json"], out.append)
    assert dry == EXIT_OK
    assert json.loads(out[0])["dry_run"] is True
    assert "setup_hash" not in client.calls
    applied: list[str] = []
    code = cli.main(["setup", "bigquery", "--apply", "--json"], applied.append)
    assert code == EXIT_OK
    assert json.loads(applied[0])["status"] == "ready"
    assert client.calls.count("setup_hash") == 1
    assert client.hash_loads


def test_setup_refuses_project_readers_and_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from test_bq_hash import DEFAULT_READERS

    blocked = ApplyClient()
    blocked.hash_access = DEFAULT_READERS
    _ready(tmp_path / "blocked", monkeypatch, blocked)
    code = cli.main(["setup", "bigquery", "--apply"])
    err = capsys.readouterr().err
    assert code == EXIT_FAILED
    assert "operator-only" in err
    assert blocked.hash_loads == []

    mismatch = ApplyClient(hash_mismatch=True)
    _ready(tmp_path / "mismatch", monkeypatch, mismatch)
    code = cli.main(["setup", "bigquery", "--apply"])
    err = capsys.readouterr().err
    assert code == EXIT_FAILED
    assert "rotate explicitly" in err
    assert mismatch.hash_loads == []

    rotated = ApplyClient(hash_mismatch=True)
    _ready(tmp_path / "rotated", monkeypatch, rotated)
    out: list[str] = []
    code = cli.main(
        ["setup", "bigquery", "--rotate-hash-key", "--apply", "--json"],
        out.append,
    )
    rotate_err = capsys.readouterr().err
    assert code == EXIT_OK
    assert "changes every pseudonym" in rotate_err
    assert "0 live hash grant(s)" in rotate_err
    assert rotated.hash_loads


def test_rotate_refuses_live_hash_grants_unless_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    blocked = ApplyClient()
    blocked.live_hash_grants = 2
    _ready(tmp_path / "blocked", monkeypatch, blocked)
    code = cli.main(["setup", "bigquery", "--rotate-hash-key", "--apply"])
    err = capsys.readouterr().err
    assert code == EXIT_FAILED
    assert "2 live hash grant(s)" in err
    assert "pass --force" in err
    assert blocked.hash_loads == []

    forced = ApplyClient()
    forced.live_hash_grants = 2
    _ready(tmp_path / "forced", monkeypatch, forced)
    out: list[str] = []
    code = cli.main(
        ["setup", "bigquery", "--rotate-hash-key", "--force", "--apply", "--json"],
        out.append,
    )
    force_err = capsys.readouterr().err
    assert code == EXIT_OK
    assert "2 live hash grant(s)" in force_err
    assert json.loads(out[0])["live_hash_grants"] == 2
    assert forced.hash_loads


def test_cli_inspect_uses_source_project_not_grant_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    yaml = MIXED.replace(
        "  - name: bq_clinic\n    engine: bigquery\n    database: clinic-proj",
        "  - name: bq_clinic\n    engine: bigquery\n    database: source-proj",
    )
    path = tmp_path / "cross.yaml"
    path.write_text(yaml)
    path.chmod(0o600)
    client = ApplyClient()
    _ready(tmp_path, monkeypatch, client)
    code = cli.main([*BQ_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_OK
    assert "inspect_table" in client.calls
    assert client.inspect_project == "source-proj"
    assert client.inspect_project != "clinic-proj"


def test_cli_inspect_types_null_mask_case_insensitive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datagrant.bq.mask import TableCatalog

    yaml = MIXED.replace(
        "columns: {patient_id: passthrough, ssn: hash}",
        'columns: {patient_id: passthrough, ssn: hash, email: "null"}',
    )
    path = tmp_path / "null.yaml"
    path.write_text(yaml)
    path.chmod(0o600)
    client = ApplyClient()
    client.catalog = TableCatalog({"Patient_ID": "INT64", "ssn": "STRING", "Email": "DATE"})
    _ready(tmp_path, monkeypatch, client)
    code = cli.main(
        [
            *BQ_REQ,
            "--columns",
            "patient_id,email",
            "--policy",
            str(path),
            "--apply",
        ]
    )
    assert code == EXIT_OK
    assert "inspect_table" in client.calls
    assert client.view_sql is not None
    assert "CAST(NULL AS DATE) AS `email`" in client.view_sql
    assert "CAST(NULL AS STRING) AS `email`" not in client.view_sql
