"""Check the assembled client against the lifecycle and SDK boundary."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_bq_dataset_access import AUTHORIZATION, Response, Session, source
from test_bq_grant import GID, NOW, PRINCIPAL, PROJECT, _sink, dec, req
from test_bq_state import SDK, Client

from datagrant.bigquery_support import BigQuerySetupError
from datagrant.bq.client import BigQueryGrantClient, open_grant_client
from datagrant.bq.grant import apply_plan, build_plan, dataset_binding, job_user_binding
from datagrant.bq.revoke import RevokeClient, revoke


class QueryClient(Client):
    def query(self, sql: str, **kwargs: Any) -> "QueryClient":
        kwargs.setdefault("job_config", {})
        super().query(sql, **kwargs)
        return self


def test_issue_and_revoke_through_assembled_client(tmp_path: Path) -> None:
    plan = build_plan(
        dec({"patient_id": "passthrough", "ssn": "redact"}),
        req(), project=PROJECT, principal=PRINCIPAL, grant_id=GID, location="US", now=NOW,
    )
    binding = dataset_binding(plan)
    entry = {
        "role": binding["role"],
        "userByEmail": PRINCIPAL.split(":", 1)[1],
        "condition": binding["condition"],
    }
    session = Session(
        Response(body={"location": "US"}), source([AUTHORIZATION]),
        source([]), Response(),
        Response(body={"version": 1, "etag": "first"}), Response(),
        Response(body={"version": 3, "etag": "second", "bindings": [job_user_binding(plan)]}),
        Response(), source([entry]), Response(),
    )
    sdk = QueryClient()
    client: RevokeClient = BigQueryGrantClient(
        sdk, SDK, session, project=PROJECT, state_location="US"
    )
    sink = _sink(tmp_path)
    apply_plan(client, plan, sink)
    assert "INSERT INTO" in sdk.calls[0][0]
    assert sdk.calls[1][0].startswith("CREATE VIEW ")
    assert sdk.calls[-1][1]["target"] == ("STRING", "active")
    assert len(session.calls) == 6

    row = {name: value for name, (_, value) in sdk.calls[0][1].items()}
    row.update(
        status="active", started_at=NOW, revision=3,
        cleanup_complete=False, cleanup_reason=None, claimed_at=None,
    )
    sdk.rows = [row]
    result = revoke(client, GID, receipts=sink, now=NOW)
    assert result.outcome == "revoked"
    assert result.receipt_error is None
    assert result.cancel_error == "BigQuery grant-specific job cancellation is unavailable"
    assert sdk.calls[-2][0] == f"DROP VIEW IF EXISTS `{plan.view_id}`"
    assert sdk.calls[-1][1]["status"] == ("STRING", "revoked")
    assert session.calls[-3][2]["json"]["policy"]["bindings"] == []
    assert session.calls[-1][2]["json"] == {"access": []}


def test_factory_reuses_credentials_and_closes_both_transports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credentials = object()
    closed = []

    def adc(scopes: list[str]) -> object:
        assert "https://www.googleapis.com/auth/bigquery" in scopes
        assert "https://www.googleapis.com/auth/cloudplatformprojects" in scopes
        return credentials

    def create_sdk(**kwargs: Any) -> SimpleNamespace:
        assert kwargs == {"project": PROJECT, "credentials": credentials}
        return SimpleNamespace(close=lambda: closed.append("sdk"))

    def create_session(creds: object) -> SimpleNamespace:
        assert creds is credentials
        return SimpleNamespace(close=lambda: closed.append("http"))

    monkeypatch.setattr("datagrant.bq.client.load_adc", adc)
    monkeypatch.setattr("datagrant.bq.client.load_client", lambda: SimpleNamespace(Client=create_sdk))
    monkeypatch.setattr(
        "datagrant.bq.client.importlib",
        SimpleNamespace(import_module=lambda _: SimpleNamespace(AuthorizedSession=create_session)),
    )
    with open_grant_client(PROJECT, "US") as client:
        assert isinstance(client, BigQueryGrantClient)
    assert closed == ["http", "sdk"]


def test_missing_adc_does_not_open_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("datagrant.bq.client.load_client", lambda: object())
    monkeypatch.setattr("datagrant.bq.client.load_adc", lambda _: None)
    with pytest.raises(BigQuerySetupError, match="no BigQuery ADC"), open_grant_client(PROJECT, "US"):
        pytest.fail("missing credentials should prevent connection")
