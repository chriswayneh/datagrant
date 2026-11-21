"""Check the assembled client against the lifecycle and SDK boundary."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_bq_dataset_access import AUTHORIZATION, OPERATOR_ACCESS, Response, Session, source
from test_bq_grant import GID, KEY, NOW, PRINCIPAL, PROJECT, _sink, dec, req
from test_bq_state import SDK, Client

from datagrant.bigquery_support import BigQuerySetupError
from datagrant.bq.client import BigQueryGrantClient, open_grant_client
from datagrant.bq.grant import (
    GrantError,
    apply_plan,
    build_plan,
    dataset_binding,
    job_user_binding,
)
from datagrant.bq.revoke import RevokeClient, revoke


class QueryClient(Client):
    def query(self, sql: str, **kwargs: Any) -> "QueryClient":
        kwargs.setdefault("job_config", {})
        if "COUNTIF" in sql:
            self.rows = [{"n": 1, "matched": 1}]
        super().query(sql, **kwargs)
        return self


def test_issue_and_revoke_through_assembled_client(tmp_path: Path) -> None:
    plan = build_plan(
        dec({"patient_id": "passthrough", "ssn": "hash"}),
        req(),
        project=PROJECT,
        principal=PRINCIPAL,
        grant_id=GID,
        location="US",
        now=NOW,
        hash_key=KEY,
    )
    binding = dataset_binding(plan)
    entry = {
        "role": binding["role"],
        "userByEmail": PRINCIPAL.split(":", 1)[1],
        "condition": binding["condition"],
    }
    session = Session(
        source(OPERATOR_ACCESS),
        Response(body={"routineReference": {"routineId": "hash_hmac"}}),
        Response(body={"tableReference": {"tableId": "_hash_master"}}),
        Response(status_code=404, body={}),
        Response(status_code=404, body={}),
        Response(body={"location": "US"}),
        source([AUTHORIZATION]),
        source([]),
        Response(),
        Response(body={"version": 1, "etag": "first"}),
        Response(),
        Response(body={"version": 3, "etag": "second", "bindings": [job_user_binding(plan)]}),
        Response(),
        source([entry]),
        Response(),
    )
    sdk = QueryClient()
    client: RevokeClient = BigQueryGrantClient(
        sdk, SDK, session, project=PROJECT, state_location="US"
    )
    sink = _sink(tmp_path)
    apply_plan(client, plan, sink)
    hex_key = KEY.derived.hex()
    sqls = [sql for sql, _ in sdk.calls]
    assert not any("CREATE TABLE IF NOT EXISTS" in sql for sql in sqls)
    assert not any(sql.startswith("MERGE ") for sql in sqls)
    assert not any("@key" in sql for sql in sqls)
    assert hex_key not in "\n".join(sqls)
    assert sdk.loads == []
    fp = next(sql for sql in sqls if "COUNTIF" in sql)
    assert "@fp" in fp
    insert = next(i for i, sql in enumerate(sqls) if "INSERT INTO" in sql)
    view = next(i for i, sql in enumerate(sqls) if sql.startswith("CREATE VIEW "))
    assert insert < view
    fp_params = next(cfg for sql, cfg in sdk.calls if "COUNTIF" in sql)
    assert list(fp_params) == ["fp"]
    assert fp_params["fp"][0] == "STRING"
    assert hex_key not in str(fp_params)
    assert sdk.calls[-1][1]["target"] == ("STRING", "active")
    assert len(session.calls) == 11
    assert session.calls[0][0:2] == (
        "GET",
        f"https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}/datasets/datagrant",
    )
    assert session.calls[1][0:2] == (
        "GET",
        f"https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}/datasets/datagrant/routines/hash_hmac",
    )
    assert session.calls[2][0:2] == (
        "GET",
        f"https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}/datasets/datagrant/tables/_hash_master",
    )
    assert session.calls[3][0] == "POST"
    assert session.calls[4][0] == "POST"

    insert_params = next(cfg for sql, cfg in sdk.calls if "INSERT INTO" in sql)
    row = {name: value for name, (_, value) in insert_params.items()}
    row.update(
        status="active",
        started_at=NOW,
        revision=3,
        cleanup_complete=False,
        cleanup_reason=None,
        claimed_at=None,
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
    monkeypatch.setattr(
        "datagrant.bq.client.load_client", lambda: SimpleNamespace(Client=create_sdk)
    )
    monkeypatch.setattr(
        "datagrant.bq.client.importlib",
        SimpleNamespace(import_module=lambda _: SimpleNamespace(AuthorizedSession=create_session)),
    )
    with open_grant_client(PROJECT, "US") as client:
        assert isinstance(client, BigQueryGrantClient)
    assert closed == ["http", "sdk"]


def test_setup_hash_rotate_replaces_duplicate_rows() -> None:
    class DupClient(Client):
        def query(self, sql: str, **kwargs: Any) -> "DupClient":
            kwargs.setdefault("job_config", {})
            if "COUNTIF" in sql:
                self.rows = [{"n": 2, "matched": 1}]
            super().query(sql, **kwargs)
            return self

    session = Session(
        source(OPERATOR_ACCESS),
        Response(status_code=404, body={}),
        Response(status_code=404, body={}),
        Response(body={"location": "US"}),
        Response(body={"location": "US"}),
        source(OPERATOR_ACCESS),
        Response(),
        source(OPERATOR_ACCESS),
        Response(),
    )
    sdk = DupClient()
    client = BigQueryGrantClient(sdk, SDK, session, project=PROJECT, state_location="US")
    client.setup_hash(KEY, rotate=True)
    assert sdk.loads
    table, _data, config = sdk.loads[-1]
    assert "_hash_master" in table
    assert config["write_disposition"] == "WRITE_TRUNCATE"
    assert all(field.mode == "REQUIRED" for field in config["schema"])


def test_setup_hash_refuses_duplicate_rows_without_rotate() -> None:
    class DupClient(Client):
        def query(self, sql: str, **kwargs: Any) -> "DupClient":
            kwargs.setdefault("job_config", {})
            if "COUNTIF" in sql:
                self.rows = [{"n": 2, "matched": 1}]
            super().query(sql, **kwargs)
            return self

    session = Session(
        source(OPERATOR_ACCESS),
        Response(status_code=404, body={}),
        Response(status_code=404, body={}),
    )
    sdk = DupClient()
    client = BigQueryGrantClient(sdk, SDK, session, project=PROJECT, state_location="US")
    with pytest.raises(GrantError, match="duplicate rows"):
        client.setup_hash(KEY, rotate=False)
    assert sdk.loads == []


def test_missing_adc_does_not_open_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("datagrant.bq.client.load_client", lambda: object())
    monkeypatch.setattr("datagrant.bq.client.load_adc", lambda _: None)
    with (
        pytest.raises(BigQuerySetupError, match="no BigQuery ADC"),
        open_grant_client(PROJECT, "US"),
    ):
        pytest.fail("missing credentials should prevent connection")
