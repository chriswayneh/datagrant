"""BigQuery INFORMATION_SCHEMA inspect and typed null masks."""

from __future__ import annotations

from typing import Any

import pytest
from test_bq_grant import GID, KEY, NOW, PRINCIPAL, PROJECT, dec, req
from test_bq_state import SDK

from datagrant.bq.grant import GrantError, build_plan, view_select_sql
from datagrant.bq.mask import TableCatalog, column_type, inspect_table, sql_type


class _InspectClient:
    def __init__(self, rows: list[Any] | None = None, boom: Exception | None = None) -> None:
        self.rows = rows if rows is not None else [{"column_name": "id", "data_type": "INT64"}]
        self.boom = boom
        self.sql = ""
        self.params: Any = None
        self.kwargs: dict[str, Any] = {}

    def query(self, sql: str, **kwargs: Any) -> _InspectClient:
        if self.boom is not None:
            raise self.boom
        self.sql = sql
        self.kwargs = kwargs
        self.params = kwargs.get("job_config")
        return self

    def result(self, *, timeout: int, job_retry: None) -> list[Any]:
        assert timeout > 0 and job_retry is None
        return list(self.rows)


def test_sql_type_allowlist() -> None:
    assert sql_type("int64") == "INT64"
    assert sql_type(" ARRAY<STRING> ") == "ARRAY<STRING>"
    with pytest.raises(GrantError, match="unsupported column type"):
        sql_type("STRUCT<foo INT64>")
    with pytest.raises(GrantError, match="unsupported column type"):
        sql_type("STRING); DROP TABLE t")
    with pytest.raises(GrantError, match="unsupported column type"):
        sql_type("ARRAY<STRUCT>")


def test_inspect_table_parameterizes_name_and_types_columns() -> None:
    client = _InspectClient(
        [
            {"column_name": "patient_id", "data_type": "INT64"},
            {"column_name": "email", "data_type": "STRING"},
            ("tags", "ARRAY<STRING>"),
        ]
    )
    cat = inspect_table(
        client, SDK, project=PROJECT, dataset="clinic", table="patients", location="US"
    )
    assert cat.columns == {
        "patient_id": "INT64",
        "email": "STRING",
        "tags": "ARRAY<STRING>",
    }
    assert "INFORMATION_SCHEMA" in client.sql
    assert "COLUMNS" in client.sql
    assert "@table_name" in client.sql
    assert "patients" not in client.sql.split("WHERE", 1)[1]
    assert client.params == {"table_name": ("STRING", "patients")}
    assert client.kwargs["job_retry"] is None


def test_inspect_table_missing_or_unsafe_fails_closed() -> None:
    with pytest.raises(GrantError, match="not found"):
        inspect_table(
            _InspectClient([]),
            SDK,
            project=PROJECT,
            dataset="clinic",
            table="missing",
            location="US",
        )
    with pytest.raises(GrantError, match="unsupported column type"):
        inspect_table(
            _InspectClient([("email", "STRING); DROP")]),
            SDK,
            project=PROJECT,
            dataset="clinic",
            table="patients",
            location="US",
        )
    with pytest.raises(GrantError, match="invalid column name"):
        inspect_table(
            _InspectClient([("", "INT64")]),
            SDK,
            project=PROJECT,
            dataset="clinic",
            table="patients",
            location="US",
        )


def test_inspect_provider_error_is_wrapped() -> None:
    with pytest.raises(GrantError, match="catalog inspect failed") as err:
        inspect_table(
            _InspectClient(boom=RuntimeError("SELECT ... patients")),
            SDK,
            project=PROJECT,
            dataset="clinic",
            table="patients",
            location="US",
        )
    assert "patients" not in str(err.value)
    assert err.value.__cause__ is None


def test_column_type_is_case_insensitive() -> None:
    catalog = TableCatalog({"Email": "DATE", "ssn": "STRING"})
    assert column_type(catalog, "email") == "DATE"
    assert column_type(catalog, "SSN") == "STRING"
    sql = view_select_sql(
        req(columns=("email",)),
        {"email": "null"},
        project=PROJECT,
        source_dataset="clinic",
        hash_scope="bq_clinic",
        catalog=catalog,
    )
    assert "CAST(NULL AS DATE) AS `email`" in sql
    with pytest.raises(GrantError, match="ambiguous"):
        column_type(TableCatalog({"email": "STRING", "Email": "DATE"}), "EMAIL")


def test_null_mask_uses_catalog_type() -> None:
    catalog = TableCatalog({"patient_id": "INT64", "ssn": "STRING", "email": "DATE"})
    sql = view_select_sql(
        req(columns=("patient_id", "ssn", "email")),
        {"patient_id": "passthrough", "ssn": "hash", "email": "null"},
        project=PROJECT,
        source_dataset="clinic",
        hash_scope="bq_clinic",
        catalog=catalog,
    )
    assert "CAST(NULL AS DATE) AS `email`" in sql
    assert "CAST(NULL AS STRING) AS `email`" not in sql
    dry = view_select_sql(
        req(columns=("patient_id", "ssn", "email")),
        {"patient_id": "passthrough", "ssn": "hash", "email": "null"},
        project=PROJECT,
        source_dataset="clinic",
        hash_scope="bq_clinic",
    )
    assert "CAST(NULL AS STRING) AS `email`" in dry


def test_build_plan_typed_null_and_missing_column() -> None:
    catalog = TableCatalog({"patient_id": "INT64", "ssn": "BYTES", "email": "BOOL"})
    plan = build_plan(
        dec({"patient_id": "passthrough", "ssn": "hash", "email": "null"}),
        req(columns=("patient_id", "ssn", "email")),
        project=PROJECT,
        principal=PRINCIPAL,
        source_dataset="clinic",
        grant_id=GID,
        now=NOW,
        hash_key=KEY,
        catalog=catalog,
    )
    assert "CAST(NULL AS BOOL) AS `email`" in plan.view_sql
    assert KEY.derived.hex() not in plan.view_sql
    with pytest.raises(GrantError, match="does not exist"):
        build_plan(
            dec(),
            req(),
            project=PROJECT,
            principal=PRINCIPAL,
            source_dataset="clinic",
            grant_id=GID,
            now=NOW,
            hash_key=KEY,
            catalog=TableCatalog({"other": "STRING"}),
        )


def test_catalog_rejects_injected_null_type() -> None:
    with pytest.raises(GrantError, match="unsupported column type"):
        view_select_sql(
            req(columns=("email",)),
            {"email": "null"},
            project=PROJECT,
            source_dataset="clinic",
            hash_scope="bq_clinic",
            catalog=TableCatalog({"email": "STRING); DROP TABLE t"}),
        )


def test_row_filter_missing_catalog_column_fails() -> None:
    with pytest.raises(GrantError, match="row filter columns not in table"):
        view_select_sql(
            req(row_filter="region = 'TX'"),
            {"patient_id": "passthrough", "ssn": "passthrough"},
            project=PROJECT,
            source_dataset="clinic",
            hash_scope="bq_clinic",
            catalog=TableCatalog({"patient_id": "INT64", "ssn": "STRING"}),
        )
