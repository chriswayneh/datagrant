"""Policy `engine` / optional Snowflake `schema` / BigQuery `location`."""

from __future__ import annotations

import copy
from datetime import timedelta
from typing import Any

import pytest
from test_policy import BASE, doc, table

from datagrant.policy import PolicyError, Request, evaluate, parse_policy


def _snow_ds(**extra: Any) -> dict[str, Any]:
    ds: dict[str, Any] = {
        "name": "snow_clinic",
        "engine": "snowflake",
        "database": "CLINIC_DB",
        "tables": [
            {
                "name": "PUBLIC.PATIENTS",
                "allowed_groups": ["ml"],
                "columns": {"PATIENT_ID": "passthrough", "SSN": "hash"},
            }
        ],
    }
    ds.update(extra)
    return ds


def test_omit_engine_is_postgres() -> None:
    p = parse_policy(doc())
    assert p.datasets["clinic"].engine == "postgres"
    assert p.datasets["clinic"].schema is None


def test_explicit_postgres_engine() -> None:
    d = doc()
    d["datasets"][0]["engine"] = "postgres"
    p = parse_policy(d)
    assert p.datasets["clinic"].engine == "postgres"


def test_snowflake_engine_and_schema() -> None:
    d = doc()
    d["datasets"].append(_snow_ds(schema="PUBLIC"))
    p = parse_policy(d)
    assert p.datasets["clinic"].engine == "postgres"
    snow = p.datasets["snow_clinic"]
    assert snow.engine == "snowflake"
    assert snow.database == "CLINIC_DB"
    assert snow.schema == "PUBLIC"
    assert "PUBLIC.PATIENTS" in snow.tables


def test_mixed_file_evaluates_both_engines() -> None:
    d = doc()
    d["datasets"].append(_snow_ds())
    p = parse_policy(d)
    pg = evaluate(
        p,
        Request(
            "alice",
            "clinic",
            "public.patients",
            ("id",),
            timedelta(hours=1),
            "eval",
            "region = 'west'",
        ),
    )
    sf = evaluate(
        p,
        Request(
            "alice",
            "snow_clinic",
            "PUBLIC.PATIENTS",
            ("PATIENT_ID",),
            timedelta(hours=1),
            "eval",
            None,
        ),
    )
    assert pg.allowed and sf.allowed


@pytest.mark.parametrize(
    ("patch", "msg"),
    [
        ({"engine": "redshift"}, "engine"),
        ({"engine": "Snowflake"}, "engine"),
        ({"engine": ""}, "engine"),
        ({"engine": 1}, "engine"),
        ({"schema": "PUBLIC"}, "schema"),
        ({"location": "US"}, "location"),
    ],
)
def test_invalid_engine_on_postgres_dataset(patch: dict[str, Any], msg: str) -> None:
    d = doc()
    d["datasets"][0].update(patch)
    with pytest.raises(PolicyError, match=msg):
        parse_policy(d)


def test_table_level_engine_is_unknown_key() -> None:
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy(table(engine="snowflake"))


def test_snowflake_invalid_schema() -> None:
    d = doc()
    d["datasets"].append(_snow_ds(schema="PUBLIC;DROP"))
    with pytest.raises(PolicyError, match="schema"):
        parse_policy(d)


def test_unknown_dataset_key_still_errors() -> None:
    d = doc()
    d["datasets"][0]["warehouse"] = "x"
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy(d)


def test_copy_base_still_parses() -> None:
    parse_policy(copy.deepcopy(BASE))


def _bq_ds(**extra: Any) -> dict[str, Any]:
    ds: dict[str, Any] = {
        "name": "bq_clinic",
        "engine": "bigquery",
        "database": "clinic-proj",
        "schema": "clinic_ds",
        "tables": [
            {
                "name": "clinic_ds.patients",
                "allowed_groups": ["ml"],
                "columns": {"patient_id": "passthrough", "ssn": "hash"},
            }
        ],
    }
    ds.update(extra)
    return ds


def test_bigquery_engine_schema_and_location() -> None:
    d = doc()
    d["datasets"].append(_bq_ds(location="US"))
    p = parse_policy(d)
    assert p.datasets["clinic"].engine == "postgres"
    bq = p.datasets["bq_clinic"]
    assert bq.engine == "bigquery"
    assert bq.database == "clinic-proj"
    assert bq.schema == "clinic_ds"
    assert bq.location == "US"
    assert "clinic_ds.patients" in bq.tables


def test_bigquery_three_part_table_matching_project() -> None:
    d = doc()
    d["datasets"].append(
        _bq_ds(
            tables=[
                {
                    "name": "clinic-proj.clinic_ds.patients",
                    "allowed_groups": ["ml"],
                    "columns": {"patient_id": "passthrough"},
                }
            ]
        )
    )
    p = parse_policy(d)
    assert "clinic-proj.clinic_ds.patients" in p.datasets["bq_clinic"].tables


def test_bigquery_three_part_table_wrong_project() -> None:
    d = doc()
    d["datasets"].append(
        _bq_ds(
            tables=[
                {
                    "name": "other-proj.clinic_ds.patients",
                    "allowed_groups": ["ml"],
                    "columns": {"patient_id": "passthrough"},
                }
            ]
        )
    )
    with pytest.raises(PolicyError, match="must match dataset.database"):
        parse_policy(d)


def test_mixed_file_evaluates_postgres_snowflake_bigquery() -> None:
    d = doc()
    d["datasets"].append(_snow_ds())
    d["datasets"].append(_bq_ds())
    p = parse_policy(d)
    pg = evaluate(
        p,
        Request(
            "alice",
            "clinic",
            "public.patients",
            ("id",),
            timedelta(hours=1),
            "eval",
            "region = 'west'",
        ),
    )
    sf = evaluate(
        p,
        Request(
            "alice",
            "snow_clinic",
            "PUBLIC.PATIENTS",
            ("PATIENT_ID",),
            timedelta(hours=1),
            "eval",
            None,
        ),
    )
    bq = evaluate(
        p,
        Request(
            "alice",
            "bq_clinic",
            "clinic_ds.patients",
            ("patient_id",),
            timedelta(hours=1),
            "eval",
            None,
        ),
    )
    assert pg.allowed and sf.allowed and bq.allowed


def test_bigquery_row_filter_needs_filter_columns() -> None:
    d = doc()
    d["datasets"].append(
        _bq_ds(
            tables=[
                {
                    "name": "clinic_ds.patients",
                    "allowed_groups": ["ml"],
                    "columns": {"patient_id": "passthrough"},
                    "row_filters": ["region = 'west'"],
                }
            ]
        )
    )
    with pytest.raises(PolicyError, match="filter_columns"):
        parse_policy(d)


def test_location_refused_on_snowflake() -> None:
    d = doc()
    d["datasets"].append(_snow_ds(location="US"))
    with pytest.raises(PolicyError, match="location"):
        parse_policy(d)


def test_bigquery_invalid_project_id() -> None:
    d = doc()
    d["datasets"].append(_bq_ds(database="Clinic_DB"))
    with pytest.raises(PolicyError, match="GCP project id"):
        parse_policy(d)


def test_bigquery_invalid_location() -> None:
    d = doc()
    d["datasets"].append(_bq_ds(location="us central"))
    with pytest.raises(PolicyError, match="location"):
        parse_policy(d)


def test_bigquery_table_schema_mismatch() -> None:
    d = doc()
    d["datasets"].append(
        _bq_ds(
            tables=[
                {
                    "name": "other_ds.patients",
                    "allowed_groups": ["ml"],
                    "columns": {"patient_id": "passthrough"},
                }
            ]
        )
    )
    with pytest.raises(PolicyError, match="must match dataset.schema"):
        parse_policy(d)


def test_bigquery_one_part_table_name() -> None:
    d = doc()
    d["datasets"].append(
        _bq_ds(
            tables=[
                {
                    "name": "patients",
                    "allowed_groups": ["ml"],
                    "columns": {"patient_id": "passthrough"},
                }
            ]
        )
    )
    with pytest.raises(PolicyError, match="dataset.table"):
        parse_policy(d)
