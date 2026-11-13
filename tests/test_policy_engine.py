"""Policy `engine` / optional Snowflake `schema` (M4 construction PR 1)."""

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
        ({"engine": "bigquery"}, "engine"),
        ({"engine": "Snowflake"}, "engine"),
        ({"engine": ""}, "engine"),
        ({"engine": 1}, "engine"),
        ({"schema": "PUBLIC"}, "schema"),
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
