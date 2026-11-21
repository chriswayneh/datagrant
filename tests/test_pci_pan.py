from __future__ import annotations

import pytest
from test_policy import table

from datagrant.bq.grant import _col_expr as bq_expr
from datagrant.pg.mask import ColumnType, TableCatalog, column_expr
from datagrant.policy import PolicyError, parse_policy
from datagrant.sf.grant import _col_expr as sf_expr


@pytest.mark.parametrize("mask", ["passthrough", "partial", "hash"])
def test_tagged_pan_refuses_other_exposing_masks(mask: str) -> None:
    with pytest.raises(PolicyError, match="tagged PAN"):
        parse_policy(table(columns={"region": "redact", "pan": mask}, card_data={"PAN": "pan"}))


@pytest.mark.parametrize("tag", ["cvv", "track"])
def test_sensitive_authentication_data_cannot_be_listed(tag: str) -> None:
    with pytest.raises(PolicyError, match="not grantable"):
        parse_policy(table(columns={"region": "redact", "secret": "null"}, card_data={"secret": tag}))


@pytest.mark.parametrize("tag", ["pan", "cvv", "track"])
def test_tagged_card_data_cannot_be_used_as_a_filter(tag: str) -> None:
    with pytest.raises(PolicyError, match="card data cannot be used in filters"):
        parse_policy(table(
            card_data={"REGION": tag}, columns={"id": "redact"}, filter_columns=["region"],
        ))


def test_pan_mask_requires_explicit_tag() -> None:
    with pytest.raises(PolicyError, match="pan mask requires a PAN tag"):
        parse_policy(table(columns={"region": "redact", "pan": "pan"}))
    policy = parse_policy(table(
        columns={"region": "redact", "pan": "pan"}, card_data={"pan": "pan", "cvv": "cvv"},
    ))
    assert policy.datasets["clinic"].tables["public.patients"].columns["pan"] == "pan"


def test_all_engines_gate_pan_format_and_keep_only_the_edges() -> None:
    catalog = TableCatalog({"pan": ColumnType("pg_catalog", "text")}, None)
    postgres = column_expr("pan", "pan", catalog).as_string(None)
    snowflake = sf_expr("pan", "pan", "scope")
    bigquery = bq_expr("pan", "pan", "scope", project="grant-project")
    assert "BETWEEN 12 AND 19" in postgres and "'[^0123456789]'" in postgres
    assert "REGEXP_LIKE" in snowflake and "[0123456789]{12,19}" in snowflake
    assert "SAFE_CAST" in bigquery and "^[0123456789]{12,19}$" in bigquery
    for expression in (postgres, snowflake, bigquery):
        upper = expression.upper()
        assert "LEFT(" in upper and ", 6)" in upper
        assert "RIGHT(" in upper and ", 4)" in upper
        assert " - 10" in expression and "[REDACTED]" in expression
