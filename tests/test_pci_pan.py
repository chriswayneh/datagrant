from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from test_policy import table

from datagrant.bq.grant import _col_expr as bq_expr
from datagrant.pg.mask import ColumnType, TableCatalog, column_expr
from datagrant.policy import PolicyError, Request, evaluate, load_policy, parse_policy
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


@pytest.mark.parametrize(("dataset", "relation", "pan", "cvv"), [
    ("pg_payments", "public.transactions", "pan", "cvv"),
    ("sf_payments", "PUBLIC.TRANSACTIONS", "PAN", "CVV"),
    ("bq_payments", "payments.transactions", "pan", "cvv"),
])
def test_sample_policy_restricts_card_data(
    dataset: str, relation: str, pan: str, cvv: str,
) -> None:
    path = Path(__file__).resolve().parents[1] / "examples" / "policies" / "pci.yaml"
    policy = load_policy(path)
    requester = "support@example.com"
    groups = frozenset({"payment-support"})
    req = Request(requester, dataset, relation, (pan,), timedelta(minutes=20), "investigate")
    decision = evaluate(policy, req, extra_groups=groups)
    assert decision.allowed and decision.approval == "two-person"
    assert decision.masks == {pan: "pan"}
    assert not evaluate(policy, req).allowed
    assert not evaluate(
        policy, Request(requester, dataset, relation, (cvv,), req.duration, req.purpose),
        extra_groups=groups,
    ).allowed
    assert not evaluate(
        policy, Request(requester, dataset, relation, (pan,), timedelta(hours=1), req.purpose),
        extra_groups=groups,
    ).allowed
    assert policy.can_approve(requester, requester, frozenset({"payment-reviewers"}))
    assert not policy.can_approve("reviewer@example.com", requester, frozenset({"payment-reviewers"}))
