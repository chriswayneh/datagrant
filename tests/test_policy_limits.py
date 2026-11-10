"""M2 construction PR 2: pending_ttl, max_columns, max_concurrent_grants."""

from __future__ import annotations

import copy
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from datagrant.policy import PolicyError, Request, evaluate, parse_policy
from datagrant.receipt import RECEIPT_VERSION

BASE: dict[str, Any] = {
    "version": 1,
    "approval": "auto",
    "max_duration": "8h",
    "groups": {"ml": ["alice"], "other": ["eve"]},
    "datasets": [
        {
            "name": "clinic",
            "database": "clinicdb",
            "tables": [
                {
                    "name": "public.patients",
                    "allowed_groups": ["ml"],
                    "max_duration": "4h",
                    "columns": {
                        "id": "hash",
                        "zip": "partial",
                        "name": "redact",
                        "region": "passthrough",
                    },
                    "row_filters": ["region = 'west'"],
                    "require_row_filter": True,
                }
            ],
        }
    ],
}


def doc(**patch: Any) -> dict[str, Any]:
    d = copy.deepcopy(BASE)
    d.update(patch)
    return d


def table(**patch: Any) -> dict[str, Any]:
    d = doc()
    d["datasets"][0]["tables"][0].update(patch)
    return d


def req(**kw: Any) -> Request:
    base: dict[str, Any] = {
        "requester": "alice",
        "dataset": "clinic",
        "table": "public.patients",
        "columns": ("id", "zip"),
        "duration": timedelta(hours=2),
        "purpose": "model eval",
        "row_filter": "region = 'west'",
    }
    base.update(kw)
    return Request(**base)


def test_omitted_limit_keys_match_v030() -> None:
    p = parse_policy(doc())
    assert p.version == 1
    assert p.pending_ttl is None
    assert p.max_concurrent_grants is None
    assert p.datasets["clinic"].max_concurrent_grants is None
    assert p.datasets["clinic"].tables["public.patients"].max_columns is None
    assert p.concurrent_grant_cap("clinic") is None
    d = evaluate(p, req())
    assert d.allowed


def test_pending_ttl_parses_and_bounds() -> None:
    p = parse_policy(doc(pending_ttl="24h"))
    assert p.pending_ttl == timedelta(hours=24)
    p = parse_policy(doc(pending_ttl="1m"))
    assert p.pending_ttl == timedelta(minutes=1)
    p = parse_policy(doc(pending_ttl="7d"))
    assert p.pending_ttl == timedelta(days=7)


@pytest.mark.parametrize(
    ("value", "msg"),
    [
        ("8d", "1m..7d"),
        ("30s", "invalid duration"),
        (True, "expected a string"),
        (24, "expected a string"),
        ("0h", "invalid duration"),
    ],
)
def test_pending_ttl_invalid(value: object, msg: str) -> None:
    with pytest.raises(PolicyError, match=msg):
        parse_policy(doc(pending_ttl=value))


def test_max_columns_parses_and_evaluate_boundary() -> None:
    p = parse_policy(table(max_columns=2))
    assert p.datasets["clinic"].tables["public.patients"].max_columns == 2
    assert evaluate(p, req(columns=("id", "zip"))).allowed
    d = evaluate(p, req(columns=("id", "zip", "name")))
    assert not d.allowed
    assert any("max_columns" in r and "3" in r for r in d.reasons)


def test_max_columns_one_allows_single_column() -> None:
    p = parse_policy(table(max_columns=1))
    assert evaluate(p, req(columns=("id",))).allowed
    d = evaluate(p, req(columns=("id", "zip")))
    assert not d.allowed


@pytest.mark.parametrize(
    ("value", "msg"),
    [
        (0, "positive integer"),
        (-1, "positive integer"),
        (True, "positive integer"),
        ("2", "positive integer"),
        (5, "cannot exceed"),
    ],
)
def test_max_columns_invalid(value: object, msg: str) -> None:
    with pytest.raises(PolicyError, match=msg):
        parse_policy(table(max_columns=value))


def test_max_concurrent_grants_policy_and_dataset_min() -> None:
    d = doc(max_concurrent_grants=3)
    d["datasets"][0]["max_concurrent_grants"] = 1
    p = parse_policy(d)
    assert p.max_concurrent_grants == 3
    assert p.datasets["clinic"].max_concurrent_grants == 1
    assert p.concurrent_grant_cap("clinic") == 1
    only_policy = parse_policy(doc(max_concurrent_grants=3))
    assert only_policy.concurrent_grant_cap("clinic") == 3
    only_ds = doc()
    only_ds["datasets"][0]["max_concurrent_grants"] = 2
    assert parse_policy(only_ds).concurrent_grant_cap("clinic") == 2


@pytest.mark.parametrize("where", ["policy", "dataset"])
@pytest.mark.parametrize("value", [0, -1, True, "1", 1.5])
def test_max_concurrent_grants_invalid(where: str, value: object) -> None:
    if where == "policy":
        data: dict[str, Any] = doc(max_concurrent_grants=value)
    else:
        data = doc()
        data["datasets"][0]["max_concurrent_grants"] = value
    with pytest.raises(PolicyError, match="positive integer"):
        parse_policy(data)


def test_unknown_limit_keys_still_fail() -> None:
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy(doc(max_rows=10))
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy(table(max_rows=10))
    d = doc()
    d["datasets"][0]["rate_limit"] = 1
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy(d)


def test_receipt_version_unchanged() -> None:
    assert RECEIPT_VERSION == 1


def test_policy_check_accepts_new_optional_keys(tmp_path: Path) -> None:
    from datagrant.cli import EXIT_OK, main

    p = tmp_path / "p.yaml"
    p.write_text(
        "version: 1\napproval: auto\nmax_duration: 8h\npending_ttl: 24h\n"
        "max_concurrent_grants: 2\ngroups: {ml: [alice]}\ndatasets:\n"
        "  - name: clinic\n    database: clinicdb\n    max_concurrent_grants: 1\n"
        "    tables:\n      - name: public.patients\n        allowed_groups: [ml]\n"
        "        max_columns: 1\n        columns: {id: hash, zip: partial}\n"
    )
    assert main(["policy", "check", str(p)], lambda s: None) == EXIT_OK
