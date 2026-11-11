"""M2 distinct-groups separation of duties."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from datagrant.cli import EXIT_FAILED, EXIT_OK, main
from datagrant.policy import PolicyError, parse_policy

SOD_BASE: dict[str, Any] = {
    "version": 1,
    "approval": "two-person",
    "approvers": ["sec"],
    "separation_of_duties": "distinct-groups",
    "max_duration": "8h",
    "groups": {
        "employees": ["alice", "carol", "dave", "erin"],
        "ml": ["alice", "carol"],
        "analysts": ["dave"],
        "sec": ["carol", "dave", "erin"],
    },
    "datasets": [
        {
            "name": "clinic",
            "database": "clinicdb",
            "tables": [
                {
                    "name": "public.patients",
                    "allowed_groups": ["ml", "analysts"],
                    "columns": {"id": "hash", "zip": "partial"},
                }
            ],
        }
    ],
}


def sod_doc(**patch: Any) -> dict[str, Any]:
    d = copy.deepcopy(SOD_BASE)
    d.update(patch)
    return d


def test_omitted_separation_of_duties_is_none() -> None:
    d = sod_doc()
    del d["separation_of_duties"]
    p = parse_policy(d)
    assert p.separation_of_duties == "none"
    assert p.sod_reasons("alice", "carol", frozenset({"ml", "analysts"})) == []


def test_explicit_none_allows_shared_allowed_group() -> None:
    p = parse_policy(sod_doc(separation_of_duties="none"))
    assert p.separation_of_duties == "none"
    assert p.sod_reasons("alice", "carol", frozenset({"ml"})) == []


def test_distinct_groups_refuses_shared_allowed_group() -> None:
    p = parse_policy(sod_doc())
    reasons = p.sod_reasons("alice", "carol", frozenset({"ml", "analysts"}))
    assert reasons and "ml" in reasons[0] and "distinct-groups" in reasons[0]


def test_distinct_groups_allows_no_overlap() -> None:
    p = parse_policy(sod_doc())
    assert p.sod_reasons("alice", "dave", frozenset({"ml", "analysts"})) == []


def test_distinct_groups_allows_overlap_outside_allowed_groups() -> None:
    p = parse_policy(sod_doc())
    # alice and erin share employees, which is not in allowed_groups
    assert p.sod_reasons("alice", "erin", frozenset({"ml", "analysts"})) == []


def test_distinct_groups_counts_mapped_groups() -> None:
    p = parse_policy(sod_doc())
    # neither is statically in ml; overlap comes from group_map extras
    reasons = p.sod_reasons(
        "erin",
        "dave",
        frozenset({"ml", "analysts"}),
        requester_extra=frozenset({"ml"}),
        approver_extra=frozenset({"ml", "sec"}),
    )
    assert reasons and "ml" in reasons[0]


def test_separation_of_duties_unknown_value() -> None:
    with pytest.raises(PolicyError, match="none"):
        parse_policy(sod_doc(separation_of_duties="same-team"))


@pytest.mark.parametrize("value", [True, 1, ["distinct-groups"]])
def test_separation_of_duties_wrong_type(value: object) -> None:
    with pytest.raises(PolicyError, match="none"):
        parse_policy(sod_doc(separation_of_duties=value))


def test_dataset_level_separation_of_duties_is_unknown_key() -> None:
    d = sod_doc()
    d["datasets"][0]["separation_of_duties"] = "distinct-groups"
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy(d)


def test_table_level_separation_of_duties_is_unknown_key() -> None:
    d = sod_doc()
    d["datasets"][0]["tables"][0]["separation_of_duties"] = "distinct-groups"
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy(d)


def test_policy_check_rejects_unknown_sod(tmp_path: Path) -> None:
    p = tmp_path / "p.yaml"
    p.write_text(
        "version: 1\napproval: two-person\napprovers: [sec]\n"
        "separation_of_duties: maybe\nmax_duration: 8h\n"
        "groups: {ml: [alice], sec: [carol]}\ndatasets:\n"
        "  - name: clinic\n    database: clinicdb\n    tables:\n"
        "      - name: public.patients\n        allowed_groups: [ml]\n"
        "        columns: {id: hash}\n"
    )
    assert main(["policy", "check", str(p)], lambda s: None) == EXIT_FAILED


def test_policy_check_accepts_distinct_groups(tmp_path: Path) -> None:
    p = tmp_path / "p.yaml"
    p.write_text(
        "version: 1\napproval: two-person\napprovers: [sec]\n"
        "separation_of_duties: distinct-groups\nmax_duration: 8h\n"
        "groups: {ml: [alice], sec: [carol]}\ndatasets:\n"
        "  - name: clinic\n    database: clinicdb\n    tables:\n"
        "      - name: public.patients\n        allowed_groups: [ml]\n"
        "        columns: {id: hash}\n"
    )
    assert main(["policy", "check", str(p)], lambda s: None) == EXIT_OK
