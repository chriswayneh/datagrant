from __future__ import annotations

import copy
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from datagrant.policy import (
    PolicyError,
    Request,
    evaluate,
    load_policy,
    parse_duration,
    parse_policy,
)

EXAMPLE = Path(__file__).parent.parent / "examples" / "policy.yaml"

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


def test_example_policy_loads_and_allows() -> None:
    p = load_policy(EXAMPLE)
    assert len(p.sha256) == 64
    d = evaluate(
        p,
        Request(
            "alice",
            "clinic",
            "public.patients",
            ("patient_id", "zip"),
            timedelta(hours=1),
            "debug",
            "region = 'west'",
        ),
    )
    assert d.allowed and d.masks == {"patient_id": "hash", "zip": "partial"}


@pytest.mark.parametrize(
    ("value", "expected"),
    [("30m", timedelta(minutes=30)), ("4h", timedelta(hours=4)), ("2d", timedelta(days=2))],
)
def test_parse_duration_ok(value: str, expected: timedelta) -> None:
    assert parse_duration(value) == expected


@pytest.mark.parametrize("value", ["0h", "4", "h", "-1h", "4w", 4, None])
def test_parse_duration_bad(value: object) -> None:
    with pytest.raises(PolicyError):
        parse_duration(value)


def test_valid_policy_parses() -> None:
    p = parse_policy(doc())
    assert p.approval == "auto" and p.groups_of("alice") == {"ml"}


def test_approval_defaults_to_auto_and_two_person_ok() -> None:
    d = doc()
    del d["approval"]
    assert parse_policy(d).approval == "auto"
    assert parse_policy(doc(approval="two-person", approvers=["other"])).approval == "two-person"


@pytest.mark.parametrize(
    ("data", "msg"),
    [
        ([], "top level"),
        (doc(extra=1), "unknown key"),
        (doc(version=2), "unsupported version"),
        (doc(version=True), "expected int"),
        (doc(approval="manual"), "approval"),
        (doc(max_duration="forever"), "invalid duration"),
        (doc(groups={"bad name!": ["a"]}), "invalid group"),
        (doc(groups={"ml": "alice"}), "list of non-empty"),
        (doc(datasets=[]), "at least one dataset"),
        (doc(datasets=["x"]), "expected a mapping"),
        (doc(datasets=[BASE["datasets"][0], BASE["datasets"][0]]), "duplicate dataset"),
        (doc(datasets=[{**BASE["datasets"][0], "database": "db;drop"}]), "invalid database"),
        (doc(datasets=[{**BASE["datasets"][0], "tables": []}]), "at least one table"),
        (doc(datasets=[{**BASE["datasets"][0], "tables": ["x"]}]), "expected a mapping"),
        (table(name="patients"), "schema.table"),
        (table(name="public.pat;ients"), "schema.table"),
        (table(allowed_groups=["nope"]), "unknown group"),
        (table(columns={}), "at least one column"),
        (table(columns={"id": "encrypt"}), "unknown mask"),
        (table(columns={"bad col": "hash"}), "invalid column"),
        (table(require_row_filter="yes"), "true/false"),
        (table(row_filters=[]), "no row_filters"),
        (table(max_duration="9h"), "exceeds"),
        (table(foo=1), "unknown key"),
        (table(row_filters=["ssn = '1'"]), "not listed in columns"),
        (table(row_filters=["region = 'x' OR ssn = 1"]), r"\['ssn'\]"),
        (table(columns={"id": ["hash"]}), "unknown mask"),
        (table(columns={"id": {"a": 1}}), "unknown mask"),
        (doc(max_duration="99999999999d"), "invalid duration"),
        (table(max_duration="99999999999d"), "invalid duration"),
    ],
)
def test_invalid_policies(data: object, msg: str) -> None:
    with pytest.raises(PolicyError, match=msg):
        parse_policy(data)


def test_missing_key() -> None:
    d = doc()
    del d["groups"]
    with pytest.raises(PolicyError, match="missing required key 'groups'"):
        parse_policy(d)


def test_duplicate_table() -> None:
    d = doc()
    t = d["datasets"][0]["tables"][0]
    d["datasets"][0]["tables"].append(copy.deepcopy(t))
    with pytest.raises(PolicyError, match="duplicate table"):
        parse_policy(d)


def test_table_inherits_global_max() -> None:
    d = table()
    del d["datasets"][0]["tables"][0]["max_duration"]
    p = parse_policy(d)
    assert p.datasets["clinic"].tables["public.patients"].max_duration == timedelta(hours=8)


def test_load_errors(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: [1\n")
    with pytest.raises(PolicyError, match="not valid YAML"):
        load_policy(bad)
    big = tmp_path / "big.yaml"
    big.write_bytes(b"#" * 1_000_001)
    with pytest.raises(PolicyError, match="larger than"):
        load_policy(big)
    unsafe = tmp_path / "unsafe.yaml"
    unsafe.write_text("!!python/object/apply:os.system ['echo hi']\n")
    with pytest.raises(PolicyError, match="not valid YAML"):
        load_policy(unsafe)


def test_allow() -> None:
    d = evaluate(parse_policy(doc(), "abc"), req())
    assert d.allowed and d.policy_sha256 == "abc" and d.masks["id"] == "hash"


@pytest.mark.parametrize(
    ("kw", "msg"),
    [
        ({"dataset": "nope"}, "dataset 'nope'"),
        ({"table": "public.other"}, "table 'public.other'"),
        ({"requester": "eve"}, "not in an allowed group"),
        ({"requester": "mallory"}, "not in an allowed group"),
        ({"columns": ("id", "ssn")}, "columns not allowed: ssn"),
        ({"columns": ("id", "id")}, "duplicate columns"),
        ({"columns": ()}, "at least one column"),
        ({"duration": timedelta(hours=5)}, "exceeds max"),
        ({"duration": timedelta(0)}, "must be positive"),
        ({"row_filter": None}, "row filter is required"),
        ({"row_filter": "1=1"}, "not one of"),
        ({"purpose": "  "}, "purpose is required"),
    ],
)
def test_deny(kw: dict[str, Any], msg: str) -> None:
    d = evaluate(parse_policy(doc()), req(**kw))
    assert not d.allowed and d.masks == {}
    assert any(msg in r for r in d.reasons), d.reasons


def test_deny_collects_multiple_reasons() -> None:
    d = evaluate(parse_policy(doc()), req(requester="eve", columns=("ssn",), row_filter=None))
    assert not d.allowed and len(d.reasons) == 3


def test_optional_row_filter() -> None:
    p = parse_policy(table(require_row_filter=False))
    assert evaluate(p, req(row_filter=None)).allowed


def test_two_person_mode_reported() -> None:
    d = evaluate(parse_policy(doc(approval="two-person", approvers=["other"])), req())
    assert d.allowed and d.approval == "two-person"


def test_huge_duration_rejected() -> None:
    with pytest.raises(PolicyError):
        parse_duration("9999999d")
    assert parse_duration("999999d") == timedelta(days=999999)  # regex bound fits timedelta


def _write(tmp_path: Path, text: str) -> Path:
    f = tmp_path / "p.yaml"
    f.write_text(text)
    return f


def test_deep_nesting_rejected(tmp_path: Path) -> None:
    f = _write(tmp_path, "a: " + "[" * 5000 + "]" * 5000 + "\n")
    with pytest.raises(PolicyError):
        load_policy(f)


def test_deep_nesting_in_parse_caught(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import datagrant.policy as mod

    def boom(*_: object, **__: object) -> object:
        raise RecursionError

    monkeypatch.setattr(mod.yaml, "load", boom)
    with pytest.raises(PolicyError, match="nested too deeply"):
        load_policy(_write(tmp_path, "version: 1\n"))


@pytest.mark.parametrize(
    "text",
    [
        "groups: &g {ml: [alice]}\nother: *g\n",
        "a: &x 1\n",
        "a: [&x 1, *x]\n",
    ],
)
def test_anchors_and_aliases_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(PolicyError, match="anchors/aliases"):
        load_policy(_write(tmp_path, text))


def test_duplicate_keys_rejected(tmp_path: Path) -> None:
    text = EXAMPLE.read_text() + "approval: two-person\n"
    with pytest.raises(PolicyError, match="duplicate YAML key 'approval'"):
        load_policy(_write(tmp_path, text))
    with pytest.raises(PolicyError, match="duplicate YAML key"):
        load_policy(_write(tmp_path, "a:\n  b: 1\n  b: 2\n"))


def test_unhashable_key_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        load_policy(_write(tmp_path, "? [a, b]\n: 1\n"))


def test_directory_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="not a regular file"):
        load_policy(tmp_path)


def test_size_limit_boundary(tmp_path: Path) -> None:
    from datagrant.policy import MAX_POLICY_BYTES

    ok = tmp_path / "ok.yaml"
    ok.write_bytes(b"#" * MAX_POLICY_BYTES)
    with pytest.raises(PolicyError, match="top level"):  # read fully, parsed as empty
        load_policy(ok)
    big = tmp_path / "big.yaml"
    big.write_bytes(b"#" * (MAX_POLICY_BYTES + 1))
    with pytest.raises(PolicyError, match="larger than"):
        load_policy(big)


def test_read_oserror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = _write(tmp_path, "x: 1\n")

    def bad_open(*_: object, **__: object) -> object:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "open", bad_open)
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(f)


def test_approvers_rules() -> None:
    with pytest.raises(PolicyError, match="needs at least one approver group"):
        parse_policy(doc(approval="two-person"))
    with pytest.raises(PolicyError, match="unknown groups"):
        parse_policy(doc(approvers=["nope"]))
    p = parse_policy(doc(approval="two-person", approvers=["other"]))
    assert p.can_approve("eve", "alice") == []
    assert any("different person" in r for r in p.can_approve("alice", "alice"))
    assert any("not in an approver group" in r for r in p.can_approve("bob", "alice"))
