"""M2 quorum: policy-wide approvals_required (1..8), durable votes, receipts."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from datagrant.cli import EXIT_FAILED, EXIT_OK, main
from datagrant.pg.grant import GrantError
from datagrant.policy import PolicyError, parse_policy
from datagrant.receipt import EVENTS, RECEIPT_VERSION, verify

BASE: dict[str, Any] = {
    "version": 1,
    "approval": "two-person",
    "approvers": ["sec"],
    "max_duration": "8h",
    "groups": {"ml": ["alice"], "sec": ["carol", "dave"]},
    "datasets": [
        {
            "name": "clinic",
            "database": "clinicdb",
            "tables": [
                {
                    "name": "public.patients",
                    "allowed_groups": ["ml"],
                    "columns": {"id": "hash", "zip": "partial"},
                }
            ],
        }
    ],
}


def doc(**patch: Any) -> dict[str, Any]:
    d = copy.deepcopy(BASE)
    d.update(patch)
    return d


def test_omitted_approvals_required_is_one() -> None:
    p = parse_policy(doc())
    assert p.approvals_required == 1
    assert p.version == 1


def test_approvals_required_parses_bounds() -> None:
    assert parse_policy(doc(approvals_required=1)).approvals_required == 1
    assert parse_policy(doc(approvals_required=2)).approvals_required == 2
    assert parse_policy(doc(approvals_required=8)).approvals_required == 8


@pytest.mark.parametrize(
    ("value", "msg"),
    [
        (0, "1 to 8"),
        (9, "1 to 8"),
        (-1, "1 to 8"),
        (True, "integer"),
        ("2", "integer"),
        (1.5, "integer"),
    ],
)
def test_approvals_required_invalid(value: object, msg: str) -> None:
    with pytest.raises(PolicyError, match=msg):
        parse_policy(doc(approvals_required=value))


def test_approvals_required_illegal_on_auto() -> None:
    d = doc(approval="auto", approvals_required=2)
    with pytest.raises(PolicyError, match="two-person"):
        parse_policy(d)


def test_dataset_level_approvals_required_is_unknown_key() -> None:
    d = doc()
    d["datasets"][0]["approvals_required"] = 2
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy(d)


def test_table_level_approvals_required_is_unknown_key() -> None:
    d = doc()
    d["datasets"][0]["tables"][0]["approvals_required"] = 2
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy(d)


def test_policy_check_rejects_out_of_range(tmp_path: Path) -> None:
    p = tmp_path / "p.yaml"
    p.write_text(
        "version: 1\napproval: two-person\napprovers: [sec]\napprovals_required: 9\n"
        "max_duration: 8h\ngroups: {ml: [alice], sec: [carol]}\ndatasets:\n"
        "  - name: clinic\n    database: clinicdb\n    tables:\n"
        "      - name: public.patients\n        allowed_groups: [ml]\n"
        "        columns: {id: hash}\n"
    )
    assert main(["policy", "check", str(p)], lambda s: None) == EXIT_FAILED


def test_policy_check_accepts_approvals_required(tmp_path: Path) -> None:
    p = tmp_path / "p.yaml"
    p.write_text(
        "version: 1\napproval: two-person\napprovers: [sec]\napprovals_required: 2\n"
        "max_duration: 8h\ngroups: {ml: [alice], sec: [carol, dave]}\ndatasets:\n"
        "  - name: clinic\n    database: clinicdb\n    tables:\n"
        "      - name: public.patients\n        allowed_groups: [ml]\n"
        "        columns: {id: hash}\n"
    )
    assert main(["policy", "check", str(p)], lambda s: None) == EXIT_OK


def test_record_approval_uses_row_lock_and_is_idempotent() -> None:
    from datagrant.pg import requests as rq

    now = datetime(2026, 1, 1, tzinfo=UTC)
    votes: list[dict[str, Any]] = []
    log: list[str] = []

    class Cur:
        def __init__(self, rows: list[tuple[Any, ...]]) -> None:
            self.rows = rows

        def fetchone(self) -> tuple[Any, ...] | None:
            return self.rows[0] if self.rows else None

        def fetchall(self) -> list[tuple[Any, ...]]:
            return self.rows

    class Conn:
        def transaction(self) -> Any:
            import contextlib

            @contextlib.contextmanager
            def _tx() -> Any:
                log.append("BEGIN")
                yield
                log.append("COMMIT")

            return _tx()

        def execute(self, q: Any, params: Any = None) -> Cur:
            text = q.as_string(None)
            log.append(text)
            if "FOR UPDATE" in text:
                ident = json.dumps(None)
                appr = json.dumps(votes)
                return Cur(
                    [
                        (
                            "r1",
                            "alice",
                            "clinic",
                            "public.p",
                            ["id"],
                            None,
                            3600,
                            "x",
                            "sha",
                            "V",
                            now,
                            now + timedelta(hours=1),
                            "pending",
                            None,
                            None,
                            ident,
                            appr,
                        )
                    ]
                )
            if "UPDATE" in text and "approvals" in text:
                raw = params[0] if params else "[]"
                votes.clear()
                votes.extend(json.loads(raw) if isinstance(raw, str) else raw)
            return Cur([])

    first = rq.record_approval(
        Conn(),  # type: ignore[arg-type]
        "r1",
        approver="carol",
        identity={"source": "flag"},
        required=2,
        now=now,
    )
    assert first.recorded == 1 and first.required == 2
    assert first.is_final is False and first.already is False
    assert any("FOR UPDATE" in q for q in log)
    second = rq.record_approval(
        Conn(),  # type: ignore[arg-type]
        "r1",
        approver="carol",
        identity={"source": "flag"},
        required=2,
        now=now,
    )
    assert second.already is True and second.recorded == 1 and second.is_final is False
    dave = rq.record_approval(
        Conn(),  # type: ignore[arg-type]
        "r1",
        approver="dave",
        identity={"source": "flag"},
        required=2,
        now=now,
    )
    assert dave.recorded == 2 and dave.is_final is True and dave.already is False


def test_record_approval_oidc_duplicate_by_iss_sub() -> None:
    from datagrant.pg import requests as rq

    now = datetime(2026, 1, 1, tzinfo=UTC)
    votes: list[dict[str, Any]] = [
        {
            "approver": "carol@example.com",
            "at": now.isoformat(),
            "identity": {
                "source": "oidc",
                "iss": "https://idp.example",
                "sub": "sub-1",
                "token_sha256": "a" * 64,
            },
        }
    ]

    class Cur:
        def __init__(self, rows: list[tuple[Any, ...]]) -> None:
            self.rows = rows

        def fetchone(self) -> tuple[Any, ...] | None:
            return self.rows[0] if self.rows else None

    class Conn:
        def transaction(self) -> Any:
            import contextlib

            @contextlib.contextmanager
            def _tx() -> Any:
                yield

            return _tx()

        def execute(self, q: Any, params: Any = None) -> Cur:
            text = q.as_string(None)
            if "search_path" in text:
                return Cur([])
            if "FOR UPDATE" in text:
                return Cur(
                    [
                        (
                            "r1",
                            "alice",
                            "clinic",
                            "public.p",
                            ["id"],
                            None,
                            3600,
                            "x",
                            "sha",
                            "V",
                            now,
                            now + timedelta(hours=1),
                            "pending",
                            None,
                            None,
                            None,
                            json.dumps(votes),
                        )
                    ]
                )
            raise AssertionError(f"should not write a second vote: {text}")

    out = rq.record_approval(
        Conn(),  # type: ignore[arg-type]
        "r1",
        approver="carol-renamed@example.com",
        identity={
            "source": "oidc",
            "iss": "https://idp.example",
            "sub": "sub-1",
            "token_sha256": "b" * 64,
        },
        required=2,
        now=now,
    )
    assert out.already is True and out.recorded == 1


def test_record_approval_rejects_non_pending() -> None:
    from datagrant.pg import requests as rq

    now = datetime(2026, 1, 1, tzinfo=UTC)

    class Cur:
        def __init__(self, rows: list[tuple[Any, ...]]) -> None:
            self.rows = rows

        def fetchone(self) -> tuple[Any, ...] | None:
            return self.rows[0] if self.rows else None

    class Conn:
        def transaction(self) -> Any:
            import contextlib

            @contextlib.contextmanager
            def _tx() -> Any:
                yield

            return _tx()

        def execute(self, q: Any, params: Any = None) -> Cur:
            return Cur(
                [
                    (
                        "r1",
                        "alice",
                        "clinic",
                        "public.p",
                        ["id"],
                        None,
                        3600,
                        "x",
                        "sha",
                        None,
                        now,
                        now,
                        "expired",
                        None,
                        None,
                        None,
                        "[]",
                    )
                ]
            )

    with pytest.raises(GrantError, match="not pending"):
        rq.record_approval(
            Conn(),  # type: ignore[arg-type]
            "r1",
            approver="carol",
            identity={"source": "flag"},
            required=1,
            now=now,
        )


def _lock_row(
    *,
    status: str = "pending",
    verifier: str | None = "V",
    approvals: str = "[]",
    now: datetime | None = None,
) -> Any:
    now = now or datetime(2026, 1, 1, tzinfo=UTC)

    class Cur:
        def __init__(self, rows: list[tuple[Any, ...]]) -> None:
            self.rows = rows

        def fetchone(self) -> tuple[Any, ...] | None:
            return self.rows[0] if self.rows else None

    class Conn:
        def __init__(self, rows: list[tuple[Any, ...]]) -> None:
            self.rows = rows
            self.updated: list[Any] = []

        def transaction(self) -> Any:
            import contextlib

            @contextlib.contextmanager
            def _tx() -> Any:
                yield

            return _tx()

        def execute(self, q: Any, params: Any = None) -> Cur:
            text = q.as_string(None)
            if "FOR UPDATE" in text:
                return Cur(self.rows)
            if "UPDATE" in text and params:
                self.updated.append(params[0])
            return Cur([])

    row = (
        "r1",
        "alice",
        "clinic",
        "public.p",
        ["id"],
        None,
        3600,
        "x",
        "sha",
        verifier,
        now,
        now + timedelta(hours=1),
        status,
        None,
        None,
        None,
        approvals,
    )
    return Conn([row] if status != "missing" else [])


def test_record_approval_unknown_request() -> None:
    from datagrant.pg import requests as rq

    conn = _lock_row(status="missing")
    with pytest.raises(GrantError, match="unknown request"):
        rq.record_approval(
            conn, "r1", approver="carol", identity={"source": "flag"}, required=2
        )


def test_record_approval_already_at_n_does_not_append() -> None:
    from datagrant.pg import requests as rq

    now = datetime(2026, 1, 1, tzinfo=UTC)
    votes = [
        {"approver": "carol", "at": now.isoformat(), "identity": {"source": "flag"}},
        {"approver": "dave", "at": now.isoformat(), "identity": {"source": "flag"}},
    ]
    conn = _lock_row(approvals=json.dumps(votes), now=now)
    out = rq.record_approval(
        conn, "r1", approver="eve", identity={"source": "flag"}, required=2, now=now
    )
    assert out.is_final is True and out.added is False and out.recorded == 2
    assert conn.updated == []


def test_drop_last_approval_removes_newest_vote() -> None:
    from datagrant.pg import requests as rq

    now = datetime(2026, 1, 1, tzinfo=UTC)
    votes = [
        {"approver": "carol", "at": now.isoformat(), "identity": {"source": "flag"}},
        {"approver": "dave", "at": now.isoformat(), "identity": {"source": "flag"}},
    ]
    conn = _lock_row(approvals=json.dumps(votes), now=now)
    rq.drop_last_approval(conn, "r1")  # type: ignore[arg-type]
    kept = json.loads(conn.updated[0])
    assert [v["approver"] for v in kept] == ["carol"]
    missing = _lock_row(status="missing")
    rq.drop_last_approval(missing, "r1")  # type: ignore[arg-type]


def test_approval_recorded_in_events_and_verifies(tmp_path: Path) -> None:
    from datagrant.keys import init_keys, load_signing_key
    from datagrant.receipt import GrantFacts, append

    init_keys(tmp_path)
    key = load_signing_key(tmp_path / "signing.key")
    t0 = datetime(2026, 11, 2, 18, tzinfo=UTC)
    facts = GrantFacts(
        "",
        "alice",
        "clinic",
        "public.p",
        ("id",),
        {"id": "passthrough"},
        None,
        "ok",
        t0,
        t0 + timedelta(hours=1),
        "a" * 64,
        1,
        "two-person",
        ("carol",),
        {"source": "flag"},
        ({"approver": "carol", "source": "flag"},),
    )
    log = tmp_path / "r.jsonl"
    append(log, "issued", facts, key, event_at=t0, host="h")
    append(
        log,
        "approval_recorded",
        facts,
        key,
        event_at=t0,
        host="h",
        details={
            "request_id": "aaaaaaaaaaaa",
            "approvals_recorded": 1,
            "approvals_required": 2,
            "phase": "approve",
        },
    )
    assert "approval_recorded" in EVENTS
    assert RECEIPT_VERSION == 1
    bodies = [json.loads(x)["receipt"] for x in log.read_bytes().splitlines()]
    assert bodies[0]["event"] == "issued" and "grant_id" in bodies[0]
    assert bodies[1]["event"] == "approval_recorded" and "grant_id" not in bodies[1]
    assert bodies[1]["details"]["approvals_recorded"] == 1
    assert bodies[1]["approver_identities"][0]["approver"] == "carol"
    res = verify(log, key.private.public_key())
    assert res.ok and res.count == 2
