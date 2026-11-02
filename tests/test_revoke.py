"""Unit tests for revoke/sweep control flow with a scripted fake connection."""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator
from typing import Any

import psycopg
import pytest

from datagrant.pg import revoke as rv
from datagrant.pg.grant import GrantError

Handler = Callable[[str, Any], list[tuple[Any, ...]]]


class _Cur:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.rows[0] if self.rows else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self.rows


class FakeConn:
    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.log: list[str] = []

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        self.log.append("BEGIN")
        try:
            yield
        except BaseException:
            self.log.append("ROLLBACK")
            raise
        self.log.append("COMMIT")

    def execute(self, q: Any, params: Any = None) -> _Cur:
        text = q.as_string(None)
        self.log.append(text)
        return _Cur(self.handler(text, params))


def _handler(
    status: str = "active",
    terminate: list[tuple[Any, ...]] | None = None,
    counts: list[int] | None = None,
    fail_on: str | None = None,
    role_exists: bool = True,
) -> Handler:
    counts = list(counts or [0])

    def h(text: str, params: Any) -> list[tuple[Any, ...]]:
        if fail_on and fail_on in text:
            raise psycopg.errors.DependentObjectsStillExist("boom")
        if "FOR UPDATE" in text:
            return [("dg_abc", "datagrant_views.g_abc", status)] if status else []
        if "pg_terminate_backend" in text:
            return terminate or []
        if "count(*)" in text:
            return [(counts.pop(0) if len(counts) > 1 else counts[0],)]
        if "pg_roles" in text:
            return [(1,)] if role_exists else []
        if "SELECT role_name FROM" in text:
            return [("dg_abc",)]
        if "SELECT id FROM" in text:
            return [("aaaaaaaaaaaa",), ("bbbbbbbbbbbb",)]
        return []

    return h


def test_revoke_order_and_safe_path() -> None:
    c = FakeConn(_handler(terminate=[(7, True)], counts=[1, 0]))
    res = rv.revoke(c, "abc")  # type: ignore[arg-type]
    assert res == rv.RevokeResult("abc", "revoked", 1)
    body = [q for q in c.log if q not in ("BEGIN", "COMMIT")]
    assert body[0] == "SET LOCAL search_path = pg_catalog, pg_temp"
    order = [
        "NOLOGIN",
        "pg_terminate_backend",
        "DROP VIEW",
        "REASSIGN OWNED",
        "DROP OWNED",
        "DROP ROLE",
        "SET status",
    ]
    idx = [next(i for i, q in enumerate(body) if k in q) for k in order]
    assert idx == sorted(idx)
    assert "'manual'" not in "".join(body)  # values are bound, not inlined
    assert c.log[-1] == "COMMIT"


def test_noop_when_not_active() -> None:
    c = FakeConn(_handler(status="revoked"))
    assert rv.revoke(c, "abc").outcome == "noop"  # type: ignore[arg-type]
    assert not any("DROP" in q for q in c.log)


def test_unknown_grant_raises() -> None:
    c = FakeConn(_handler(status=""))
    with pytest.raises(GrantError, match="unknown grant"):
        rv.revoke(c, "abc")  # type: ignore[arg-type]


def test_role_already_gone_still_drops_view() -> None:
    c = FakeConn(_handler(role_exists=False))
    assert rv.revoke(c, "abc").outcome == "revoked"  # type: ignore[arg-type]
    assert any("DROP VIEW" in q for q in c.log) and not any("DROP ROLE" in q for q in c.log)


def test_terminate_refused_is_failure() -> None:
    c = FakeConn(_handler(terminate=[(7, False)]))
    res = rv.revoke(c, "abc")  # type: ignore[arg-type]
    assert res.outcome == "failed" and "pg_signal_backend" in (res.error or "")
    assert "ROLLBACK" in c.log and any("last_error" in q for q in c.log)


def test_sessions_that_never_exit_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rv, "SESSION_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(rv.time, "sleep", lambda s: None)
    c = FakeConn(_handler(terminate=[(7, True)], counts=[1]))
    res = rv.revoke(c, "abc")  # type: ignore[arg-type]
    assert res.outcome == "failed" and "still open" in (res.error or "")


def test_db_error_recorded_and_update_never_marks_revoked() -> None:
    c = FakeConn(_handler(fail_on="DROP VIEW"))
    res = rv.revoke(c, "abc")  # type: ignore[arg-type]
    assert res.outcome == "failed" and res.error and "database error" in res.error
    assert not any("SET status" in q for q in c.log)


def test_failure_recording_errors_are_swallowed() -> None:
    c = FakeConn(_handler(fail_on="DROP VIEW"))
    orig = c.handler

    def h(text: str, params: Any) -> list[tuple[Any, ...]]:
        if "last_error = %s" in text:
            raise psycopg.errors.QueryCanceled("x")
        return orig(text, params)

    c.handler = h
    assert rv.revoke(c, "abc").outcome == "failed"  # type: ignore[arg-type]


def test_sweep_revokes_each_due_grant_separately() -> None:
    c = FakeConn(_handler())
    out = rv.sweep(c)  # type: ignore[arg-type]
    assert [r.grant_id for r in out] == ["aaaaaaaaaaaa", "bbbbbbbbbbbb"]
    assert c.log.count("BEGIN") == 3 and all(r.outcome == "revoked" for r in out)
    assert any("'expired'" not in q and "expires_at <= pg_catalog.now()" in q for q in c.log)
