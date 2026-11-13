"""Snowflake revoke and sweep: reverse-drop, atomic claims, mocked connector."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from datagrant import cli
from datagrant.cli import EXIT_OK, EXIT_USAGE
from datagrant.keys import init_keys, load_signing_key
from datagrant.pg.grant import ReceiptSink
from datagrant.receipt import ReceiptError
from datagrant.sf.grant import GrantError
from datagrant.sf.revoke import (
    ISSUING_GRACE_MINUTES,
    _claim,
    _facts,
    _fetchall,
    _fetchone,
    _parse_dt,
    due_grant_ids,
    expire_stale_requests,
    get_grant,
    list_grants,
    pending_expired_ids,
    revoke,
    sweep,
)
from datagrant.snowflake_support import APPLY_UNAVAILABLE, SNOWFLAKE_DSN_ENV

NOW = datetime(2026, 11, 13, 3, 0, tzinfo=UTC)
GID = "abcdef012345"
_GRANT_KEYS = (
    "id",
    "role_name",
    "view_name",
    "user_name",
    "dataset",
    "table_name",
    "requester",
    "purpose",
    "columns",
    "row_filter",
    "approval",
    "policy_sha256",
    "created_at",
    "expires_at",
    "started_at",
    "status",
    "public_key_fingerprint",
    "last_error",
)
_REQ_KEYS = (
    "id",
    "requester",
    "dataset",
    "table_name",
    "columns",
    "row_filter",
    "duration_seconds",
    "purpose",
    "policy_sha256",
    "created_at",
    "expires_at",
    "requester_identity",
)


def grant_row(**kw: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": GID,
        "role_name": f"DG_R_{GID}",
        "view_name": f"DATAGRANT_VIEWS.G_{GID}",
        "user_name": f"DG_{GID}",
        "dataset": "snow_clinic",
        "table_name": "PUBLIC.PATIENTS",
        "requester": "alice",
        "purpose": "eval",
        "columns": '["PATIENT_ID"]',
        "row_filter": None,
        "approval": "auto",
        "policy_sha256": "a" * 64,
        "created_at": NOW,
        "expires_at": NOW,
        "started_at": NOW,
        "status": "active",
        "public_key_fingerprint": "b" * 64,
        "last_error": None,
        "expired": True,
        "stale": False,
    }
    row.update(kw)
    return row


def request_row(**kw: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": "aabbccddeeff",
        "requester": "alice",
        "dataset": "snow_clinic",
        "table_name": "PUBLIC.PATIENTS",
        "columns": '["PATIENT_ID"]',
        "row_filter": None,
        "duration_seconds": 3600,
        "purpose": "eval",
        "policy_sha256": "a" * 64,
        "created_at": NOW,
        "expires_at": NOW,
        "requester_identity": None,
        "status": "pending",
        "expired": True,
    }
    row.update(kw)
    return row


def _tuple(row: dict[str, Any], keys: tuple[str, ...]) -> tuple[Any, ...]:
    return tuple(row[k] for k in keys)


class StoreConn:
    """In-memory Snowflake grants/requests store with qmark-shaped execute."""

    def __init__(
        self,
        grants: dict[str, dict[str, Any]] | None = None,
        requests: dict[str, dict[str, Any]] | None = None,
        running_queries: dict[str, list[str]] | None = None,
        fail_on: str | None = None,
        refuse_claim: bool = False,
        hide_status: str | None = None,
        history_rows: list[tuple[Any, ...]] | None = None,
    ) -> None:
        self.grants = grants if grants is not None else {}
        self.requests = requests if requests is not None else {}
        self.running_queries = running_queries or {}
        self.fail_on = fail_on
        self.refuse_claim = refuse_claim
        self.hide_status = hide_status
        self.history_rows = history_rows
        self.queries: list[tuple[str, Any]] = []
        self.rowcount = 0
        self._one: tuple[Any, ...] | None = None
        self._rows: list[tuple[Any, ...]] = []

    def cursor(self) -> StoreConn:
        return self

    def close(self) -> None:
        return None

    def fetchone(self) -> tuple[Any, ...] | None:
        if self._one is not None:
            row = self._one
            self._one = None
            return row
        if self._rows:
            return self._rows.pop(0)
        return None

    def fetchall(self) -> list[tuple[Any, ...]]:
        rows = self._rows
        self._rows = []
        return rows

    def execute(self, sql: str, params: Any = None) -> StoreConn:
        self.queries.append((sql, params))
        if self.fail_on and self.fail_on.upper() in sql.upper():
            raise RuntimeError(f"stub:{self.fail_on}")
        su = sql.upper()
        self.rowcount = 0
        self._one = None
        self._rows = []
        args: tuple[Any, ...] = () if params is None else tuple(params)

        if "QUERY_HISTORY" in su:
            if self.history_rows is not None:
                self._rows = list(self.history_rows)
            else:
                user = str(args[0]) if args else ""
                self._rows = [(qid,) for qid in self.running_queries.get(user, [])]
            return self
        if "SYSTEM$CANCEL_QUERY" in su:
            self.rowcount = 1
            return self
        if su.startswith("UPDATE") and "GRANTS" in su:
            self._update_grant(su, args)
            return self
        if su.startswith("UPDATE") and "REQUESTS" in su:
            to_status, rid, from_status = args[0], args[1], args[2]
            row = self.requests.get(str(rid))
            extra_ok = True
            if "EXPIRES_AT <=" in su:
                extra_ok = bool(row and row.get("expired", True))
            if row is not None and row["status"] == from_status and extra_ok:
                row["status"] = to_status
                self.rowcount = 1
            return self
        if su.startswith("SELECT") and "REQUESTS" in su:
            status = args[0] if args else "pending"
            items = [r for r in self.requests.values() if r["status"] == status]
            if "EXPIRES_AT <=" in su:
                items = [r for r in items if r.get("expired", True)]
            if "SELECT ID FROM" in su:
                self._rows = [(r["id"],) for r in items]
            else:
                self._rows = [_tuple(r, _REQ_KEYS) for r in items]
            return self
        if su.startswith("SELECT") and "GRANTS" in su:
            self._select_grants(su, args)
        return self

    def _update_grant(self, su: str, args: tuple[Any, ...]) -> None:
        if "WHERE ID = ? AND STATUS = ?" in su:
            to_status, gid, from_status = args[0], args[1], args[2]
            row = self.grants.get(str(gid))
            extra_ok = True
            if "EXPIRES_AT <=" in su:
                extra_ok = bool(row and row.get("expired", True))
            if self.refuse_claim:
                self.rowcount = 0
                return
            if row is not None and row["status"] == from_status and extra_ok:
                row["status"] = str(to_status)
                self.rowcount = 1
            return
        if "WHERE ID = ?" in su:
            status, last_error, gid = args[0], args[1], args[2]
            row = self.grants.get(str(gid))
            if row is not None:
                row["status"] = str(status)
                row["last_error"] = last_error
                self.rowcount = 1

    def _select_grants(self, su: str, args: tuple[Any, ...]) -> None:
        if "WHERE ID = ?" in su:
            row = self.grants.get(str(args[0]))
            if row is not None and self.hide_status and row["status"] == self.hide_status:
                self._one = None
                self._rows = []
                return
            self._one = _tuple(row, _GRANT_KEYS) if row is not None else None
            self._rows = [self._one] if self._one is not None else []
            return
        if "STATUS IN" in su:
            wanted = {str(a) for a in args}
            self._rows = [(gid,) for gid, r in self.grants.items() if r["status"] in wanted]
            return
        status = str(args[0]) if args else None
        items = [r for r in self.grants.values() if status is None or r["status"] == status]
        if "EXPIRES_AT <=" in su:
            items = [r for r in items if r.get("expired", True)]
        if "DATEADD" in su:
            items = [r for r in items if r.get("stale")]
        if "SELECT ID FROM" in su:
            self._rows = [(r["id"],) for r in items]
        else:
            self._rows = [_tuple(r, _GRANT_KEYS) for r in items]
            self._one = self._rows[0] if self._rows else None


def _sink(tmp_path: Path) -> ReceiptSink:
    _, sp, _ = init_keys(tmp_path / "keys")
    return ReceiptSink(tmp_path / "r.jsonl", load_signing_key(sp), host="test")


def _events(tmp_path: Path) -> list[str]:
    log = tmp_path / "r.jsonl"
    if not log.exists():
        return []
    return [
        json.loads(line)["receipt"]["event"]
        for line in log.read_text().splitlines()
        if line.strip()
    ]


def _sqls(conn: StoreConn) -> list[str]:
    return [s for s, _p in conn.queries]


def test_revoke_disable_cancel_drop_order_and_receipt(tmp_path: Path) -> None:
    row = grant_row()
    conn = StoreConn({GID: row}, running_queries={f"DG_{GID}": ["qid-1"]})
    r = revoke(conn, GID, "manual", _sink(tmp_path))
    assert r.outcome == "revoked"
    assert r.sessions_terminated == 1
    assert conn.grants[GID]["status"] == "revoked"
    sqls = _sqls(conn)
    dis = next(i for i, s in enumerate(sqls) if "DISABLED = TRUE" in s)
    hist = next(i for i, s in enumerate(sqls) if "QUERY_HISTORY" in s)
    cancel = next(i for i, s in enumerate(sqls) if "SYSTEM$CANCEL_QUERY" in s)
    view = next(i for i, s in enumerate(sqls) if s.startswith("DROP VIEW"))
    role = next(i for i, s in enumerate(sqls) if s.startswith("DROP ROLE"))
    user = next(i for i, s in enumerate(sqls) if s.startswith("DROP USER"))
    assert dis < hist < cancel < view < role < user
    hist_sql, hist_params = conn.queries[hist]
    assert "?" in hist_sql and "DG_" not in hist_sql
    assert hist_params == (f"DG_{GID}", "RUNNING")
    cancel_sql, cancel_params = conn.queries[cancel]
    assert cancel_sql == "SELECT SYSTEM$CANCEL_QUERY(?)"
    assert cancel_params == ("qid-1",)
    assert _events(tmp_path) == ["revoked"]
    body = json.loads((tmp_path / "r.jsonl").read_text().splitlines()[0])["receipt"]
    assert body["details"]["engine"] == "snowflake"
    assert "private_key" not in json.dumps(body)


def test_revoke_idempotent_and_unknown() -> None:
    for status in ("revoked", "expired", "failed"):
        conn = StoreConn({GID: grant_row(status=status)})
        r = revoke(conn, GID, "manual")
        assert r.outcome == "noop"
        assert not any("DROP USER" in s for s in _sqls(conn))
    with pytest.raises(GrantError, match="unknown grant"):
        revoke(StoreConn(), GID, "manual")


def test_revoke_partial_grant_missing_user(tmp_path: Path) -> None:
    row = grant_row(user_name=None, role_name=None, view_name=None)
    conn = StoreConn({GID: row}, fail_on="ALTER USER")
    r = revoke(conn, GID, "manual", _sink(tmp_path))
    assert r.outcome == "revoked"
    blob = "\n".join(_sqls(conn))
    assert f'DROP VIEW IF EXISTS "DATAGRANT_VIEWS"."G_{GID}"' in blob
    assert f'DROP ROLE IF EXISTS "DG_R_{GID}"' in blob
    assert f'DROP USER IF EXISTS "DG_{GID}"' in blob
    assert conn.grants[GID]["status"] == "revoked"


def test_claim_is_atomic_qmark_rowcount() -> None:
    row = grant_row(status="active")
    store = {GID: row}
    first = StoreConn(store)
    second = StoreConn(store)
    assert _claim(first, GID, from_status="active", to_status="revoking") is True
    assert _claim(second, GID, from_status="active", to_status="revoking") is False
    sql, params = first.queries[-1]
    assert "STATUS = ?" in sql and "ID = ?" in sql and "STATUS = ?" in sql
    assert "?" in sql and GID not in sql and "revoking" not in sql
    assert params == ("revoking", GID, "active")
    r = revoke(second, GID, "manual")
    assert r.outcome == "revoked"  # inflight retry of the claimed row
    third = StoreConn(store)
    again = revoke(third, GID, "manual")
    assert again.outcome == "noop"
    assert not any("DROP USER" in s for s in _sqls(third))


def test_sweep_skips_young_issuing_and_cleans_stale(tmp_path: Path) -> None:
    young = grant_row(id="111111111111", status="issuing", stale=False, expired=False)
    stale = grant_row(id="222222222222", status="issuing", stale=True, expired=False)
    due = grant_row(id="333333333333", status="active", expired=True)
    store = {r["id"]: r for r in (young, stale, due)}
    conn = StoreConn(store)
    preview = due_grant_ids(conn)
    assert "111111111111" not in preview
    assert "222222222222" in preview
    assert "333333333333" in preview
    results = sweep(conn, _sink(tmp_path))
    outcomes = {r.grant_id: r.outcome for r in results}
    assert "111111111111" not in outcomes
    assert outcomes["222222222222"] == "revoked"
    assert outcomes["333333333333"] == "revoked"
    assert store["111111111111"]["status"] == "issuing"
    assert store["222222222222"]["status"] == "failed"
    assert store["333333333333"]["status"] == "expired"
    dateadd = next((s, p) for s, p in conn.queries if s and "DATEADD" in s)
    assert "?" in dateadd[0]
    assert dateadd[1] == ("issuing", -ISSUING_GRACE_MINUTES)
    assert ISSUING_GRACE_MINUTES == 10
    events = _events(tmp_path)
    assert "expired" in events
    assert "revoke_failed" in events
    assert not any(s.startswith("DROP USER") and "111111111111" in s for s in _sqls(conn))


def test_expire_pending_does_not_drop_snowflake_objects() -> None:
    req = request_row()
    conn = StoreConn(requests={req["id"]: req})
    expired = expire_stale_requests(conn)
    assert [e["id"] for e in expired] == [req["id"]]
    assert conn.requests[req["id"]]["status"] == "expired"
    assert not any("DROP USER" in s or "DROP ROLE" in s or "DROP VIEW" in s for s in _sqls(conn))
    sql, params = next(q for q in conn.queries if q[0].startswith('UPDATE "DATAGRANT"."REQUESTS"'))
    assert "?" in sql and "expired" not in sql
    assert params == ("expired", req["id"], "pending")
    again = expire_stale_requests(conn)
    assert again == []
    assert pending_expired_ids(StoreConn(requests={req["id"]: {**req, "status": "pending"}})) == [
        req["id"]
    ]


def test_get_grant_roundtrip() -> None:
    conn = StoreConn({GID: grant_row()})
    got = get_grant(conn, GID)
    assert got is not None and got["id"] == GID and got["status"] == "active"
    sql, params = conn.queries[0]
    assert "ID = ?" in sql and GID not in sql
    assert params == (GID,)


def _cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, conn: StoreConn) -> Path:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    monkeypatch.setattr("datagrant.snowflake_support.connect", lambda dsn: conn)
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.setenv(
        SNOWFLAKE_DSN_ENV, "snowflake://svc@xy12345/CLINIC_DB?private_key_file=/k.p8"
    )
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
    assert cli.main(["keys", "init", "--apply"], lambda s: None) == 0
    return tmp_path


def test_cli_revoke_sweep_list_with_snowflake_dsn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = grant_row()
    conn = StoreConn({GID: row})
    _cli_env(tmp_path, monkeypatch, conn)
    out: list[str] = []
    assert cli.main(["grant", "list", "--json"], out.append) == EXIT_OK
    listed = json.loads(out[0])
    assert listed["engine"] == "snowflake"
    assert listed["grants"][0]["id"] == GID
    out = []
    assert cli.main(["revoke", GID, "--json"], out.append) == EXIT_OK
    dry = json.loads(out[0])
    assert dry["dry_run"] is True and dry["would_revoke"] is True
    assert conn.grants[GID]["status"] == "active"
    out = []
    assert cli.main(["revoke", GID, "--apply", "--json"], out.append) == EXIT_OK
    applied = json.loads(out[0])
    assert applied["outcome"] == "revoked"
    assert conn.grants[GID]["status"] == "revoked"
    assert "revoked" in _events(tmp_path)


def test_cli_sweep_apply_and_request_apply_still_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    due = grant_row(status="active", expired=True)
    conn = StoreConn({GID: due}, requests={"aabbccddeeff": request_row()})
    _cli_env(tmp_path, monkeypatch, conn)
    out: list[str] = []
    assert cli.main(["sweep", "--json"], out.append) == EXIT_OK
    dry = json.loads(out[0])
    assert dry["dry_run"] is True
    assert GID in dry["would_revoke"]
    out = []
    assert cli.main(["sweep", "--apply", "--json"], out.append) == EXIT_OK
    body = json.loads(out[0])
    assert body["engine"] == "snowflake"
    assert conn.grants[GID]["status"] == "expired"
    assert conn.requests["aabbccddeeff"]["status"] == "expired"
    assert "aabbccddeeff" in body["expired_requests"]
    assert not any("DROP USER" in s and "aabbccddeeff" in str(p) for s, p in conn.queries)
    pol = tmp_path / "p.yaml"
    pol.write_text(
        "version: 1\napproval: auto\nmax_duration: 8h\ngroups:\n  ml: [alice]\n"
        "datasets:\n  - name: snow_clinic\n    engine: snowflake\n    database: CLINIC_DB\n"
        "    tables:\n      - name: PUBLIC.PATIENTS\n        allowed_groups: [ml]\n"
        "        columns: {PATIENT_ID: passthrough}\n"
    )
    pol.chmod(0o600)
    out = []
    code = cli.main(
        [
            "request",
            "--dataset",
            "snow_clinic",
            "--table",
            "PUBLIC.PATIENTS",
            "--columns",
            "PATIENT_ID",
            "--duration",
            "1h",
            "--purpose",
            "eval",
            "--as-user",
            "alice",
            "--policy",
            str(pol),
            "--apply",
            "--json",
        ],
        out.append,
    )
    assert code == EXIT_USAGE
    assert APPLY_UNAVAILABLE in out[0]


class _ConnFetch:
    def __init__(
        self,
        one: tuple[Any, ...] | None = None,
        rows: list[tuple[Any, ...]] | None = None,
    ) -> None:
        self._one = one
        self._rows = rows or []

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._one

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows


def test_fetchone_and_fetchall_fall_back_to_conn() -> None:
    conn = _ConnFetch(one=("gid", "active"), rows=[("a",), ("b",)])
    assert _fetchone(None, conn) == ("gid", "active")
    assert _fetchall(None, conn) == [("a",), ("b",)]

    class EmptyResult:
        def fetchone(self) -> None:
            return None

        def fetchall(self) -> list[tuple[Any, ...]]:
            return []

    again = _ConnFetch(one=("from-conn",), rows=[("c",)])
    assert _fetchone(EmptyResult(), again) == ("from-conn",)
    assert _fetchall(EmptyResult(), again) == [("c",)]
    assert _fetchone(object(), _ConnFetch(one=("no-attr",))) == ("no-attr",)
    assert _fetchall(object(), _ConnFetch(rows=[("d",)])) == [("d",)]
    assert _fetchone(None, object()) is None
    assert _fetchall(None, object()) == []


def test_parse_dt_accepts_isoformat_and_facts_column_shapes() -> None:
    assert _parse_dt(NOW) is NOW
    parsed = _parse_dt("2026-11-13T03:00:00+00:00")
    assert parsed.year == 2026 and parsed.hour == 3
    iso = "2026-11-13T03:00:00+00:00"
    json_facts = _facts(grant_row(created_at=iso, expires_at=iso))
    assert json_facts.columns == ("PATIENT_ID",)
    bad = _facts(grant_row(columns="not-json"))
    assert bad.columns == ()
    listed = _facts(grant_row(columns=["PATIENT_ID", "SSN"]))
    assert listed.columns == ("PATIENT_ID", "SSN")
    empty = _facts(grant_row(columns=None))
    assert empty.columns == ()


def test_revoke_skips_null_query_ids_and_survives_cancel_errors(tmp_path: Path) -> None:
    row = grant_row(columns=["PATIENT_ID"], created_at=NOW.isoformat(), expires_at=NOW.isoformat())
    conn = StoreConn(
        {GID: row},
        history_rows=[(), (None,), ("qid-ok",)],
        fail_on="SYSTEM$CANCEL_QUERY",
    )
    r = revoke(conn, GID, "manual", _sink(tmp_path))
    assert r.outcome == "revoked"
    assert r.sessions_terminated == 0
    assert any("SYSTEM$CANCEL_QUERY" in s for s in _sqls(conn))
    assert any(s.startswith("DROP USER") for s in _sqls(conn))
    assert conn.grants[GID]["status"] == "revoked"


def test_revoke_query_history_error_still_drops(tmp_path: Path) -> None:
    conn = StoreConn({GID: grant_row()}, fail_on="QUERY_HISTORY")
    r = revoke(conn, GID, "manual", _sink(tmp_path))
    assert r.outcome == "revoked"
    assert r.sessions_terminated == 0
    assert any(s.startswith("DROP VIEW") for s in _sqls(conn))
    assert conn.grants[GID]["status"] == "revoked"


def test_revoke_unqualified_view_and_drop_failure_marks_failed(tmp_path: Path) -> None:
    row = grant_row(view_name=f"G_{GID}")
    conn = StoreConn({GID: row}, fail_on="DROP VIEW")
    r = revoke(conn, GID, "manual", _sink(tmp_path))
    assert r.outcome == "failed"
    assert r.error is not None and "DROP VIEW" in r.error
    assert conn.grants[GID]["status"] == "revoking"
    assert conn.grants[GID]["last_error"]
    assert "revoke_failed" in _events(tmp_path)


def test_revoke_receipt_write_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sink = _sink(tmp_path)

    def receipt_boom(*_a: Any, **_k: Any) -> None:
        raise ReceiptError("receipt broke")

    monkeypatch.setattr("datagrant.receipt.append", receipt_boom)
    r = revoke(StoreConn({GID: grant_row()}), GID, "manual", sink)
    assert r.outcome == "revoked"
    assert r.receipt_error == "receipt broke"

    def other_boom(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("disk full")

    monkeypatch.setattr("datagrant.receipt.append", other_boom)
    other = "bbbbbbbbbbbb"
    r2 = revoke(StoreConn({other: grant_row(id=other)}), other, "manual", sink)
    assert r2.outcome == "revoked"
    assert r2.receipt_error == "disk full"


def test_revoke_active_not_yet_due_is_noop() -> None:
    conn = StoreConn({GID: grant_row(status="active", expired=False)})
    r = revoke(conn, GID, "expired")
    assert r.outcome == "noop"
    assert conn.grants[GID]["status"] == "active"
    assert not any(s.startswith("DROP USER") for s in _sqls(conn))


def test_revoke_issuing_claim_miss_and_hidden_row(tmp_path: Path) -> None:
    missed = StoreConn({GID: grant_row(status="issuing")}, refuse_claim=True)
    r = revoke(missed, GID, "stale_issuing")
    assert r.outcome == "noop"
    assert missed.grants[GID]["status"] == "issuing"
    hidden = StoreConn(
        {GID: grant_row(status="issuing")},
        hide_status="sweeping",
    )
    r2 = revoke(hidden, GID, "stale_issuing", _sink(tmp_path))
    assert r2.outcome == "revoked"
    assert hidden.grants[GID]["status"] == "failed"
    mystery = StoreConn({GID: grant_row(status="mystery")})
    r3 = revoke(mystery, GID, "manual")
    assert r3.outcome == "noop"
    assert mystery.grants[GID]["status"] == "mystery"


def test_revoke_issuing_manual_and_stale_cleanup(tmp_path: Path) -> None:
    sink = _sink(tmp_path)
    conn = StoreConn({GID: grant_row(status="issuing")})
    r = revoke(conn, GID, "manual", sink)
    assert r.outcome == "revoked"
    assert conn.grants[GID]["status"] == "revoked"
    assert "revoked" in _events(tmp_path)
    other = "cccccccccccc"
    stale = StoreConn({other: grant_row(id=other, status="issuing")})
    r2 = revoke(stale, other, "stale_issuing", sink)
    assert r2.outcome == "revoked"
    assert stale.grants[other]["status"] == "failed"


def test_sweep_skips_duplicate_ids_and_retries_inflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    due_id = "aaaaaaaaaaaa"
    stale_id = "bbbbbbbbbbbb"
    inflight_id = "cccccccccccc"
    store = {
        due_id: grant_row(id=due_id, status="active", expired=True),
        stale_id: grant_row(id=stale_id, status="issuing", stale=True, expired=False),
        inflight_id: grant_row(id=inflight_id, status="revoking", expired=False),
    }
    conn = StoreConn(store)
    import datagrant.sf.revoke as rv

    real = rv._list_ids

    def overlapping(c: Any, sql: str, params: tuple[Any, ...]) -> list[str]:
        ids = real(c, sql, params)
        su = sql.upper()
        if "STATUS IN" in su:
            return [due_id, inflight_id]
        if params and params[0] == "active":
            return [due_id, due_id]
        if params and params[0] == "issuing":
            return [due_id, stale_id]
        return ids

    monkeypatch.setattr(rv, "_list_ids", overlapping)
    results = sweep(conn, _sink(tmp_path))
    by_id = {r.grant_id: r.outcome for r in results}
    assert list(by_id) == [due_id, stale_id, inflight_id]
    assert by_id[due_id] == "revoked"
    assert by_id[stale_id] == "revoked"
    assert by_id[inflight_id] == "revoked"
    assert store[due_id]["status"] == "expired"
    assert store[stale_id]["status"] == "failed"
    assert store[inflight_id]["status"] == "revoked"


def test_list_grants_all_and_cli_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    active = grant_row()
    done = grant_row(id="dddddddddddd", status="revoked", expired=False)
    conn = StoreConn({GID: active, "dddddddddddd": done})
    only_active = list_grants(conn, active_only=True)
    assert [r["id"] for r in only_active] == [GID]
    every = list_grants(conn, active_only=False)
    assert {r["id"] for r in every} == {GID, "dddddddddddd"}
    _cli_env(tmp_path, monkeypatch, conn)
    out: list[str] = []
    assert cli.main(["grant", "status", GID, "--json"], out.append) == EXIT_OK
    body = json.loads(out[0])
    assert body["id"] == GID
    assert body["status"] == "active"
    out = []
    assert cli.main(["grant", "list", "--all", "--json"], out.append) == EXIT_OK
    listed = json.loads(out[0])
    assert listed["engine"] == "snowflake"
    assert {g["id"] for g in listed["grants"]} == {GID, "dddddddddddd"}
