"""Snowflake grant engine: SQL plan, fail-safe apply, mocked connector."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from datagrant.keys import HashKey, init_keys, load_signing_key
from datagrant.pg.grant import ReceiptSink
from datagrant.policy import Decision, Request
from datagrant.sf.grant import (
    HASH_TABLE,
    ROW_FILTER_UNAVAILABLE,
    Bound,
    GrantError,
    apply_plan,
    build_plan,
    create_pending,
    days_to_expiry,
    get_pending,
    lit,
    new_keypair,
    q,
    reverse_drop,
    stmt_sql,
)

NOW = datetime(2026, 11, 13, 3, 0, tzinfo=UTC)
KEY = HashKey("0123456789abcdef", b"k" * 32)


def req(**kw: object) -> Request:
    base: dict[str, object] = {
        "requester": "alice",
        "dataset": "snow_clinic",
        "table": "PUBLIC.PATIENTS",
        "columns": ("PATIENT_ID", "SSN"),
        "duration": timedelta(hours=2),
        "purpose": "eval",
        "row_filter": None,
    }
    base.update(kw)
    return Request(**base)  # type: ignore[arg-type]


def dec(masks: dict[str, str] | None = None, **kw: object) -> Decision:
    base: dict[str, object] = {
        "allowed": True,
        "reasons": ("ok",),
        "approval": "auto",
        "policy_sha256": "f" * 64,
        "masks": masks or {"PATIENT_ID": "passthrough", "SSN": "hash"},
        "hash_scope": "snow_clinic",
        "policy_version": 1,
    }
    base.update(kw)
    return Decision(**base)  # type: ignore[arg-type]


class FakeConn:
    def __init__(self, fail_on: str | None = None, pending_row: tuple[Any, ...] | None = None):
        self.queries: list[tuple[str, Any]] = []
        self.fail_on = fail_on
        self.pending_row = pending_row

    def cursor(self) -> FakeConn:
        return self

    def execute(self, sql: str, params: Any = None) -> FakeConn:
        self.queries.append((sql, params))
        if self.fail_on and self.fail_on.upper() in sql.upper():
            raise RuntimeError(f"stub:{self.fail_on}")
        return self

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.pending_row

    def close(self) -> None:
        return None


def _sqls(conn: FakeConn) -> list[str]:
    return [s for s, _p in conn.queries]


def _plan(**kw: Any) -> Any:
    pair = kw.pop("pair", None) or new_keypair()
    return build_plan(
        dec(),
        req(),
        database="CLINIC_DB",
        public_body=pair.public_body,
        fingerprint=pair.fingerprint,
        grant_id="abcdef012345",
        now=NOW,
        hash_key=KEY,
        private_pem=pair.private_pem,
        **kw,
    )


def _sink(tmp_path: Path) -> ReceiptSink:
    _, sp, _ = init_keys(tmp_path / "keys")
    return ReceiptSink(tmp_path / "r.jsonl", load_signing_key(sp), host="test")


def test_keypair_fingerprint_is_sha256_of_der() -> None:
    pair = new_keypair()
    assert len(pair.fingerprint) == 64
    assert "BEGIN" in pair.private_pem
    assert "BEGIN" not in pair.public_body
    assert pair.private_pem not in pair.public_body


def test_plan_sql_order_and_invariants() -> None:
    pair = new_keypair()
    plan = _plan(pair=pair)
    text = [stmt_sql(s) for s in plan.statements]
    blob = "\n".join(text)
    insert = plan.statements[0]
    assert isinstance(insert, Bound)
    assert insert.sql.startswith('INSERT INTO "DATAGRANT"."GRANTS"')
    assert insert.sql.count("?") == 17
    assert "issuing" in insert.params
    assert "issuing" not in insert.sql
    assert text[1].startswith('CREATE USER "DG_abcdef012345" TYPE = SERVICE')
    assert "RSA_PUBLIC_KEY" in text[1]
    assert "DISABLED" in text[1]
    assert "DAYS_TO_EXPIRY = 1" in text[1]
    assert pair.public_body in text[1]
    assert pair.private_pem not in blob
    assert "PASSWORD" not in text[1]
    assert KEY.derived.hex() not in blob
    assert "HASH_HMAC" in blob
    assert 'CREATE SECURE VIEW "DATAGRANT_VIEWS"."G_abcdef012345"' in blob
    usage = (
        'GRANT USAGE ON FUNCTION "DATAGRANT"."HASH_HMAC"(VARCHAR, VARCHAR)'
        ' TO ROLE "DG_R_abcdef012345"'
    )
    assert usage in blob
    assert f'GRANT SELECT ON "DATAGRANT"."{HASH_TABLE}"' not in blob
    assert text[-2] == 'ALTER USER "DG_abcdef012345" SET DISABLED = FALSE'
    active = plan.statements[-1]
    assert isinstance(active, Bound)
    assert active.params == ("active", "abcdef012345")
    idx_user = next(i for i, s in enumerate(text) if s.startswith("CREATE USER"))
    idx_insert = next(i for i, s in enumerate(text) if s.startswith("INSERT INTO"))
    assert idx_insert < idx_user


def test_view_calls_udf_not_key_bytes() -> None:
    plan = _plan()
    view = next(s for s in plan.statements if "CREATE SECURE VIEW" in stmt_sql(s))
    assert '"DATAGRANT"."HASH_HMAC"' in view
    assert KEY.derived.hex() not in view
    assert "k" * 32 not in view


def test_apply_enable_last_then_active(tmp_path: Path) -> None:
    conn = FakeConn()
    plan = _plan()
    apply_plan(conn, plan, _sink(tmp_path))
    sqls = _sqls(conn)
    insert_i = next(i for i, s in enumerate(sqls) if 'INSERT INTO "DATAGRANT"."GRANTS"' in s)
    user_i = next(i for i, s in enumerate(sqls) if s.startswith("CREATE USER"))
    enable_i = next(i for i, s in enumerate(sqls) if "DISABLED = FALSE" in s)
    active_i = next(
        i for i, (_s, p) in enumerate(conn.queries) if p == ("active", "abcdef012345")
    )
    assert insert_i < user_i < enable_i < active_i
    lines = (tmp_path / "r.jsonl").read_text().strip().splitlines()
    body = json.loads(lines[0])["receipt"]
    assert body["event"] == "issued"
    assert body["details"]["public_key_fingerprint"] == plan.fingerprint
    assert "private_key" not in json.dumps(body)
    assert plan.private_pem not in json.dumps(body)
    merge = next(s for s in sqls if "MERGE INTO" in s)
    assert "?" in merge
    assert "%s" not in merge
    assert KEY.derived.hex() not in merge
    params = next(p for s, p in conn.queries if s and "MERGE INTO" in s)
    assert params is not None and KEY.derived in params
    assert KEY.derived.hex() not in "\n".join(sqls)


def test_receipt_failure_does_not_enable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from datagrant import receipt as rec

    def boom(*_a: Any, **_k: Any) -> None:
        raise rec.ReceiptError("disk full")

    monkeypatch.setattr(rec, "append", boom)
    conn = FakeConn()
    with pytest.raises(GrantError, match="receipt not written"):
        apply_plan(conn, _plan(), _sink(tmp_path))
    sqls = _sqls(conn)
    assert any("CREATE USER" in s for s in sqls)
    assert not any("DISABLED = FALSE" in s for s in sqls)
    assert any("DROP USER" in s for s in sqls)
    assert any(p == ("failed", "abcdef012345") for _s, p in conn.queries)
    assert not (tmp_path / "r.jsonl").exists() or (tmp_path / "r.jsonl").read_text() == ""


def test_enable_failure_after_issued_not_active(tmp_path: Path) -> None:
    conn = FakeConn(fail_on="DISABLED = FALSE")
    with pytest.raises(GrantError, match="ENABLE failed"):
        apply_plan(conn, _plan(), _sink(tmp_path))
    sqls = _sqls(conn)
    assert not any("STATUS = 'active'" in s for s in sqls)
    assert any("DROP USER" in s for s in sqls)
    events = [
        json.loads(line)["receipt"]["event"]
        for line in (tmp_path / "r.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert events[0] == "issued"
    assert "revoked" in events


def test_failure_after_create_user_reverse_drops(tmp_path: Path) -> None:
    conn = FakeConn(fail_on="CREATE SECURE VIEW")
    with pytest.raises(GrantError):
        apply_plan(conn, _plan(), _sink(tmp_path))
    sqls = _sqls(conn)
    assert any("CREATE USER" in s for s in sqls)
    assert not any("DISABLED = FALSE" in s for s in sqls)
    assert any("DROP USER IF EXISTS" in s for s in sqls)
    assert any(p == ("failed", "abcdef012345") for _s, p in conn.queries)


def test_two_person_pending_stores_public_key_not_private() -> None:
    pair = new_keypair()
    conn = FakeConn()
    rid = create_pending(
        conn,
        req(),
        policy_sha256="a" * 64,
        public_body=pair.public_body,
        fingerprint=pair.fingerprint,
        ttl=timedelta(hours=24),
        now=NOW,
    )
    blob = "\n".join(_sqls(conn))
    pending = next((s, p) for s, p in conn.queries if s.startswith('INSERT INTO "DATAGRANT"."REQUESTS"'))
    assert pair.public_body in pending[1]
    assert pair.fingerprint in pending[1]
    assert pair.public_body not in pending[0]
    assert pair.private_pem not in blob
    assert "CREATE USER" not in blob
    assert rid


def test_q_rejects_unsafe_identifier() -> None:
    with pytest.raises(GrantError, match="unsafe identifier"):
        q("bad-name")


def test_build_plan_refuses_denied_and_bad_id() -> None:
    pair = new_keypair()
    with pytest.raises(GrantError, match="denied"):
        build_plan(
            dec(allowed=False),
            req(),
            database="CLINIC_DB",
            public_body=pair.public_body,
            fingerprint=pair.fingerprint,
        )
    with pytest.raises(GrantError, match="12 lowercase"):
        build_plan(
            dec(),
            req(),
            database="CLINIC_DB",
            public_body=pair.public_body,
            fingerprint=pair.fingerprint,
            grant_id="nope",
            hash_key=KEY,
        )


def test_get_pending_maps_row() -> None:
    pair = new_keypair()
    row = (
        "aabbccddeeff",
        "alice",
        "snow_clinic",
        "PUBLIC.PATIENTS",
        '["PATIENT_ID"]',
        None,
        3600,
        "eval",
        "a" * 64,
        pair.public_body,
        pair.fingerprint,
        NOW.isoformat(),
        NOW.isoformat(),
        "pending",
        None,
    )
    conn = FakeConn(pending_row=row)
    got = get_pending(conn, "aabbccddeeff")
    assert got is not None
    assert got["id"] == "aabbccddeeff"
    assert got["rsa_public_key"] == pair.public_body
    assert pair.private_pem not in str(got)
    assert get_pending(FakeConn(pending_row=None), "missing") is None


def test_reverse_drop_disables_first_when_enabled() -> None:
    conn = FakeConn()
    reverse_drop(conn, _plan(), enabled=True)
    sqls = _sqls(conn)
    assert "DISABLED = TRUE" in sqls[0]
    assert any("DROP VIEW" in s for s in sqls)
    assert any("DROP ROLE" in s for s in sqls)
    assert any("DROP USER" in s for s in sqls)
    assert any(p == ("failed", "abcdef012345") for _s, p in conn.queries)


def test_lit_escapes_backslash_before_quote() -> None:
    assert lit("\\") == "'\\\\'"
    assert lit("'") == "''''"
    assert lit("\\'") == "'\\\\'''"
    assert lit("$$") == "'$$'"


@pytest.mark.parametrize("payload", ["\\", "\\'", "$$", "x\\', '2099-01-01', 'active"])
def test_dml_binds_backslash_quote_and_dollar(payload: str) -> None:
    plan = build_plan(
        dec(),
        req(purpose=payload),
        database="CLINIC_DB",
        public_body=payload,
        fingerprint="a" * 64,
        grant_id="abcdef012345",
        now=NOW,
        hash_key=KEY,
    )
    insert = plan.statements[0]
    assert isinstance(insert, Bound)
    assert payload not in insert.sql
    assert payload in insert.params
    create = stmt_sql(plan.statements[1])
    assert f"RSA_PUBLIC_KEY = {lit(payload)}" in create
    assert "DAYS_TO_EXPIRY =" in create


def test_days_to_expiry_ceils_duration() -> None:
    assert days_to_expiry(timedelta(hours=2)) == 1
    assert days_to_expiry(timedelta(days=3)) == 3
    pair = new_keypair()
    plan = build_plan(
        dec(),
        req(duration=timedelta(days=3)),
        database="CLINIC_DB",
        public_body=pair.public_body,
        fingerprint=pair.fingerprint,
        grant_id="abcdef012345",
        now=NOW,
        hash_key=KEY,
    )
    create = stmt_sql(plan.statements[1])
    assert "DAYS_TO_EXPIRY = 3" in create
    assert plan.days_to_expiry == 3


def test_build_plan_and_pending_refuse_row_filter() -> None:
    pair = new_keypair()
    with pytest.raises(GrantError, match="row filters"):
        build_plan(
            dec(),
            req(row_filter="REGION = 'west'"),
            database="CLINIC_DB",
            public_body=pair.public_body,
            fingerprint=pair.fingerprint,
            hash_key=KEY,
        )
    with pytest.raises(GrantError, match=ROW_FILTER_UNAVAILABLE):
        create_pending(
            FakeConn(),
            req(row_filter="REGION = 'west'"),
            policy_sha256="a" * 64,
            public_body=pair.public_body,
            fingerprint=pair.fingerprint,
            ttl=timedelta(hours=1),
        )
