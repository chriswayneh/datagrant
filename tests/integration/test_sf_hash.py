"""Opt-in Snowflake SQL/Python UDF smoke test using isolated disposable schemas."""

from __future__ import annotations

import hmac
import os
import secrets
from collections.abc import Iterator
from typing import Any

import pytest

from datagrant.keys import HashKey
from datagrant.sf import grant
from datagrant.snowflake_support import connect

DSN = os.environ.get("DATAGRANT_TEST_SNOWFLAKE_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DATAGRANT_TEST_SNOWFLAKE_DSN not set")


@pytest.fixture
def warehouse(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    assert DSN
    state = "DG_TEST_STATE_" + secrets.token_hex(6).upper()
    views = "DG_TEST_VIEWS_" + secrets.token_hex(6).upper()
    monkeypatch.setattr(grant, "STATE_SCHEMA", state)
    monkeypatch.setattr(grant, "VIEW_SCHEMA", views)
    conn = connect(DSN)
    try:
        grant.ensure_state(conn)
        yield conn
    finally:
        try:
            with conn.cursor() as cur:
                try:
                    cur.execute(f"DROP SCHEMA IF EXISTS {grant.q(views)} CASCADE")
                finally:
                    cur.execute(f"DROP SCHEMA IF EXISTS {grant.q(state)} CASCADE")
        finally:
            conn.close()


def test_live_hash_wrapper_vectors_nulls_scopes_and_secure_view(warehouse: Any) -> None:
    key = HashKey("fictional", b"k" * 32)
    grant._bind_hash_key(warehouse, key)
    fn = f"{grant.q(grant.STATE_SCHEMA)}.{grant.q(grant.HASH_UDF)}"
    primitive = f"{grant.q(grant.STATE_SCHEMA)}.{grant.q(grant.HMAC_UDF)}"
    with warehouse.cursor() as cur:
        cur.execute(f"SELECT {primitive}(?, ?)", (b"\x0b" * 20, "Hi There"))
        assert bytes(cur.fetchone()[0]).hex() == (
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        )
        for scope in ("clinic", "research"):
            for value in (None, "", "fictional-123", "O'Brien é 患者 U0001f9ec"):
                cur.execute(f"SELECT {fn}(?, ?)", (scope, value))
                actual = cur.fetchone()[0]
                expected = (
                    None
                    if value is None
                    else hmac.digest(key.scoped(scope).derived, value.encode(), "sha256")
                    .hex()
                    .upper()
                )
                assert actual == expected
        view = f"{grant.q(grant.VIEW_SCHEMA)}.{grant.q('HASH_SMOKE')}"
        cur.execute(
            f"CREATE SECURE VIEW {view} AS SELECT "
            f"{fn}('clinic', 'fictional-123') AS MASKED, {fn}('clinic', NULL) AS MISSING"
        )
        cur.execute(f"SELECT MASKED, MISSING FROM {view}")
        expected_hash = (
            hmac.digest(key.scoped("clinic").derived, b"fictional-123", "sha256").hex().upper()
        )
        assert cur.fetchone() == (expected_hash, None)
