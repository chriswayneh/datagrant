"""Hash-master table, parameterized key bind, and hash_hmac UDF."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from test_bq_grant import GID, KEY, NOW, PRINCIPAL, PROJECT, FakeClient, _plan, _sink, dec, req
from test_bq_state import SDK, Client

from datagrant.bq.grant import GrantError, apply_plan, build_plan
from datagrant.bq.hash import (
    HASH_MASTER_ID,
    HASH_TABLE,
    HashStore,
    bind_hash_key_sql,
    create_hash_hmac_sql,
    create_hash_table_sql,
    create_hmac_helpers_sql,
    hash_routine_entry,
)


def _blob(client: Client) -> str:
    return "\n".join(sql for sql, _ in client.calls) + repr(client.calls)


def test_create_table_is_idempotent_and_unparameterized() -> None:
    sql = create_hash_table_sql(PROJECT)
    assert "CREATE TABLE IF NOT EXISTS" in sql
    assert f"`{PROJECT}`.`datagrant`.`{HASH_TABLE}`" in sql
    assert "BYTES" in sql
    assert "@key" not in sql
    assert KEY.derived.hex() not in sql


def test_bind_sql_uses_named_query_parameters() -> None:
    sql = bind_hash_key_sql(PROJECT)
    assert "@id" in sql and "@key" in sql
    assert "MERGE" in sql
    assert KEY.derived.hex() not in sql
    assert "FROM_HEX" not in sql
    assert "'master'" not in sql and '"master"' not in sql


def test_hash_hmac_reads_table_and_omits_key_bytes() -> None:
    sql = create_hash_hmac_sql(PROJECT)
    helpers = "\n".join(create_hmac_helpers_sql(PROJECT))
    blob = sql + helpers
    assert f"`{PROJECT}`.`datagrant`.`hash_hmac`" in sql
    assert f"`{PROJECT}`.`datagrant`.`{HASH_TABLE}`" in sql
    assert "datagrant/hash-scope/v1:" in sql
    assert "SHA256" in helpers
    assert KEY.derived.hex() not in blob
    assert "@key" not in blob


def test_hash_store_binds_key_as_bytes_parameter() -> None:
    client = Client()
    store = HashStore(client, SDK, PROJECT, "US")
    store.ensure_table()
    store.ensure_udf()
    sql = store.bind_key(KEY)
    assert KEY.derived.hex() not in sql
    assert KEY.derived.hex() not in _blob(client)
    merge_sql, params = client.calls[-1]
    assert "@key" in merge_sql and KEY.derived.hex() not in merge_sql
    assert params["id"] == ("STRING", HASH_MASTER_ID)
    assert params["key"] == ("BYTES", KEY.derived)
    assert any("CREATE TABLE IF NOT EXISTS" in s for s, _ in client.calls)
    assert any("hash_hmac" in s and "CREATE OR REPLACE FUNCTION" in s for s, _ in client.calls)


def test_hash_store_is_idempotent() -> None:
    client = Client()
    store = HashStore(client, SDK, PROJECT, "US")
    store.ensure_table()
    store.ensure_table()
    store.ensure_udf()
    store.ensure_udf()
    store.bind_key(KEY)
    store.bind_key(KEY)
    assert all("CREATE TABLE IF NOT EXISTS" in s for s, _ in client.calls if "CREATE TABLE" in s)
    assert KEY.derived.hex() not in _blob(client)


def test_provider_error_does_not_leak_key() -> None:
    class Boom(Client):
        def query(self, sql: str, **kwargs: Any) -> Client:
            super().query(sql, **kwargs)
            raise RuntimeError(f"invalid {KEY.derived.hex()} job")

    store = HashStore(Boom(), SDK, PROJECT, "US")
    with pytest.raises(GrantError, match="hash-master query failed") as err:
        store.bind_key(KEY)
    assert KEY.derived.hex() not in str(err.value)
    assert err.value.__cause__ is None


def test_interpolated_key_is_refused_before_query() -> None:
    client = Client()
    store = HashStore(client, SDK, PROJECT, "US")
    with pytest.raises(GrantError, match="leaked"):
        store._run(f"SELECT '{KEY.derived.hex()}'", {"key": ("BYTES", KEY.derived)})
    assert not client.calls


def test_apply_plan_acl_is_routine_only_and_key_stays_out_of_sql(tmp_path: Path) -> None:
    client = FakeClient()
    sink = _sink(tmp_path)
    plan = _plan()
    apply_plan(client, plan, sink)
    entry = {"routine": hash_routine_entry(PROJECT)}
    assert client.views_access == [entry]
    assert client.state_access == [entry]
    for item in (*client.views_access, *client.state_access):
        assert list(item) == ["routine"]
        assert "userByEmail" not in item
        assert "groupByEmail" not in item
        assert "iamMember" not in item
        assert PRINCIPAL not in repr(item)
    members = [m for b in client.dataset_policy.bindings for m in b.get("members", [])]
    assert PRINCIPAL in members
    assert PRINCIPAL not in repr(client.state_access)
    hex_key = KEY.derived.hex()
    assert hex_key not in "\n".join(client.hash_sqls)
    assert hex_key not in plan.view_sql
    assert hex_key not in sink.log.read_text()
    assert hex_key not in repr(client.calls)
    assert client.hash_params == [KEY.derived]
    assert "@key" in bind_hash_key_sql(PROJECT)


def test_hash_preflight_fails_closed_before_issuing(tmp_path: Path) -> None:
    client = FakeClient(missing_hash_objects=True)
    sink = _sink(tmp_path)
    with pytest.raises(GrantError, match="hash_hmac routine is unavailable"):
        apply_plan(client, _plan(), sink)
    assert client.calls == ["ensure_hash"]
    assert "insert_issuing" not in client.calls
    assert client.status == {}
    assert client.views == set()
    assert not client.dataset_policy.bindings
    assert not client.project_policy.bindings
    assert not sink.log.exists()


def test_passthrough_skips_hash_object_preflight(tmp_path: Path) -> None:
    client = FakeClient(missing_hash_objects=True)
    plan = build_plan(
        dec({"patient_id": "passthrough", "ssn": "redact"}),
        req(),
        project=PROJECT,
        principal=PRINCIPAL,
        grant_id=GID,
        now=NOW,
    )
    apply_plan(client, plan, _sink(tmp_path))
    assert client.status[GID] == "active"
    assert "insert_issuing" in client.calls


def test_ensure_hash_failure_creates_nothing(tmp_path: Path) -> None:
    client = FakeClient(fail_on="ensure_hash")
    sink = _sink(tmp_path)
    with pytest.raises(GrantError, match="stub:ensure_hash"):
        apply_plan(client, _plan(), sink)
    assert client.calls == ["ensure_hash"]
    assert client.views == set()
    assert client.status == {}
    assert not sink.log.exists()
    assert "bind_iam" not in client.calls
    assert "insert_issuing" not in client.calls
