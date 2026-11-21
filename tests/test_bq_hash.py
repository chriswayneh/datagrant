"""Hash-master table, load-job key write, fingerprint preflight, and dataset ACL."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from test_bq_grant import GID, KEY, NOW, PRINCIPAL, PROJECT, FakeClient, _plan, _sink, dec, req
from test_bq_state import SDK, Client

from datagrant.bq.dataset_access import check_hash_dataset_access
from datagrant.bq.grant import GrantError, apply_plan, build_plan
from datagrant.bq.hash import (
    HASH_MASTER_ID,
    HASH_TABLE,
    HashStore,
    create_hash_hmac_sql,
    create_hash_table_sql,
    create_hmac_helpers_sql,
    fingerprint_sql,
    key_fingerprint,
)

OPERATOR_ACCESS = [
    {"role": "OWNER", "specialGroup": "projectOwners"},
    {"role": "WRITER", "specialGroup": "projectWriters"},
]
DEFAULT_READERS = [
    *OPERATOR_ACCESS,
    {"role": "READER", "specialGroup": "projectReaders"},
]
READER_GROUP = [
    *OPERATOR_ACCESS,
    {"role": "READER", "groupByEmail": "readers@example.com"},
]


def _blob(client: Client) -> str:
    return "\n".join(sql for sql, _ in client.calls) + repr(client.calls)


def test_create_table_is_idempotent_and_unparameterized() -> None:
    sql = create_hash_table_sql(PROJECT)
    assert "CREATE TABLE IF NOT EXISTS" in sql
    assert f"`{PROJECT}`.`datagrant`.`{HASH_TABLE}`" in sql
    assert "BYTES" in sql
    assert "@key" not in sql
    assert KEY.derived.hex() not in sql


def test_fingerprint_sql_sends_only_hash() -> None:
    sql = fingerprint_sql(PROJECT)
    assert "@fp" in sql
    assert "TO_HEX(SHA256(key))" in sql
    assert "@key" not in sql
    assert KEY.derived.hex() not in sql


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


def test_hash_store_loads_key_without_query_parameter() -> None:
    client = Client()
    store = HashStore(client, SDK, PROJECT, "US")
    store.ensure_table()
    store.ensure_udf()
    store.load_key(KEY)
    assert KEY.derived.hex() not in _blob(client)
    assert client.loads
    table, data, config = client.loads[-1]
    assert HASH_TABLE in table
    payload = json.loads(data.decode("ascii").strip())
    assert payload["id"] == HASH_MASTER_ID
    assert base64.b64decode(payload["key"]) == KEY.derived
    assert config["write_disposition"] == "WRITE_TRUNCATE"
    assert config["source_format"] == "NEWLINE_DELIMITED_JSON"
    assert all(field.mode == "REQUIRED" for field in config["schema"])
    assert any("CREATE TABLE IF NOT EXISTS" in s for s, _ in client.calls)
    assert any("hash_hmac" in s and "CREATE OR REPLACE FUNCTION" in s for s, _ in client.calls)
    assert not any("@key" in s for s, _ in client.calls)


def test_hash_store_is_idempotent_ddl() -> None:
    client = Client()
    store = HashStore(client, SDK, PROJECT, "US")
    store.ensure_table()
    store.ensure_table()
    store.ensure_udf()
    store.ensure_udf()
    assert all("CREATE TABLE IF NOT EXISTS" in s for s, _ in client.calls if "CREATE TABLE" in s)
    assert KEY.derived.hex() not in _blob(client)


def test_mismatched_key_is_refused_with_no_write() -> None:
    client = Client()
    client.rows = [{"n": 1, "matched": 0}]
    store = HashStore(client, SDK, PROJECT, "US")
    n, matched = store.master_state(KEY)
    assert n == 1 and matched == 0
    with pytest.raises(GrantError, match="rotate explicitly"):
        store.require_fingerprint(KEY)
    assert not client.loads
    sql, params = client.calls[-1]
    assert "@fp" in sql
    assert params["fp"] == ("STRING", key_fingerprint(KEY))
    assert KEY.derived.hex() not in sql
    assert KEY.derived.hex() not in str(params)


def test_duplicate_rows_are_refused() -> None:
    client = Client()
    client.rows = [{"n": 2, "matched": 1}]
    store = HashStore(client, SDK, PROJECT, "US")
    with pytest.raises(GrantError, match="duplicate rows"):
        store.require_fingerprint(KEY)
    assert not client.loads


def test_rotate_cleans_duplicate_master_rows() -> None:
    client = FakeClient(hash_duplicate=True)
    client.setup_hash(KEY, rotate=True)
    assert client.hash_loads
    assert client.hash_duplicate is False


def test_provider_error_does_not_leak_key() -> None:
    class Boom(Client):
        def load_table_from_file(self, fileobj: Any, table: str, **kwargs: Any) -> Client:
            super().load_table_from_file(fileobj, table, **kwargs)
            raise RuntimeError(f"invalid {KEY.derived.hex()} job")

    store = HashStore(Boom(), SDK, PROJECT, "US")
    with pytest.raises(GrantError, match="hash-master load failed") as err:
        store.load_key(KEY)
    assert KEY.derived.hex() not in str(err.value)
    assert err.value.__cause__ is None


def test_bytes_query_parameter_is_refused() -> None:
    client = Client()
    store = HashStore(client, SDK, PROJECT, "US")
    with pytest.raises(GrantError, match="must not be a query parameter"):
        store._run("SELECT 1", {"key": ("BYTES", KEY.derived)})
    assert not client.calls


def test_default_project_readers_list_is_refused() -> None:
    with pytest.raises(GrantError, match="operator-only"):
        check_hash_dataset_access(DEFAULT_READERS, PROJECT)


def test_reader_group_is_refused() -> None:
    with pytest.raises(GrantError, match="operator-only"):
        check_hash_dataset_access(READER_GROUP, PROJECT)


def test_operator_only_list_passes() -> None:
    check_hash_dataset_access(OPERATOR_ACCESS, PROJECT)
    check_hash_dataset_access(
        [
            *OPERATOR_ACCESS,
            {"role": "OWNER", "userByEmail": "ops@example.com"},
            {"routine": {"projectId": PROJECT, "datasetId": "datagrant", "routineId": "hash_hmac"}},
        ],
        PROJECT,
    )


@pytest.mark.parametrize(
    "entry",
    [
        {"role": "OWNER", "specialGroup": "allAuthenticatedUsers"},
        {"role": "OWNER", "iamMember": "allUsers"},
        {"role": "WRITER", "domain": "example.com"},
        {"dataset": {"projectId": PROJECT, "datasetId": "other"}},
        {"view": {"projectId": PROJECT, "datasetId": "v", "tableId": "t"}},
        {"routine": {"projectId": PROJECT, "datasetId": "datagrant", "routineId": "other"}},
    ],
)
def test_open_acl_entries_are_refused(entry: dict[str, Any]) -> None:
    with pytest.raises(GrantError, match="operator-only"):
        check_hash_dataset_access([*OPERATOR_ACCESS, entry], PROJECT)


def test_grant_path_issues_no_ddl_or_key_write(tmp_path: Path) -> None:
    client = FakeClient()
    sink = _sink(tmp_path)
    apply_plan(client, _plan(), sink)
    assert client.hash_params == []
    assert client.hash_loads == []
    assert client.hash_sqls == []
    assert "CREATE TABLE" not in repr(client.calls)
    assert "setup_hash" not in client.calls
    hex_key = KEY.derived.hex()
    assert hex_key not in plan_sql(client)
    assert hex_key not in sink.log.read_text()
    assert client.views_access == []
    assert client.state_access == []
    members = [m for b in client.dataset_policy.bindings for m in b.get("members", [])]
    assert PRINCIPAL in members


def plan_sql(client: FakeClient) -> str:
    return "\n".join(filter(None, [client.view_sql, *client.hash_sqls, repr(client.calls)]))


def test_apply_plan_refuses_open_hash_acl(tmp_path: Path) -> None:
    client = FakeClient()
    client.hash_access = DEFAULT_READERS
    with pytest.raises(GrantError, match="operator-only"):
        apply_plan(client, _plan(), _sink(tmp_path))
    assert "insert_issuing" not in client.calls
    assert client.hash_loads == []
    assert client.status == {}


def test_apply_plan_refuses_reader_group(tmp_path: Path) -> None:
    client = FakeClient()
    client.hash_access = READER_GROUP
    with pytest.raises(GrantError, match="operator-only"):
        apply_plan(client, _plan(), _sink(tmp_path))
    assert "insert_issuing" not in client.calls


def test_apply_plan_accepts_operator_only_acl(tmp_path: Path) -> None:
    client = FakeClient()
    client.hash_access = OPERATOR_ACCESS
    apply_plan(client, _plan(), _sink(tmp_path))
    assert client.status[GID] == "active"
    assert client.hash_loads == []


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
    client.hash_access = DEFAULT_READERS
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


def test_grant_mismatch_and_duplicate_do_not_write(tmp_path: Path) -> None:
    mismatch = FakeClient(hash_mismatch=True)
    with pytest.raises(GrantError, match="rotate explicitly"):
        apply_plan(mismatch, _plan(), _sink(tmp_path / "m"))
    assert mismatch.hash_loads == []
    assert "insert_issuing" not in mismatch.calls
    dup = FakeClient(hash_duplicate=True)
    with pytest.raises(GrantError, match="duplicate rows"):
        apply_plan(dup, _plan(), _sink(tmp_path / "d"))
    assert dup.hash_loads == []


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
