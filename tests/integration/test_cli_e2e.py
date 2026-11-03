"""End-to-end CLI tests against a real Postgres. Set DATAGRANT_TEST_DSN (superuser) to run."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg import sql

from datagrant.cli import EXIT_FAILED, EXIT_OK, main

DSN = os.environ.get("DATAGRANT_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DATAGRANT_TEST_DSN not set")

POLICY = """\
version: 1
approval: {approval}
approvers: [sec]
max_duration: 8h
groups:
  ml: [alice, bob]
  sec: [carol]
datasets:
  - name: clinic
    database: postgres
    tables:
      - name: public.dg_cli
        allowed_groups: [ml]
        columns: {{id: passthrough, ssn: hash, region: passthrough}}
        row_filters: ["region = 'west'"]
"""


def run(*argv: str) -> tuple[int, dict[str, Any]]:
    out: list[str] = []
    code = main(["--json", *argv], out.append)
    return code, json.loads(out[-1]) if out else {}


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Path]]:
    assert DSN
    monkeypatch.setenv("DATAGRANT_DSN", DSN)
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "receipts.jsonl"))
    paths = {}
    for mode in ("auto", "two-person"):
        p = tmp_path / f"{mode}.yaml"
        p.write_text(POLICY.format(approval=mode))
        paths[mode] = p
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        conn.execute("DROP TABLE IF EXISTS public.dg_cli")
        conn.execute("CREATE TABLE public.dg_cli (id int, ssn text, region text)")
        conn.execute(
            "INSERT INTO public.dg_cli VALUES (1,'a','west'),(2,'b','east'),(3,'c','west')"
        )
        assert run("keys", "init")[0] == EXIT_OK
        yield paths
        for role, view in conn.execute(
            "SELECT role_name, view_name FROM datagrant.grants"
        ).fetchall():
            conn.execute(sql.SQL("DROP VIEW IF EXISTS {}").format(sql.Identifier(*view.split("."))))
            if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        conn.execute("TRUNCATE datagrant.grants, datagrant.hash_keys, datagrant.requests")
        conn.execute("DROP TABLE public.dg_cli")


REQ = (
    "--dataset",
    "clinic",
    "--table",
    "public.dg_cli",
    "--columns",
    "id,ssn",
    "--row-filter",
    "region = 'west'",
    "--purpose",
    "e2e",
)


def login(conn_info: dict[str, Any], password: str) -> psycopg.Connection:
    return psycopg.connect(**conn_info, password=password, autocommit=True)


def test_auto_request_login_revoke(env: dict[str, Path]) -> None:
    pol = str(env["auto"])
    assert run("preflight")[0] == EXIT_OK
    code, dry = run(
        "request", "--policy", pol, "--as-user", "alice", "--duration", "1h", "--dry-run", *REQ
    )
    assert code == EXIT_OK and "PASSWORD '<redacted>'" in dry["sql"][0]
    assert "SCRAM" not in json.dumps(dry)
    code, g = run("request", "--policy", pol, "--as-user", "alice", "--duration", "1h", *REQ)
    assert code == EXIT_OK and g["status"] == "granted" and g["identity_source"] == "flag"
    with login(g["connection"], g["password"]) as c:
        rows = c.execute(f"SELECT id FROM {g['view']} ORDER BY id").fetchall()
    assert rows == [(1,), (3,)]
    code, lst = run("grant", "list")
    assert [x["id"] for x in lst["grants"]] == [g["grant_id"]]
    assert run("grant", "status", g["grant_id"])[1]["status"] == "active"
    log = Path(os.environ["DATAGRANT_RECEIPT_LOG"]).read_text()
    assert g["password"] not in log
    code, r = run("revoke", g["grant_id"])
    assert code == EXIT_OK and r["outcome"] == "revoked"
    with pytest.raises(psycopg.OperationalError):
        login(g["connection"], g["password"])
    assert run("revoke", g["grant_id"])[1]["outcome"] == "noop"
    assert run("grant", "status", "000000000000")[0] == EXIT_FAILED


def test_two_person_flow_and_sweep_and_verify(env: dict[str, Path]) -> None:
    pol = str(env["two-person"])
    code, p = run("request", "--policy", pol, "--as-user", "alice", "--duration", "1h", *REQ)
    assert code == EXIT_OK and p["status"] == "pending"
    rid, pw = p["request_id"], p["password"]
    code, rej = run("approve", rid, "--policy", pol, "--as-user", "alice")
    assert code == EXIT_FAILED and any("different person" in x for x in rej["reasons"])
    code, rej = run("approve", rid, "--policy", pol, "--as-user", "bob")
    assert code == EXIT_FAILED and any("approver group" in x for x in rej["reasons"])
    code, g = run("approve", rid, "--policy", pol, "--as-user", "carol")
    assert code == EXIT_OK and g["status"] == "granted" and "password" not in g
    with login(g["connection"], pw) as c:
        assert c.execute(f"SELECT count(*) FROM {g['view']}").fetchone() == (2,)
    assert run("approve", rid, "--policy", pol, "--as-user", "carol")[0] == EXIT_FAILED
    assert run("grant", "status", g["grant_id"])[1]["approvers"] == ["carol"]

    # a pending request that times out is expired by sweep
    code, p2 = run(
        "request",
        "--policy",
        pol,
        "--as-user",
        "bob",
        "--duration",
        "1h",
        "--pending-ttl",
        "1m",
        *REQ,
    )
    assert code == EXIT_OK, p2
    assert DSN
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(
            "UPDATE datagrant.requests SET expires_at = now() - interval '1 second' WHERE id = %s",
            (p2["request_id"],),
        )
    code, sw = run("sweep")
    assert code == EXIT_OK and sw["expired_requests"] == [p2["request_id"]]
    assert run("approve", p2["request_id"], "--policy", pol, "--as-user", "carol")[0] == 1

    # expire the live grant by moving its expiry into the past, then sweep
    assert DSN
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(
            "UPDATE datagrant.grants SET expires_at = now() - interval '1 minute' WHERE id = %s",
            (g["grant_id"],),
        )
    code, sw = run("sweep")
    assert code == EXIT_OK and [r["outcome"] for r in sw["results"]] == ["revoked"]
    assert run("sweep")[1]["results"] == []

    code, v = run("receipts", "verify")
    assert code == EXIT_OK and v["ok"] and v["count"] == 2  # issued + expired
    events = [
        json.loads(x)["receipt"]
        for x in Path(os.environ["DATAGRANT_RECEIPT_LOG"]).read_text().splitlines()
    ]
    assert [e["event"] for e in events] == ["issued", "expired"]
    assert events[0]["approvers"] == ["carol"] and events[0]["approval"] == "two-person"
    assert events[0]["requester"] == "alice"
    head = v["head_sha256"]
    assert run("receipts", "verify", "--expect-head", head)[0] == EXIT_OK
    assert run("receipts", "verify", "--expect-head", "0" * 64)[0] == EXIT_FAILED


def test_revoke_without_signing_key_still_revokes(
    env: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, g = run(
        "request", "--policy", str(env["auto"]), "--as-user", "alice", "--duration", "1h", *REQ
    )
    assert code == EXIT_OK
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "missing.key"))
    code, r = run("revoke", g["grant_id"])
    assert code == 3 and r["outcome"] == "revoked" and r["key_problem"]
    code, _ = run(
        "request", "--policy", str(env["auto"]), "--as-user", "alice", "--duration", "1h", *REQ
    )
    assert code == EXIT_FAILED  # no signing key, no grant
