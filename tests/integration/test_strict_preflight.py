"""strict_preflight and file modes against a live Postgres. Set DATAGRANT_TEST_DSN."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg import sql

from datagrant.cli import EXIT_FAILED, EXIT_OK, EXIT_RECEIPT, main

DSN = os.environ.get("DATAGRANT_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DATAGRANT_TEST_DSN is not set")

POLICY = """\
version: 1
approval: auto
max_duration: 8h
{extras}
groups:
  ml: [alice]
datasets:
  - name: clinic
    database: postgres
    tables:
      - name: public.dg_strict
        allowed_groups: [ml]
        columns: {{id: passthrough, ssn: hash}}
"""

REQ = (
    "--dataset",
    "clinic",
    "--table",
    "public.dg_strict",
    "--columns",
    "id,ssn",
    "--duration",
    "1h",
    "--purpose",
    "x",
    "--as-user",
    "alice",
)


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
    assert run("keys", "init", "--apply")[0] == EXIT_OK
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        conn.execute("DROP TABLE IF EXISTS public.dg_strict")
        conn.execute("CREATE TABLE public.dg_strict (id int, ssn text)")
        conn.execute("INSERT INTO public.dg_strict VALUES (1, 'a')")
        yield {"tmp": tmp_path}
        for role, view in conn.execute(
            "SELECT role_name, view_name FROM datagrant.grants"
        ).fetchall():
            conn.execute(sql.SQL("DROP VIEW IF EXISTS {}").format(sql.Identifier(*view.split("."))))
            if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        conn.execute("TRUNCATE datagrant.grants, datagrant.hash_keys, datagrant.requests")
        conn.execute("DROP TABLE public.dg_strict")


def _write_policy(tmp: Path, extras: str = "", mode: int = 0o600) -> Path:
    p = tmp / "p.yaml"
    p.write_text(POLICY.format(extras=extras))
    os.chmod(p, mode)
    return p


def test_omit_strict_preflight_grants(env: dict[str, Path]) -> None:
    pol = _write_policy(env["tmp"])
    code, d = run("request", "--apply", "--policy", str(pol), *REQ)
    assert code == EXIT_OK, d
    assert d["status"] == "granted"


def test_strict_preflight_refuses_when_public_warnings(env: dict[str, Path]) -> None:
    pol = _write_policy(env["tmp"], extras="strict_preflight: true\n")
    pf_code, pf = run("preflight", "--policy", str(pol))
    assert pf_code == EXIT_OK
    warnings = [w for w in pf.get("warnings", []) if not str(w).startswith("dry run:")]
    if not warnings:
        pytest.skip("this DSN has no PUBLIC preflight warnings")
    code, d = run("request", "--apply", "--policy", str(pol), *REQ)
    assert code == EXIT_FAILED, d
    assert "strict_preflight" in d.get("error", "")


def test_strict_preflight_revoke_still_runs(env: dict[str, Path]) -> None:
    pol = _write_policy(env["tmp"])
    code, d = run("request", "--apply", "--policy", str(pol), *REQ)
    assert code == EXIT_OK, d
    gid = d["grant_id"]
    strict = _write_policy(env["tmp"], extras="strict_preflight: true\n")
    os.environ["DATAGRANT_POLICY"] = str(strict)
    code, rd = run("revoke", "--apply", gid)
    assert code == EXIT_OK, rd
    assert rd["outcome"] == "revoked"


def test_junk_strict_env_does_not_block_revoke(
    env: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = _write_policy(env["tmp"])
    code, d = run("request", "--apply", "--policy", str(pol), *REQ)
    assert code == EXIT_OK, d
    monkeypatch.setenv("DATAGRANT_STRICT_POLICY_PERMISSIONS", "enabled")
    monkeypatch.setenv("DATAGRANT_POLICY", str(pol))
    code, rd = run("revoke", "--apply", d["grant_id"])
    assert code == EXIT_OK, rd
    assert rd["outcome"] == "revoked"


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_policy_0644_warns_and_grants(env: dict[str, Path]) -> None:
    pol = _write_policy(env["tmp"], mode=0o644)
    code, d = run("request", "--apply", "--policy", str(pol), *REQ)
    assert code == EXIT_OK, d
    assert d["status"] == "granted"


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_strict_policy_permissions_refuses_0644(env: dict[str, Path]) -> None:
    pol = _write_policy(env["tmp"], extras="strict_policy_permissions: true\n", mode=0o644)
    code, d = run("request", "--apply", "--policy", str(pol), *REQ)
    assert code == EXIT_FAILED, d
    assert "group/other-accessible" in d.get("error", "")


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_receipt_log_0644_refuses_request_apply(env: dict[str, Path]) -> None:
    pol = _write_policy(env["tmp"])
    log = Path(os.environ["DATAGRANT_RECEIPT_LOG"])
    log.write_text("")
    os.chmod(log, 0o644)
    code, d = run("request", "--apply", "--policy", str(pol), *REQ)
    assert code == EXIT_FAILED, d
    assert "receipt log" in d.get("error", "")


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_receipt_log_0644_revoke_still_drops_exit_3(env: dict[str, Path]) -> None:
    pol = _write_policy(env["tmp"])
    code, d = run("request", "--apply", "--policy", str(pol), *REQ)
    assert code == EXIT_OK, d
    gid = d["grant_id"]
    log = Path(os.environ["DATAGRANT_RECEIPT_LOG"])
    os.chmod(log, 0o644)
    code, rd = run("revoke", "--apply", gid)
    assert code == EXIT_RECEIPT, rd
    assert rd["outcome"] == "revoked"
    with psycopg.connect(DSN, autocommit=True) as conn:
        row = conn.execute("SELECT status FROM datagrant.grants WHERE id = %s", (gid,)).fetchone()
    assert row is not None and row[0] == "revoked"
