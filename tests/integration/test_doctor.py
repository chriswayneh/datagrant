"""datagrant doctor against a real Postgres. Set DATAGRANT_TEST_DSN to run."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest

from datagrant.cli import EXIT_FAILED, EXIT_OK, EXIT_USAGE, main
from datagrant.doctor import CHECK_CONNECT, CHECK_ORDER, STATUS_FAIL

DSN = os.environ.get("DATAGRANT_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DATAGRANT_TEST_DSN not set")

POLICY = """\
version: 1
approval: auto
max_duration: 8h
groups:
  ml: [alice]
datasets:
  - name: clinic
    database: postgres
    tables:
      - name: public.dg_doctor
        allowed_groups: [ml]
        columns: {id: passthrough}
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
    pol = tmp_path / "p.yaml"
    pol.write_text(POLICY)
    if os.name != "nt":
        os.chmod(pol, 0o600)
    log = tmp_path / "receipts.jsonl"
    log.write_text("")
    if os.name != "nt":
        os.chmod(log, 0o600)
    assert run("keys", "init", "--apply")[0] == EXIT_OK
    yield {"policy": pol}


def test_doctor_exits_0_on_live_dsn(env: dict[str, Path]) -> None:
    assert DSN
    with psycopg.connect(DSN, autocommit=True) as conn:
        before = {
            r[0] for r in conn.execute("SELECT nspname FROM pg_catalog.pg_namespace").fetchall()
        }
        log_stmt = conn.execute("SHOW log_statement").fetchone()
    code, d = run("doctor", "--policy", str(env["policy"]))
    failed = [c for c in d.get("checks", []) if c.get("status") == STATUS_FAIL]
    assert code == EXIT_OK and d.get("ok") is True, failed or d
    assert [c["name"] for c in d["checks"]] == list(CHECK_ORDER)
    assert not failed
    with psycopg.connect(DSN, autocommit=True) as conn:
        after = {
            r[0] for r in conn.execute("SELECT nspname FROM pg_catalog.pg_namespace").fetchall()
        }
        after_log = conn.execute("SHOW log_statement").fetchone()
    assert after == before
    assert after_log == log_stmt


def test_doctor_unreachable_dsn_fails(
    env: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATAGRANT_DSN", "postgresql://admin:pw9secret@127.0.0.1:1/clinicdb")
    code, d = run("doctor", "--policy", str(env["policy"]))
    assert code == EXIT_FAILED
    connect = next(c for c in d["checks"] if c["name"] == CHECK_CONNECT)
    assert connect["status"] == STATUS_FAIL
    assert "pw9secret" not in json.dumps(d)


def test_doctor_apply_usage() -> None:
    assert main(["doctor", "--apply"], lambda s: None) == EXIT_USAGE
