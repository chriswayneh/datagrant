"""Advisory lock against a real Postgres. Set DATAGRANT_TEST_DSN to run."""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest

from datagrant.cli import EXIT_FAILED, EXIT_OK, main
from datagrant.pg.lock import (
    DATAGRANT_ADVISORY_LOCK_KEY,
    acquire_advisory_lock,
    holding_advisory_lock,
    release_advisory_lock,
)

DSN = os.environ.get("DATAGRANT_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DATAGRANT_TEST_DSN not set")

POLICY = """\
version: 1
approval: auto
max_duration: 8h
max_concurrent_grants: 1
groups:
  ml: [alice]
datasets:
  - name: clinic
    database: postgres
    tables:
      - name: public.dg_lock
        allowed_groups: [ml]
        columns: {id: passthrough, region: passthrough}
"""


def _try(conn: psycopg.Connection) -> bool:
    row = conn.execute(
        "SELECT pg_catalog.pg_try_advisory_lock(%s)",
        (DATAGRANT_ADVISORY_LOCK_KEY,),
    ).fetchone()
    assert row is not None
    return bool(row[0])


def test_session_lock_survives_commit_on_autocommit() -> None:
    assert DSN
    with (
        psycopg.connect(DSN, autocommit=True) as holder,
        psycopg.connect(DSN, autocommit=True) as other,
    ):
        acquire_advisory_lock(holder)
        holder.execute("SELECT 1")
        assert _try(other) is False
        release_advisory_lock(holder)
        assert _try(other) is True
        other.execute(
            "SELECT pg_catalog.pg_advisory_unlock(%s)",
            (DATAGRANT_ADVISORY_LOCK_KEY,),
        )


def test_second_connection_waits_until_unlock() -> None:
    assert DSN
    got = threading.Event()
    with (
        psycopg.connect(DSN, autocommit=True) as holder,
        psycopg.connect(DSN, autocommit=True) as waiter,
    ):
        acquire_advisory_lock(holder)

        def take() -> None:
            acquire_advisory_lock(waiter)
            got.set()
            release_advisory_lock(waiter)

        t = threading.Thread(target=take)
        t.start()
        time.sleep(0.3)
        assert not got.is_set()
        release_advisory_lock(holder)
        t.join(timeout=5)
        assert got.is_set()


def test_unlock_in_finally_releases_on_exception() -> None:
    assert DSN
    with (
        psycopg.connect(DSN, autocommit=True) as holder,
        psycopg.connect(DSN, autocommit=True) as other,
    ):
        with pytest.raises(RuntimeError, match="boom"), holding_advisory_lock(holder):
            holder.execute("SELECT 1")
            raise RuntimeError("boom")
        assert _try(other) is True
        other.execute(
            "SELECT pg_catalog.pg_advisory_unlock(%s)",
            (DATAGRANT_ADVISORY_LOCK_KEY,),
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
    pol = tmp_path / "p.yaml"
    pol.write_text(POLICY)
    with psycopg.connect(DSN, autocommit=True) as conn:
        from psycopg import sql

        from datagrant.pg.grant import ensure_state

        conn.execute("DROP TABLE IF EXISTS public.dg_lock")
        conn.execute("CREATE TABLE public.dg_lock (id int, region text)")
        conn.execute("INSERT INTO public.dg_lock VALUES (1, 'west')")
        ensure_state(conn)
        assert run("keys", "init", "--apply")[0] == EXIT_OK
        yield {"policy": pol}
        for role, view in conn.execute(
            "SELECT role_name, view_name FROM datagrant.grants"
        ).fetchall():
            conn.execute(sql.SQL("DROP VIEW IF EXISTS {}").format(sql.Identifier(*view.split("."))))
            if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        conn.execute("TRUNCATE datagrant.grants, datagrant.hash_keys, datagrant.requests")
        conn.execute("DROP TABLE public.dg_lock")


REQ = (
    "--dataset",
    "clinic",
    "--table",
    "public.dg_lock",
    "--columns",
    "id,region",
    "--duration",
    "1h",
    "--purpose",
    "x",
    "--as-user",
    "alice",
)


def test_cli_dry_run_does_not_hold_lock(env: dict[str, Path]) -> None:
    assert DSN
    code, d = run("request", "--policy", str(env["policy"]), *REQ)
    assert code == EXIT_OK and d.get("dry_run")
    with psycopg.connect(DSN, autocommit=True) as other:
        assert _try(other) is True
        other.execute(
            "SELECT pg_catalog.pg_advisory_unlock(%s)",
            (DATAGRANT_ADVISORY_LOCK_KEY,),
        )


def test_concurrent_cap_race_cannot_double_insert(env: dict[str, Path]) -> None:
    barrier = threading.Barrier(2)
    results: list[tuple[int, dict[str, Any]]] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        code, data = run("request", "--apply", "--policy", str(env["policy"]), *REQ)
        with lock:
            results.append((code, data))

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)
    granted = [d for c, d in results if c == EXIT_OK and d.get("status") == "granted"]
    denied = [d for c, d in results if c == EXIT_FAILED]
    assert len(results) == 2
    assert len(granted) == 1
    assert len(denied) == 1
    assert any("max_concurrent_grants" in r for r in denied[0].get("reasons", []))
