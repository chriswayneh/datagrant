"""Receipt sink delivery against a real Postgres. Set DATAGRANT_TEST_DSN (superuser) to run."""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from datagrant import outbox
from datagrant.cli import EXIT_OK, EXIT_RECEIPT

from . import test_cli_e2e as e2e

REQ, login, run = e2e.REQ, e2e.login, e2e.run
env = e2e.env  # shared fixture

DSN = os.environ.get("DATAGRANT_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DATAGRANT_TEST_DSN not set")
TOKEN = "e2e-token-0123456789"


class Hook:
    def __init__(self) -> None:
        self.lines: list[bytes] = []
        self.status = 204
        self.auth: list[str | None] = []


@pytest.fixture
def hook() -> Iterator[tuple[str, Hook]]:
    st = Hook()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            st.auth.append(self.headers.get("Authorization"))
            if st.status < 300:
                st.lines.extend(body.splitlines())
            self.send_response(st.status)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/r", st
    finally:
        srv.shutdown()
        srv.server_close()


def _grant(pol: Path, *extra: str) -> tuple[int, dict[str, Any]]:
    return run(
        "request",
        "--apply",
        "--policy",
        str(pol),
        "--as-user",
        "alice",
        "--duration",
        "1h",
        *REQ,
        *extra,
    )


def _log() -> Path:
    return Path(os.environ["DATAGRANT_RECEIPT_LOG"])


def _events() -> list[str]:
    return [json.loads(x)["receipt"]["event"] for x in _log().read_text().splitlines()]


def test_file_sink_best_effort_grant_and_revoke(env: dict[str, Path], tmp_path: Path) -> None:
    remote = tmp_path / "remote.jsonl"
    sink = ("--receipt-sink", remote.as_uri())
    code, g = _grant(env["auto"], *sink)
    assert code == EXIT_OK and g["status"] == "granted"
    assert remote.read_bytes() == _log().read_bytes()
    code, r = run("revoke", "--apply", g["grant_id"], *sink)
    assert code == EXIT_OK and r["sink"] == {"delivered": 1, "pending": 0, "error": None}
    assert remote.read_bytes() == _log().read_bytes()
    assert outbox.read_cursor(_log()) == 1


def test_webhook_best_effort_outbox_then_push(
    env: dict[str, Path],
    hook: tuple[str, Hook],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    url, st = hook
    monkeypatch.setenv("DATAGRANT_RECEIPT_SINK", url)
    monkeypatch.setenv("DATAGRANT_RECEIPT_SINK_TOKEN", TOKEN)
    st.status = 503
    code, g = _grant(env["auto"])
    assert code == EXIT_OK and g["status"] == "granted"  # best effort: the grant stands
    err = capsys.readouterr().err
    assert "not delivered to sink" in err and TOKEN not in err
    code, r = run("revoke", "--apply", g["grant_id"])  # never blocked by the sink
    assert code == EXIT_OK and r["outcome"] == "revoked" and r["sink"]["pending"] == 2
    assert TOKEN not in json.dumps(r)
    st.status = 204
    code, p = run("receipts", "push", "--apply")
    assert code == EXIT_OK and p == {"delivered": 2, "pending": 0, "error": None}
    assert st.lines == _log().read_bytes().splitlines()
    assert set(st.auth) == {f"Bearer {TOKEN}"}


def test_webhook_required_failure_revokes_grant(
    env: dict[str, Path],
    hook: tuple[str, Hook],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url, st = hook
    monkeypatch.setenv("DATAGRANT_RECEIPT_SINK_TOKEN", TOKEN)
    st.status = 503
    code, out = _grant(env["auto"], "--receipt-sink", url, "--receipt-sink-mode", "required")
    assert code == EXIT_RECEIPT
    assert out["error"].endswith("; grant revoked") and TOKEN not in out["error"]
    code, lst = run("grant", "list", "--all")
    assert [x["status"] for x in lst["grants"]] == ["revoked"]
    assert _events() == ["issued", "revoked"]
    assert outbox.read_cursor(_log()) == -1  # both still pending for a later push


def test_webhook_required_success(env: dict[str, Path], hook: tuple[str, Hook]) -> None:
    url, st = hook
    sink = ("--receipt-sink", url, "--receipt-sink-mode", "required")
    code, g = _grant(env["auto"], *sink)
    assert code == EXIT_OK and g["status"] == "granted"
    with login(g["connection"], g["password"]) as c:
        assert c.execute(f"SELECT count(*) FROM {g['view']}").fetchone() == (2,)
    assert len(st.lines) == 1
    st.status = 500
    code, r = run("revoke", "--apply", g["grant_id"], *sink)  # required never blocks revoke
    assert code == EXIT_OK and r["outcome"] == "revoked" and r["sink"]["pending"] == 1


def test_two_person_approve_delivers(env: dict[str, Path], tmp_path: Path) -> None:
    remote = tmp_path / "remote.jsonl"
    sink = ("--receipt-sink", remote.as_uri(), "--receipt-sink-mode", "required")
    code, p = _grant(env["two-person"], *sink)
    assert code == EXIT_OK and p["status"] == "pending"
    code, _ = run(
        "approve",
        "--apply",
        "--policy",
        str(env["two-person"]),
        "--as-user",
        "carol",
        p["request_id"],
        *sink,
    )
    assert code == EXIT_OK
    assert remote.read_bytes() == _log().read_bytes()
    assert _events() == ["issued"]


@pytest.mark.parametrize("problem", ["ahead", "loose"])
def test_bad_outbox_refuses_before_issuing(
    env: dict[str, Path], tmp_path: Path, problem: str
) -> None:
    sink = ("--receipt-sink", (tmp_path / "remote.jsonl").as_uri())
    cur = outbox.cursor_path(_log())
    cur.parent.mkdir(parents=True, exist_ok=True)
    cur.write_text('{"acked_seq": 999}' if problem == "ahead" else '{"acked_seq": -1}')
    cur.chmod(0o600 if problem == "ahead" else 0o644)
    for mode in ("best-effort", "required"):
        code, out = _grant(env["auto"], *sink, "--receipt-sink-mode", mode)
        assert code == EXIT_RECEIPT and "not issuing" in out["error"]
    assert run("grant", "list", "--all")[1]["grants"] == []
    assert not _log().exists() or _log().read_text() == ""
