from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from datagrant import outbox, receipt
from datagrant.cli import EXIT_FAILED, EXIT_OK, main
from datagrant.keys import init_keys, load_signing_key
from datagrant.receipt import GrantFacts
from datagrant.sink import FileSink

T0 = datetime(2026, 11, 2, 18, 0, tzinfo=UTC)
FACTS = GrantFacts(
    "abcdef012345",
    "alice",
    "clinic",
    "public.patients",
    ("id",),
    {"id": "passthrough"},
    None,
    "debug",
    T0,
    T0 + timedelta(hours=2),
    "f" * 64,
    1,
    "auto",
)
TOKEN = "verify-token-123456"


def _make_log(d: Path, n: int, tag: str) -> Path:
    _, sp, _ = init_keys(
        d / "keys", hash_path=d / "keys" / "hash.key", signing_path=d / "keys" / "signing.key"
    )
    key = load_signing_key(sp)
    log = d / "r.jsonl"
    for i in range(n):
        receipt.append(log, "issued", FACTS, key, event_at=T0, host=tag, details={"i": i})
    return log


@pytest.fixture
def local(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "local"
    log = _make_log(d, 3, "a")
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(log))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(d / "keys" / "signing.key"))
    monkeypatch.delenv("DATAGRANT_RECEIPT_SINK", raising=False)
    return log


def _remote(tmp_path: Path, lines: list[bytes]) -> Path:
    p = tmp_path / "remote.jsonl"
    s = FileSink(p)
    for ln in lines:
        s.deliver(ln)
    return p


def verify(*argv: str) -> tuple[int, dict[str, Any]]:
    out: list[str] = []
    code = main(["--json", "receipts", "verify", *argv], out.append)
    return code, json.loads(out[-1])


def _readonly(local: Path, remote: Path | None, before: bytes | None) -> None:
    assert not outbox.cursor_path(local).exists()
    if remote is not None and before is not None:
        assert remote.read_bytes() == before


def test_equal(local: Path, tmp_path: Path) -> None:
    lines = local.read_bytes().splitlines()
    r = _remote(tmp_path, lines)
    before = r.read_bytes()
    code, out = verify("--sink", r.as_uri())
    assert code == EXIT_OK and out["ok"] is True
    assert out["sink_seq"] == 2 and out["undelivered"] == 0
    assert out["sink_head_sha256"] == out["head_sha256"]
    _readonly(local, r, before)


def test_remote_behind_is_pending(local: Path, tmp_path: Path) -> None:
    r = _remote(tmp_path, local.read_bytes().splitlines()[:1])
    before = r.read_bytes()
    code, out = verify("--receipt-sink", r.as_uri())
    assert code == EXIT_OK and out["sink_seq"] == 0 and out["undelivered"] == 2
    _readonly(local, r, before)


def test_remote_empty_is_pending(local: Path, tmp_path: Path) -> None:
    code, out = verify("--sink", (tmp_path / "none.jsonl").as_uri())
    assert code == EXIT_OK and out["sink_seq"] is None and out["undelivered"] == 3
    assert not (tmp_path / "none.jsonl").exists()


def test_remote_ahead_means_local_truncated(local: Path, tmp_path: Path) -> None:
    lines = local.read_bytes().splitlines()
    r = _remote(tmp_path, lines)
    local.write_bytes(b"\n".join(lines[:2]) + b"\n")  # newest receipt deleted
    code, out = verify("--sink", r.as_uri())
    assert code == EXIT_FAILED and out["ok"] is False
    assert "sink is ahead" in out["error"] and out["sink_seq"] == 2


def test_hash_mismatch_same_seq(local: Path, tmp_path: Path) -> None:
    other = _make_log(tmp_path / "other", 3, "b").read_bytes().splitlines()
    r = _remote(tmp_path, other)
    code, out = verify("--sink", r.as_uri())
    assert code == EXIT_FAILED and "chains differ at seq 2" in out["error"]


def test_hash_mismatch_when_remote_behind(local: Path, tmp_path: Path) -> None:
    other = _make_log(tmp_path / "other", 2, "b").read_bytes().splitlines()
    r = _remote(tmp_path, other)
    code, out = verify("--sink", r.as_uri())
    assert code == EXIT_FAILED and "chains differ at seq 1" in out["error"]


def test_local_failure_skips_sink(local: Path, tmp_path: Path) -> None:
    r = _remote(tmp_path, local.read_bytes().splitlines())
    code, out = verify("--sink", r.as_uri(), "--expect-head", "0" * 64)
    assert code == EXIT_FAILED and "head hash differs" in out["error"]


# ---------- webhook ----------


@pytest.fixture
def hook() -> Iterator[tuple[str, dict[str, Any]]]:
    st: dict[str, Any] = {"head": None, "posts": 0, "auth": []}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def do_POST(self) -> None:
            st["posts"] += 1
            self.send_response(500)
            self.end_headers()

        def do_GET(self) -> None:
            st["auth"].append(self.headers.get("Authorization"))
            if st["head"] is None:
                self.send_response(404)
                self.end_headers()
                return
            out = json.dumps(st["head"]).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/r", st
    finally:
        srv.shutdown()
        srv.server_close()


def test_webhook_cases(
    local: Path, hook: tuple[str, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    url, st = hook
    monkeypatch.setenv("DATAGRANT_RECEIPT_SINK", url)  # env config
    monkeypatch.setenv("DATAGRANT_RECEIPT_SINK_TOKEN", TOKEN)
    lines = local.read_bytes().splitlines()
    h = [hashlib.sha256(x).hexdigest() for x in lines]
    st["head"] = {"seq": 2, "head_sha256": h[2]}
    assert verify()[0] == EXIT_OK
    st["head"] = {"seq": 1, "head_sha256": h[1]}
    code, out = verify()
    assert code == EXIT_OK and out["undelivered"] == 1
    st["head"] = {"seq": 5, "head_sha256": h[2]}
    assert verify()[0] == EXIT_FAILED
    st["head"] = {"seq": 2, "head_sha256": "a" * 64}
    assert verify()[0] == EXIT_FAILED
    st["head"] = None
    code, out = verify()
    assert code == EXIT_OK and out["undelivered"] == 3
    assert st["posts"] == 0 and set(st["auth"]) == {f"Bearer {TOKEN}"}
    assert not outbox.cursor_path(local).exists()


def test_unreachable_sink_fails_and_hides_token(
    local: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DATAGRANT_RECEIPT_SINK_TOKEN", TOKEN)
    code, out = verify("--sink", f"http://127.0.0.1:9/{TOKEN}")
    assert code == EXIT_FAILED and "remote check could not run" in out["error"]
    assert out["count"] == 3 and out["head_sha256"]  # local result still reported
    assert TOKEN not in json.dumps(out) + capsys.readouterr().err
    assert main(["receipts", "verify", "--sink", f"http://127.0.0.1:9/{TOKEN}"]) == EXIT_FAILED
    assert TOKEN not in capsys.readouterr().out


def test_text_output(local: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    r = _remote(tmp_path, local.read_bytes().splitlines()[:2])
    assert main(["receipts", "verify", "--sink", r.as_uri()]) == EXIT_OK
    assert "1 receipt(s) not yet delivered" in capsys.readouterr().out


# ---------- acknowledgements and bounds ----------


def test_empty_sink_after_acks_fails(local: Path, tmp_path: Path) -> None:
    outbox.write_cursor(local, 1)  # sink had acknowledged seq 0 and 1
    code, out = verify("--sink", (tmp_path / "fresh.jsonl").as_uri())
    assert code == EXIT_FAILED
    assert "sink is behind its own acknowledgements" in out["error"]
    assert "acked seq 1, sink head none" in out["error"]


def test_rolled_back_sink_head_fails(local: Path, tmp_path: Path) -> None:
    r = _remote(tmp_path, local.read_bytes().splitlines()[:1])
    outbox.write_cursor(local, 2)
    code, out = verify("--sink", r.as_uri())
    assert code == EXIT_FAILED and "acked seq 2, sink head 0" in out["error"]


def test_acked_and_matching_passes(local: Path, tmp_path: Path) -> None:
    r = _remote(tmp_path, local.read_bytes().splitlines()[:2])
    outbox.write_cursor(local, 1)
    code, out = verify("--sink", r.as_uri())
    assert code == EXIT_OK and out["undelivered"] == 1
    assert json.loads(outbox.cursor_path(local).read_text()) == {"acked_seq": 1}


@pytest.mark.parametrize("bad", ["corrupt", "ahead"])
def test_bad_cursor_fails_closed(local: Path, tmp_path: Path, bad: str) -> None:
    r = _remote(tmp_path, local.read_bytes().splitlines())
    p = outbox.cursor_path(local)
    if bad == "corrupt":
        p.write_text("not json")
        p.chmod(0o600)
    else:
        outbox.write_cursor(local, 7)
    code, out = verify("--sink", r.as_uri())
    assert code == EXIT_FAILED
    assert ("outbox cursor unusable" if bad == "corrupt" else "outbox cursor is at seq 7") in out[
        "error"
    ]


def test_line_hash_read_is_bounded(tmp_path: Path) -> None:
    log = tmp_path / "big.jsonl"
    log.write_bytes(b"x" * (receipt.MAX_LINE_BYTES + 10) + b"\n")
    remote = tmp_path / "remote.jsonl"
    remote.write_bytes(b"")
    remote.chmod(0o600)

    class Head:
        name = "fixed"

        def deliver(self, line: bytes) -> None:
            raise AssertionError("read-only")

        def head(self) -> tuple[int, str] | None:
            return 0, "0" * 64

    chk = outbox.compare_with_sink(log, Head(), 1)
    assert not chk.ok and "line too long" in (chk.error or "")
