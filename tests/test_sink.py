from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from datagrant import receipt, sink
from datagrant.keys import init_keys, load_signing_key
from datagrant.receipt import GrantFacts
from datagrant.sink import FileSink, SinkConfigError, SinkError, WebhookSink

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
TOKEN = "s3cr3t-token-value"


@pytest.fixture
def lines(tmp_path: Path) -> list[bytes]:
    _, sp, _ = init_keys(tmp_path / "keys")
    key = load_signing_key(sp)
    log = tmp_path / "r.jsonl"
    for i in range(3):
        receipt.append(log, "issued", FACTS, key, event_at=T0, host="h", details={"i": i})
    return log.read_bytes().splitlines()


# ---------- file sink ----------


def test_file_sink_roundtrip(tmp_path: Path, lines: list[bytes]) -> None:
    s = FileSink(tmp_path / "out" / "s.jsonl")
    (tmp_path / "out").mkdir()
    assert s.head() is None
    for ln in lines:
        s.deliver(ln)
    s.deliver(lines[-1])  # idempotent resend of the last line
    assert s.head() == (2, hashlib.sha256(lines[-1]).hexdigest())
    if os.name == "posix":
        assert os.stat(s.path).st_mode & 0o777 == 0o600


def test_file_sink_refuses_gap_and_rewrite(tmp_path: Path, lines: list[bytes]) -> None:
    s = FileSink(tmp_path / "s.jsonl")
    with pytest.raises(SinkError, match="expects seq 0"):
        s.deliver(lines[1])
    s.deliver(lines[0])
    s.deliver(lines[1])
    with pytest.raises(SinkError, match="expects seq 2, got 3"):
        s.deliver(lines[2].replace(b'"seq":2', b'"seq":3'))


def test_file_sink_idempotent_per_seq(tmp_path: Path, lines: list[bytes]) -> None:
    s = FileSink(tmp_path / "s.jsonl")
    for ln in lines:
        s.deliver(ln)
    before = s.path.read_bytes()
    s.deliver(lines[1])  # identical resend of an older seq: no-op
    s.deliver(lines[0])
    assert s.path.read_bytes() == before
    forged = lines[1].replace(b'"h"', b'"x"')
    assert forged != lines[1]
    with pytest.raises(SinkError, match="different receipt at seq 1"):
        s.deliver(forged)
    assert s.path.read_bytes() == before


def test_file_sink_rejects_bad_lines(tmp_path: Path) -> None:
    s = FileSink(tmp_path / "s.jsonl")
    for bad in (b"", b"not json", b'{"receipt": {"seq": -1}}', b"a\nb"):
        with pytest.raises(SinkError):
            s.deliver(bad)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks and modes")
def test_file_sink_no_symlink_and_private(tmp_path: Path, lines: list[bytes]) -> None:
    target = tmp_path / "t.jsonl"
    target.touch(mode=0o600)
    link = tmp_path / "l.jsonl"
    link.symlink_to(target)
    with pytest.raises(SinkError, match="cannot open"):
        FileSink(link).deliver(lines[0])
    loose = tmp_path / "loose.jsonl"
    loose.touch()
    loose.chmod(0o644)
    with pytest.raises(SinkError, match="group/others"):
        FileSink(loose).deliver(lines[0])


# ---------- webhook sink with a local stdlib server ----------


class _State:
    def __init__(self) -> None:
        self.lines: list[bytes] = []
        self.auth: list[str | None] = []
        self.fail_next = 0
        self.status = 200


@pytest.fixture
def server() -> Iterator[tuple[str, _State]]:
    st = _State()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def do_POST(self) -> None:
            st.auth.append(self.headers.get("Authorization"))
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if st.fail_next:
                st.fail_next -= 1
                self.send_response(503)
            elif st.status != 200:
                self.send_response(st.status)
            else:
                assert self.headers["Content-Type"] == "application/x-ndjson"
                st.lines.extend(body.splitlines())
                self.send_response(204)
            self.end_headers()

        def do_GET(self) -> None:
            if self.path != "/sink/head":
                self.send_response(400)
                self.end_headers()
                return
            if not st.lines:
                self.send_response(404)
                self.end_headers()
                return
            last = st.lines[-1]
            doc = {
                "seq": json.loads(last)["receipt"]["seq"],
                "head_sha256": hashlib.sha256(last).hexdigest(),
            }
            out = json.dumps(doc).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/sink", st
    finally:
        srv.shutdown()
        srv.server_close()


def test_webhook_roundtrip(server: tuple[str, _State], lines: list[bytes]) -> None:
    url, st = server
    s = sink.parse_sink_url(url, TOKEN)
    assert isinstance(s, WebhookSink)
    assert s.head() is None
    for ln in lines:
        s.deliver(ln)
    assert st.lines == lines
    assert st.auth == [f"Bearer {TOKEN}"] * 3
    assert s.head() == (2, hashlib.sha256(lines[-1]).hexdigest())
    assert TOKEN not in repr(s)


def test_webhook_retries_then_succeeds(server: tuple[str, _State], lines: list[bytes]) -> None:
    url, st = server
    st.fail_next = 2
    WebhookSink(url, retry_delays=(0, 0, 0)).deliver(lines[0])
    assert st.lines == [lines[0]]


def test_webhook_refusal_not_retried(server: tuple[str, _State], lines: list[bytes]) -> None:
    url, st = server
    st.status = 409
    with pytest.raises(SinkError, match="HTTP 409"):
        WebhookSink(url, TOKEN, retry_delays=(0, 0, 0)).deliver(lines[0])
    assert len(st.auth) == 1


def test_webhook_unreachable_redacts_token(lines: list[bytes]) -> None:
    s = WebhookSink(f"http://127.0.0.1:9/{TOKEN}", TOKEN, timeout=1, retry_delays=(0,))
    with pytest.raises(SinkError) as ei:
        s.deliver(lines[0])
    assert TOKEN not in str(ei.value)
    assert "***" in str(ei.value)
    with pytest.raises(SinkError) as ei2:
        s.head()
    assert TOKEN not in str(ei2.value)


def test_webhook_malformed_head(server: tuple[str, _State]) -> None:
    url, _ = server
    with pytest.raises(SinkError, match="HTTP 400"):
        WebhookSink(url + "/x").head()


# ---------- config ----------


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/r",
        "ftp://example.com/r",
        "https://user:pw@example.com/r",
        f"https://{TOKEN}@example.com/r",
        "https:///r",
        "https://example.com/r?token=x",
        "https://example.com:notaport/r",
        "file://otherhost/r",
        "file:relative",
        "",
        "/abs/path",
    ],
)
def test_bad_urls_refused(url: str) -> None:
    with pytest.raises(SinkConfigError) as ei:
        sink.parse_sink_url(url, TOKEN)
    assert TOKEN not in str(ei.value)
    assert "pw" not in str(ei.value)


def test_good_urls(tmp_path: Path) -> None:
    assert isinstance(sink.parse_sink_url("https://siem.example/r"), WebhookSink)
    assert isinstance(sink.parse_sink_url("http://localhost:8080/r"), WebhookSink)
    f = sink.parse_sink_url((tmp_path / "s.jsonl").as_uri())
    assert isinstance(f, FileSink)


def test_config_from_env(tmp_path: Path) -> None:
    assert sink.sink_from_config(env={}) is None
    env = {sink.SINK_ENV: "https://siem.example/r", sink.SINK_TOKEN_ENV: TOKEN}
    cfg = sink.sink_from_config(env=env)
    assert cfg is not None and cfg.mode == "best-effort"
    assert TOKEN not in repr(cfg)
    cfg2 = sink.sink_from_config("https://other.example/r", "required", env=env)
    assert (
        cfg2 is not None and cfg2.mode == "required" and cfg2.sink.name.startswith("https://other")
    )
    with pytest.raises(SinkConfigError, match="mode"):
        sink.sink_from_config(env={sink.SINK_MODE_ENV: "sometimes"})


# ---------- wall-clock limit ----------


@pytest.fixture
def slow_server() -> Iterator[str]:
    stop = threading.Event()

    class Slow(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def _trickle(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            for _ in range(1000):  # one byte every 0.2 s: never idle long enough to time out
                if stop.is_set():
                    return
                try:
                    self.wfile.write(b"x")
                    self.wfile.flush()
                except OSError:
                    return
                time.sleep(0.2)

        def do_GET(self) -> None:
            self._trickle()

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers["Content-Length"]))
            self._trickle()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Slow)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/sink"
    finally:
        stop.set()
        srv.shutdown()
        srv.server_close()


def test_webhook_total_deadline_on_trickle(slow_server: str, lines: list[bytes]) -> None:
    s = WebhookSink(slow_server, TOKEN, timeout=1.0, retry_delays=())
    t = time.monotonic()
    with pytest.raises(SinkError, match="timed out"):
        s.head()
    assert time.monotonic() - t < 3
    t = time.monotonic()
    with pytest.raises(SinkError, match="timed out"):
        s.deliver(lines[0])
    assert time.monotonic() - t < 3


# ---------- token validation ----------


@pytest.mark.parametrize("bad", ["abc123\r\n", "has space", "tab\there", "caf\u00e9", "nul\x00x"])
def test_bad_token_refused_without_echo(bad: str, tmp_path: Path) -> None:
    errors: list[str] = []
    with pytest.raises(SinkConfigError, match="invalid characters") as e1:
        WebhookSink("https://siem.example/r", bad)
    errors.append(str(e1.value))
    errors.append(repr(e1.value))
    env = {sink.SINK_ENV: "https://siem.example/r", sink.SINK_TOKEN_ENV: bad}
    with pytest.raises(SinkConfigError) as e2:
        sink.sink_from_config(env=env)
    errors.append(str(e2.value))
    errors.append(repr(e2.value))
    with pytest.raises(SinkConfigError) as e3:
        sink.parse_sink_url("https://siem.example/r", bad)
    errors.append(str(e3.value))
    for text in errors:
        assert bad not in text
        assert repr(bad) not in text
        assert bad.strip() not in text


def test_good_token_never_in_repr() -> None:
    s = WebhookSink("https://siem.example/r", TOKEN)
    assert TOKEN not in repr(s) and TOKEN not in str(s)
    cfg = sink.sink_from_config(
        env={sink.SINK_ENV: "https://x.example/r", sink.SINK_TOKEN_ENV: TOKEN}
    )
    assert cfg is not None and TOKEN not in repr(cfg)
