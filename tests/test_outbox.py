from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from datagrant import outbox, receipt
from datagrant.cli import EXIT_OK, EXIT_RECEIPT, EXIT_USAGE, main
from datagrant.keys import init_keys, load_signing_key
from datagrant.receipt import GrantFacts, ReceiptError
from datagrant.sink import FileSink, SinkError

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
TOKEN = "tok-1234567890"


def _log(tmp_path: Path, n: int = 3) -> Path:
    _, sp, _ = init_keys(tmp_path / "keys")
    key = load_signing_key(sp)
    log = tmp_path / "r.jsonl"
    for i in range(n):
        receipt.append(log, "issued", FACTS, key, event_at=T0, host="h", details={"i": i})
    return log


class Flaky:
    """Delivers to a FileSink but fails on chosen seqs."""

    name = "flaky"

    def __init__(self, path: Path, fail: set[int]) -> None:
        self.inner = FileSink(path)
        self.fail = fail
        self.calls: list[int] = []

    def deliver(self, line: bytes) -> None:
        seq = json.loads(line)["receipt"]["seq"]
        self.calls.append(seq)
        if seq in self.fail:
            raise SinkError(f"down at {seq}")
        self.inner.deliver(line)

    def head(self) -> tuple[int, str] | None:
        return self.inner.head()


def test_flush_all_then_nothing(tmp_path: Path) -> None:
    log = _log(tmp_path)
    s = FileSink(tmp_path / "remote.jsonl")
    assert outbox.flush(log, s) == outbox.FlushResult(3, 0, None)
    assert outbox.read_cursor(log) == 2
    assert (tmp_path / "remote.jsonl").read_bytes() == log.read_bytes()
    assert outbox.flush(log, s) == outbox.FlushResult(0, 0, None)
    if os.name == "posix":
        assert os.stat(outbox.cursor_path(log)).st_mode & 0o777 == 0o600


def test_cursor_advances_only_after_success(tmp_path: Path) -> None:
    log = _log(tmp_path)
    s = Flaky(tmp_path / "remote.jsonl", {1})
    res = outbox.flush(log, s)
    assert (res.delivered, res.pending) == (1, 2) and "down at 1" in (res.error or "")
    assert outbox.read_cursor(log) == 0
    s.fail = set()
    assert outbox.flush(log, s) == outbox.FlushResult(2, 0, None)
    assert s.calls == [0, 1, 1, 2]


def test_crash_between_deliver_and_cursor_resends(tmp_path: Path) -> None:
    log = _log(tmp_path)
    s = FileSink(tmp_path / "remote.jsonl")
    for ln in log.read_bytes().splitlines()[:2]:
        s.deliver(ln)  # delivered, but the cursor was never written (crash)
    assert outbox.read_cursor(log) == -1
    assert outbox.flush(log, s) == outbox.FlushResult(3, 0, None)
    assert (tmp_path / "remote.jsonl").read_bytes() == log.read_bytes()


def test_cursor_ahead_of_log_is_an_error(tmp_path: Path) -> None:
    log = _log(tmp_path, 1)
    outbox.write_cursor(log, 5)
    res = outbox.flush(log, FileSink(tmp_path / "remote.jsonl"))
    assert res.error and "truncated or replaced" in res.error


def test_corrupt_cursor(tmp_path: Path) -> None:
    log = _log(tmp_path, 1)
    p = outbox.cursor_path(log)
    p.write_text("nope")
    p.chmod(0o600)
    with pytest.raises(ReceiptError, match="corrupt"):
        outbox.read_cursor(log)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks and modes")
def test_cursor_file_rules(tmp_path: Path) -> None:
    log = _log(tmp_path, 1)
    p = outbox.cursor_path(log)
    target = tmp_path / "elsewhere"
    target.write_text('{"acked_seq": 0}')
    target.chmod(0o600)
    p.symlink_to(target)
    with pytest.raises(ReceiptError, match="cannot open"):
        outbox.read_cursor(log)
    p.unlink()
    p.write_text('{"acked_seq": 0}')
    p.chmod(0o644)
    with pytest.raises(ReceiptError, match="group/others"):
        outbox.read_cursor(log)


# ---------- receipts push (no database needed) ----------


def _push(*argv: str) -> tuple[int, dict[str, object]]:
    out: list[str] = []
    code = main(["--json", "receipts", "push", *argv], out.append)
    return code, json.loads(out[-1]) if out else {}


def test_push_dry_run_then_apply(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = _log(tmp_path)
    remote = tmp_path / "remote.jsonl"
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(log))
    monkeypatch.setenv("DATAGRANT_RECEIPT_SINK", remote.as_uri())
    code, out = _push()
    assert code == EXIT_OK and out["dry_run"] is True and out["pending"] == 3
    assert not remote.exists()
    code, out = _push("--apply")
    assert code == EXIT_OK and out == {"delivered": 3, "pending": 0, "error": None}
    assert _push("--apply")[1]["delivered"] == 0


def test_push_without_sink_is_usage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATAGRANT_RECEIPT_SINK", raising=False)
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(_log(tmp_path)))
    assert _push("--apply")[0] == EXIT_USAGE


def test_push_failure_exit_3_and_token_hidden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(_log(tmp_path)))
    monkeypatch.setenv("DATAGRANT_RECEIPT_SINK_TOKEN", TOKEN)
    code, out = _push("--apply", "--receipt-sink", f"http://127.0.0.1:9/{TOKEN}")
    assert code == EXIT_RECEIPT and out["pending"] == 3
    assert TOKEN not in json.dumps(out) + capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["receipts", "push", "--receipt-sink", "http://example.com/r"],
        ["receipts", "push", "--receipt-sink", f"https://u:{TOKEN}@example.com/r"],
        ["revoke", "abc", "--receipt-sink", "ftp://x/r"],
        ["sweep", "--receipt-sink-mode", "sometimes"],
    ],
)
def test_bad_sink_config_is_usage_before_db(
    argv: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DATAGRANT_DSN", "postgresql://nobody@127.0.0.1:1/x")
    assert main(argv) == EXIT_USAGE
    assert TOKEN not in capsys.readouterr().err


def test_bad_token_env_is_usage(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DATAGRANT_RECEIPT_SINK", "https://x.example/r")
    monkeypatch.setenv("DATAGRANT_RECEIPT_SINK_TOKEN", "abc 123\r\n")
    assert main(["receipts", "push"]) == EXIT_USAGE
    assert "abc 123" not in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="no flush lock on Windows (single writer)")
def test_concurrent_flushes_keep_cursor_monotonic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading

    log = _log(tmp_path, 6)
    seen: list[int] = []
    real = outbox.write_cursor

    def spy(lg: Path, seq: int) -> None:
        seen.append(seq)
        real(lg, seq)

    monkeypatch.setattr(outbox, "write_cursor", spy)
    s = FileSink(tmp_path / "remote.jsonl")
    errs: list[str | None] = []
    ts = [
        threading.Thread(target=lambda: errs.append(outbox.flush(log, s).error)) for _ in range(4)
    ]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert errs == [None] * 4
    assert outbox.read_cursor(log) == 5
    assert seen == list(range(6))  # locked: each seq written once, in order
    assert (tmp_path / "remote.jsonl").read_bytes() == log.read_bytes()
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".sink.")]


def test_required_revoke_failure_says_still_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import argparse
    from types import SimpleNamespace

    from datagrant import cli
    from datagrant.pg.revoke import RevokeResult
    from datagrant.sink import SinkConfig

    log = _log(tmp_path, 1)
    bad = Flaky(tmp_path / "remote.jsonl", {0})
    args = argparse.Namespace(json=True, _remote=SinkConfig(bad, "required"))
    ctx = cli.Ctx(args, print)
    monkeypatch.setattr(
        "datagrant.pg.revoke.revoke",
        lambda *a, **k: RevokeResult("abcdef012345", "failed", 0, "db down"),
    )
    with pytest.raises(cli.CliError) as ei:
        cli._deliver_issued(
            ctx, None, SimpleNamespace(grant_id="abcdef012345"), SimpleNamespace(log=log)
        )
    assert ei.value.code == EXIT_RECEIPT
    assert "grant STILL ACTIVE until the next sweep" in str(ei.value)
