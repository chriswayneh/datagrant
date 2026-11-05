"""Receipt outbox: deliver local receipts to the external sink (sink PR 2 of 4).

The outbox is not a second file of record. It is the local receipt log plus a
small cursor file (``<receipt-log>.sink``, 0600, no symlinks) holding the last
``seq`` the sink acknowledged. Lines after the cursor are pending.

Crash safety: the cursor only advances after a successful ``deliver``. If the
process dies between the two, the next flush resends that line, and sinks are
idempotent per ``seq`` (an identical resend is a no-op).
"""

from __future__ import annotations

import copy
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from datagrant.receipt import ReceiptError, _locked
from datagrant.sink import ReceiptSink, SinkError, WebhookSink, _line_seq

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)


@dataclass(frozen=True)
class FlushResult:
    delivered: int
    pending: int
    error: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {"delivered": self.delivered, "pending": self.pending, "error": self.error}


def cursor_path(log: str | Path) -> Path:
    p = Path(log)
    return p.with_name(p.name + ".sink")


def _read_private(p: Path, what: str) -> bytes | None:
    try:
        fd = os.open(p, os.O_RDONLY | _NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ReceiptError(f"cannot open {what} {p}: {exc.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ReceiptError(f"{what} {p} is not a regular file")
        if os.name == "posix" and st.st_mode & 0o077:
            raise ReceiptError(f"{what} {p} must not be readable by group/others (chmod 600)")
        chunks = []
        while chunk := os.read(fd, 1 << 16):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_cursor(log: str | Path) -> int:
    """Last seq the sink acknowledged, or -1 if nothing was delivered yet."""
    raw = _read_private(cursor_path(log), "sink cursor")
    if raw is None:
        return -1
    try:
        seq = json.loads(raw)["acked_seq"]
    except (ValueError, KeyError, TypeError):
        raise ReceiptError(f"sink cursor {cursor_path(log)} is corrupt") from None
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < -1:
        raise ReceiptError(f"sink cursor {cursor_path(log)} is corrupt")
    return seq


def write_cursor(log: str | Path, seq: int) -> None:
    """Atomically replace the cursor (temp file 0600, O_EXCL, no symlinks, fsync, rename)."""
    p = cursor_path(log)
    try:
        fd, name = tempfile.mkstemp(dir=p.parent, prefix=".sink.")  # unique, O_EXCL, 0600
        tmp = Path(name)
        try:
            os.chmod(tmp, 0o600)
            data = json.dumps({"acked_seq": seq}).encode() + b"\n"
            if os.write(fd, data) != len(data):
                raise ReceiptError("short write to sink cursor")
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            tmp.unlink(missing_ok=True)
            raise
        os.close(fd)
        os.replace(tmp, p)
    except OSError as exc:
        raise ReceiptError(f"cannot write sink cursor {p}: {exc.strerror}") from None


def pending_lines(log: str | Path) -> list[bytes]:
    """Local receipt lines the sink hasn't acknowledged, in seq order."""
    acked = read_cursor(log)
    raw = _read_private(Path(log), "receipt log")
    lines = raw.splitlines() if raw else []
    if acked >= len(lines):
        raise ReceiptError(
            f"sink cursor is at seq {acked} but the receipt log has {len(lines)} receipt(s)"
            " (local log truncated or replaced?)"
        )
    out = lines[acked + 1 :]
    for i, ln in enumerate(out, start=acked + 1):
        try:
            seq = _line_seq(ln)
        except SinkError:
            raise ReceiptError(f"receipt log line {i + 1} is not a receipt") from None
        if seq != i:
            raise ReceiptError(f"receipt log line {i + 1} has seq {seq}, expected {i}")
    return out


def quick(sink: ReceiptSink) -> ReceiptSink:
    """The same sink without retries, for paths that must not wait (revoke, sweep)."""
    if isinstance(sink, WebhookSink):
        s = copy.copy(sink)
        s.retry_delays = ()
        return s
    return sink


@contextmanager
def flush_lock(log: str | Path) -> Iterator[None]:
    """Serialize flushes on ``<receipt-log>.sink.lock`` (no lock on Windows, like the log)."""
    p = Path(log)
    lock = p.with_name(p.name + ".sink.lock")
    try:
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | _NOFOLLOW, 0o600)
    except OSError as exc:
        raise ReceiptError(f"cannot open sink lock {lock}: {exc.strerror}") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ReceiptError(f"sink lock {lock} is not a regular file")
        with _locked(fd):
            yield
    finally:
        os.close(fd)


def flush(log: str | Path, sink: ReceiptSink) -> FlushResult:
    """Deliver every pending line in order, under the flush lock; stop at the first failure."""
    try:
        with flush_lock(log):
            return _flush(log, sink)
    except ReceiptError as exc:
        return FlushResult(0, 0, str(exc))


def _flush(log: str | Path, sink: ReceiptSink) -> FlushResult:
    try:
        lines = pending_lines(log)
    except ReceiptError as exc:
        return FlushResult(0, 0, str(exc))
    done = 0
    for ln in lines:
        try:
            sink.deliver(ln)
            seq = _line_seq(ln)
            write_cursor(log, seq)
        except (SinkError, ReceiptError) as exc:
            return FlushResult(done, len(lines) - done, str(exc))
        done += 1
    return FlushResult(done, 0, None)
