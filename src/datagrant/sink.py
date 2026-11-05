"""External receipt sinks (design: docs/design/receipt-sink.md, PR 1 of 4).

A sink receives the exact signed receipt lines already written to the local
log and can report its head ``(seq, sha256 of last line)``. Sinks are chosen by
URL scheme: ``https://`` (webhook, stdlib only) or ``file://`` (append-only
file, e.g. on a remote append-only mount). Not yet wired into any command.

The bearer token comes only from ``$DATAGRANT_RECEIPT_SINK_TOKEN`` and is
redacted from every error message.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from datagrant.receipt import MAX_LINE_BYTES, ReceiptError, _last_line, _locked

SINK_ENV = "DATAGRANT_RECEIPT_SINK"
SINK_MODE_ENV = "DATAGRANT_RECEIPT_SINK_MODE"
SINK_TOKEN_ENV = "DATAGRANT_RECEIPT_SINK_TOKEN"  # nosec B105
MODES = ("required", "best-effort")
DEFAULT_MODE = "best-effort"
CONNECT_TIMEOUT = 5.0
TOTAL_TIMEOUT = 10.0
RETRY_DELAYS: tuple[float, ...] = (0.5, 1.0, 2.0)
_LOCAL_HOSTS = ("127.0.0.1", "localhost")


class SinkError(RuntimeError):
    """A sink could not be configured, written or read."""


class SinkConfigError(SinkError):
    """Invalid sink configuration (usage error)."""


class ReceiptSink(Protocol):
    name: str

    def deliver(self, line: bytes) -> None: ...

    def head(self) -> tuple[int, str] | None: ...


def _line_seq(line: bytes) -> int:
    try:
        seq = json.loads(line)["receipt"]["seq"]
    except (ValueError, KeyError, TypeError):
        raise SinkError("not a receipt line") from None
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise SinkError("receipt line has an invalid seq")
    return seq


def _check_line(line: bytes) -> bytes:
    if line.endswith(b"\n"):
        line = line[:-1]
    if not line or b"\n" in line or len(line) + 1 > MAX_LINE_BYTES:
        raise SinkError("receipt line must be one non-empty line within the size limit")
    _line_seq(line)
    return line


def _redact(text: str, token: str | None) -> str:
    return text.replace(token, "***") if token else text


class FileSink:
    """Append-only JSONL file: 0600, no symlinks, locked like the receipt log.

    Lines must arrive in seq order. Re-sending the current last line is a no-op;
    any other line at an already-used seq is refused (a rewrite).
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.name = f"file://{self.path}"

    def _open(self, write: bool) -> int:
        flags = (
            (os.O_RDWR | os.O_APPEND | os.O_CREAT if write else os.O_RDONLY)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        try:
            fd = os.open(self.path, flags, 0o600)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise SinkError(f"cannot open sink file {self.path}: {exc.strerror}") from None
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            raise SinkError(f"sink file {self.path} is not a regular file")
        if os.name == "posix" and st.st_mode & 0o077:
            os.close(fd)
            raise SinkError(f"sink file {self.path} must not be readable by group/others")
        return fd

    @staticmethod
    def _last(fd: int) -> bytes | None:
        try:
            return _last_line(fd, os.fstat(fd).st_size)
        except ReceiptError as exc:
            raise SinkError(f"sink file: {exc}") from None

    def deliver(self, line: bytes) -> None:
        line = _check_line(line)
        seq = _line_seq(line)
        fd = self._open(write=True)
        try:
            with _locked(fd):
                last = self._last(fd)
                next_seq = 0 if last is None else _line_seq(last) + 1
                if last is not None and seq == next_seq - 1 and line == last:
                    return
                if seq != next_seq:
                    raise SinkError(f"sink expects seq {next_seq}, got {seq}")
                data = line + b"\n"
                if os.write(fd, data) != len(data):
                    raise SinkError("short write to sink file")
                os.fsync(fd)
        except OSError as exc:
            raise SinkError(f"cannot write sink file {self.path}: {exc.strerror}") from None
        finally:
            os.close(fd)

    def head(self) -> tuple[int, str] | None:
        try:
            fd = self._open(write=False)
        except FileNotFoundError:
            return None
        try:
            last = self._last(fd)
        finally:
            os.close(fd)
        if last is None:
            return None
        return _line_seq(last), hashlib.sha256(last).hexdigest()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None  # never follow redirects (would resend the token elsewhere)


class WebhookSink:
    """POST signed lines as NDJSON to ``url``; read the head from ``url/head``."""

    def __init__(
        self,
        url: str,
        token: str | None = None,
        *,
        timeout: float = TOTAL_TIMEOUT,
        retry_delays: Sequence[float] = RETRY_DELAYS,
    ) -> None:
        self.url = url.rstrip("/")
        self._token = token or None
        self.name = self.url
        self.timeout = timeout
        self.retry_delays = tuple(retry_delays)
        self._opener = urllib.request.build_opener(_NoRedirect)

    def __repr__(self) -> str:
        return f"WebhookSink({self.url!r}, token={'***' if self._token else None})"

    def _request(self, method: str, url: str, body: bytes | None) -> tuple[int, bytes]:
        headers = {"User-Agent": "datagrant-sink"}
        if body is not None:
            headers["Content-Type"] = "application/x-ndjson"
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            timeout = min(CONNECT_TIMEOUT, self.timeout)
            with self._opener.open(req, timeout=timeout) as resp:  # nosec B310
                return resp.status, resp.read(MAX_LINE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except (urllib.error.URLError, OSError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            raise SinkError(
                _redact(f"sink {self.url} unreachable: {reason}", self._token)
            ) from None

    def deliver(self, line: bytes) -> None:
        body = _check_line(line) + b"\n"
        deadline = time.monotonic() + self.timeout + sum(self.retry_delays)
        last = "no attempt"
        for attempt in range(len(self.retry_delays) + 1):
            if attempt:
                time.sleep(self.retry_delays[attempt - 1])
            try:
                status, _ = self._request("POST", self.url, body)
            except SinkError as exc:
                last = str(exc)
            else:
                if 200 <= status < 300:
                    return
                last = f"sink {self.url} returned HTTP {status}"
                if 400 <= status < 500 and status not in (408, 429):
                    break  # refused (e.g. reused seq): retrying won't help
            if time.monotonic() >= deadline:
                break
        raise SinkError(_redact(last, self._token))

    def head(self) -> tuple[int, str] | None:
        status, raw = self._request("GET", self.url + "/head", None)
        if status == 404:
            return None
        if not 200 <= status < 300:
            raise SinkError(f"sink {self.url}/head returned HTTP {status}")
        try:
            doc = json.loads(raw)
            seq, head = doc["seq"], doc["head_sha256"]
        except (ValueError, KeyError, TypeError):
            raise SinkError(f"sink {self.url}/head returned a malformed head") from None
        if (
            not isinstance(seq, int)
            or isinstance(seq, bool)
            or seq < 0
            or not isinstance(head, str)
            or len(head) != 64
            or any(c not in "0123456789abcdef" for c in head)
        ):
            raise SinkError(f"sink {self.url}/head returned a malformed head")
        return seq, head


@dataclass(frozen=True)
class SinkConfig:
    sink: ReceiptSink
    mode: str


def parse_sink_url(url: str, token: str | None = None) -> ReceiptSink:
    """Build a sink from a URL; raises SinkConfigError on anything unsafe."""
    try:
        u = urllib.parse.urlsplit(url)
        host = u.hostname
        _ = u.port
    except ValueError:
        raise SinkConfigError("receipt sink URL is malformed") from None
    if u.username is not None or u.password is not None or "@" in u.netloc:
        raise SinkConfigError(
            "receipt sink URL must not contain credentials; use $" + SINK_TOKEN_ENV
        )
    if u.scheme == "file":
        if u.netloc not in ("", "localhost") or not u.path or u.query or u.fragment:
            raise SinkConfigError("file sink must be file:///absolute/path")
        path = urllib.request.url2pathname(u.path)
        if not os.path.isabs(path):
            raise SinkConfigError("file sink path must be absolute")
        return FileSink(path)
    if u.scheme == "https" or (u.scheme == "http" and host in _LOCAL_HOSTS):
        if not host:
            raise SinkConfigError("receipt sink URL has no host")
        if u.query or u.fragment:
            raise SinkConfigError("receipt sink URL must not have a query or fragment")
        return WebhookSink(urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, "", "")), token)
    if u.scheme == "http":
        raise SinkConfigError("receipt sink must use https (http only for localhost)")
    raise SinkConfigError("receipt sink URL scheme must be https or file")


def sink_from_config(
    url: str | None = None, mode: str | None = None, env: Mapping[str, str] | None = None
) -> SinkConfig | None:
    """Resolve flag, then env. ``None`` means no sink configured (today's behavior)."""
    env = os.environ if env is None else env
    url = url or env.get(SINK_ENV) or None
    mode = mode or env.get(SINK_MODE_ENV) or DEFAULT_MODE
    if mode not in MODES:
        raise SinkConfigError(f"receipt sink mode must be one of: {', '.join(MODES)}")
    if url is None:
        return None
    return SinkConfig(parse_sink_url(url, env.get(SINK_TOKEN_ENV) or None), mode)
