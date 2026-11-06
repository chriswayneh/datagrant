"""Signed, hash-chained access receipts (unit U5).

Each line of the JSONL log is canonical JSON ``{"receipt": {...}, "sig": "<hex>"}``.
``sig`` is an ed25519 signature over the canonical bytes of ``receipt``. Every
receipt carries ``seq`` (0-based line number) and ``prev_receipt_sha256``, the
SHA-256 of the previous line's bytes (64 zeros for the first), so editing,
deleting, or reordering any line breaks verification. Truncating the newest
lines can only be caught against an externally kept head hash (see verify).

Receipts never contain passwords or key material; only the signing key id.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from datagrant.keys import DEFAULT_KEY_DIR, SigningKey, key_id_for

RECEIPT_VERSION = 1
GENESIS = "0" * 64
MAX_LINE_BYTES = 64 * 1024
RECEIPT_LOG_ENV = "DATAGRANT_RECEIPT_LOG"
Event = Literal["issued", "revoked", "expired", "revoke_failed"]
EVENTS = ("issued", "revoked", "expired", "revoke_failed")
_FORBIDDEN_KEYS = {
    "password",
    "hash_key",
    "key",
    "derived",
    "secret",
    "private_key",
    "id_token",
    "oidc_token",
    "token",
    "access_token",
}


class ReceiptError(RuntimeError):
    """Raised when a receipt cannot be built or written."""


def default_log_path() -> Path:
    env = os.environ.get(RECEIPT_LOG_ENV)
    return Path(env) if env else DEFAULT_KEY_DIR / "receipts.jsonl"


def _check_value(v: Any, where: str) -> None:
    if isinstance(v, bool) or v is None or isinstance(v, (int, str)):
        return
    if isinstance(v, float):
        raise ReceiptError(f"{where}: floats are not allowed in receipts")
    if isinstance(v, Mapping):
        for k, x in v.items():
            if not isinstance(k, str):
                raise ReceiptError(f"{where}: keys must be strings")
            if k.lower() in _FORBIDDEN_KEYS:
                raise ReceiptError(f"{where}.{k}: secrets must never be in a receipt")
            _check_value(x, f"{where}.{k}")
        return
    if isinstance(v, (list, tuple)):
        for i, x in enumerate(v):
            _check_value(x, f"{where}[{i}]")
        return
    raise ReceiptError(f"{where}: unsupported type {type(v).__name__}")


def canonical(obj: Any) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, UTF-8, no floats/NaN."""
    _check_value(obj, "receipt")
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _utc(ts: datetime) -> str:
    if ts.tzinfo is None:
        raise ReceiptError("timestamps must be timezone-aware")
    return ts.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class GrantFacts:
    """What a receipt says about a grant (from the plan or the datagrant.grants row)."""

    grant_id: str
    requester: str
    dataset: str
    table: str
    columns: Sequence[str]
    masks: Mapping[str, str]
    row_filter: str | None
    purpose: str
    starts_at: datetime
    expires_at: datetime
    policy_sha256: str
    policy_version: int
    approval: str
    approvers: Sequence[str] = ()
    identity: Mapping[str, Any] | None = None
    approver_identities: Sequence[Mapping[str, Any]] | None = None


def receipt_body(
    event: Event,
    facts: GrantFacts,
    *,
    key_id: str,
    seq: int,
    prev: str,
    event_at: datetime | None = None,
    host: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if event not in EVENTS:
        raise ReceiptError(f"unknown receipt event {event!r}")
    body: dict[str, Any] = {
        "version": RECEIPT_VERSION,
        "event": event,
        "event_at": _utc(event_at or datetime.now(UTC)),
        "host": host or socket.gethostname(),
        "grant_id": facts.grant_id,
        "requester": facts.requester,
        "dataset": facts.dataset,
        "table": facts.table,
        "columns": [{"name": c, "mask": facts.masks.get(c, "unknown")} for c in facts.columns],
        "row_filter": facts.row_filter,
        "purpose": facts.purpose,
        "starts_at": _utc(facts.starts_at),
        "expires_at": _utc(facts.expires_at),
        "policy_sha256": facts.policy_sha256,
        "policy_version": facts.policy_version,
        "approval": facts.approval,
        "approvers": list(facts.approvers),
        "details": dict(details or {}),
        "seq": seq,
        "prev_receipt_sha256": prev,
        "key_id": key_id,
    }
    if facts.identity is not None:
        body["identity"] = dict(facts.identity)
    if facts.approver_identities is not None:
        body["approver_identities"] = [dict(x) for x in facts.approver_identities]
    return body


def sign_line(body: Mapping[str, Any], key: SigningKey) -> bytes:
    sig = key.private.sign(canonical(body)).hex()
    return canonical({"receipt": dict(body), "sig": sig})


@contextmanager
def _locked(fd: int) -> Iterator[None]:
    if sys.platform == "win32":  # no flock: single writer assumed (documented)
        yield
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)


def _last_line(fd: int, size: int) -> bytes | None:
    if size == 0:
        return None
    window = min(size, MAX_LINE_BYTES + 2)
    os.lseek(fd, size - window, os.SEEK_SET)
    buf = b""
    while len(buf) < window:
        chunk = os.read(fd, window - len(buf))
        if not chunk:
            break
        buf += chunk
    if not buf.endswith(b"\n"):
        raise ReceiptError(
            "receipt log does not end with a newline (partial write?); not appending"
        )
    body = buf[:-1]
    cut = body.rfind(b"\n")
    if cut < 0 and window < size:
        raise ReceiptError("last receipt line is too long")
    return body[cut + 1 :]


def append(
    log: str | Path,
    event: Event,
    facts: GrantFacts,
    key: SigningKey,
    *,
    event_at: datetime | None = None,
    host: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Sign and append one receipt (0600 file, O_APPEND, no symlinks). Returns the body."""
    p = Path(log)
    flags = (
        os.O_RDWR
        | os.O_APPEND
        | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(p, flags, 0o600)
    except OSError as exc:
        raise ReceiptError(f"cannot open receipt log {p}: {exc.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ReceiptError(f"receipt log {p} is not a regular file")
        if os.name == "posix" and st.st_mode & 0o077:
            raise ReceiptError(f"receipt log {p} must not be readable by group/others (chmod 600)")
        with _locked(fd):
            size = os.fstat(fd).st_size
            last = _last_line(fd, size)
            if last is None:
                seq, prev = 0, GENESIS
            else:
                try:
                    seq = int(json.loads(last)["receipt"]["seq"]) + 1
                except (ValueError, KeyError, TypeError):
                    raise ReceiptError(
                        "last receipt line is not a receipt; not appending"
                    ) from None
                prev = hashlib.sha256(last).hexdigest()
            body = receipt_body(
                event,
                facts,
                key_id=key.key_id,
                seq=seq,
                prev=prev,
                event_at=event_at,
                host=host,
                details=details,
            )
            line = sign_line(body, key) + b"\n"
            if len(line) > MAX_LINE_BYTES:
                raise ReceiptError("receipt too large")
            written = os.write(fd, line)
            if written != len(line):
                raise ReceiptError("short write to receipt log")
            os.fsync(fd)
    except OSError as exc:
        raise ReceiptError(f"cannot write receipt log {p}: {exc.strerror}") from None
    finally:
        os.close(fd)
    return body


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    count: int
    head_sha256: str
    error: str | None = None
    line: int | None = None  # 1-based line of the first break


def verify(
    log: str | Path, public_key: Ed25519PublicKey, *, expect_head: str | None = None
) -> VerifyResult:
    """Check every signature, seq number and hash link; report the first break.

    ``expect_head`` (the head hash recorded earlier, e.g. in a ticket) also
    catches deletion of the newest lines.
    """
    kid = key_id_for(public_key)
    prev, n = GENESIS, 0

    def fail(msg: str, line: int) -> VerifyResult:
        return VerifyResult(False, n, prev, msg, line)

    try:
        fh = Path(log).open("rb")  # noqa: SIM115 - closed by the with below
    except OSError as exc:
        return VerifyResult(False, 0, GENESIS, f"cannot read log: {exc.strerror}", None)
    with fh:
        for lineno, raw in enumerate(fh, start=1):
            if not raw.endswith(b"\n"):
                return fail("line is not newline-terminated (partial write)", lineno)
            line = raw[:-1]
            if len(line) > MAX_LINE_BYTES:
                return fail("line too long", lineno)
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict) or set(obj) != {"receipt", "sig"}:
                    return fail("line is not a valid receipt", lineno)
                body, sig_hex = obj["receipt"], obj["sig"]
                if not isinstance(body, dict) or not isinstance(sig_hex, str):
                    return fail("line is not a valid receipt", lineno)
                sig = bytes.fromhex(sig_hex)
                if canonical(obj) != line:
                    return fail("line is not canonical JSON", lineno)
            except (ValueError, KeyError, TypeError, RecursionError, ReceiptError):
                return fail("line is not a valid receipt", lineno)
            if body.get("key_id") != kid:
                return fail(f"signed by a different key ({body.get('key_id')!r})", lineno)
            try:
                public_key.verify(sig, canonical(body))
            except InvalidSignature:
                return fail("bad signature (receipt was modified)", lineno)
            if body.get("seq") != n:
                return fail(f"sequence break: expected {n}, found {body.get('seq')!r}", lineno)
            if body.get("prev_receipt_sha256") != prev:
                return fail("hash chain break (a receipt was removed or reordered)", lineno)
            prev = hashlib.sha256(line).hexdigest()
            n += 1
    if expect_head is not None and expect_head != prev:
        return VerifyResult(False, n, prev, "head hash differs (newest receipts missing?)", None)
    return VerifyResult(True, n, prev)
