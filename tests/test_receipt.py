from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from datagrant import receipt
from datagrant.keys import KeyFileError, init_keys, load_public_key, load_signing_key
from datagrant.receipt import EVENTS, GrantFacts, ReceiptError, canonical, verify

T0 = datetime(2026, 11, 2, 18, 0, tzinfo=UTC)
FACTS = GrantFacts(
    "abcdef012345",
    "alice",
    "clinic",
    "public.patients",
    ("id", "ssn"),
    {"id": "passthrough", "ssn": "hash"},
    "region = 'west'",
    "debug",
    T0,
    T0 + timedelta(hours=2),
    "f" * 64,
    1,
    "auto",
)


@pytest.fixture
def key(tmp_path: Path):  # type: ignore[no-untyped-def]
    _, sp, _ = init_keys(tmp_path / "keys")
    return load_signing_key(sp)


def _log(tmp_path: Path, key, n: int = 3) -> Path:  # type: ignore[no-untyped-def]
    log = tmp_path / "r.jsonl"
    events = ["issued", "revoked", "expired", "revoke_failed"]
    for i in range(n):
        receipt.append(
            log,
            events[i % 4],
            FACTS,
            key,
            event_at=T0,
            host="h",  # type: ignore[arg-type]
            details={"i": i},
        )
    return log


def test_init_keys_modes_and_refuse_overwrite(tmp_path: Path) -> None:
    hp, sp, pub = init_keys(tmp_path / "k")
    assert len(pub) == 64 and load_signing_key(sp).public_hex() == pub
    if os.name == "posix":
        assert hp.stat().st_mode & 0o777 == 0o600 and sp.stat().st_mode & 0o777 == 0o600
        assert (tmp_path / "k").stat().st_mode & 0o777 == 0o700
    before = sp.read_bytes()
    with pytest.raises(KeyFileError, match="refusing to overwrite"):
        init_keys(tmp_path / "k")
    assert sp.read_bytes() == before


def test_init_keys_env_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "a" / "h.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "b" / "s.key"))
    hp, sp, _ = init_keys()
    assert hp == tmp_path / "a" / "h.key" and sp == tmp_path / "b" / "s.key"
    assert load_signing_key().key_id == load_signing_key(sp).key_id


def test_signing_key_validation(tmp_path: Path) -> None:
    p = tmp_path / "s.key"
    p.write_text("ab" * 31)
    p.chmod(0o600)
    with pytest.raises(KeyFileError, match="exactly 32 bytes"):
        load_signing_key(p)
    with pytest.raises(KeyFileError, match="64 hex"):
        load_public_key("zz")
    if os.name == "posix":
        p.write_text("ab" * 32)
        p.chmod(0o640)
        with pytest.raises(KeyFileError, match="group/others"):
            load_signing_key(p)


def test_canonical_rejects_floats_and_secrets() -> None:
    assert canonical({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode()
    with pytest.raises(ReceiptError, match="floats"):
        canonical({"x": 1.5})
    with pytest.raises(ReceiptError, match="secrets"):
        canonical({"details": {"password": "x"}})
    with pytest.raises(ReceiptError, match="unsupported"):
        canonical({"x": object()})
    with pytest.raises(ReceiptError, match="keys must be strings"):
        canonical({1: 2})


def test_append_and_verify_chain(tmp_path: Path, key) -> None:  # type: ignore[no-untyped-def]
    log = _log(tmp_path, key, 4)
    lines = log.read_bytes().splitlines()
    bodies = [json.loads(x)["receipt"] for x in lines]
    assert [b["seq"] for b in bodies] == [0, 1, 2, 3]
    assert bodies[0]["prev_receipt_sha256"] == receipt.GENESIS
    assert bodies[0]["columns"] == [
        {"name": "id", "mask": "passthrough"},
        {"name": "ssn", "mask": "hash"},
    ]
    assert bodies[0]["key_id"] == key.key_id and bodies[0]["event_at"] == "2026-11-02T18:00:00Z"
    assert "password" not in log.read_text()
    if os.name == "posix":
        assert log.stat().st_mode & 0o777 == 0o600
    res = verify(log, key.private.public_key())
    assert res.ok and res.count == 4
    assert verify(log, key.private.public_key(), expect_head=res.head_sha256).ok


def _rewrite(log: Path, lines: list[bytes]) -> None:
    log.write_bytes(b"".join(x + b"\n" for x in lines))


def test_tamper_detected(tmp_path: Path, key) -> None:  # type: ignore[no-untyped-def]
    log = _log(tmp_path, key)
    lines = log.read_bytes().splitlines()
    obj = json.loads(lines[1])
    obj["receipt"]["requester"] = "mallory"
    lines[1] = canonical(obj)
    _rewrite(log, lines)
    res = verify(log, key.private.public_key())
    assert not res.ok and res.line == 2 and "signature" in (res.error or "")


def test_deletion_and_reorder_detected(tmp_path: Path, key) -> None:  # type: ignore[no-untyped-def]
    log = _log(tmp_path, key, 4)
    lines = log.read_bytes().splitlines()
    _rewrite(log, [lines[0], lines[2], lines[3]])
    res = verify(log, key.private.public_key())
    assert not res.ok and res.line == 2 and "sequence" in (res.error or "")
    _rewrite(log, [lines[1], lines[0], lines[2], lines[3]])
    assert verify(log, key.private.public_key()).line == 1
    head = None
    _rewrite(log, lines)
    head = verify(log, key.private.public_key()).head_sha256
    _rewrite(log, lines[:3])  # truncate newest: only caught with the external head
    assert verify(log, key.private.public_key()).ok
    res = verify(log, key.private.public_key(), expect_head=head)
    assert not res.ok and "head" in (res.error or "")


def test_forged_chain_with_valid_seq_detected(tmp_path: Path, key) -> None:  # type: ignore[no-untyped-def]
    # Splice a line from a different log with the same seq: signature fine, chain broken.
    log = _log(tmp_path, key, 2)
    other = tmp_path / "o"
    other.mkdir()
    olog = _log(other, key, 2)
    a, b = log.read_bytes().splitlines(), olog.read_bytes().splitlines()
    obj = json.loads(b[1])
    obj["receipt"]["details"] = {"i": 9}
    obj["sig"] = key.private.sign(canonical(obj["receipt"])).hex()
    obj["receipt"]["prev_receipt_sha256"] = "1" * 64
    obj["sig"] = key.private.sign(canonical(obj["receipt"])).hex()
    _rewrite(log, [a[0], canonical(obj)])
    res = verify(log, key.private.public_key())
    assert not res.ok and res.line == 2 and "chain" in (res.error or "")


def test_wrong_key_and_garbage(tmp_path: Path, key) -> None:  # type: ignore[no-untyped-def]
    log = _log(tmp_path, key, 1)
    _, sp2, _ = init_keys(tmp_path / "k2")
    other = load_signing_key(sp2).private.public_key()
    assert "different key" in (verify(log, other).error or "")
    log.write_bytes(log.read_bytes() + b'{"x": 1}\n')
    assert verify(log, key.private.public_key()).line == 2
    log.write_bytes(b'{"sig":"00", "receipt":{}}\n')
    assert "canonical" in (verify(log, key.private.public_key()).error or "")
    log.write_bytes(b"no newline")
    assert "partial" in (verify(log, key.private.public_key()).error or "")
    assert "cannot read" in (verify(tmp_path / "missing", other).error or "")


def test_append_refuses_corrupt_or_open_log(tmp_path: Path, key) -> None:  # type: ignore[no-untyped-def]
    log = tmp_path / "r.jsonl"
    log.write_bytes(b"partial")
    log.chmod(0o600)
    with pytest.raises(ReceiptError, match="newline"):
        receipt.append(log, "issued", FACTS, key)
    log.write_bytes(b"not json\n")
    with pytest.raises(ReceiptError, match="not a receipt"):
        receipt.append(log, "issued", FACTS, key)
    with pytest.raises(ReceiptError, match="unknown receipt event"):
        receipt.append(tmp_path / "n.jsonl", "bogus", FACTS, key)  # type: ignore[arg-type]
    with pytest.raises(ReceiptError, match="receipt log"):
        receipt.append(tmp_path, "issued", FACTS, key)  # a directory
    if os.name == "posix":
        log.write_bytes(b"")
        log.chmod(0o644)
        with pytest.raises(ReceiptError, match="group/others"):
            receipt.append(log, "issued", FACTS, key)
        link = tmp_path / "link.jsonl"
        link.symlink_to(tmp_path / "target.jsonl")
        with pytest.raises(ReceiptError, match="cannot open"):
            receipt.append(link, "issued", FACTS, key)


def test_naive_timestamp_rejected(key) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ReceiptError, match="timezone"):
        receipt.receipt_body(
            "issued", FACTS, key_id="k", seq=0, prev="0", event_at=datetime(2026, 1, 1)
        )


def test_default_log_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "x.jsonl"))
    assert receipt.default_log_path() == tmp_path / "x.jsonl"
    monkeypatch.delenv("DATAGRANT_RECEIPT_LOG")
    assert receipt.default_log_path().name == "receipts.jsonl"


@pytest.mark.parametrize(
    "line",
    [
        b'{"receipt":1,"sig":"00"}',
        b'{"receipt":{},"sig":0}',
        b'{"receipt":{},"sig":null}',
        b'{"receipt":{},"sig":["00"]}',
        b'{"receipt":[],"sig":"00"}',
        b'{"receipt":"x","sig":"00"}',
        b'{"receipt":{},"sig":"zz"}',
        b'{"receipt":{"seq":1.5},"sig":"00"}',
        b'{"receipt":{}}',
        b"[1,2]",
        b"1",
        b'"s"',
        b"null",
        b"[" * 5000 + b"]" * 5000,
        b"\xff\xfe",
    ],
)
def test_verify_type_confusion_never_crashes(tmp_path: Path, key, line: bytes) -> None:  # type: ignore[no-untyped-def]
    log = tmp_path / "r.jsonl"
    log.write_bytes(line + b"\n")
    res = verify(log, key.private.public_key())
    assert not res.ok and res.line == 1 and "not" in (res.error or "")


def test_append_missing_parent_dir_is_receipt_error(tmp_path: Path, key) -> None:  # type: ignore[no-untyped-def]
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(ReceiptError, match="cannot open receipt log"):
        receipt.append(blocker / "sub" / "r.jsonl", "issued", FACTS, key)


def test_new_events_are_signed_chained_and_omit_grant_id(tmp_path: Path, key) -> None:  # type: ignore[no-untyped-def]
    log = tmp_path / "r.jsonl"
    details = {
        "denied": {"reasons": ["not in an allowed group"], "phase": "request"},
        "not_approved": {
            "reasons": ["approver must be a different person than the requester"],
            "phase": "approve",
            "request_id": "aaaaaaaaaaaa",
        },
        "request_expired": {"request_id": "bbbbbbbbbbbb"},
    }
    for event, det in details.items():
        receipt.append(log, event, FACTS, key, event_at=T0, host="h", details=det)
    lines = log.read_bytes().splitlines()
    bodies = [json.loads(x)["receipt"] for x in lines]
    assert [b["event"] for b in bodies] == ["denied", "not_approved", "request_expired"]
    assert [b["seq"] for b in bodies] == [0, 1, 2]
    for b, (event, det) in zip(bodies, details.items(), strict=True):
        assert "grant_id" not in b
        assert b["details"] == det
        assert b["event"] == event
        assert b["version"] == 1
        assert "password" not in b
    res = verify(log, key.private.public_key())
    assert res.ok and res.count == 3


def test_verify_v030_log_still_ok_with_new_kinds(tmp_path: Path, key) -> None:  # type: ignore[no-untyped-def]
    log = tmp_path / "mixed.jsonl"
    for event in ("issued", "revoked", "expired", "revoke_failed"):
        receipt.append(log, event, FACTS, key, event_at=T0, host="h")
    receipt.append(
        log,
        "denied",
        FACTS,
        key,
        event_at=T0,
        host="h",
        details={"reasons": ["max_columns"], "phase": "request"},
    )
    res = verify(log, key.private.public_key())
    assert res.ok and res.count == 5
    events = [json.loads(x)["receipt"]["event"] for x in log.read_bytes().splitlines()]
    assert events[:4] == ["issued", "revoked", "expired", "revoke_failed"]
    assert events[4] == "denied"
    assert "approval_recorded" not in EVENTS
