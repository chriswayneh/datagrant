from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from test_receipt import FACTS, T0

from datagrant import receipt
from datagrant.cli import main
from datagrant.keys import init_keys, load_signing_key


def test_report_uses_verified_fields_and_rejects_truncated_or_modified_log(tmp_path: Path) -> None:
    _, secret_path, _ = init_keys(tmp_path / "keys")
    key = load_signing_key(secret_path)
    pub = key.private.public_key()
    hex_key = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    log = tmp_path / "receipts.jsonl"
    facts = replace(FACTS, requester="alice|<tag>", purpose="omit this", approvers=("bob",))
    receipt.append(log, "issued", facts, key, event_at=T0)
    receipt.append(log, "revoked", facts, key, event_at=T0)
    head = receipt.verify(log, pub).head_sha256
    args = ["receipts", "report", "--pubkey", hex_key, "--receipt-log", str(log)]
    output: list[str] = []
    assert main([*args, "--expect-head", head], out=output.append) == 0
    markdown = output.pop()
    assert "alice&#124;&#60;tag&#62;" in markdown
    assert "omit this" not in markdown and "region" not in markdown
    assert "Verified receipts: 2" in markdown
    assert main([*args, "--json"], out=output.append) == 0
    assert '"expected_head_checked": false' in output.pop()
    original = log.read_bytes()
    log.write_bytes(original.splitlines(keepends=True)[0])
    assert main([*args, "--json", "--expect-head", head], out=output.append) != 0
    assert all('"events"' not in line for line in output)
    output.clear()
    log.write_bytes(original.replace(b"alice", b"carol", 1))
    assert main(args, out=output.append) != 0
    assert all("Verified receipts" not in line for line in output)
