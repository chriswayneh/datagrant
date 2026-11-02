from __future__ import annotations

import os
from pathlib import Path

import pytest

from datagrant import keys
from datagrant.keys import KeyFileError, hash_key_path, load_hash_key

HEX = "ab" * 32


def write(tmp_path: Path, text: str | bytes, mode: int = 0o600) -> Path:
    p = tmp_path / "hash.key"
    p.write_bytes(text if isinstance(text, bytes) else text.encode())
    p.chmod(mode)
    return p


def test_load_and_derive(tmp_path: Path) -> None:
    k1 = load_hash_key(write(tmp_path, HEX + "\n"))
    assert len(k1.derived) == 32 and len(k1.key_id) == 16
    assert k1.derived != bytes.fromhex(HEX)  # file key never used directly
    assert load_hash_key(tmp_path / "hash.key") == k1  # stable
    assert HEX not in repr(k1) and k1.derived.hex() not in repr(k1)


def test_path_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(keys.HASH_KEY_ENV, raising=False)
    assert hash_key_path() == keys.DEFAULT_KEY_DIR / "hash.key"
    p = write(tmp_path, HEX)
    monkeypatch.setenv(keys.HASH_KEY_ENV, str(p))
    assert load_hash_key().key_id == load_hash_key(p).key_id


@pytest.mark.parametrize(
    ("content", "mode", "msg"),
    [
        ("ab" * 16, 0o600, "at least 32"),
        ("zz" * 32, 0o600, "hex only"),
        (b"\xff" * 64, 0o600, "hex only"),
        ("a" * 2000, 0o600, "too large"),
        (HEX, 0o644, "chmod 600"),
    ],
)
def test_bad_files(tmp_path: Path, content: str | bytes, mode: int, msg: str) -> None:
    if msg == "chmod 600" and os.name != "posix":
        pytest.skip("POSIX permissions only")
    with pytest.raises(KeyFileError, match=msg):
        load_hash_key(write(tmp_path, content, mode))


def test_missing_and_directory(tmp_path: Path) -> None:
    with pytest.raises(KeyFileError, match="cannot read"):
        load_hash_key(tmp_path / "missing")
    with pytest.raises(KeyFileError, match="not a regular file"):
        load_hash_key(tmp_path)


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="needs O_NOFOLLOW")
def test_symlink_not_followed(tmp_path: Path) -> None:
    target = write(tmp_path, HEX)
    link = tmp_path / "link.key"
    link.symlink_to(target)
    with pytest.raises(KeyFileError, match="cannot read"):
        load_hash_key(link)


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_mode_checked_on_opened_fd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = write(tmp_path, HEX, 0o644)
    # Path-based stat must not be what decides: checks run on the opened fd.
    monkeypatch.setattr(Path, "stat", lambda self, **kw: os.stat(os.devnull))
    with pytest.raises(KeyFileError, match="group/others"):
        load_hash_key(p)
