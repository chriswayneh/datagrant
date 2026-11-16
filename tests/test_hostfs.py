"""Host-file mode checks: FIFO must not hang; writable is the stronger finding."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from datagrant.hostfs import inspect_existing, posix_mode_problem
from datagrant.keys import KeyFileError, load_hash_key

HEX = "ab" * 32


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no mkfifo")
def test_fifo_posix_mode_problem_does_not_hang(tmp_path: Path) -> None:
    pipe = tmp_path / "sink.fifo"
    os.mkfifo(pipe, 0o600)
    msg = posix_mode_problem(pipe, "receipt log")
    assert msg is not None
    assert "regular file" in msg


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no mkfifo")
def test_fifo_key_file_does_not_hang(tmp_path: Path) -> None:
    pipe = tmp_path / "hash.key"
    os.mkfifo(pipe, 0o600)
    with pytest.raises(KeyFileError, match="regular file"):
        load_hash_key(pipe)


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_writable_is_stronger_than_readable(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    p.write_text("x")
    os.chmod(p, 0o644)
    report = inspect_existing(p, "policy file")
    assert not isinstance(report, str) and report is not None
    readable = report.access_message()
    assert readable is not None
    assert readable.endswith("group/other-accessible (chmod 600)")
    os.chmod(p, 0o666)
    report = inspect_existing(p, "policy file")
    assert not isinstance(report, str) and report is not None
    writable = report.access_message()
    assert writable is not None
    assert writable.endswith("group/other-accessible (writable; chmod 600)")


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_owner_mismatch_and_parent_writable_are_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = tmp_path / "policy.yaml"
    p.write_text("x")
    os.chmod(p, 0o600)
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    os.chmod(tmp_path, 0o777)
    report = inspect_existing(p, "policy file")
    assert not isinstance(report, str) and report is not None
    assert report.access_message() is None
    extras = report.extra_warnings()
    assert any("not owned by the current user" in e for e in extras)
    assert any("group/other-writable" in e for e in extras)


def test_missing_path_is_not_a_problem(tmp_path: Path) -> None:
    assert posix_mode_problem(tmp_path / "gone", "receipt log") is None
