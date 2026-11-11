"""Host-file checks used by doctor, keys, and --apply (POSIX modes, no FIFO hang)."""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


@dataclass(frozen=True)
class ModeReport:
    """Result of inspecting an existing path (opened fd, then fstat)."""

    path: Path
    what: str
    st_mode: int
    st_uid: int
    parent_mode: int | None

    @property
    def regular(self) -> bool:
        return stat.S_ISREG(self.st_mode)

    @property
    def group_other_writable(self) -> bool:
        return bool(self.st_mode & 0o022)

    @property
    def group_other_accessible(self) -> bool:
        return bool(self.st_mode & 0o077)

    @property
    def owner_mismatch(self) -> bool:
        geteuid = getattr(os, "geteuid", None)
        return geteuid is not None and self.st_uid != geteuid()

    @property
    def parent_group_other_writable(self) -> bool:
        return self.parent_mode is not None and bool(self.parent_mode & 0o022)

    def access_message(self) -> str | None:
        """Main finding: not a private regular file. Writable is the stronger case."""
        if not self.regular:
            return f"{self.what} {self.path} is not a regular file"
        if os.name != "posix":
            return None
        if self.group_other_writable:
            return f"{self.what} {self.path} is group/other-accessible (writable; chmod 600)"
        if self.group_other_accessible:
            return f"{self.what} {self.path} is group/other-accessible (chmod 600)"
        return None

    def extra_warnings(self) -> list[str]:
        out: list[str] = []
        if self.owner_mismatch:
            out.append(f"{self.what} {self.path} is not owned by the current user")
        if os.name == "posix" and self.parent_group_other_writable:
            out.append(f"parent directory of {self.what} {self.path} is group/other-writable")
        return out


def _parent_mode(path: Path) -> int | None:
    try:
        return os.lstat(path.parent).st_mode
    except OSError:
        return None


def open_existing_fd(path: Path) -> int:
    """Open ``path`` read-only without following a symlink or hanging on a FIFO.

    ``lstat`` first: a FIFO/socket/device/directory is refused before ``open``.
    ``O_NONBLOCK`` is a second belt so a race to replace the path with a FIFO
    cannot stall the process.
    """
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode):
        raise OSError(errno.EINVAL, "Not a regular file")
    flags = os.O_RDONLY | _NOFOLLOW | _BINARY | _NONBLOCK
    return os.open(path, flags)


def inspect_existing(path: Path, what: str) -> ModeReport | str | None:
    """Inspect ``path`` if it exists.

    Returns:
    - ``None`` if the path is missing (and not a dangling symlink)
    - a problem string if it cannot be opened
    - ``ModeReport`` after a successful open + fstat
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"cannot open {what} {path}: {exc.strerror}"
    if not stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode):
        return f"{what} {path} is not a regular file"
    try:
        fd = open_existing_fd(path)
    except OSError as exc:
        return f"cannot open {what} {path}: {exc.strerror}"
    try:
        opened = os.fstat(fd)
        return ModeReport(
            path,
            what,
            opened.st_mode,
            opened.st_uid,
            _parent_mode(path),
        )
    finally:
        os.close(fd)


def posix_mode_problem(path: Path, what: str) -> str | None:
    """Access problem (not regular, or group/other-accessible), or None.

    Extra uid/parent warnings are not included; see ``inspect_existing``.
    Missing paths are not a problem (caller decides).
    """
    result = inspect_existing(path, what)
    if result is None:
        return None
    if isinstance(result, str):
        return result
    return result.access_message()
