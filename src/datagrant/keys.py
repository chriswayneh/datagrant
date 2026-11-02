"""Local key files (decision 2026-11-02: keys live in local files, env var override).

The hash-masking key file holds >=32 random bytes as hex. datagrant never sends
the file's key to Postgres; it sends a key derived from it (HMAC-SHA256 with a
fixed label), so rotating or revoking the database copy never exposes the file.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

HASH_KEY_ENV = "DATAGRANT_HASH_KEY"
DEFAULT_KEY_DIR = Path.home() / ".config" / "datagrant"
MIN_KEY_BYTES = 32
_MAX_FILE_BYTES = 1024
_LABEL = b"datagrant/hash-mask/v1"


class KeyFileError(ValueError):
    """Raised when a key file is missing, unreadable, too open, or malformed."""


@dataclass(frozen=True)
class HashKey:
    key_id: str
    derived: bytes = field(repr=False)


def hash_key_path() -> Path:
    """Path of the hash key file: $DATAGRANT_HASH_KEY (a path) or the default."""
    env = os.environ.get(HASH_KEY_ENV)
    return Path(env) if env else DEFAULT_KEY_DIR / "hash.key"


def load_hash_key(path: str | Path | None = None) -> HashKey:
    p = Path(path) if path is not None else hash_key_path()
    try:
        st = p.stat()
        if not stat.S_ISREG(st.st_mode):
            raise KeyFileError(f"hash key {p} is not a regular file")
        if os.name == "posix" and st.st_mode & 0o077:
            raise KeyFileError(f"hash key {p} must not be readable by group/others (chmod 600)")
        with p.open("rb") as fh:
            raw = fh.read(_MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise KeyFileError(f"cannot read hash key {p}: {exc.strerror}") from None
    if len(raw) > _MAX_FILE_BYTES:
        raise KeyFileError(f"hash key {p} is too large")
    try:
        master = bytes.fromhex(raw.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        raise KeyFileError(f"hash key {p} must contain hex only") from None
    if len(master) < MIN_KEY_BYTES:
        raise KeyFileError(f"hash key {p} must be at least {MIN_KEY_BYTES} bytes")
    derived = hmac.digest(master, _LABEL, "sha256")
    return HashKey(hashlib.sha256(derived).hexdigest()[:16], derived)
