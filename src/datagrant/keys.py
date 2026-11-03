"""Local key files (decision 2026-11-02: keys live in local files, env var override).

The hash-masking key file holds >=32 random bytes as hex. datagrant never sends
the file's key to Postgres; it sends a key derived from it (HMAC-SHA256 with a
fixed label), so rotating or revoking the database copy never exposes the file.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

HASH_KEY_ENV = "DATAGRANT_HASH_KEY"
SIGNING_KEY_ENV = "DATAGRANT_SIGNING_KEY"
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


def _read_key_file(p: Path, kind: str) -> bytes:
    """Hardened read: no symlink follow, checks on the opened fd, owner-only, bounded."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(p, flags)
    except OSError as exc:
        if p.is_dir():  # Windows cannot open a directory at all
            raise KeyFileError(f"{kind} {p} is not a regular file") from None
        raise KeyFileError(f"cannot read {kind} {p}: {exc.strerror}") from None
    try:
        # Check the opened file itself (no stat-then-open race, no symlink follow).
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise KeyFileError(f"{kind} {p} is not a regular file")
        if os.name == "posix" and st.st_mode & 0o077:
            raise KeyFileError(f"{kind} {p} must not be readable by group/others (chmod 600)")
        chunks: list[bytes] = []
        remaining = _MAX_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError as exc:
        raise KeyFileError(f"cannot read {kind} {p}: {exc.strerror}") from None
    finally:
        os.close(fd)
    if len(raw) > _MAX_FILE_BYTES:
        raise KeyFileError(f"{kind} {p} is too large")
    try:
        return bytes.fromhex(raw.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        raise KeyFileError(f"{kind} {p} must contain hex only") from None


def load_hash_key(path: str | Path | None = None) -> HashKey:
    p = Path(path) if path is not None else hash_key_path()
    master = _read_key_file(p, "hash key")
    if len(master) < MIN_KEY_BYTES:
        raise KeyFileError(f"hash key {p} must be at least {MIN_KEY_BYTES} bytes")
    derived = hmac.digest(master, _LABEL, "sha256")
    return HashKey(hashlib.sha256(derived).hexdigest()[:16], derived)


# --- U5: receipt signing key (ed25519) ---


@dataclass(frozen=True)
class SigningKey:
    key_id: str
    private: Ed25519PrivateKey = field(repr=False)

    def public_hex(self) -> str:
        return public_key_hex(self.private.public_key())


def public_key_hex(pub: Ed25519PublicKey) -> str:
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def key_id_for(pub: Ed25519PublicKey) -> str:
    """Key id = first 16 hex chars of SHA-256 over the raw public key."""
    return hashlib.sha256(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()[:16]


def load_public_key(hex_text: str) -> Ed25519PublicKey:
    try:
        raw = bytes.fromhex(hex_text.strip())
        if len(raw) != 32:
            raise ValueError
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        raise KeyFileError("public key must be 64 hex characters (32 bytes)") from None


def signing_key_path() -> Path:
    """Path of the signing key file: $DATAGRANT_SIGNING_KEY (a path) or the default."""
    env = os.environ.get(SIGNING_KEY_ENV)
    return Path(env) if env else DEFAULT_KEY_DIR / "signing.key"


def load_signing_key(path: str | Path | None = None) -> SigningKey:
    p = Path(path) if path is not None else signing_key_path()
    seed = _read_key_file(p, "signing key")
    if len(seed) != 32:
        raise KeyFileError(f"signing key {p} must be exactly 32 bytes (64 hex chars)")
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return SigningKey(key_id_for(priv.public_key()), priv)


def _write_new_key(p: Path, hex_text: str) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(p, flags, 0o600)
    except FileExistsError:
        raise KeyFileError(f"{p} already exists; refusing to overwrite a key") from None
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(hex_text + "\n")


def resolve_key_path(
    kind: str, explicit: str | Path | None = None, directory: str | Path | None = None
) -> Path:
    """One resolver for every command: explicit file > env var > directory > default.

    ``kind`` is "hash" or "signing".
    """
    env, name = (HASH_KEY_ENV, "hash.key") if kind == "hash" else (SIGNING_KEY_ENV, "signing.key")
    if explicit:
        return Path(explicit)
    if os.environ.get(env):
        return Path(os.environ[env])
    if directory:
        return Path(directory) / name
    return DEFAULT_KEY_DIR / name


def init_keys(
    directory: str | Path | None = None,
    *,
    hash_path: str | Path | None = None,
    signing_path: str | Path | None = None,
) -> tuple[Path, Path, str]:
    """Create hash.key and signing.key (0600) in 0700 directories; never overwrite.

    Returns (hash_key_path, signing_key_path, public_key_hex). Each path resolves
    as explicit file > env var > ``directory`` > ~/.config/datagrant.
    """
    hp = resolve_key_path("hash", hash_path, directory)
    sp = resolve_key_path("signing", signing_path, directory)
    if hp.absolute() == sp.absolute():
        raise KeyFileError(f"hash key and signing key must be different files ({sp})")
    for existing in (hp, sp):
        if existing.exists() or existing.is_symlink():
            raise KeyFileError(f"{existing} already exists; refusing to overwrite a key")
    for d in {hp.parent, sp.parent}:
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    _write_new_key(hp, secrets.token_hex(MIN_KEY_BYTES))
    _write_new_key(sp, seed.hex())
    return hp, sp, public_key_hex(priv.public_key())
