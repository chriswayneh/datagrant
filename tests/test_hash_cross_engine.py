"""Offline pin: BQ TO_HEX, PG encode(hex), and SF HEX_ENCODE of the same HMAC."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from datagrant.bq.hash import _IPAD, _OPAD, SCOPE_LABEL
from datagrant.keys import HashKey
from datagrant.sf.grant import _hmac_udf_sql


def _bq_key_block(key: bytes) -> bytes:
    k = hashlib.sha256(key).digest() if len(key) > 64 else key
    return k + bytes(64 - len(k))


def _bq_xor_pad(block: bytes, pad: int) -> bytes:
    return bytes(c ^ pad for c in block[:64])


def _bq_hmac(key: bytes, val: str) -> bytes:
    """Emulate datagrant._hmac_sha256 (ipad/opad SHA256, CAST(val AS BYTES))."""
    block = _bq_key_block(key)
    inner = hashlib.sha256(_bq_xor_pad(block, _IPAD) + val.encode("utf-8")).digest()
    return hashlib.sha256(_bq_xor_pad(block, _OPAD) + inner).digest()


def _bq_hash(key: HashKey, scope: str, val: str) -> str:
    """Emulate hash_hmac then TO_HEX (lowercase)."""
    scoped = _bq_hmac(key.derived, f"{SCOPE_LABEL}{scope}")
    return _bq_hmac(scoped, val).hex()


def _pg_hash(key: HashKey, scope: str, val: str) -> str:
    """Emulate pgcrypto hmac(...) then encode(..., 'hex') (lowercase)."""
    return hmac.digest(key.scoped(scope).derived, val.encode("utf-8"), "sha256").hex()


def _sf_handler() -> Any:
    namespace: dict[str, Any] = {}
    source = _hmac_udf_sql().split("$$")[1]
    exec(compile(source, "snowflake_hmac_handler", "exec"), namespace)  # noqa: S102
    return namespace["hmac_sha256"]


def _sf_hash(key: HashKey, scope: str, val: str) -> str:
    """Emulate nested _HMAC_SHA256 then HEX_ENCODE (uppercase)."""
    handler = _sf_handler()
    scoped = handler(key.derived, f"{SCOPE_LABEL}{scope}")
    digest: bytes = handler(scoped, val)
    return digest.hex().upper()


def test_bq_pg_sf_hashes_match_under_the_same_scope() -> None:
    key = HashKey("fictional", b"k" * 32)
    scope = "clinic"
    value = "000-00-0001"
    bq = _bq_hash(key, scope, value)
    pg = _pg_hash(key, scope, value)
    sf = _sf_hash(key, scope, value)
    assert bq == pg == sf.lower()
    assert sf == pg.upper()
    assert bq != _bq_hash(key, "research", value)
