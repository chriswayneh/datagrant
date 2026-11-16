"""Execute the exact inline Snowflake handler against known HMAC vectors."""

from __future__ import annotations

import hmac
from typing import Any

import pytest

from datagrant.keys import HashKey
from datagrant.sf.grant import _hash_udf_sql, _hmac_udf_sql, ensure_state_sql


@pytest.fixture
def handler() -> Any:
    namespace: dict[str, Any] = {}
    source = _hmac_udf_sql().split("$$")[1]
    # Execute only the repository-owned inline handler, with no user input.
    exec(compile(source, "snowflake_hmac_handler", "exec"), namespace)  # noqa: S102
    return namespace["hmac_sha256"]


@pytest.mark.parametrize(
    ("key", "message", "expected"),
    [
        (
            b"\x0b" * 20,
            "Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            b"Jefe",
            "what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        (
            b"\xaa" * 131,
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        ),
    ],
)
def test_inline_handler_rfc4231_vectors(
    handler: Any, key: bytes, message: str, expected: str
) -> None:
    assert handler(key, message).hex() == expected


def test_inline_handler_null_empty_unicode_and_scope(handler: Any) -> None:
    key = HashKey("fictional", b"k" * 32)
    assert handler(key.derived, None) is None
    assert handler(key.derived, "") == hmac.digest(key.derived, b"", "sha256")
    value = "O'Brien é 患者 U0001f9ec"
    scope_key = handler(key.derived, "datagrant/hash-scope/v1:clinic")
    assert scope_key == key.scoped("clinic").derived
    assert handler(scope_key, value) == hmac.digest(scope_key, value.encode(), "sha256")
    other = handler(key.derived, "datagrant/hash-scope/v1:research")
    assert handler(scope_key, value) != handler(other, value)


def test_inline_handler_missing_key_fails_without_disclosing_values(handler: Any) -> None:
    with pytest.raises(ValueError, match="^datagrant hash key is unavailable$"):
        handler(None, "fictional sensitive input")


def test_setup_provisions_primitive_before_key_reading_wrapper() -> None:
    statements = ensure_state_sql()
    assert statements.index(_hmac_udf_sql()) < statements.index(_hash_udf_sql())
    assert "SECURE FUNCTION" in _hmac_udf_sql()
    assert "LANGUAGE PYTHON RUNTIME_VERSION = '3.12'" in _hmac_udf_sql()
    assert "SHA2_HMAC" not in "\n".join(statements)
    wrapper = _hash_udf_sql()
    assert "CASE WHEN VAL IS NULL THEN NULL" in wrapper
    assert "COALESCE(VAL" not in wrapper
    assert 'SELECT KEY FROM "DATAGRANT"."_HASH_MASTER"' in wrapper
    assert wrapper.count('"DATAGRANT"."_HMAC_SHA256"') == 2
