from __future__ import annotations

import pytest

from datagrant.pg.mask import ColumnType, MaskError, TableCatalog, column_expr

CAT = TableCatalog(
    {"ssn": ColumnType("pg_catalog", "text"), "dob": ColumnType("pg_catalog", "date")},
    "ext",
)


def r(col: str, mask: str, **kw: object) -> str:
    return column_expr(col, mask, CAT, **kw).as_string(None)  # type: ignore[arg-type]


def test_passthrough() -> None:
    assert r("ssn", "passthrough") == '"ssn"'


def test_null_is_typed() -> None:
    assert r("dob", "null") == 'CAST(NULL AS "pg_catalog"."date") AS "dob"'


def test_redact() -> None:
    assert r("ssn", "redact") == "CAST('[REDACTED]' AS pg_catalog.text) AS \"ssn\""


def test_partial() -> None:
    out = r("dob", "partial")
    assert (
        'CAST("dob" AS pg_catalog.text)' in out
        and "pg_catalog.right(" in out
        and out.endswith('AS "dob"')
    )


def test_hash_uses_key_id_not_key() -> None:
    out = r("ssn", "hash", hash_key_id="abc")
    assert out.startswith(
        'pg_catalog.encode("ext"."hmac"(pg_catalog.convert_to(CAST("ssn" AS pg_catalog.text)'
    )
    assert '"datagrant"."hash_keys"' in out and "k.id = 'abc'" in out


@pytest.mark.parametrize(
    ("col", "mask", "kw", "cat", "msg"),
    [
        ("nope", "redact", {}, CAT, "does not exist"),
        ("ssn", "encrypt", {}, CAT, "unknown mask"),
        ("ssn", "hash", {}, CAT, "needs a hash key"),
        ("ssn", "hash", {"hash_key_id": "a"}, TableCatalog(CAT.columns, None), "pgcrypto"),
    ],
)
def test_errors(col: str, mask: str, kw: dict[str, str], cat: TableCatalog, msg: str) -> None:
    with pytest.raises(MaskError, match=msg):
        column_expr(col, mask, cat, **kw)
