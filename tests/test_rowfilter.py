from __future__ import annotations

import pytest

from datagrant.rowfilter import RowFilterError, parse_row_filter


def render(text: str) -> str:
    return parse_row_filter(text)[0].as_string(None)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("region = 'west'", "\"region\" = 'west'"),
        ("a = 1 AND b <> 'x''y'", "\"a\" = 1 AND \"b\" <> 'x''y'"),
        ("a != 2.5 or b is null", '"a" <> 2.5 OR "b" IS NULL'),
        (
            "(a >= -3 OR b IS NOT NULL) AND c = true",
            '("a" >=  -3 OR "b" IS NOT NULL) AND "c" = true',
        ),
        (
            "a < 1 and b <= 2 and c > 3 and d = FALSE",
            '"a" < 1 AND "b" <= 2 AND "c" > 3 AND "d" = false',
        ),
    ],
)
def test_parse_ok(text: str, expected: str) -> None:
    assert render(text) == expected


def test_columns_collected() -> None:
    assert parse_row_filter("a = 1 OR (b = 2 AND a = 3)")[1] == {"a", "b"}


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "region = 'west'; DROP TABLE x",
        "region = 'west' --",
        "1 = 1",
        "a = b",
        "a = 'x' OR",
        "(a = 1",
        "a = 1)",
        "a IS 1",
        "a LIKE 'x'",
        "f(a) = 1",
        "a = 'unterminated",
        "and = 1",
        "a",
        "a = 1 a",
        'a = "x"',
        "a = 1 OR 1=1 /* */",
        "x" * 1001,
        "(" * 20 + "a = 1" + ")" * 20,
    ],
)
def test_parse_rejects(text: str) -> None:
    with pytest.raises(RowFilterError):
        parse_row_filter(text)
