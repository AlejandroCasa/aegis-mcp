"""RFC 8785 (JCS) canonicalization test vectors."""

import hashlib
import math

import pytest

from app.canonical import canonical_bytes, canonicalize, sha256_hex


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (100.0, "100"),
        (4.5, "4.5"),
        (-4.5, "-4.5"),
        (0.002, "0.002"),
        (0.000001, "0.000001"),
        (1e-7, "1e-7"),
        (1.5e-7, "1.5e-7"),
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (123456789012345680000.0, "123456789012345680000"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (333333333.3333333, "333333333.3333333"),
    ],
)
def test_numbers_follow_ecmascript_serialization(value: float, expected: str) -> None:
    """Floats use the ES Number-to-String algorithm mandated by RFC 8785."""
    assert canonicalize(value) == expected


def test_literals_integers_and_arrays() -> None:
    """Literals, integers, tuples, and nested arrays serialize compactly."""
    assert canonicalize([None, True, False, 7, -3, (1, "a")]) == (
        '[null,true,false,7,-3,[1,"a"]]'
    )


def test_strings_escape_minimally() -> None:
    """Only quote, backslash, and control characters are escaped."""
    text = 'q"b\\\b\f\n\r\t\x01\U000020ac\U00002028'
    assert canonicalize(text) == '"q\\"b\\\\\\b\\f\\n\\r\\t\\u0001\U000020ac\U00002028"'


def test_object_members_sorted_by_utf16_code_units() -> None:
    """Astral characters (surrogates 0xD83D) sort before U+FB33 in UTF-16."""
    value = {"\U0000fb33": 1, "\U0001f600": 2, "b": 3, "a": {"z": 1, "y": 2}}
    assert canonicalize(value) == (
        '{"a":{"y":2,"z":1},"b":3,"\U0001f600":2,"\U0000fb33":1}'
    )


@pytest.mark.parametrize("bad", [math.nan, math.inf, {1: "x"}, {1, 2}, b"raw"])
def test_rejects_non_json_values(bad: object) -> None:
    """NaN/Infinity, non-string keys, and non-JSON types raise ValueError."""
    with pytest.raises(ValueError):
        canonicalize(bad)


def test_digest_helpers() -> None:
    """sha256_hex hashes the UTF-8 canonical bytes."""
    value = {"b": [1, 2.5], "a": "\U000000e9"}
    assert canonical_bytes(value) == '{"a":"\U000000e9","b":[1,2.5]}'.encode()
    assert sha256_hex(value) == hashlib.sha256(canonical_bytes(value)).hexdigest()
