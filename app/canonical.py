"""RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256 digests.

JCS gives every JSON value exactly one byte representation so hashes over
policy documents, MCP tool definitions, and audit entries are reproducible by
any independent verifier:

* object members sorted by the UTF-16 code units of their names;
* no insignificant whitespace;
* strings escaped minimally (only quote, backslash and control characters);
* numbers serialized with the ECMAScript ``Number.prototype.toString``
  algorithm (shortest round-trip digits, ``1e+21`` style exponents).

Non-finite numbers and non-string object keys are rejected (``ValueError``).
"""

import hashlib
import math
from decimal import Decimal
from typing import Any

_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f"}
_ESCAPES.update({"\n": "\\n", "\r": "\\r", "\t": "\\t"})


def _escape_char(char: str) -> str:
    """Escape one character per RFC 8785 section 3.2.2.2."""
    if char in _ESCAPES:
        return _ESCAPES[char]
    if ord(char) < 0x20:
        return f"\\u{ord(char):04x}"
    return char


def _string(value: str) -> str:
    """Serialize a JSON string with minimal escaping."""
    return '"' + "".join(_escape_char(char) for char in value) + '"'


def _shortest_digits(value: float) -> tuple[str, int]:
    """Return shortest round-trip digits and the ES decimal-point position."""
    _, digit_tuple, exponent = Decimal(repr(abs(value))).as_tuple()
    all_digits = "".join(str(digit) for digit in digit_tuple)
    return all_digits.rstrip("0"), len(all_digits) + int(exponent)


def _exponent_form(digits: str, point: int) -> str:
    """Format digits in ES scientific notation (``1.5e-7``, ``1e+21``)."""
    exp = point - 1
    mantissa = digits if len(digits) == 1 else digits[0] + "." + digits[1:]
    return f"{mantissa}e{'+' if exp >= 0 else '-'}{abs(exp)}"


def _number(value: float) -> str:
    """Serialize a float with the ECMAScript Number-to-String algorithm."""
    if not math.isfinite(value):
        raise ValueError("JCS forbids NaN and Infinity.")
    if value == 0:
        return "0"
    digits, point = _shortest_digits(value)
    sign = "-" if value < 0 else ""
    if len(digits) <= point <= 21:
        body = digits + "0" * (point - len(digits))
    elif 0 < point <= 21:
        body = digits[:point] + "." + digits[point:]
    elif -6 < point <= 0:
        body = "0." + "0" * -point + digits
    else:
        body = _exponent_form(digits, point)
    return sign + body


def _utf16_key(item: tuple[str, Any]) -> bytes:
    """Sort key: object member names compared as UTF-16 code units."""
    return item[0].encode("utf-16-be")


def _object(value: dict[Any, Any]) -> str:
    """Serialize an object with members sorted by UTF-16 code units."""
    if not all(isinstance(key, str) for key in value):
        raise ValueError("JCS object keys must be strings.")
    members = sorted(value.items(), key=_utf16_key)
    return "{" + ",".join(f"{_string(k)}:{canonicalize(v)}" for k, v in members) + "}"


_LITERALS: dict[object, str] = {None: "null", True: "true", False: "false"}


def canonicalize(value: Any) -> str:
    """Return the RFC 8785 canonical JSON text of ``value``."""
    if value is None or isinstance(value, bool):
        return _LITERALS[value]
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, dict):
        return _object(value)
    if isinstance(value, list | tuple):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    raise ValueError(f"JCS cannot serialize {type(value).__name__}.")


def canonical_bytes(value: Any) -> bytes:
    """Return the UTF-8 encoded RFC 8785 canonical form of ``value``."""
    return canonicalize(value).encode("utf-8")


def sha256_hex(value: Any) -> str:
    """Return the hex SHA-256 digest of the JCS canonical form of ``value``."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
