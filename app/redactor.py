"""Deterministic, checksum-validated DLP redactor for MCP arguments.

Detection is a table-driven pipeline of :class:`Detector` specs evaluated in
order. Each detector pairs a candidate regular expression with a pure
validator (Luhn, ISO 7064 mod-97, DNI/NIE control letter, JWT JSON shape,
Shannon entropy) so look-alike benign values (order IDs, timestamps, hashes)
are not redacted.

Placeholders are static (``[REDACTED_EMAIL]``) unless ``AEGIS_DLP_HMAC_KEY``
is set, in which case they carry a referential HMAC-SHA256 tag
(``[REDACTED_EMAIL#a1b2c3]``): identical values map to identical tokens
without exposing the underlying data. Placeholders never match any detector,
so redaction is idempotent.
"""

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.config import settings
from app.normalize import (
    ENCODED_TOKEN_PATTERN,
    canonicalize_text,
    decode_token,
    detection_views,
)

Extractor = Callable[[str], str | None]

_PEM_KIND = r"(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?"
PRIVATE_KEY_PATTERN = re.compile(
    rf"-----BEGIN {_PEM_KIND}PRIVATE KEY-----"
    rf"(?:[\s\S]*?-----END {_PEM_KIND}PRIVATE KEY-----|[A-Za-z0-9+/=\r\n]*)"
)
JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}"
    r"\.[A-Za-z0-9_-]{8,}"
)
SECRET_PATTERN = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{12,}"
    r"|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{22,}"
    r"|(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|xox[baprs]-[0-9A-Za-z-]{10,}"
    r"|(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|glpat-[0-9A-Za-z_-]{20,}"
    r"|AccountKey=[A-Za-z0-9+/=]{40,}"
    r"|\bsig=[A-Za-z0-9%+/=]{20,}"
    r"|Bearer\s+[A-Za-z0-9._\-]{12,})"
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IBAN_PATTERN = re.compile(
    r"\b[A-Z]{2}\d{2}(?:(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?|[A-Z0-9]{11,30})\b"
)
CREDIT_CARD_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+_.-])"
    r"(?:\d{13,19}|\d{4}([ -])\d{6}\1\d{5}|\d{4}([ -])\d{4}(?:\2\d{4}){1,2}"
    r"(?:\2\d{1,3})?)"
    r"(?![A-Za-z0-9_]|[ .-]\d)"
)
NATIONAL_ID_PATTERN = re.compile(r"\b(?:[XYZ]\d{7}|\d{8})-?[A-Z]\b")
PHONE_PATTERN = re.compile(r"(?<![\w+])\+[1-9](?:[ -]?\d){7,14}(?![\d:])")
KEY_VALUE_SECRET_PATTERN = re.compile(
    r"(?i:password|passwd|pwd|secret|api[_-]?key|client[_-]?secret|"
    r"access[_-]?token|auth[_-]?token|private[_-]?key)"
    r"[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{16,128})"
)

SENSITIVE_KEY_NAMES: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "client_secret",
    "access_token",
    "auth_token",
    "private_key",
    "signing_key",
)
_BENIGN_SECRET_SHAPES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\s"),
    re.compile(r"^\[REDACTED_"),
    re.compile(r"://"),
    re.compile(r"^(?:/|~/|\./|[A-Za-z]:[\\/])"),
    re.compile(r"^[0-9a-f]{64}$"),
    re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
        r"-[0-9a-fA-F]{12}$"
    ),
)
_CHAR_CLASSES: tuple[Callable[[str], bool], ...] = (
    str.isupper,
    str.islower,
    str.isdigit,
    lambda char: not char.isalnum(),
)
ENTROPY_THRESHOLD = 3.75
ENTROPY_THRESHOLD_ALNUM = 4.0
MIN_SECRET_LENGTH = 16
MAX_SECRET_LENGTH = 256
_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"
_NIE_PREFIX = {"X": "0", "Y": "1", "Z": "2"}
_SEPARATORS = re.compile(r"[\s-]")


# ---------------------------------------------------------------------------
# Pure validators
# ---------------------------------------------------------------------------


def _digits(value: str) -> str:
    """Return ``value`` without spaces and hyphens."""
    return _SEPARATORS.sub("", value)


def luhn_valid(number: str) -> bool:
    """Return True when the digit string passes the Luhn mod-10 checksum."""
    total = 0
    for index, char in enumerate(reversed(number)):
        digit = int(char)
        if index % 2:
            digit = digit * 2 - 9 if digit > 4 else digit * 2
        total += digit
    return total % 10 == 0


def is_credit_card(candidate: str) -> bool:
    """Luhn-valid 13-19 digit PAN with a card-network prefix, not repetitive."""
    number = _digits(candidate)
    return (
        13 <= len(number) <= 19
        and number[0] in "23456"
        and len(set(number)) > 1
        and luhn_valid(number)
    )


def iban_valid(candidate: str) -> bool:
    """Return True when the IBAN passes the ISO 7064 mod-97 checksum."""
    compact = _digits(candidate).upper()
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(int(char, 36)) for char in rearranged)
    return int(numeric) % 97 == 1


def _longest_valid_iban(candidate: str) -> str | None:
    """Return the longest space-group prefix of ``candidate`` that is an IBAN.

    Grouped matches may absorb a trailing 4-character word; trimming whole
    groups recovers the real IBAN instead of rejecting the whole candidate.
    """
    parts = candidate.split(" ")
    for end in range(len(parts), 0, -1):
        prefix = " ".join(parts[:end])
        if iban_valid(prefix):
            return prefix
    return None


def national_id_valid(candidate: str) -> bool:
    """Validate a Spanish DNI/NIE control letter (mod 23)."""
    compact = candidate.replace("-", "")
    body, letter = compact[:-1], compact[-1]
    number = _NIE_PREFIX.get(body[0], body[0]) + body[1:]
    return _DNI_LETTERS[int(number) % 23] == letter


def _json_object_segment(segment: str) -> bool:
    """Return True when a Base64URL segment decodes to a UTF-8 JSON object."""
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        return isinstance(json.loads(raw.decode("utf-8")), dict)
    except (binascii.Error, ValueError):
        return False


def jwt_valid(candidate: str) -> bool:
    """Return True when JWS header and payload are Base64URL JSON objects."""
    header, payload, _ = candidate.split(".")
    return _json_object_segment(header) and _json_object_segment(payload)


def phone_valid(candidate: str) -> bool:
    """Return True for an E.164 number with 8-15 digits."""
    return 8 <= len(_digits(candidate)) - 1 <= 15


def shannon_entropy(token: str) -> float:
    """Return the Shannon entropy of ``token`` in bits per character."""
    if not token:
        return 0.0
    length = len(token)
    return -sum(
        count / length * math.log2(count / length) for count in Counter(token).values()
    )


def _char_class_count(token: str) -> int:
    """Count character classes (upper, lower, digit, symbol) in ``token``."""
    return sum(any(test(char) for char in token) for test in _CHAR_CLASSES)


def looks_like_secret(value: str) -> bool:
    """Return True when ``value`` has the shape and entropy of a secret."""
    if not MIN_SECRET_LENGTH <= len(value) <= MAX_SECRET_LENGTH:
        return False
    if any(shape.search(value) for shape in _BENIGN_SECRET_SHAPES):
        return False
    entropy = shannon_entropy(value)
    classes = _char_class_count(value)
    return (entropy >= ENTROPY_THRESHOLD and classes >= 3) or (
        entropy >= ENTROPY_THRESHOLD_ALNUM and classes >= 2
    )


def is_sensitive_key(key: str) -> bool:
    """Return True when a dictionary key names a secret (e.g. ``db_password``)."""
    normalized = key.lower().replace("-", "_")
    return normalized.endswith(SENSITIVE_KEY_NAMES)


# ---------------------------------------------------------------------------
# Placeholders and HMAC tokenization
# ---------------------------------------------------------------------------


def _normalize_for_token(category: str, raw: str) -> str:
    """Canonicalize a raw match so formatting variants share one token."""
    if category == "email":
        return raw.lower()
    if category in {"credit_card", "iban", "phone", "national_id"}:
        return _digits(raw).upper()
    return raw


def placeholder(category: str, raw: str) -> str:
    """Return the static or HMAC-tagged placeholder for a redacted value."""
    label = f"REDACTED_{category.upper()}"
    key = settings.dlp_hmac_key
    if not key:
        return f"[{label}]"
    message = _normalize_for_token(category, raw).encode("utf-8")
    tag = hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()[:6]
    return f"[{label}#{tag}]"


# ---------------------------------------------------------------------------
# Detector pipeline
# ---------------------------------------------------------------------------


def _accept_if(validator: Callable[[str], bool]) -> Extractor:
    """Build an extractor that keeps the whole candidate when it validates."""
    return lambda candidate: candidate if validator(candidate) else None


def _always(candidate: str) -> str | None:
    """Extractor for detectors whose regex alone is conclusive."""
    return candidate


@dataclass(frozen=True)
class Detector:
    """One DLP detector: candidate regex, extractor/validator, and category."""

    category: str
    pattern: re.Pattern[str]
    extract: Extractor
    group: int = 0


DETECTORS: tuple[Detector, ...] = (
    Detector("private_key", PRIVATE_KEY_PATTERN, _always),
    Detector("jwt", JWT_PATTERN, _accept_if(jwt_valid)),
    Detector("secret", SECRET_PATTERN, _always),
    Detector("email", EMAIL_PATTERN, _always),
    Detector("iban", IBAN_PATTERN, _longest_valid_iban),
    Detector("credit_card", CREDIT_CARD_PATTERN, _accept_if(is_credit_card)),
    Detector("national_id", NATIONAL_ID_PATTERN, _accept_if(national_id_valid)),
    Detector("phone", PHONE_PATTERN, _accept_if(phone_valid)),
)
ENTROPY_DETECTOR = Detector(
    "high_entropy_secret",
    KEY_VALUE_SECRET_PATTERN,
    _accept_if(looks_like_secret),
    group=1,
)


def _active_detectors() -> tuple[Detector, ...]:
    """Return the detector table honoring runtime settings."""
    if settings.dlp_entropy_enabled:
        return (*DETECTORS, ENTROPY_DETECTOR)
    return DETECTORS


def _apply_detector(detector: Detector, text: str, found: set[str]) -> str:
    """Replace every validated match of ``detector`` in ``text``."""

    def _replace(match: re.Match[str]) -> str:
        candidate = match.group(detector.group)
        hit = detector.extract(candidate)
        if hit is None:
            return match.group()
        found.add(detector.category)
        whole = match.group()
        start = match.start(detector.group) - match.start()
        end = start + len(hit)
        return whole[:start] + placeholder(detector.category, hit) + whole[end:]

    return detector.pattern.sub(_replace, text)


def _redact_plain(value: str) -> tuple[str, set[str]]:
    """Run the detector pipeline over a string and return detected categories."""
    categories: set[str] = set()
    result = value
    for detector in _active_detectors():
        result = _apply_detector(detector, result, categories)
    return result, categories


def redact_text(value: str) -> tuple[str, set[str]]:
    """Scrub secrets and PII, including obfuscated occurrences.

    The raw text is redacted first. If its canonical form (Unicode folding
    plus percent/HTML decoding, ``app/normalize.py``) reveals further
    sensitive data, the redacted canonical form replaces the value. Base64 /
    hex tokens that decode to sensitive text become ``[REDACTED_ENCODED]``.
    """
    result, categories = _redact_plain(value)
    canonical = canonicalize_text(result)
    if canonical != result:
        revealed, hidden = _redact_plain(canonical)
        if hidden:
            result, categories = revealed, categories | hidden
    encoded: set[str] = set()

    def _scrub_token(match: re.Match[str]) -> str:
        decoded = decode_token(match.group())
        found = _sensitive_categories(decoded) if decoded else set()
        encoded.update(found)
        return placeholder("encoded", match.group()) if found else match.group()

    result = ENCODED_TOKEN_PATTERN.sub(_scrub_token, result)
    return result, categories | encoded


def _sensitive_categories(text: str) -> set[str]:
    """Return DLP categories present in any detection view of ``text``."""
    found: set[str] = set()
    for view in detection_views(text).views:
        found.update(_redact_plain(view)[1])
    return found


def _redact_value(key: str, value: Any) -> tuple[Any, set[str]]:
    """Redact a dictionary value, adding entropy checks for secret-named keys."""
    clean, found = _redact_node(value)
    if (
        not found
        and isinstance(value, str)
        and settings.dlp_entropy_enabled
        and is_sensitive_key(key)
        and looks_like_secret(value)
    ):
        return placeholder("high_entropy_secret", value), {"high_entropy_secret"}
    return clean, found


def _redact_dict(node: dict[Any, Any]) -> tuple[dict[str, Any], set[str]]:
    """Redact every value of a dictionary (keys are stringified)."""
    sanitized: dict[str, Any] = {}
    found: set[str] = set()
    for key, value in node.items():
        clean, sub_categories = _redact_value(str(key), value)
        sanitized[str(key)] = clean
        found.update(sub_categories)
    return sanitized, found


def _redact_list(node: list[Any]) -> tuple[list[Any], set[str]]:
    """Redact every item of a list."""
    sanitized: list[Any] = []
    found: set[str] = set()
    for item in node:
        clean, sub_categories = _redact_node(item)
        sanitized.append(clean)
        found.update(sub_categories)
    return sanitized, found


def _redact_node(node: Any) -> tuple[Any, set[str]]:
    """Recursively scrub strings inside nested dictionaries and lists."""
    if isinstance(node, str):
        return redact_text(node)
    if isinstance(node, dict):
        return _redact_dict(node)
    if isinstance(node, list):
        return _redact_list(node)
    return node, set()


def redact_payload(arguments: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Scrub sensitive values from MCP tool arguments and return sorted categories."""
    sanitized, categories = _redact_node(arguments)
    return dict(sanitized), sorted(categories)
