"""Deterministic DLP redactor for scrubbing PII and secrets from MCP arguments."""

import re
from typing import Any

from app.normalize import (
    ENCODED_TOKEN_PATTERN,
    canonicalize_text,
    decode_token,
    detection_views,
)

SECRET_PATTERN = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{16,}|"
    r"AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._\-]{12,})"
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IBAN_PATTERN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")


def redact_text(value: str) -> tuple[str, set[str]]:
    """Scrub secrets, emails, and IBANs, including obfuscated occurrences.

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
        return "[REDACTED_ENCODED]" if found else match.group()

    result = ENCODED_TOKEN_PATTERN.sub(_scrub_token, result)
    return result, categories | encoded


def _sensitive_categories(text: str) -> set[str]:
    """Return DLP categories present in any detection view of ``text``."""
    found: set[str] = set()
    for view in detection_views(text).views:
        found.update(_redact_plain(view)[1])
    return found


def _redact_plain(value: str) -> tuple[str, set[str]]:
    """Scrub secrets, emails, and IBANs from a string and return detected categories."""
    categories: set[str] = set()
    result = value

    if SECRET_PATTERN.search(result):
        result = SECRET_PATTERN.sub("[REDACTED_SECRET]", result)
        categories.add("secret")

    if EMAIL_PATTERN.search(result):
        result = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", result)
        categories.add("email")

    if IBAN_PATTERN.search(result):
        result = IBAN_PATTERN.sub("[REDACTED_IBAN]", result)
        categories.add("iban")

    return result, categories


def _redact_node(node: Any) -> tuple[Any, set[str]]:
    """Recursively scrub strings inside nested dictionaries and lists."""
    if isinstance(node, str):
        return redact_text(node)

    if isinstance(node, dict):
        sanitized_dict: dict[str, Any] = {}
        found: set[str] = set()
        for k, v in node.items():
            clean_v, sub_cats = _redact_node(v)
            sanitized_dict[str(k)] = clean_v
            found.update(sub_cats)
        return sanitized_dict, found

    if isinstance(node, list):
        sanitized_list: list[Any] = []
        found_list: set[str] = set()
        for item in node:
            clean_item, sub_cats = _redact_node(item)
            sanitized_list.append(clean_item)
            found_list.update(sub_cats)
        return sanitized_list, found_list

    return node, set()


def redact_payload(arguments: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Scrub sensitive values from MCP tool arguments and return sorted categories."""
    sanitized, categories = _redact_node(arguments)
    return dict(sanitized), sorted(categories)
