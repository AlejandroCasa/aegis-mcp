"""Deterministic DLP redactor for scrubbing PII and secrets from MCP arguments."""

import re
from typing import Any

SECRET_PATTERN = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{16,}|"
    r"AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._\-]{12,})"
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IBAN_PATTERN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")


def redact_text(value: str) -> tuple[str, set[str]]:
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
