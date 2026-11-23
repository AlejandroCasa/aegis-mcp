"""Argument-level ABAC: declarative per-tool constraints on argument values.

RBAC (``app/policy.py``) decides *which* tools an agent may call; these
constraints decide *how*. Every ``ToolConstraint`` whose scope globs match the
call applies, and each failed check yields one violation code:

* ``argument_path_not_allowed``: a path argument escapes every ``path_allow``
  root after ``realpath`` canonicalization (defeats symlinks, dot-dot
  segments, percent-encoded ``file://`` URIs, and NUL-byte truncation).
* ``argument_sql_not_read_only``: ``sql_mode: read_only`` admits exactly one
  ``SELECT``/``WITH`` statement with no write/DDL/session keyword outside of
  comments and quoted literals.
* ``argument_egress_not_allowed``: an http(s) URL argument targets a host
  outside ``egress_allow`` (exact host, or ``*.domain`` for subdomains).
* ``argument_max_bytes_exceeded`` / ``argument_max_items_exceeded``: the
  serialized arguments or any nested array/object exceed the configured caps.

Path checks resolve symlinks on the gateway host, so they are authoritative
when Aegis shares the filesystem namespace with the MCP server (sidecar).
"""

import json
import os
import re
from collections.abc import Callable, Iterator
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import unquote, urlsplit

from app.schemas import PolicyDocument, ToolConstraint

PATH_VIOLATION = "argument_path_not_allowed"
SQL_VIOLATION = "argument_sql_not_read_only"
EGRESS_VIOLATION = "argument_egress_not_allowed"
BYTES_VIOLATION = "argument_max_bytes_exceeded"
ITEMS_VIOLATION = "argument_max_items_exceeded"

READ_ONLY_LEADS = frozenset({"SELECT", "WITH"})
SQL_WRITE_TOKENS = frozenset(
    {
        "INSERT", "UPDATE", "DELETE", "MERGE", "UPSERT", "REPLACE", "DROP",
        "CREATE", "ALTER", "TRUNCATE", "RENAME", "GRANT", "REVOKE", "ATTACH",
        "DETACH", "PRAGMA", "VACUUM", "REINDEX", "COPY", "CALL", "EXEC",
        "EXECUTE", "DO", "LOCK", "SET", "RESET", "COMMENT", "INTO", "LOAD",
        "HANDLER", "PREPARE", "DEALLOCATE", "LISTEN", "NOTIFY", "REFRESH",
        "PG_SLEEP", "PG_TERMINATE_BACKEND", "PG_CANCEL_BACKEND", "PG_READ_FILE",
        "PG_READ_BINARY_FILE", "PG_LS_DIR", "LO_IMPORT", "LO_EXPORT", "DBLINK",
        "DBLINK_EXEC", "LOAD_FILE", "SET_CONFIG", "NEXTVAL", "SETVAL",
    }
)  # fmt: skip

# Comments and quoted literals/identifiers, matched left-to-right so a quote
# inside a comment (or a comment marker inside a literal) cannot desync parsing.
_SQL_OPAQUE = re.compile(
    r"--[^\n]*"
    r"|/\*.*?\*/"
    r"|'(?:[^']|'')*'"
    r'|"(?:[^"]|"")*"'
    r"|`[^`]*`"
    r"|\$(?P<tag>[A-Za-z_]*)\$.*?\$(?P=tag)\$",
    re.DOTALL,
)
_SQL_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")
_URL_FORBIDDEN = re.compile(r"[\\\s\x00-\x1f\x7f]")


def is_read_only_sql(statement: str) -> bool:
    """Return True for exactly one SELECT/WITH statement without write tokens."""
    visible = _SQL_OPAQUE.sub(" ", statement)
    statements = [part for part in visible.split(";") if part.strip()]
    if len(statements) != 1:
        return False
    words = {word.upper() for word in _SQL_WORD.findall(statements[0])}
    first = _SQL_WORD.search(statements[0])
    return (
        first is not None
        and first.group(0).upper() in READ_ONLY_LEADS
        and not words & SQL_WRITE_TOKENS
    )


def resolve_path(raw: str, base: str) -> str:
    """Canonicalize ``raw`` (path or ``file://`` URI) with ``realpath``.

    Relative paths resolve against ``base`` (the first allowed root). NUL bytes
    raise ``ValueError`` (C-level truncation attack).
    """
    candidate = raw
    if candidate.lower().startswith("file://"):
        candidate = unquote(urlsplit(candidate).path)
    if "\x00" in candidate:
        raise ValueError("NUL byte in path argument.")
    if not os.path.isabs(candidate):
        candidate = os.path.join(base, candidate)
    return os.path.realpath(candidate)


def path_within(path: str, roots: list[str]) -> bool:
    """Return True if canonical ``path`` lies inside any canonical root."""
    for root in roots:
        real_root = os.path.realpath(root)
        if os.path.commonpath([path, real_root]) == real_root:
            return True
    return False


def _domain_matches(host: str, pattern: str) -> bool:
    """Exact host match, or strict subdomain match for ``*.domain``."""
    normalized = pattern.lower().rstrip(".")
    if normalized.startswith("*."):
        return host.endswith(normalized[1:])
    return host == normalized


def egress_allowed(url: str, patterns: list[str]) -> bool:
    """Return True if ``url`` is http(s) and its IDNA host is allow-listed."""
    if _URL_FORBIDDEN.search(url):
        return False
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").rstrip(".")
        _ = parts.port
        ascii_host = host.encode("idna").decode("ascii").lower()
    except (ValueError, UnicodeError):
        return False
    if parts.scheme.lower() not in ("http", "https") or not ascii_host:
        return False
    return any(_domain_matches(ascii_host, pattern) for pattern in patterns)


def _string_values(arguments: dict[str, Any], keys: list[str]) -> Iterator[Any]:
    """Yield every value (flattening one list level) of the constrained keys."""
    for key in keys:
        if key not in arguments:
            continue
        value = arguments[key]
        yield from value if isinstance(value, list) else [value]


def _check_paths(constraint: ToolConstraint, arguments: dict[str, Any]) -> bool:
    """Return True if every path argument stays inside ``path_allow``."""
    for value in _string_values(arguments, constraint.path_args):
        if not isinstance(value, str):
            return False
        try:
            resolved = resolve_path(value, constraint.path_allow[0])
        except ValueError:
            return False
        if not path_within(resolved, constraint.path_allow):
            return False
    return True


def _check_sql(constraint: ToolConstraint, arguments: dict[str, Any]) -> bool:
    """Return True if every SQL argument is a single read-only statement."""
    return all(
        isinstance(value, str) and is_read_only_sql(value)
        for value in _string_values(arguments, constraint.sql_args)
    )


def _check_egress(constraint: ToolConstraint, arguments: dict[str, Any]) -> bool:
    """Return True if every URL argument targets an allow-listed host."""
    return all(
        isinstance(value, str) and egress_allowed(value, constraint.egress_allow)
        for value in _string_values(arguments, constraint.url_args)
    )


def _check_bytes(constraint: ToolConstraint, arguments: dict[str, Any]) -> bool:
    """Return True if the compact UTF-8 JSON size is within ``max_bytes``."""
    serialized = json.dumps(arguments, separators=(",", ":"), ensure_ascii=False)
    return len(serialized.encode("utf-8")) <= int(constraint.max_bytes or 0)


def _containers(value: Any) -> Iterator[list[Any] | dict[str, Any]]:
    """Iteratively yield every nested list/dict (no recursion-depth risk)."""
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            yield node
            stack.extend(node.values())
        elif isinstance(node, list):
            yield node
            stack.extend(node)


def _check_items(constraint: ToolConstraint, arguments: dict[str, Any]) -> bool:
    """Return True if no nested array/object exceeds ``max_items`` elements."""
    limit = int(constraint.max_items or 0)
    return all(len(node) <= limit for node in _containers(arguments))


Check = Callable[[ToolConstraint, dict[str, Any]], bool]

CHECKS: tuple[tuple[str, Callable[[ToolConstraint], bool], Check], ...] = (
    (PATH_VIOLATION, lambda c: bool(c.path_allow), _check_paths),
    (SQL_VIOLATION, lambda c: c.sql_mode == "read_only", _check_sql),
    (EGRESS_VIOLATION, lambda c: bool(c.egress_allow), _check_egress),
    (BYTES_VIOLATION, lambda c: c.max_bytes is not None, _check_bytes),
    (ITEMS_VIOLATION, lambda c: c.max_items is not None, _check_items),
)


def _applies(
    constraint: ToolConstraint,
    agent_id: str,
    server_name: str,
    tool_name: str,
    environment: str,
) -> bool:
    """Return True if the constraint's scope globs match the call."""
    return (
        environment in constraint.environments
        and fnmatchcase(agent_id, constraint.agent_id)
        and fnmatchcase(server_name, constraint.server_name)
        and fnmatchcase(tool_name, constraint.tool_name)
    )


def evaluate_constraints(
    document: PolicyDocument,
    scope: tuple[str, str, str, str],
    arguments: dict[str, Any],
) -> list[str]:
    """Return de-duplicated violation codes for ``(agent, server, tool, env)``."""
    violations: dict[str, None] = {}
    for constraint in document.tool_constraints:
        if not _applies(constraint, *scope):
            continue
        for code, enabled, check in CHECKS:
            if enabled(constraint) and not check(constraint, arguments):
                violations[code] = None
    return list(violations)
