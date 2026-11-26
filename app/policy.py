"""Declarative per-agent / per-server / per-environment RBAC policy matrix.

Evaluation semantics (deny-overrides):

1. Select every rule whose ``agent_id`` / ``server_name`` globs match the call
   and whose ``environments`` include the call's environment.
2. If any selected rule's ``deny_tools`` matches the tool, the call is denied.
3. If any selected rule declares a non-empty ``allow_tools``, the tool must
   match at least one of those allowlists.
4. Otherwise the document's ``default_action`` applies.

Matching uses case-sensitive ``fnmatch`` globs so ``Admin_*`` cannot bypass an
``admin_*`` denylist entry through casing.

Startup is fail-closed in ``prod``: a missing or invalid policy yields a
deny-all engine (``fail_closed=True``) instead of the permissive default.
Every document is versioned by ``policy_version`` (SHA-256 over its RFC 8785
canonical JSON) so each audit entry records exactly which policy decided it.
"""

import logging
import threading
from collections.abc import Iterable
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Self

import yaml
from pydantic import ValidationError

from app.canonical import sha256_hex
from app.schemas import Environment, PolicyAction, PolicyDocument, PolicyRule

RBAC_VIOLATION = "rbac_policy_denied"
FAIL_CLOSED_VIOLATION = "policy_fail_closed"
RBAC_RISK_SCORE = 100
MAX_POLICY_FILE_BYTES = 1_048_576

logger = logging.getLogger("aegis_mcp.policy")


class PolicyLoadError(ValueError):
    """Raised when a policy source cannot be read, parsed, or validated."""


def parse_policy_yaml(text: str) -> PolicyDocument:
    """Parse YAML text with ``yaml.safe_load`` into a validated PolicyDocument."""
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"Invalid RBAC policy YAML: {exc}") from exc
    if raw is None:
        return PolicyDocument()
    if not isinstance(raw, dict):
        raise PolicyLoadError("RBAC policy YAML root must be a mapping.")
    try:
        return PolicyDocument.model_validate(raw)
    except ValidationError as exc:
        raise PolicyLoadError(f"RBAC policy failed validation: {exc}") from exc


def load_policy_file(path: str | Path) -> PolicyDocument:
    """Load a YAML policy file, failing closed on any read or size error."""
    policy_path = Path(path)
    try:
        with policy_path.open("rb") as handle:
            data = handle.read(MAX_POLICY_FILE_BYTES + 1)
    except OSError as exc:
        raise PolicyLoadError(f"Cannot read RBAC policy file: {exc}") from exc
    if len(data) > MAX_POLICY_FILE_BYTES:
        raise PolicyLoadError(
            f"RBAC policy file exceeds {MAX_POLICY_FILE_BYTES} bytes."
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyLoadError("RBAC policy file is not valid UTF-8.") from exc
    return parse_policy_yaml(text)


def _matches_any(name: str, patterns: Iterable[str]) -> bool:
    """Return True if ``name`` matches at least one case-sensitive glob."""
    return any(fnmatchcase(name, pattern) for pattern in patterns)


def _rule_applies(
    rule: PolicyRule, agent_id: str, server_name: str, environment: str
) -> bool:
    """Return True if the rule's agent/server/environment scope matches."""
    return (
        environment in rule.environments
        and fnmatchcase(agent_id, rule.agent_id)
        and fnmatchcase(server_name, rule.server_name)
    )


def evaluate_action(
    document: PolicyDocument,
    agent_id: str,
    server_name: str,
    tool_name: str,
    environment: str,
) -> PolicyAction:
    """Return the policy action (``allow|deny|require_approval``) for a call.

    ``deny_tools`` win; a ``require_approval_tools`` match satisfies any
    allowlist in scope but gates the call behind human approval; otherwise
    allowlists and then ``default_action`` decide.
    """
    matching = [
        rule
        for rule in document.rules
        if _rule_applies(rule, agent_id, server_name, environment)
    ]
    if any(_matches_any(tool_name, rule.deny_tools) for rule in matching):
        return "deny"
    if any(_matches_any(tool_name, rule.require_approval_tools) for rule in matching):
        return "require_approval"
    return _allowlist_action(matching, tool_name, document.default_action)


def _allowlist_action(
    matching: list[PolicyRule], tool_name: str, default_action: PolicyAction
) -> PolicyAction:
    """Allowlists in scope decide; with none, ``default_action`` applies."""
    allowlists = [rule.allow_tools for rule in matching if rule.allow_tools]
    if not allowlists:
        return default_action
    allowed = any(_matches_any(tool_name, allow) for allow in allowlists)
    return "allow" if allowed else "deny"


def evaluate_policy(
    document: PolicyDocument,
    agent_id: str,
    server_name: str,
    tool_name: str,
    environment: str,
) -> bool:
    """Return True unless the matrix denies the call (approval still permits)."""
    action = evaluate_action(document, agent_id, server_name, tool_name, environment)
    return action != "deny"


def policy_version(document: PolicyDocument) -> str:
    """Return the SHA-256 of the document's RFC 8785 canonical JSON form.

    Empty ``taint_rules`` and per-rule ``require_approval_tools`` are omitted
    so documents predating those features keep their historical version.
    """
    exclude: dict[str, Any] = {}
    if not document.taint_rules:
        exclude["taint_rules"] = True
    if not any(rule.require_approval_tools for rule in document.rules):
        exclude["rules"] = {"__all__": {"require_approval_tools"}}
    return sha256_hex(document.model_dump(mode="json", exclude=exclude or None))


def fail_closed_document() -> PolicyDocument:
    """Return the deny-all document used when no valid policy can be loaded."""
    return PolicyDocument(default_action="deny")


class PolicyEngine:
    """Thread-safe holder for the active RBAC PolicyDocument and its version."""

    def __init__(
        self, document: PolicyDocument | None = None, *, fail_closed: bool = False
    ) -> None:
        """Initialize with ``document`` or the permissive default policy.

        ``fail_closed=True`` installs the deny-all document regardless of
        ``document`` and tags every denial with ``policy_fail_closed``.
        """
        self._lock = threading.Lock()
        self._fail_closed = fail_closed
        source = fail_closed_document() if fail_closed else document
        self._document = (source or PolicyDocument()).model_copy(deep=True)
        self._version = policy_version(self._document)

    @classmethod
    def from_path(cls, path: str | None) -> Self:
        """Build an engine from a YAML file, or the default policy if None."""
        return cls(load_policy_file(path) if path else None)

    @property
    def document(self) -> PolicyDocument:
        """Return a defensive copy of the active policy document."""
        with self._lock:
            return self._document.model_copy(deep=True)

    @property
    def version(self) -> str:
        """Return the ``policy_version`` hash of the active document."""
        with self._lock:
            return self._version

    @property
    def fail_closed(self) -> bool:
        """Return True while the engine runs the startup deny-all fallback."""
        with self._lock:
            return self._fail_closed

    def load(self, document: PolicyDocument) -> None:
        """Atomically replace the active policy document (clears fail-closed)."""
        snapshot = document.model_copy(deep=True)
        version = policy_version(snapshot)
        with self._lock:
            self._document = snapshot
            self._version = version
            self._fail_closed = False

    def reset(self) -> None:
        """Restore the permissive default policy."""
        self.load(PolicyDocument())

    def snapshot(self) -> tuple[PolicyDocument, str, bool]:
        """Return the active document, version, and fail-closed flag atomically."""
        with self._lock:
            return self._document, self._version, self._fail_closed

    def is_allowed(
        self, agent_id: str, server_name: str, tool_name: str, environment: str
    ) -> bool:
        """Evaluate the active matrix for a single tool call."""
        with self._lock:
            document = self._document
        return evaluate_policy(document, agent_id, server_name, tool_name, environment)


def build_policy_engine(path: str | None, environment: Environment) -> PolicyEngine:
    """Build the startup engine, failing closed (deny-all) in ``prod``.

    * ``prod``: a missing or invalid policy yields a deny-all engine.
    * ``dev``/``staging``: a missing policy keeps the permissive default (with
      a warning); an invalid policy still raises ``PolicyLoadError``.
    """
    if path is None:
        if environment == "prod":
            logger.error("AEGIS_POLICY_PATH unset in prod: failing closed (deny-all).")
            return PolicyEngine(fail_closed=True)
        logger.warning(
            "AEGIS_POLICY_PATH is not set: RBAC matrix defaults to allow-all."
        )
        return PolicyEngine()
    try:
        return PolicyEngine(load_policy_file(path))
    except PolicyLoadError:
        if environment != "prod":
            raise
        logger.exception("Invalid RBAC policy in prod: failing closed (deny-all).")
        return PolicyEngine(fail_closed=True)
