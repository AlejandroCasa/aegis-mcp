"""Claude Code + ECC Zero-Trust Dogfooding Guardrail and Quality Gate Engine."""

import json
import os
import re
from typing import Any

from app.firewall import MCPFirewall
from app.schemas import MCPToolCallRequest

PROTECTED_PATHS: tuple[str, ...] = (
    ".claude/settings.json",
    ".claude/rules/",
    ".pre-commit-config.yaml",
    "AGENTS.md",
    "CLAUDE.md",
    "app/claude_guard.py",
    "scripts/claude_aegis_guard.py",
)

CTO_BASH_GUARDRAILS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "git_forbidden_push_main",
        re.compile(
            r"\bgit\s+push\b[^\n;]*\b(?:main|master)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "git_forbidden_force_push",
        re.compile(
            r"\bgit\s+push\b[^\n;]*(?:--force\b|-f\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "git_bypass_hooks",
        re.compile(
            r"\bgit\s+(?:commit|push)\b[^\n;]*(?:--no-verify\b|-n\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "unmanaged_pip_install",
        re.compile(
            r"(?:^|[;&|]\s*)(?:pip|pip3)\s+install\b|\bpython(?:3)?\s+-m\s+pip\b",
            re.IGNORECASE,
        ),
    ),
)


def _normalize_path(raw_path: str) -> str:
    """Normalize a file path to forward slashes for deterministic matching."""
    return raw_path.replace("\\", "/").strip()


def _touches_protected_path(text: str) -> bool:
    """Return True if the serialized input references a protected guardrail file."""
    normalized = _normalize_path(text)
    return any(protected in normalized for protected in PROTECTED_PATHS)


def _is_guard_edit_allowed() -> bool:
    """Return True only when explicit human/governor override env var is enabled."""
    return os.environ.get("AEGIS_ALLOW_GUARD_EDIT", "0") == "1"


def check_cto_guardrails(tool_name: str, tool_input: dict[str, Any]) -> list[str]:
    """Evaluate CTO Zero-Trust guardrails against Claude Code tool invocations."""
    violations: list[str] = []
    serialized = json.dumps(tool_input, sort_keys=True)

    if tool_name in {"Edit", "Write", "MultiEdit", "NotebookEdit"} and (
        not _is_guard_edit_allowed() and _touches_protected_path(serialized)
    ):
        violations.append("governance_tampering_protected_file")

    command_text = str(tool_input.get("command", ""))
    if command_text:
        for rule_code, pattern in CTO_BASH_GUARDRAILS:
            if pattern.search(command_text):
                violations.append(rule_code)
        if not _is_guard_edit_allowed() and _touches_protected_path(command_text):
            violations.append("governance_tampering_via_shell")

    return violations


def evaluate_pre_tool_event(
    payload: dict[str, Any],
    firewall: MCPFirewall | None = None,
) -> tuple[int, str]:
    """Inspect a Claude Code PreToolUse event through CTO rules and Aegis-MCP."""
    active_fw = firewall or MCPFirewall()
    tool_name = str(payload.get("tool_name", "unknown_tool"))
    raw_input = payload.get("tool_input")
    tool_input: dict[str, Any] = raw_input if isinstance(raw_input, dict) else {}
    agent_id = str(payload.get("agent_id", "claude-code-ecc"))

    cto_violations = check_cto_guardrails(tool_name, tool_input)
    mcp_request = MCPToolCallRequest(
        agent_id=agent_id,
        server_name="claude-code-harness",
        tool_name=tool_name,
        arguments=tool_input,
        environment="dev",
    )
    inspection = active_fw.inspect(mcp_request)
    combined_violations = list(dict.fromkeys([*cto_violations, *inspection.violations]))

    if cto_violations or not inspection.allowed:
        report = {
            "status": "BLOCKED_BY_AEGIS_MCP",
            "tool_name": tool_name,
            "risk_score": max(inspection.risk_score, 95 if cto_violations else 0),
            "violations": combined_violations,
            "audit_hash": inspection.audit_hash,
            "prev_hash": inspection.prev_hash,
        }
        return 2, json.dumps(report)

    ok_report = {
        "status": inspection.decision,
        "tool_name": tool_name,
        "audit_hash": inspection.audit_hash,
        "redacted_categories": inspection.redacted_categories,
    }
    return 0, json.dumps(ok_report)


def evaluate_post_tool_event(
    payload: dict[str, Any],
    firewall: MCPFirewall | None = None,
) -> tuple[int, str]:
    """Record a Claude Code PostToolUse event into the Aegis-MCP SHA-256 ledger."""
    active_fw = firewall or MCPFirewall()
    tool_name = f"post:{payload.get('tool_name', 'unknown_tool')}"
    raw_input = payload.get("tool_input")
    tool_input: dict[str, Any] = raw_input if isinstance(raw_input, dict) else {}

    mcp_request = MCPToolCallRequest(
        agent_id="claude-code-ecc",
        server_name="claude-code-harness",
        tool_name=tool_name,
        arguments=tool_input,
        environment="dev",
    )
    inspection = active_fw.inspect(mcp_request)
    return 0, json.dumps(
        {
            "status": "AUDITED",
            "tool_name": tool_name,
            "audit_hash": inspection.audit_hash,
        }
    )


def verify_audit_chain_integrity(
    firewall: MCPFirewall | None = None,
) -> tuple[bool, str]:
    """Verify the cryptographic integrity of the Claude Code Aegis-MCP ledger."""
    active_fw = firewall or MCPFirewall()
    verification = active_fw.verify_chain()
    return verification.valid, verification.model_dump_json()
