"""Unit and integration tests for Claude Code + ECC Aegis-MCP dogfooding guardrails."""

import json
from pathlib import Path

import pytest

from app.claude_guard import (
    check_cto_guardrails,
    evaluate_post_tool_event,
    evaluate_pre_tool_event,
    verify_audit_chain_integrity,
)
from app.firewall import MCPFirewall


def test_pre_tool_allows_benign_uv_command(tmp_path: Path) -> None:
    """Verify benign uv commands pass PreToolUse and record a SHA-256 hash link."""
    fw = MCPFirewall(db_path=str(tmp_path / "claude_audit.db"))
    code, raw = evaluate_pre_tool_event(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "uv run pytest -q"},
        },
        firewall=fw,
    )
    assert code == 0
    data = json.loads(raw)
    assert data["status"] == "ALLOWED"
    assert len(data["audit_hash"]) == 64


def test_pre_tool_sanitizes_pii_and_records_audit(tmp_path: Path) -> None:
    """Verify PII/secrets in Claude Code tool calls are redacted and audited."""
    fw = MCPFirewall(db_path=str(tmp_path / "claude_audit.db"))
    code, raw = evaluate_pre_tool_event(
        {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "tests/sample.txt",
                "content": "Contact admin@corp.io or token sk-1234567890abcdef1234",
            },
        },
        firewall=fw,
    )
    assert code == 0
    data = json.loads(raw)
    assert data["status"] == "SANITIZED"
    assert "email" in data["redacted_categories"]
    assert "secret" in data["redacted_categories"]


@pytest.mark.parametrize(
    ("tool_name", "tool_input", "expected_violation"),
    [
        (
            "Bash",
            {"command": "git push origin main"},
            "git_forbidden_push_main",
        ),
        (
            "Bash",
            {"command": "git push --force origin feat/test"},
            "git_forbidden_force_push",
        ),
        (
            "Bash",
            {"command": "git commit -m 'wip' --no-verify"},
            "git_bypass_hooks",
        ),
        (
            "Bash",
            {"command": "pip install requests"},
            "unmanaged_pip_install",
        ),
        (
            "Edit",
            {"file_path": ".claude/settings.json", "new_string": "{}"},
            "governance_tampering_protected_file",
        ),
        (
            "Bash",
            {"command": "echo '{}' > .pre-commit-config.yaml"},
            "governance_tampering_via_shell",
        ),
        (
            "Bash",
            {"command": "rm -rf /tmp/build && cat ../../etc/passwd"},
            "command_injection",
        ),
    ],
)
def test_pre_tool_blocks_cto_and_aegis_violations(
    tmp_path: Path,
    tool_name: str,
    tool_input: dict[str, str],
    expected_violation: str,
) -> None:
    """Verify CTO hard guardrails and Aegis-MCP threat rules block with exit code 2."""
    fw = MCPFirewall(db_path=str(tmp_path / "claude_audit.db"))
    code, raw = evaluate_pre_tool_event(
        {"tool_name": tool_name, "tool_input": tool_input},
        firewall=fw,
    )
    assert code == 2
    data = json.loads(raw)
    assert data["status"] == "BLOCKED_BY_AEGIS_MCP"
    assert expected_violation in data["violations"]
    assert data["risk_score"] >= 85


def test_governor_override_allows_protected_file_edit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify AEGIS_ALLOW_GUARD_EDIT=1 allows Antigravity to update guardrail files."""
    monkeypatch.setenv("AEGIS_ALLOW_GUARD_EDIT", "1")
    violations = check_cto_guardrails(
        "Edit", {"file_path": ".claude/settings.json", "new_string": "{}"}
    )
    assert violations == []


def test_post_tool_and_chain_verification(tmp_path: Path) -> None:
    """Verify PreToolUse + PostToolUse form a valid cryptographic Merkle chain."""
    fw = MCPFirewall(db_path=str(tmp_path / "claude_audit.db"))
    code1, _ = evaluate_pre_tool_event(
        {"tool_name": "Bash", "tool_input": {"command": "uv run ruff check ."}},
        firewall=fw,
    )
    code2, raw2 = evaluate_post_tool_event(
        {"tool_name": "Bash", "tool_input": {"command": "uv run ruff check ."}},
        firewall=fw,
    )
    assert code1 == 0
    assert code2 == 0
    assert json.loads(raw2)["status"] == "AUDITED"

    valid, verify_json = verify_audit_chain_integrity(firewall=fw)
    assert valid is True
    verify_data = json.loads(verify_json)
    assert verify_data["total_entries"] == 2


def test_stop_gate_skips_blocking_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify stop-gate never reads stdin even when invoked with an open pipe."""
    from scripts import claude_aegis_guard

    class _ExplodingStdin:
        def isatty(self) -> bool:
            return False

        def read(self) -> str:
            raise AssertionError("stop-gate must not read stdin")

    monkeypatch.setattr("sys.stdin", _ExplodingStdin())
    monkeypatch.setattr(
        claude_aegis_guard,
        "run_stop_gate",
        lambda: (0, json.dumps({"status": "ALL_GATES_PASSED"})),
    )

    assert claude_aegis_guard.main(["stop-gate"]) == 0


def test_read_stdin_json_returns_empty_on_idle_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify _read_stdin_json returns {} immediately when pipe has no ready bytes."""
    from scripts import claude_aegis_guard

    class _IdlePipeStdin:
        def isatty(self) -> bool:
            return False

        def read(self) -> str:
            raise AssertionError("_read_stdin_json must not block on idle pipe")

    monkeypatch.setattr("sys.stdin", _IdlePipeStdin())
    monkeypatch.setattr(claude_aegis_guard, "_has_stdin_data", lambda: False)

    assert claude_aegis_guard._read_stdin_json() == {}
