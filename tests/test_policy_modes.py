"""Fail-closed startup, shadow (monitor) mode, and policy versioning."""

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.canonical import sha256_hex
from app.config import settings
from app.firewall import GENESIS_HASH, MCPFirewall, compute_entry_hash
from app.main import app, policy_engine
from app.metrics import metrics_registry
from app.policy import (
    FAIL_CLOSED_VIOLATION,
    RBAC_VIOLATION,
    PolicyEngine,
    PolicyLoadError,
    build_policy_engine,
    policy_version,
)
from app.schemas import MCPToolCallRequest, PolicyDocument, PolicyRule

client = TestClient(app)
DESTRUCTIVE = "rm" + " -rf /var/lib"
ADMIN_KEY = "admin-" + "k" * 20


@pytest.fixture(autouse=True)
def restore_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep settings and the shared engine isolated per test."""
    monkeypatch.setattr(settings, "policy_mode", "enforce")
    monkeypatch.setattr(settings, "block_threshold_score", 70)
    monkeypatch.setattr(settings, "enable_dlp_redaction", True)
    metrics_registry.reset()
    yield
    policy_engine.reset()
    metrics_registry.reset()


def _firewall(tmp_path: Path, engine: PolicyEngine | None = None) -> MCPFirewall:
    return MCPFirewall(
        db_path=str(tmp_path / "ledger.db"), policy_engine=engine or PolicyEngine()
    )


def _call(arguments: dict[str, object] | None = None) -> MCPToolCallRequest:
    return MCPToolCallRequest(
        agent_id="ops-agent",
        server_name="shell-mcp",
        tool_name="run",
        arguments=arguments or {"cmd": "ls"},
        environment="prod",
    )


def _write_policy(tmp_path: Path, text: str) -> str:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_prod_without_policy_fails_closed(tmp_path: Path) -> None:
    """No AEGIS_POLICY_PATH in prod installs a deny-all engine."""
    engine = build_policy_engine(None, "prod")
    assert engine.fail_closed is True
    assert engine.document.default_action == "deny"
    report = _firewall(tmp_path, engine).inspect(_call())
    assert report.allowed is False
    assert report.violations == [RBAC_VIOLATION, FAIL_CLOSED_VIOLATION]


def test_prod_with_invalid_policy_fails_closed(tmp_path: Path) -> None:
    """An unparsable policy in prod degrades to deny-all instead of crashing."""
    path = _write_policy(tmp_path, "rules: [not-a-mapping")
    engine = build_policy_engine(path, "prod")
    assert engine.fail_closed is True


def test_non_prod_keeps_permissive_default_and_strict_loading(tmp_path: Path) -> None:
    """dev/staging allow-all without a policy but still reject invalid files."""
    assert build_policy_engine(None, "dev").fail_closed is False
    assert build_policy_engine(None, "staging").document.default_action == "allow"
    with pytest.raises(PolicyLoadError):
        build_policy_engine(_write_policy(tmp_path, "- 1"), "staging")


def test_valid_policy_file_is_loaded_in_prod(tmp_path: Path) -> None:
    """A valid policy in prod is used as-is (no fail-closed flag)."""
    path = _write_policy(
        tmp_path, "default_action: deny\nrules:\n  - allow_tools: ['run']\n"
    )
    engine = build_policy_engine(path, "prod")
    assert engine.fail_closed is False
    assert _firewall(tmp_path, engine).inspect(_call()).allowed is True


def test_policy_version_is_jcs_sha256_and_tracks_reloads() -> None:
    """policy_version hashes the canonical document and changes on reload."""
    document = PolicyDocument(rules=[PolicyRule(deny_tools=["drop_*"])])
    engine = PolicyEngine(fail_closed=True)
    fail_closed_version = engine.version
    engine.load(document)
    assert engine.fail_closed is False
    assert engine.version == policy_version(document)
    # An empty ``taint_rules`` is omitted so pre-taint versions stay stable.
    legacy = document.model_dump(mode="json", exclude={"taint_rules"})
    assert engine.version == sha256_hex(legacy)
    assert engine.version != fail_closed_version
    assert PolicyEngine(document).version == engine.version


def test_enforce_mode_blocks_and_flags_would_block(tmp_path: Path) -> None:
    """Enforce mode blocks threats and records the policy version."""
    firewall = _firewall(tmp_path)
    report = firewall.inspect(_call({"cmd": DESTRUCTIVE}))
    assert report.decision == "BLOCKED"
    assert report.would_block is True
    assert report.policy_mode == "enforce"
    assert report.policy_version == firewall.policy_engine.version
    entry = firewall.list_audit_entries()[0]
    assert (entry.would_block, entry.policy_mode) == (True, "enforce")
    assert entry.policy_version == report.policy_version


def test_monitor_mode_audits_without_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shadow mode lets threats and RBAC denials through but audits them."""
    monkeypatch.setattr(settings, "policy_mode", "monitor")
    engine = PolicyEngine(PolicyDocument(rules=[PolicyRule(deny_tools=["run"])]))
    firewall = _firewall(tmp_path, engine)
    secret = "sk-" + "s" * 24
    report = firewall.inspect(_call({"cmd": DESTRUCTIVE, "token": secret}))
    assert report.allowed is True
    assert report.decision == "SANITIZED"
    assert report.would_block is True
    assert report.policy_mode == "monitor"
    assert "command_injection" in report.violations
    assert RBAC_VIOLATION in report.violations
    assert report.sanitized_arguments["token"] == "[REDACTED_SECRET]"
    entry = firewall.list_audit_entries()[0]
    assert (entry.decision, entry.would_block, entry.policy_mode) == (
        "SANITIZED",
        True,
        "monitor",
    )
    assert firewall.verify_chain().valid is True


def test_monitor_mode_benign_call_is_not_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Benign calls in monitor mode carry would_block=False."""
    monkeypatch.setattr(settings, "policy_mode", "monitor")
    report = _firewall(tmp_path).inspect(_call())
    assert (report.decision, report.would_block) == ("ALLOWED", False)


def test_http_monitor_mode_counts_shadow_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The inspect endpoint exports aegis_mcp_shadow_would_block_total."""
    monkeypatch.setattr(settings, "policy_mode", "monitor")
    res = client.post(
        "/api/v1/mcp/inspect",
        json={"server_name": "shell-mcp", "tool_name": "run", "arguments": {}},
    )
    assert res.json()["would_block"] is False
    res = client.post(
        "/api/v1/mcp/inspect",
        json={
            "server_name": "shell-mcp",
            "tool_name": "run",
            "arguments": {"cmd": DESTRUCTIVE},
        },
    )
    body = res.json()
    assert (body["allowed"], body["would_block"]) == (True, True)
    metrics = client.get("/metrics").text
    assert 'aegis_mcp_shadow_would_block_total{server="shell-mcp"} 1.0' in metrics


def test_policy_status_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """GET /api/v1/policies/status reports version, mode, and fail-closed."""
    monkeypatch.setattr(settings, "api_key", ADMIN_KEY)
    res = client.get("/api/v1/policies/status", headers={"X-API-Key": ADMIN_KEY})
    assert res.status_code == 200
    assert res.json() == {
        "policy_version": policy_engine.version,
        "policy_mode": "enforce",
        "environment": settings.environment,
        "fail_closed": False,
    }
    assert client.get("/api/v1/policies/status").status_code == 401


def test_legacy_ledger_is_migrated_and_still_verifies(tmp_path: Path) -> None:
    """Pre-v0.2 ledgers gain the new columns without breaking the chain."""
    db_path = tmp_path / "legacy.db"
    ts = "2026-11-01T00:00:00+00:00"
    entry_hash = compute_entry_hash(GENESIS_HASH, ts, "a", "s", "t", "ALLOWED", 0)
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE audit_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT NOT NULL,
                server_name TEXT NOT NULL, tool_name TEXT NOT NULL,
                environment TEXT NOT NULL, decision TEXT NOT NULL,
                risk_score INTEGER NOT NULL, violations_json TEXT NOT NULL,
                redacted_json TEXT NOT NULL, prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL, timestamp TEXT NOT NULL)
            """)
        conn.execute(
            "INSERT INTO audit_ledger (agent_id, server_name, tool_name, "
            "environment, decision, risk_score, violations_json, redacted_json, "
            "prev_hash, entry_hash, timestamp) VALUES "
            "('a', 's', 't', 'dev', 'ALLOWED', 0, '[]', '[]', ?, ?, ?)",
            (GENESIS_HASH, entry_hash, ts),
        )
    firewall = MCPFirewall(db_path=str(db_path), policy_engine=PolicyEngine())
    firewall._init_db()
    legacy = firewall.list_audit_entries()[0]
    assert (legacy.policy_version, legacy.policy_mode) == ("", "enforce")
    firewall.inspect(_call())
    assert firewall.verify_chain().valid is True
