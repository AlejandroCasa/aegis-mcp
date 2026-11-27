"""TDD suite for the declarative per-agent / per-server RBAC policy matrix."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import settings
from app.firewall import MCPFirewall
from app.main import app, firewall, policy_engine
from app.metrics import metrics_registry
from app.policy import (
    MAX_POLICY_FILE_BYTES,
    RBAC_VIOLATION,
    PolicyEngine,
    PolicyLoadError,
    load_policy_file,
    parse_policy_yaml,
)
from app.schemas import MCPToolCallRequest, PolicyDocument, PolicyRule

client = TestClient(app)

ADMIN_KEY = "test-admin-key"

MATRIX_YAML = """
default_action: deny
rules:
  - agent_id: "coder-*"
    server_name: git-mcp
    environments: [dev, staging, prod]
    allow_tools: ["git_status", "git_diff", "git_log"]
  - agent_id: "coder-*"
    server_name: git-mcp
    environments: [dev]
    allow_tools: ["git_commit"]
  - agent_id: "*"
    server_name: postgres-mcp
    allow_tools: ["*"]
    deny_tools: ["drop_*", "admin_*"]
"""


@pytest.fixture(autouse=True)
def clean_state() -> Iterator[None]:
    """Reset ledger, metrics, settings, and the policy engine for each test."""
    firewall.reset()
    metrics_registry.reset()
    settings.api_key = None
    settings.block_threshold_score = 70
    settings.enable_dlp_redaction = True
    policy_engine.reset()
    yield
    policy_engine.reset()
    settings.api_key = None


def _matrix_engine() -> PolicyEngine:
    engine = PolicyEngine()
    engine.load(parse_policy_yaml(MATRIX_YAML))
    return engine


# ---------------------------------------------------------------------------
# Pure policy evaluation
# ---------------------------------------------------------------------------


def test_default_engine_is_permissive_for_backward_compatibility() -> None:
    """With no policy configured, every tool call is authorized."""
    engine = PolicyEngine()
    assert engine.document.default_action == "allow"
    assert engine.document.rules == []
    assert engine.is_allowed("any-agent", "any-server", "any_tool", "prod") is True


def test_allowlist_grants_only_listed_tools() -> None:
    """Matching allowlist rules authorize listed tools and deny everything else."""
    engine = _matrix_engine()
    assert engine.is_allowed("coder-1", "git-mcp", "git_status", "prod") is True
    assert engine.is_allowed("coder-1", "git-mcp", "git_push", "prod") is False


def test_environment_scoping_restricts_write_tools_to_dev() -> None:
    """Write tools granted only in dev are denied in staging and prod."""
    engine = _matrix_engine()
    assert engine.is_allowed("coder-1", "git-mcp", "git_commit", "dev") is True
    assert engine.is_allowed("coder-1", "git-mcp", "git_commit", "staging") is False
    assert engine.is_allowed("coder-1", "git-mcp", "git_commit", "prod") is False


def test_deny_overrides_allow_wildcard() -> None:
    """A denylist match wins over any allowlist match (deny-overrides)."""
    engine = _matrix_engine()
    assert engine.is_allowed("analyst", "postgres-mcp", "query_db", "prod") is True
    assert engine.is_allowed("analyst", "postgres-mcp", "drop_table", "prod") is False
    assert engine.is_allowed("analyst", "postgres-mcp", "admin_grant", "dev") is False


def test_unmatched_agent_falls_back_to_default_action() -> None:
    """Untrusted agents with no matching rule get the default deny."""
    engine = _matrix_engine()
    assert engine.is_allowed("rogue-agent", "git-mcp", "git_status", "dev") is False
    assert engine.is_allowed("coder-1", "filesystem-mcp", "read_file", "dev") is False


def test_deny_only_rule_defers_to_default_allow() -> None:
    """Rules with only a denylist block listed tools and defer the rest."""
    engine = PolicyEngine()
    engine.load(
        PolicyDocument(
            default_action="allow",
            rules=[PolicyRule(server_name="filesystem-mcp", deny_tools=["write_*"])],
        )
    )
    assert engine.is_allowed("a", "filesystem-mcp", "read_file", "prod") is True
    assert engine.is_allowed("a", "filesystem-mcp", "write_file", "prod") is False
    assert engine.is_allowed("a", "git-mcp", "write_file", "prod") is True


def test_glob_matching_is_case_sensitive() -> None:
    """Identifiers are matched case-sensitively to prevent casing bypass tricks."""
    engine = _matrix_engine()
    assert engine.is_allowed("CODER-1", "git-mcp", "git_status", "dev") is False
    assert engine.is_allowed("coder-1", "git-mcp", "GIT_STATUS", "dev") is False


def test_reset_restores_permissive_default() -> None:
    """reset() discards the loaded matrix."""
    engine = _matrix_engine()
    engine.reset()
    assert engine.is_allowed("rogue-agent", "git-mcp", "git_push", "prod") is True


# ---------------------------------------------------------------------------
# YAML loader and schema validation
# ---------------------------------------------------------------------------


def test_parse_policy_yaml_builds_validated_document() -> None:
    """YAML is parsed into a strongly-typed PolicyDocument."""
    doc = parse_policy_yaml(MATRIX_YAML)
    assert doc.default_action == "deny"
    assert len(doc.rules) == 3
    assert doc.rules[2].environments == ["dev", "staging", "prod"]


@pytest.mark.parametrize(
    "bad_yaml",
    [
        "rules: [unterminated",
        "- just\n- a\n- list\n",
        "default_action: maybe\n",
        "rules:\n  - agent_id: x\n    unknown_field: 1\n",
        "rules:\n  - environments: [qa]\n    deny_tools: [x]\n",
        "rules:\n  - environments: []\n    deny_tools: [x]\n",
        "rules:\n  - agent_id: noop\n",
        "!!python/object/apply:os.system ['id']",
    ],
)
def test_parse_policy_yaml_rejects_invalid_documents(bad_yaml: str) -> None:
    """Malformed, unsafe, or schema-violating YAML raises PolicyLoadError."""
    with pytest.raises(PolicyLoadError):
        parse_policy_yaml(bad_yaml)


def test_empty_yaml_document_yields_permissive_default() -> None:
    """An empty YAML file is equivalent to the permissive default policy."""
    doc = parse_policy_yaml("")
    assert doc.default_action == "allow"
    assert doc.rules == []


def test_load_policy_file_reads_yaml_from_disk(tmp_path: Path) -> None:
    """Policies can be loaded from a YAML file on disk."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(MATRIX_YAML, encoding="utf-8")
    doc = load_policy_file(policy_file)
    assert doc.default_action == "deny"


def test_load_policy_file_missing_path_fails_closed(tmp_path: Path) -> None:
    """A missing policy file raises instead of silently allowing everything."""
    with pytest.raises(PolicyLoadError):
        load_policy_file(tmp_path / "missing.yaml")


def test_load_policy_file_rejects_oversized_file(tmp_path: Path) -> None:
    """Policy files above MAX_POLICY_FILE_BYTES are rejected before parsing."""
    policy_file = tmp_path / "huge.yaml"
    policy_file.write_text("#" * (MAX_POLICY_FILE_BYTES + 1), encoding="utf-8")
    with pytest.raises(PolicyLoadError, match="exceeds"):
        load_policy_file(policy_file)


def test_engine_from_settings_path(tmp_path: Path) -> None:
    """PolicyEngine.from_path loads the configured matrix, or default if None."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(MATRIX_YAML, encoding="utf-8")
    assert PolicyEngine.from_path(str(policy_file)).document.default_action == "deny"
    assert PolicyEngine.from_path(None).document.default_action == "allow"


def test_rule_field_lengths_are_bounded() -> None:
    """Oversized identifiers are rejected by schema validation."""
    with pytest.raises(ValidationError):
        PolicyRule(agent_id="a" * 1000, deny_tools=["x"])


def test_request_identifiers_are_bounded() -> None:
    """Oversized request identifiers never reach the glob matcher."""
    with pytest.raises(ValidationError):
        MCPToolCallRequest(server_name="s", tool_name="a" * 100_000)


def test_load_policy_file_rejects_non_utf8(tmp_path: Path) -> None:
    """Undecodable policy files fail closed."""
    policy_file = tmp_path / "bad.yaml"
    policy_file.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(PolicyLoadError, match="UTF-8"):
        load_policy_file(policy_file)


# ---------------------------------------------------------------------------
# Firewall integration
# ---------------------------------------------------------------------------


def _request(
    tool: str, env: str = "prod", agent: str = "coder-1"
) -> MCPToolCallRequest:
    return MCPToolCallRequest.model_validate(
        {
            "agent_id": agent,
            "server_name": "git-mcp",
            "tool_name": tool,
            "environment": env,
            "arguments": {"repo": "/workspace"},
        }
    )


def test_firewall_blocks_rbac_denied_calls(tmp_path: Path) -> None:
    """Unauthorized tools are BLOCKED with the rbac_policy_denied violation."""
    fw = MCPFirewall(db_path=str(tmp_path / "a.db"), policy_engine=_matrix_engine())
    report = fw.inspect(_request("git_push"))
    assert report.allowed is False
    assert report.decision == "BLOCKED"
    assert report.violations == [RBAC_VIOLATION]
    assert report.risk_score == 100
    assert report.sanitized_arguments == {}
    entries = fw.list_audit_entries()
    assert entries[0].decision == "BLOCKED"
    assert entries[0].violations == [RBAC_VIOLATION]
    assert fw.verify_chain().valid is True


def test_firewall_allows_authorized_calls(tmp_path: Path) -> None:
    """Authorized tools still flow through threat rules and DLP as before."""
    fw = MCPFirewall(db_path=str(tmp_path / "b.db"), policy_engine=_matrix_engine())
    report = fw.inspect(_request("git_commit", env="dev"))
    assert report.allowed is True
    assert report.decision == "ALLOWED"
    assert RBAC_VIOLATION not in report.violations


def test_firewall_combines_rbac_with_threat_violations(tmp_path: Path) -> None:
    """RBAC denial is reported alongside content-based threat violations."""
    fw = MCPFirewall(db_path=str(tmp_path / "c.db"), policy_engine=_matrix_engine())
    req = _request("git_push")
    req.arguments = {"cmd": "rm -rf /"}
    report = fw.inspect(req)
    assert report.decision == "BLOCKED"
    assert report.violations == ["command_injection", RBAC_VIOLATION]


def test_firewall_default_engine_preserves_legacy_behavior(tmp_path: Path) -> None:
    """A firewall without an explicit engine behaves exactly as before RBAC."""
    fw = MCPFirewall(db_path=str(tmp_path / "d.db"))
    report = fw.inspect(_request("anything_goes"))
    assert report.decision == "ALLOWED"
    assert report.risk_score == 0


# ---------------------------------------------------------------------------
# HTTP API: GET / POST /api/v1/policies
# ---------------------------------------------------------------------------

API_MATRIX = {
    "default_action": "deny",
    "rules": [
        {
            "agent_id": "coder-*",
            "server_name": "git-mcp",
            "environments": ["prod"],
            "allow_tools": ["git_status"],
        }
    ],
}


def test_get_policies_returns_active_matrix() -> None:
    """GET /api/v1/policies returns the permissive default to an admin."""
    settings.api_key = ADMIN_KEY
    res = client.get("/api/v1/policies", headers={"X-API-Key": ADMIN_KEY})
    assert res.status_code == 200
    assert res.json() == {
        "default_action": "allow",
        "rules": [],
        "tool_constraints": [],
        "taint_rules": [],
        "rate_limits": [],
    }


def test_get_policies_requires_admin_key() -> None:
    """The matrix is not disclosed when no admin key is configured or supplied."""
    assert client.get("/api/v1/policies").status_code == 403
    settings.api_key = ADMIN_KEY
    assert client.get("/api/v1/policies").status_code == 401


def test_post_policies_requires_configured_api_key() -> None:
    """Policy mutation is refused when no admin API key is configured."""
    res = client.post("/api/v1/policies", json=API_MATRIX)
    assert res.status_code == 403
    assert policy_engine.document.default_action == "allow"


def test_post_policies_rejects_wrong_api_key() -> None:
    """Policy mutation with an invalid key is rejected with 401."""
    settings.api_key = ADMIN_KEY
    res = client.post(
        "/api/v1/policies", json=API_MATRIX, headers={"X-API-Key": "wrong"}
    )
    assert res.status_code == 401
    assert policy_engine.document.default_action == "allow"


def test_post_policies_validates_schema() -> None:
    """Invalid policy documents are rejected with 422 and not applied."""
    settings.api_key = ADMIN_KEY
    res = client.post(
        "/api/v1/policies",
        json={"default_action": "maybe", "rules": []},
        headers={"X-API-Key": ADMIN_KEY},
    )
    assert res.status_code == 422
    assert policy_engine.document.default_action == "allow"


def test_post_policies_replaces_matrix_and_enforces_on_inspect() -> None:
    """A posted matrix is returned by GET and enforced by /api/v1/mcp/inspect."""
    settings.api_key = ADMIN_KEY
    headers = {"X-API-Key": ADMIN_KEY}
    res = client.post("/api/v1/policies", json=API_MATRIX, headers=headers)
    assert res.status_code == 200
    assert res.json()["default_action"] == "deny"

    get_res = client.get("/api/v1/policies", headers=headers)
    assert get_res.json()["rules"][0]["allow_tools"] == ["git_status"]

    call = {
        "agent_id": "coder-7",
        "server_name": "git-mcp",
        "environment": "prod",
        "arguments": {},
    }
    ok = client.post(
        "/api/v1/mcp/inspect", json={**call, "tool_name": "git_status"}, headers=headers
    )
    assert ok.json()["decision"] == "ALLOWED"

    denied = client.post(
        "/api/v1/mcp/inspect", json={**call, "tool_name": "git_push"}, headers=headers
    )
    body = denied.json()
    assert body["decision"] == "BLOCKED"
    assert body["violations"] == [RBAC_VIOLATION]

    metrics = client.get("/metrics").text
    assert 'aegis_mcp_blocked_total{rule="rbac_policy_denied"} 1.0' in metrics
