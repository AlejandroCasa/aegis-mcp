"""TDD suite for behavioral rate limiting and exfiltration velocity detection."""

import json
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import settings
from app.firewall import MCPFirewall, limiter_config_from_settings
from app.jsonrpc import POLICY_BLOCKED
from app.main import app, firewall, jsonrpc_gateway, mcp_transport, policy_engine
from app.metrics import metrics_registry
from app.policy import PolicyEngine, parse_policy_yaml
from app.rate_limit import (
    RATE_LIMIT_RISK_SCORE,
    RATE_LIMIT_VIOLATION,
    VELOCITY_RISK_SCORE,
    VELOCITY_VIOLATION,
    BehaviorRateLimiter,
    LimiterConfig,
    RateScope,
    is_sensitive_read,
    match_rule,
)
from app.schemas import (
    MCPToolCallRequest,
    PolicyDocument,
    TokenBucketLimit,
    ToolRateLimit,
    VelocityLimit,
)
from app.webhooks import Incident

client = TestClient(app)

UPSTREAM_URL = "http://files-mcp.internal:9000/mcp"
EMPTY = PolicyDocument()


class Clock:
    """Deterministic monotonic clock."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _config(
    capacity: float = 3,
    refill: float = 1.0,
    window: float = 60.0,
    max_reads: int = 2,
    enabled: bool = True,
    max_keys: int = 100,
) -> LimiterConfig:
    return LimiterConfig(
        enabled=enabled,
        bucket=TokenBucketLimit(capacity=capacity, refill_per_sec=refill),
        velocity=VelocityLimit(window_seconds=window, max_reads=max_reads),
        max_keys=max_keys,
    )


def _scope(
    tool: str = "git_status",
    agent: str = "agent-1",
    server: str = "tools",
    session: str = "s1",
    environment: str = "prod",
) -> RateScope:
    return RateScope(agent, server, tool, environment, session)


def _request(
    tool: str = "git_status", agent: str = "agent-1", session: str = "s1"
) -> MCPToolCallRequest:
    return MCPToolCallRequest(
        agent_id=agent,
        server_name="tools",
        tool_name=tool,
        arguments={"path": "README.md"},
        environment="prod",
        session_id=session,
    )


@pytest.fixture(autouse=True)
def clean_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Isolate settings, ledger, limiter and gateway state per test."""
    original_client = jsonrpc_gateway.client
    original_limiter = firewall.rate_limiter
    monkeypatch.setattr(settings, "api_key", None)
    monkeypatch.setattr(settings, "policy_mode", "enforce")
    monkeypatch.setattr(jsonrpc_gateway.toolguard, "require_approval", False)
    firewall.reset()
    jsonrpc_gateway.toolguard.reset()
    metrics_registry.reset()
    policy_engine.reset()
    mcp_transport.sessions.clear()
    yield
    firewall.rate_limiter = original_limiter
    jsonrpc_gateway.client = original_client
    jsonrpc_gateway.set_upstreams({})
    jsonrpc_gateway.toolguard.reset()
    mcp_transport.sessions.clear()
    policy_engine.reset()
    firewall.reset()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def fw(tmp_path: Path, clock: Clock) -> Iterator[MCPFirewall]:
    instance = MCPFirewall(
        db_path=str(tmp_path / "ledger.db"),
        policy_engine=PolicyEngine(),
        rate_limiter=BehaviorRateLimiter(_config(), clock),
    )
    yield instance
    instance.close()


# -- Token bucket ------------------------------------------------------------


def test_token_bucket_exhausts_then_refills(clock: Clock) -> None:
    """A burst beyond capacity is denied until tokens refill."""
    limiter = BehaviorRateLimiter(_config(capacity=3, refill=1.0), clock)
    verdicts = [limiter.check(EMPTY, _scope()) for _ in range(4)]
    assert [v.blocking for v in verdicts] == [False, False, False, True]
    assert verdicts[-1].violations == (RATE_LIMIT_VIOLATION,)
    assert verdicts[-1].risk_score == RATE_LIMIT_RISK_SCORE
    clock.now += 0.5
    assert limiter.check(EMPTY, _scope()).blocking
    clock.now += 0.5
    assert not limiter.check(EMPTY, _scope()).blocking
    clock.now += 100  # refill is capped at capacity
    burst = [limiter.check(EMPTY, _scope()).blocking for _ in range(4)]
    assert burst == [False, False, False, True]


def test_token_bucket_is_keyed_per_agent_server_tool(clock: Clock) -> None:
    """Exhausting one key leaves other agents, servers and tools untouched."""
    limiter = BehaviorRateLimiter(_config(capacity=1, refill=0.0), clock)
    assert not limiter.check(EMPTY, _scope()).blocking
    assert limiter.check(EMPTY, _scope()).blocking
    assert not limiter.check(EMPTY, _scope(agent="agent-2")).blocking
    assert not limiter.check(EMPTY, _scope(server="other")).blocking
    assert not limiter.check(EMPTY, _scope(tool="git_log")).blocking
    # The bucket spans sessions: rotating session ids does not reset it.
    assert limiter.check(EMPTY, _scope(session="new-session")).blocking


def test_clock_regression_never_mints_tokens(clock: Clock) -> None:
    """A clock that goes backwards does not refill (no negative elapsed)."""
    limiter = BehaviorRateLimiter(_config(capacity=1, refill=10.0), clock)
    limiter.check(EMPTY, _scope())
    clock.now -= 50
    assert limiter.check(EMPTY, _scope()).blocking


def test_disabled_limiter_never_blocks(clock: Clock) -> None:
    """``AEGIS_RATE_LIMIT_ENABLED=false`` turns both detectors off."""
    limiter = BehaviorRateLimiter(_config(capacity=1, enabled=False), clock)
    verdicts = [limiter.check(EMPTY, _scope("resources/read")) for _ in range(10)]
    assert not any(v.blocking for v in verdicts)
    assert limiter.stats().tracked_buckets == 0
    assert limiter.stats().enabled is False


# -- Exfiltration velocity ---------------------------------------------------


@pytest.mark.parametrize(
    "tool",
    [
        "resources/read",
        "query_db",
        "Query_Orders",
        "read_file",
        "run_sql",
        "db_select",
        "orders_query",
        "export_table",
        "get_customer",
    ],
)
def test_sensitive_read_heuristics(tool: str) -> None:
    """Built-in name heuristics flag data-harvesting reads (case-insensitive)."""
    assert is_sensitive_read(None, tool)


@pytest.mark.parametrize("tool", ["git_status", "send_email", "tools/list", "Read"])
def test_non_sensitive_tools(tool: str) -> None:
    assert not is_sensitive_read(None, tool)


def test_velocity_burst_is_detected_within_window(clock: Clock) -> None:
    """More than ``max_reads`` sensitive reads per window is an anomaly."""
    limiter = BehaviorRateLimiter(
        _config(capacity=100, window=10.0, max_reads=3), clock
    )
    tools = ["resources/read", "query_db", "read_file", "resources/read"]
    verdicts = [limiter.check(EMPTY, _scope(tool)) for tool in tools]
    assert [v.blocking for v in verdicts] == [False, False, False, True]
    assert verdicts[-1].violations == (VELOCITY_VIOLATION,)
    assert verdicts[-1].risk_score == VELOCITY_RISK_SCORE
    # Non-sensitive tools are never counted.
    assert not limiter.check(EMPTY, _scope("git_status")).blocking
    # The sliding window frees capacity as old reads age out.
    clock.now += 10.0
    assert not limiter.check(EMPTY, _scope("resources/read")).blocking


def test_velocity_window_slides_per_read(clock: Clock) -> None:
    """Reads expire individually, not in fixed buckets."""
    limiter = BehaviorRateLimiter(
        _config(capacity=100, window=10.0, max_reads=2), clock
    )
    limiter.check(EMPTY, _scope("query_db"))
    clock.now += 6
    limiter.check(EMPTY, _scope("query_db"))
    assert limiter.check(EMPTY, _scope("query_db")).blocking
    clock.now += 4.5  # first read expired, second still live
    assert not limiter.check(EMPTY, _scope("query_db")).blocking
    assert limiter.check(EMPTY, _scope("query_db")).blocking


def test_velocity_is_keyed_per_session_and_agent(clock: Clock) -> None:
    """Separate sessions and agents get separate windows."""
    limiter = BehaviorRateLimiter(_config(capacity=100, max_reads=1), clock)
    assert not limiter.check(EMPTY, _scope("query_db")).blocking
    assert limiter.check(EMPTY, _scope("query_db")).blocking
    assert not limiter.check(EMPTY, _scope("query_db", session="s2")).blocking
    assert not limiter.check(EMPTY, _scope("query_db", agent="agent-2")).blocking


def test_sessionless_reads_share_one_agent_window(clock: Clock) -> None:
    """Dropping the session id cannot be used to dodge velocity accounting."""
    limiter = BehaviorRateLimiter(_config(capacity=100, max_reads=1), clock)
    assert not limiter.check(EMPTY, _scope("query_db", session="")).blocking
    assert limiter.check(EMPTY, _scope("query_db", session="")).blocking


def test_both_detectors_report_highest_risk(clock: Clock) -> None:
    limiter = BehaviorRateLimiter(_config(capacity=1, refill=0, max_reads=1), clock)
    limiter.check(EMPTY, _scope("query_db"))
    verdict = limiter.check(EMPTY, _scope("query_db"))
    assert verdict.violations == (RATE_LIMIT_VIOLATION, VELOCITY_VIOLATION)
    assert verdict.risk_score == VELOCITY_RISK_SCORE


# -- Bounded memory / thread safety -----------------------------------------


def test_state_is_lru_bounded(clock: Clock) -> None:
    """Bucket and window maps never exceed ``max_keys`` (LRU eviction)."""
    limiter = BehaviorRateLimiter(_config(max_keys=5), clock)
    for index in range(50):
        limiter.check(EMPTY, _scope("query_db", agent=f"a{index}", session=""))
    stats = limiter.stats()
    assert stats.tracked_buckets == 5
    assert stats.tracked_sessions == 5


def test_velocity_window_holds_at_most_max_reads(clock: Clock) -> None:
    """Anomalous reads are not recorded, bounding each window."""
    limiter = BehaviorRateLimiter(_config(capacity=10**6, max_reads=4), clock)
    for _ in range(200):
        limiter.check(EMPTY, _scope("query_db"))
    assert len(limiter._windows[("s1", "agent-1")]) == 4


def test_concurrent_checks_never_overspend_tokens() -> None:
    """Under contention exactly ``capacity`` calls are admitted."""
    limiter = BehaviorRateLimiter(_config(capacity=50, refill=0.0))
    admitted: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(25):
            ok = not limiter.check(EMPTY, _scope()).blocking
            with lock:
                admitted.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(admitted) == 50
    assert limiter.stats().rate_limited_total == 150


# -- Policy overrides --------------------------------------------------------

OVERRIDE_POLICY = """
rate_limits:
  - server_name: files-*
    tool_name: bulk_*
    environments: [prod]
    rate_limit: {capacity: 1, refill_per_sec: 0}
  - tool_name: list_tables
    velocity_limit: {window_seconds: 30, max_reads: 1}
  - tool_name: query_metrics
    sensitive_read: false
  - tool_name: dump_cache
    sensitive_read: false
    velocity_limit: {window_seconds: 30, max_reads: 1}
"""


def test_policy_yaml_overrides_bucket_and_velocity(clock: Clock) -> None:
    """Declarative ``rate_limits`` replace the defaults (first match wins)."""
    document = parse_policy_yaml(OVERRIDE_POLICY)
    limiter = BehaviorRateLimiter(_config(capacity=100, max_reads=100), clock)
    bulk = _scope("bulk_export", server="files-mcp")
    assert not limiter.check(document, bulk).blocking
    assert limiter.check(document, bulk).violations == (RATE_LIMIT_VIOLATION,)
    # Same tool in another environment falls back to the defaults.
    dev = _scope("bulk_export", agent="a2", server="files-mcp", environment="dev")
    assert not limiter.check(document, dev).blocking
    assert not limiter.check(document, dev).blocking
    # A velocity_limit marks an otherwise benign tool as a sensitive read.
    assert not limiter.check(document, _scope("list_tables")).blocking
    assert limiter.check(document, _scope("list_tables")).violations == (
        VELOCITY_VIOLATION,
    )


def test_policy_can_exempt_sensitive_reads(clock: Clock) -> None:
    """``sensitive_read: false`` overrides the heuristics and velocity rules."""
    document = parse_policy_yaml(OVERRIDE_POLICY)
    limiter = BehaviorRateLimiter(_config(capacity=100, max_reads=1), clock)
    for tool in ("query_metrics", "dump_cache"):
        verdicts = [limiter.check(document, _scope(tool)) for _ in range(5)]
        assert not any(v.blocking for v in verdicts)
    assert match_rule(document, _scope("unrelated")) is None


def test_policy_override_validation() -> None:
    """Limits are bounded and unknown keys are rejected."""
    with pytest.raises(ValidationError):
        ToolRateLimit.model_validate({"rate_limit": {"capacity": 0}})
    with pytest.raises(ValidationError):
        VelocityLimit(window_seconds=10, max_reads=10**6)
    with pytest.raises(ValidationError):
        PolicyDocument.model_validate({"rate_limits": [{"bogus": True}]})


# -- Firewall integration ----------------------------------------------------


def test_firewall_blocks_rate_limited_calls_and_ledgers_them(
    fw: MCPFirewall,
) -> None:
    """Exhaustion is BLOCKED (risk 75) and hash-chained in the audit ledger."""
    reports = [fw.inspect(_request()) for _ in range(4)]
    assert [r.decision for r in reports] == ["ALLOWED"] * 3 + ["BLOCKED"]
    blocked = reports[-1]
    assert not blocked.allowed
    assert blocked.risk_score == RATE_LIMIT_RISK_SCORE
    assert blocked.violations == [RATE_LIMIT_VIOLATION]
    assert blocked.sanitized_arguments == {}
    entry = fw.list_audit_entries()[-1]
    assert entry.decision == "BLOCKED"
    assert entry.violations == [RATE_LIMIT_VIOLATION]
    assert fw.verify_chain().valid
    exposition = metrics_registry.generate_prometheus_exposition()
    assert (
        'aegis_mcp_rate_anomalies_total{kind="rate_limit_exceeded",'
        'mode="enforce"} 1.0'
    ) in exposition


def test_firewall_velocity_anomaly_blocks_and_fires_webhook(
    fw: MCPFirewall, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read burst is BLOCKED (risk 90) and announced as an incident."""
    incidents: list[Incident] = []
    monkeypatch.setattr(fw.webhooks, "notify_incident", incidents.append)
    reports = [fw.inspect(_request("resources/read")) for _ in range(3)]
    assert [r.allowed for r in reports] == [True, True, False]
    assert reports[-1].violations == [VELOCITY_VIOLATION]
    assert reports[-1].risk_score >= 85
    assert len(incidents) == 1
    assert incidents[0].violations == (VELOCITY_VIOLATION,)
    assert incidents[0].risk_score == VELOCITY_RISK_SCORE


def test_monitor_mode_sets_would_block_and_still_alerts(
    fw: MCPFirewall, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shadow mode lets the burst through but audits ``would_block``."""
    monkeypatch.setattr(settings, "policy_mode", "monitor")
    incidents: list[Incident] = []
    monkeypatch.setattr(fw.webhooks, "notify_incident", incidents.append)
    reports = [fw.inspect(_request("query_db")) for _ in range(4)]
    assert all(r.allowed for r in reports)
    assert [r.would_block for r in reports] == [False, False, True, True]
    assert reports[-1].decision == "ALLOWED"
    assert set(reports[-1].violations) == {RATE_LIMIT_VIOLATION, VELOCITY_VIOLATION}
    entry = fw.list_audit_entries()[-1]
    assert entry.would_block and entry.policy_mode == "monitor"
    assert len(incidents) == 2
    exposition = metrics_registry.generate_prometheus_exposition()
    assert (
        'aegis_mcp_rate_anomalies_total{kind="exfiltration_velocity_anomaly",'
        'mode="monitor"} 2.0'
    ) in exposition
    assert (
        'aegis_mcp_rate_anomalies_total{kind="rate_limit_exceeded",'
        'mode="monitor"} 1.0'
    ) in exposition


def test_rate_limited_call_never_opens_hitl_request(tmp_path: Path) -> None:
    """A rate-limited ``require_approval`` call is blocked, not queued."""
    document = PolicyDocument.model_validate(
        {
            "rules": [
                {
                    "agent_id": "*",
                    "server_name": "*",
                    "require_approval_tools": ["deploy"],
                }
            ]
        }
    )
    fw = MCPFirewall(
        db_path=str(tmp_path / "ledger.db"),
        policy_engine=PolicyEngine(document),
        rate_limiter=BehaviorRateLimiter(_config(capacity=1, refill=0)),
    )
    fw.inspect(_request("deploy"))
    pending = len(fw.approvals.list_requests())
    report = fw.inspect(_request("deploy"))
    assert report.decision == "BLOCKED"
    assert RATE_LIMIT_VIOLATION in report.violations
    assert len(fw.approvals.list_requests()) == pending
    fw.close()


def test_reset_isolates_limiter_state(fw: MCPFirewall) -> None:
    """``MCPFirewall.reset()`` clears buckets, windows and counters."""
    for _ in range(5):
        fw.inspect(_request("query_db"))
    stats = fw.rate_limiter.stats()
    assert stats.rate_limited_total == 2
    assert stats.velocity_anomalies_total == 3
    fw.reset()
    stats = fw.rate_limiter.stats()
    assert (stats.tracked_buckets, stats.tracked_sessions) == (0, 0)
    assert (stats.rate_limited_total, stats.velocity_anomalies_total) == (0, 0)
    assert fw.inspect(_request("query_db")).allowed


def test_metrics_reject_unknown_anomaly_kind() -> None:
    with pytest.raises(ValueError, match="Unknown rate anomaly kind"):
        metrics_registry.record_rate_anomaly("bogus", True)


def test_default_settings_build_limiter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings map onto the limiter defaults."""
    monkeypatch.setattr(settings, "rate_limit_capacity", 7.0)
    monkeypatch.setattr(settings, "velocity_max_reads", 9)
    config = limiter_config_from_settings()
    assert config.enabled is settings.rate_limit_enabled
    assert config.bucket.capacity == 7.0
    assert config.velocity.max_reads == 9


def test_default_limits_tolerate_normal_bursts(tmp_path: Path) -> None:
    """Out-of-the-box limits leave room for ordinary agent activity."""
    fw = MCPFirewall(db_path=str(tmp_path / "ledger.db"), policy_engine=PolicyEngine())
    reports = [fw.inspect(_request("read_file")) for _ in range(20)]
    assert all(r.allowed for r in reports)
    fw.close()


# -- HTTP / JSON-RPC / Streamable HTTP integration ---------------------------


def test_stats_endpoint(monkeypatch: pytest.MonkeyPatch, clock: Clock) -> None:
    """``GET /api/v1/rate-limits/stats`` exposes limiter state (authenticated)."""
    firewall.rate_limiter = BehaviorRateLimiter(_config(capacity=1), clock)
    body = _request().model_dump(mode="json")
    headers = {"X-Aegis-Agent-Id": "agent-1"}
    first = client.post("/api/v1/mcp/inspect", json=body, headers=headers).json()
    assert first["allowed"]
    blocked = client.post("/api/v1/mcp/inspect", json=body, headers=headers).json()
    assert blocked["violations"] == [RATE_LIMIT_VIOLATION]
    stats = client.get("/api/v1/rate-limits/stats").json()
    assert stats["enabled"] is True
    assert stats["tracked_buckets"] == 1
    assert stats["rate_limited_total"] == 1
    monkeypatch.setattr(settings, "api_key", "k" * 32)
    assert client.get("/api/v1/rate-limits/stats").status_code == 401


def _upstream(request: httpx.Request) -> httpx.Response:
    body: dict[str, Any] = json.loads(request.content)
    result: dict[str, Any] = {"contents": [{"uri": "repo://x", "text": "row"}]}
    if body.get("method") == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "files"},
            "capabilities": {},
        }
    return httpx.Response(
        200, json={"jsonrpc": "2.0", "id": body.get("id"), "result": result}
    )


def _wire_upstream(clock: Clock) -> None:
    firewall.rate_limiter = BehaviorRateLimiter(
        _config(capacity=100, max_reads=2), clock
    )
    jsonrpc_gateway.set_upstreams({"files-mcp": UPSTREAM_URL})
    jsonrpc_gateway.client = httpx.Client(transport=httpx.MockTransport(_upstream))


def _read(req_id: int) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "resources/read",
        "params": {"uri": f"repo://customers/{req_id}"},
    }


def test_jsonrpc_resources_read_burst_is_blocked(clock: Clock) -> None:
    """``resources/read`` over the JSON-RPC proxy is velocity-accounted."""
    _wire_upstream(clock)
    headers = {"X-Aegis-Agent-Id": "harvester", "X-Aegis-MCP-Server": "files-mcp"}
    bodies = [
        client.post("/api/v1/mcp/jsonrpc", json=_read(i), headers=headers).json()
        for i in range(3)
    ]
    assert "result" in bodies[0] and "result" in bodies[1]
    error = bodies[2]["error"]
    assert error["code"] == POLICY_BLOCKED
    assert error["data"]["violations"] == [VELOCITY_VIOLATION]
    assert firewall.list_audit_entries()[-1].tool_name == "resources/read"


def test_streamable_http_resources_read_burst_is_blocked(clock: Clock) -> None:
    """``/mcp`` reads count against the gateway session's velocity window."""
    _wire_upstream(clock)
    headers = {
        "X-Aegis-Agent-Id": "harvester",
        "X-Aegis-MCP-Server": "files-mcp",
        "Accept": "application/json, text/event-stream",
    }
    init = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"},
        },
    }
    session = client.post("/mcp", json=init, headers=headers).headers["mcp-session-id"]
    headers["Mcp-Session-Id"] = session
    bodies = [
        client.post("/mcp", json=_read(i), headers=headers).json() for i in (1, 2, 3)
    ]
    assert "result" in bodies[0] and "result" in bodies[1]
    assert bodies[2]["error"]["data"]["violations"] == [VELOCITY_VIOLATION]
    entry = firewall.list_audit_entries()[-1]
    assert entry.session_id == session
    assert entry.decision == "BLOCKED"
    assert firewall.rate_limiter.stats().tracked_sessions == 1
