"""TDD suite for toxic-flow session taint tracking (lethal trifecta defense)."""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.firewall import MCPFirewall
from app.jsonrpc import INVALID_REQUEST, POLICY_BLOCKED, JsonRpcError, build_context
from app.main import app, firewall, jsonrpc_gateway, mcp_transport, policy_engine
from app.metrics import metrics_registry
from app.policy import PolicyEngine, parse_policy_yaml, policy_version
from app.schemas import (
    MCPToolCallRequest,
    PolicyDocument,
    TaintLabel,
    ToolTaintRule,
)
from app.streamable import McpSession, SessionStore
from app.taint import (
    TOXIC_FLOW_VIOLATION,
    SessionTaintTracker,
    TaintCall,
    carries_url,
    classify,
    evaluate_flow,
    heuristic_roles,
)

client = TestClient(app)

EMAIL = "alice" + "@" + "example.com"
UPSTREAM_URL = "http://web-mcp.internal:9000/mcp"
HOOK_URL = "https://" + "attacker.example/collect"


class Clock:
    """Deterministic monotonic clock."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture(autouse=True)
def clean_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Isolate settings, ledger, taint, and gateway state per test."""
    original_client = jsonrpc_gateway.client
    monkeypatch.setattr(settings, "api_key", None)
    monkeypatch.setattr(settings, "policy_mode", "enforce")
    monkeypatch.setattr(settings, "enable_dlp_redaction", True)
    monkeypatch.setattr(settings, "enable_taint_tracking", True)
    monkeypatch.setattr(settings, "taint_default_heuristics", True)
    monkeypatch.setattr(jsonrpc_gateway.toolguard, "require_approval", False)
    firewall.reset()
    jsonrpc_gateway.toolguard.reset()
    metrics_registry.reset()
    policy_engine.reset()
    mcp_transport.sessions.clear()
    yield
    jsonrpc_gateway.client = original_client
    jsonrpc_gateway.set_upstreams({})
    jsonrpc_gateway.toolguard.reset()
    mcp_transport.sessions.clear()
    policy_engine.reset()
    firewall.reset()


def _firewall(tmp_path: Path, document: PolicyDocument | None = None) -> MCPFirewall:
    return MCPFirewall(
        db_path=str(tmp_path / "ledger.db"), policy_engine=PolicyEngine(document)
    )


def _call(
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    server_name: str = "agent-tools",
    session_id: str = "",
) -> MCPToolCallRequest:
    return MCPToolCallRequest(
        agent_id="agent-1",
        server_name=server_name,
        tool_name=tool_name,
        arguments=arguments or {},
        environment="prod",
        session_id=session_id,
    )


# -- Classification ----------------------------------------------------------


@pytest.mark.parametrize(
    ("server", "tool", "expected"),
    [
        ("tools", "web_search", {"untrusted_content"}),
        ("tools", "Fetch_URL", {"untrusted_content"}),
        ("tools", "get_issue", {"untrusted_content"}),
        ("github-mcp", "list_commits", {"untrusted_content"}),
        ("tools", "query_orders", {"private_data"}),
        ("tools", "resources/read", {"private_data"}),
        ("postgres-mcp", "describe", {"private_data"}),
        ("tools", "SEND_EMAIL", {"egress_sink"}),
        ("mail-mcp", "send_email", {"egress_sink"}),
        ("tools", "git_push", {"egress_sink"}),
        ("tools", "list_dir", set()),
    ],
)
def test_heuristic_roles(server: str, tool: str, expected: set[str]) -> None:
    """Built-in heuristics classify by tool name and (for readers) server."""
    assert heuristic_roles(server, tool) == expected


def test_classify_unions_rules_and_respects_scope_and_heuristics() -> None:
    """Declarative rules union with heuristics; env/glob scope is honored."""
    document = PolicyDocument(
        taint_rules=[
            ToolTaintRule(tool_name="crm_lookup", roles=["private_data"]),
            ToolTaintRule(
                tool_name="notify", environments=["dev"], roles=["egress_sink"]
            ),
        ]
    )
    lookup = TaintCall("crm", "crm_lookup", "prod")
    assert classify(document, lookup, heuristics=True) == {"private_data"}
    assert classify(document, TaintCall("crm", "notify", "prod"), True) == set()
    assert classify(document, TaintCall("crm", "notify", "dev"), True) == {
        "egress_sink"
    }
    assert classify(document, TaintCall("x", "web_search", "prod"), False) == set()


def test_carries_url_walks_nested_values() -> None:
    """Any nested http(s) string value marks the call as a potential sink."""
    assert carries_url({"a": [{"b": ("x", " HTTPS://example.org")}]})
    assert carries_url({"target": HOOK_URL})
    assert not carries_url({"note": "see " + HOOK_URL, "n": 3, "path": "/tmp/x"})


def test_evaluate_flow_counts_private_data_carried_by_the_sink() -> None:
    """A sink that itself carries private data completes the trifecta."""
    call = TaintCall("tools", "send_email", "prod")
    held_untrusted: frozenset[TaintLabel] = frozenset({"untrusted_content"})
    verdict = evaluate_flow(held_untrusted, frozenset({"egress_sink"}), call, True)
    assert verdict.toxic and verdict.carried == {"private_data"}
    benign = evaluate_flow(held_untrusted, frozenset({"egress_sink"}), call, False)
    assert not benign.toxic and benign.carried == frozenset()


def test_policy_version_includes_non_empty_taint_rules() -> None:
    """Taint rules are part of the versioned policy document."""
    plain = PolicyDocument()
    tainted = PolicyDocument(
        taint_rules=[ToolTaintRule(tool_name="x", roles=["egress_sink"])]
    )
    assert policy_version(plain) != policy_version(tainted)


# -- SessionTaintTracker -----------------------------------------------------


def test_tracker_ttl_sliding_expiry_and_stateless_noop() -> None:
    """Labels slide with activity, expire after the TTL, and need a session."""
    clock = Clock()
    tracker = SessionTaintTracker(ttl_seconds=10, capacity=4, clock=clock)
    tracker.record("", "web_search", ["untrusted_content"])
    assert len(tracker) == 0 and tracker.labels("") == frozenset()
    tracker.record("s1", "web_search", ["untrusted_content"])
    clock.now += 8
    assert tracker.labels("s1") == {"untrusted_content"}
    clock.now += 8
    assert tracker.status("s1").labels == ["untrusted_content"]
    clock.now += 10
    assert tracker.labels("s1") == frozenset()
    assert tracker.status("s1").sources == []


def test_tracker_capacity_evicts_least_recently_used() -> None:
    """Capacity is bounded: expired entries purge first, then LRU eviction."""
    clock = Clock()
    tracker = SessionTaintTracker(ttl_seconds=10, capacity=2, clock=clock)
    tracker.record("a", "t", ["private_data"])
    tracker.record("b", "t", ["private_data"])
    tracker.labels("a")
    tracker.record("c", "t", ["private_data"])
    assert tracker.labels("b") == frozenset()
    assert tracker.labels("a") == tracker.labels("c") == {"private_data"}
    clock.now += 20
    tracker.record("d", "t", ["untrusted_content"])
    assert len(tracker) == 1


def test_tracker_sources_are_bounded_and_deduplicated() -> None:
    """Provenance keeps at most ``max_sources`` distinct entries."""
    tracker = SessionTaintTracker(ttl_seconds=10, capacity=2, max_sources=3)
    for index in range(5):
        tracker.record("s", f"tool{index}", ["private_data"])
        tracker.record("s", f"tool{index}", ["private_data"])
    status = tracker.status("s")
    assert status.sources == [
        "tool2:private_data",
        "tool3:private_data",
        "tool4:private_data",
    ]
    assert not status.lethal_trifecta_armed
    tracker.clear_session("s")
    assert tracker.labels("s") == frozenset()


# -- Firewall: the lethal trifecta -------------------------------------------


@pytest.mark.parametrize(
    ("first", "second"),
    [("web_search", "query_customers"), ("query_customers", "web_search")],
)
def test_lethal_trifecta_blocked_in_both_orders(
    tmp_path: Path, first: str, second: str
) -> None:
    """Untrusted + private in one session blocks any egress sink."""
    fw = _firewall(tmp_path)
    assert fw.inspect(_call(first, session_id="s1")).allowed
    assert fw.inspect(_call(second, session_id="s1")).allowed
    report = fw.inspect(_call("send_email", {"to": "x"}, session_id="s1"))
    assert not report.allowed
    assert report.decision == "BLOCKED"
    assert report.risk_score == 100
    assert TOXIC_FLOW_VIOLATION in report.violations
    assert report.sanitized_arguments == {}
    assert fw.taint.status("s1").lethal_trifecta_armed


@pytest.mark.parametrize(
    "steps",
    [
        ["web_search", "send_email"],
        ["query_customers", "send_email"],
        ["web_search", "query_customers", "list_dir"],
    ],
)
def test_benign_partial_flows_are_allowed(tmp_path: Path, steps: list[str]) -> None:
    """Two legs of the trifecta (or no sink) never block."""
    fw = _firewall(tmp_path)
    for tool in steps:
        report = fw.inspect(_call(tool, session_id="s1"))
        assert report.allowed and TOXIC_FLOW_VIOLATION not in report.violations


def test_session_isolation_and_stateless_calls(tmp_path: Path) -> None:
    """Taint never crosses sessions, and stateless calls never accumulate."""
    fw = _firewall(tmp_path)
    for tool in ("web_search", "query_customers"):
        fw.inspect(_call(tool, session_id="session-a"))
        fw.inspect(_call(tool))
    assert fw.inspect(_call("send_email", session_id="session-b")).allowed
    assert fw.inspect(_call("send_email")).allowed
    assert not fw.inspect(_call("send_email", session_id="session-a")).allowed


def test_inbound_dlp_promotes_private_data_and_url_sink(tmp_path: Path) -> None:
    """A redacted argument taints private data; URL arguments are sinks."""
    fw = _firewall(tmp_path)
    fw.inspect(_call("web_search", session_id="s1"))
    report = fw.inspect(_call("send_email", {"to": EMAIL}, session_id="s1"))
    assert TOXIC_FLOW_VIOLATION in report.violations
    fw.inspect(_call("lookup", {"owner": EMAIL}, session_id="s1"))
    assert fw.taint.status("s1").lethal_trifecta_armed
    assert not fw.inspect(_call("render", {"src": HOOK_URL}, session_id="s1")).allowed
    assert fw.inspect(_call("render", {"src": "local"}, session_id="s1")).allowed


def test_blocked_calls_do_not_taint_and_tracking_can_be_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Enforce-mode denials add no taint; the kill switch disables tracking."""
    document = parse_policy_yaml("rules:\n  - deny_tools: [web_search]\n")
    fw = _firewall(tmp_path, document)
    assert not fw.inspect(_call("web_search", session_id="s1")).allowed
    assert fw.taint.labels("s1") == frozenset()
    monkeypatch.setattr(settings, "enable_taint_tracking", False)
    fw.inspect(_call("query_customers", session_id="s1"))
    fw.inspect(_call("fetch_page", session_id="s1"))
    assert fw.taint.labels("s1") == frozenset()
    assert fw.inspect(_call("send_email", session_id="s1")).allowed


def test_yaml_taint_rules_monitor_mode_and_v2_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Declarative rules (heuristics off) in shadow mode audit would_block."""
    document = parse_policy_yaml(
        "taint_rules:\n"
        "  - tool_name: kb_article\n"
        "    roles: [untrusted_content]\n"
        "  - server_name: crm-*\n"
        "    roles: [private_data]\n"
        "  - tool_name: notify_partner\n"
        "    environments: [prod]\n"
        "    roles: [egress_sink]\n"
    )
    monkeypatch.setattr(settings, "taint_default_heuristics", False)
    monkeypatch.setattr(settings, "policy_mode", "monitor")
    fw = _firewall(tmp_path, document)
    fw.inspect(_call("kb_article", session_id="s1"))
    fw.inspect(_call("get_account", server_name="crm-mcp", session_id="s1"))
    report = fw.inspect(_call("notify_partner", session_id="s1"))
    assert report.allowed and report.would_block
    assert report.decision == "ALLOWED"
    assert TOXIC_FLOW_VIOLATION in report.violations
    entry = fw.list_audit_entries()[-1]
    assert entry.session_id == "s1" and entry.hash_version == 2
    assert TOXIC_FLOW_VIOLATION in entry.violations and entry.would_block
    assert fw.verify_chain().valid
    monkeypatch.setattr(settings, "policy_mode", "enforce")
    assert fw.inspect(_call("web_search", session_id="s2")).allowed
    assert fw.inspect(_call("send_email", session_id="s1")).allowed


# -- HTTP: /api/v1/mcp/inspect + taint status ---------------------------------


def _inspect_http(tool: str, session: str | None) -> httpx.Response:
    headers = {"X-Aegis-Session-Id": session} if session else {}
    body = {"server_name": "agent-tools", "tool_name": tool, "arguments": {}}
    response: httpx.Response = client.post(
        "/api/v1/mcp/inspect", json=body, headers=headers
    )
    return response


def test_inspect_endpoint_header_session_and_taint_status() -> None:
    """X-Aegis-Session-Id binds inspect calls; the status endpoint reports."""
    assert _inspect_http("fetch_page", "http-s1").json()["allowed"]
    status = client.get("/api/v1/sessions/http-s1/taint").json()
    assert status == {
        "session_id": "http-s1",
        "labels": ["untrusted_content"],
        "lethal_trifecta_armed": False,
        "sources": ["fetch_page:untrusted_content"],
    }
    assert _inspect_http("read_file", "http-s1").json()["allowed"]
    armed = client.get("/api/v1/sessions/http-s1/taint").json()
    assert armed["lethal_trifecta_armed"]
    blocked = _inspect_http("http_post", "http-s1").json()
    assert TOXIC_FLOW_VIOLATION in blocked["violations"] and not blocked["allowed"]
    assert _inspect_http("http_post", None).json()["allowed"]
    assert _inspect_http("http_post", "bad id").status_code == 422


def test_taint_status_requires_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The observability endpoint is behind the data-plane authentication."""
    monkeypatch.setattr(settings, "api_key", "taint-admin-key")
    assert client.get("/api/v1/sessions/x/taint").status_code == 401
    ok = client.get(
        "/api/v1/sessions/x/taint", headers={"X-API-Key": "taint-admin-key"}
    )
    assert ok.status_code == 200 and ok.json()["labels"] == []


# -- JSON-RPC gateway: outbound DLP promotion ---------------------------------


class Upstream:
    """Mock MCP upstream: ``lookup*`` replies leak an email address."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def _result(self, body: dict[str, Any]) -> Any:
        method = body["method"]
        if method == "initialize":
            return {"protocolVersion": "2025-06-18", "capabilities": {}}
        name = body.get("params", {}).get("name", method)
        self.calls.append(name)
        text = f"row owner {EMAIL}" if name.startswith("lookup") else "ok"
        return {"content": [{"type": "text", "text": text}]}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            return httpx.Response(200)
        if request.method == "GET":
            notice = {
                "jsonrpc": "2.0",
                "method": "notifications/message",
                "params": {"data": f"contact {EMAIL}"},
            }
            stream = f"data: {json.dumps(notice)}\n\n".encode()
            return httpx.Response(
                200, content=stream, headers={"Content-Type": "text/event-stream"}
            )
        body = json.loads(request.content)
        message = {"jsonrpc": "2.0", "id": body["id"], "result": self._result(body)}
        return httpx.Response(200, json=message, headers={"Mcp-Session-Id": "up-1"})


@pytest.fixture
def upstream() -> Upstream:
    """Wire the mock upstream under ``web-mcp`` (an untrusted-content server)."""
    fake = Upstream()
    jsonrpc_gateway.set_upstreams({"web-mcp": UPSTREAM_URL})
    jsonrpc_gateway.client = httpx.Client(transport=httpx.MockTransport(fake))
    return fake


def _tools_call(
    name: str, req_id: int, arguments: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


def _rpc(payload: Any, session: str | None) -> dict[str, Any]:
    headers = {"X-Aegis-MCP-Server": "web-mcp", "X-Aegis-Agent-Id": "agent-1"}
    if session is not None:
        headers["X-Aegis-Session-Id"] = session
    body: dict[str, Any] = client.post(
        "/api/v1/mcp/jsonrpc", json=payload, headers=headers
    ).json()
    return body


def test_jsonrpc_outbound_dlp_promotes_private_data(upstream: Upstream) -> None:
    """An upstream reply leaking PII taints the session and arms the sink."""
    first = _rpc(_tools_call("lookup_account", 1), "rpc-s1")
    assert EMAIL not in json.dumps(first["result"])
    assert firewall.taint.labels("rpc-s1") == {"untrusted_content", "private_data"}
    assert "lookup_account:private_data" in firewall.taint.status("rpc-s1").sources
    blocked = _rpc(_tools_call("post_comment", 2), "rpc-s1")
    assert blocked["error"]["code"] == POLICY_BLOCKED
    assert TOXIC_FLOW_VIOLATION in blocked["error"]["data"]["violations"]
    assert upstream.calls == ["lookup_account"]
    assert "result" in _rpc(_tools_call("post_comment", 3), None)


def test_jsonrpc_rejects_malformed_session_header() -> None:
    """Session ids must be printable ASCII without spaces."""
    with pytest.raises(JsonRpcError) as excinfo:
        build_context("agent", "web-mcp", "prod", "bad id")
    assert excinfo.value.code == INVALID_REQUEST
    assert build_context("agent", "web-mcp", None, "ok-1").session_id == "ok-1"


# -- Streamable HTTP ----------------------------------------------------------

STREAM_HEADERS = {
    "X-Aegis-Agent-Id": "agent-1",
    "X-Aegis-MCP-Server": "web-mcp",
    "Accept": "application/json, text/event-stream",
}


def _mcp(payload: Any, session: str | None = None) -> httpx.Response:
    headers = dict(STREAM_HEADERS)
    if session is not None:
        headers["Mcp-Session-Id"] = session
    response: httpx.Response = client.post("/mcp", json=payload, headers=headers)
    return response


def _open_session() -> str:
    init = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
    }
    return str(_mcp(init).headers["mcp-session-id"])


def test_streamable_trifecta_and_delete_clears_taint(upstream: Upstream) -> None:
    """Mcp-Session-Id carries taint; DELETE /mcp forgets it."""
    session = _open_session()
    _mcp(_tools_call("fetch_page", 1), session)
    _mcp(_tools_call("lookup_account", 2), session)
    status = client.get(f"/api/v1/sessions/{session}/taint").json()
    assert status["lethal_trifecta_armed"]
    blocked = _mcp(_tools_call("send_report", 3, {"to": "x"}), session).json()
    assert TOXIC_FLOW_VIOLATION in blocked["error"]["data"]["violations"]
    assert "send_report" not in upstream.calls
    headers = {**STREAM_HEADERS, "Mcp-Session-Id": session}
    assert client.delete("/mcp", headers=headers).status_code == 204
    assert firewall.taint.labels(session) == frozenset()


def test_streamable_server_stream_dlp_promotes_private_data(
    upstream: Upstream,
) -> None:
    """Server-initiated messages that leak PII also taint the session."""
    session = _open_session()
    headers = {**STREAM_HEADERS, "Mcp-Session-Id": session}
    res = client.get("/mcp", headers=headers)
    assert res.status_code == 200 and EMAIL not in res.text
    assert firewall.taint.labels(session) == {"private_data"}


def test_session_store_expiry_clears_taint() -> None:
    """Expired or purged transport sessions notify the end-of-session hook."""
    clock = Clock()
    ended: list[str] = []
    store = SessionStore(ttl_seconds=5, capacity=1, clock=clock, on_remove=ended.append)
    context = build_context("agent", "web-mcp", "prod")
    store.add(McpSession("old", context, "2025-06-18", None))
    clock.now += 10
    store.add(McpSession("new", context, "2025-06-18", None))
    assert ended == ["old"]
    clock.now += 10
    assert store.get("new") is None and store.get("missing") is None
    assert ended == ["old", "new"]
    assert mcp_transport.sessions.on_remove == firewall.taint.clear_session
