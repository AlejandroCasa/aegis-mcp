"""TDD suite for the native MCP Streamable HTTP transport (``/mcp``)."""

import json
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.auth import Principal
from app.config import settings
from app.jsonrpc import (
    INVALID_REQUEST,
    MAX_REQUEST_BYTES,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    POLICY_BLOCKED,
    UPSTREAM_ERROR,
    CallContext,
)
from app.main import (
    app,
    firewall,
    jsonrpc_gateway,
    mcp_routing,
    mcp_transport,
    policy_engine,
)
from app.metrics import metrics_registry
from app.sse import iter_sse_events
from app.streamable import (
    McpSession,
    SessionStore,
    TransportError,
    accepts,
    message_kind,
    server_message,
)
from scripts import scan_mcp_server

client = TestClient(app)

UPSTREAM_URL = "http://git-mcp.internal:9000/mcp"
UPSTREAM_SESSION = "upstream-session-1"
EMAIL = "alice" + "@" + "example.com"
SECRET = "sk-" + "b" * 24
TRAVERSAL = "file://" + ".." + "/" + ".." + "/secrets"
BASE = {
    "X-Aegis-Agent-Id": "coder-1",
    "X-Aegis-MCP-Server": "git-mcp",
    "Accept": "application/json, text/event-stream",
}
GIT_TOOL = {
    "name": "git_status",
    "description": "Show the working tree status.",
    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
}

Responder = Callable[[dict[str, Any]], httpx.Response]


def _sse_body(messages: list[Any], prefix: str = "") -> bytes:
    events = [
        f"id: ev-{index}\ndata: {json.dumps(message)}\n\n"
        for index, message in enumerate(messages)
    ]
    return (prefix + "".join(events)).encode()


def _sse_response(messages: list[Any], prefix: str = "") -> httpx.Response:
    return httpx.Response(
        200,
        content=_sse_body(messages, prefix),
        headers={"Content-Type": "text/event-stream"},
    )


def _events(res: httpx.Response) -> list[tuple[dict[str, Any], str | None]]:
    assert res.headers["content-type"].startswith("text/event-stream")
    return [
        (json.loads(event.data), event.event_id)
        for event in iter_sse_events(res.text.splitlines())
    ]


def _raise_connect_error(body: dict[str, Any]) -> httpx.Response:
    raise httpx.ConnectError("upstream down")


class McpUpstream:
    """Mock Streamable HTTP upstream (JSON or SSE replies, GET stream)."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.version = "2025-06-18"
        self.session_header: str | None = UPSTREAM_SESSION
        self.sse = False
        self.responder: Responder | None = None
        self.one_way_status = 202
        self.get_response: httpx.Response = _sse_response([])

    def _result(self, body: dict[str, Any]) -> Any:
        method = body["method"]
        if method == "initialize":
            return {
                "protocolVersion": self.version,
                "serverInfo": {"name": "git"},
                "capabilities": {"tools": {}},
            }
        if method == "tools/list":
            return {"tools": [GIT_TOOL]}
        return {"content": [{"type": "text", "text": f"owner {EMAIL}"}]}

    def _reply(self, body: dict[str, Any]) -> httpx.Response:
        message = {"jsonrpc": "2.0", "id": body["id"], "result": self._result(body)}
        if not self.sse:
            return httpx.Response(200, json=message)
        progress = {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": 1, "message": f"mail {EMAIL}"},
        }
        stray = {"jsonrpc": "2.0", "id": 999, "result": {}}
        return _sse_response(
            [progress, stray, message], prefix=": ping\n\ndata: {broken\n\n"
        )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.method == "GET":
            return self.get_response
        if request.method == "DELETE":
            return httpx.Response(200)
        body = json.loads(request.content)
        if "id" not in body or "method" not in body:
            return httpx.Response(self.one_way_status)
        response = (self.responder or self._reply)(body)
        if self.session_header:
            response.headers["Mcp-Session-Id"] = self.session_header
        return response

    def bodies(self) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.requests if r.method == "POST"]


@pytest.fixture
def upstream(monkeypatch: pytest.MonkeyPatch) -> Iterator[McpUpstream]:
    """Wire a mock upstream and isolate gateway state."""
    fake = McpUpstream()
    original = jsonrpc_gateway.client
    monkeypatch.setattr(settings, "api_key", None)
    monkeypatch.setattr(settings, "policy_mode", "enforce")
    monkeypatch.setattr(settings, "enable_dlp_redaction", True)
    monkeypatch.setattr(settings, "mcp_allowed_origins", ["https://app.example"])
    monkeypatch.setattr(jsonrpc_gateway.toolguard, "require_approval", False)
    firewall.reset()
    jsonrpc_gateway.toolguard.reset()
    metrics_registry.reset()
    policy_engine.reset()
    mcp_transport.sessions.clear()
    jsonrpc_gateway.set_upstreams({"git-mcp": UPSTREAM_URL})
    jsonrpc_gateway.client = httpx.Client(transport=httpx.MockTransport(fake))
    yield fake
    jsonrpc_gateway.client = original
    jsonrpc_gateway.set_upstreams({})
    jsonrpc_gateway.toolguard.reset()
    mcp_transport.sessions.clear()


def _req(method: str, params: Any = None, req_id: Any = 1) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def _init_params(version: str = "2025-06-18") -> dict[str, Any]:
    return {
        "protocolVersion": version,
        "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "1.0"},
    }


def _post(
    payload: Any, session: str | None = None, headers: dict[str, str] | None = None
) -> httpx.Response:
    merged = {**BASE, **(headers or {})}
    if session is not None:
        merged["Mcp-Session-Id"] = session
    response: httpx.Response = client.post("/mcp", json=payload, headers=merged)
    return response


def _initialize(version: str = "2025-06-18") -> str:
    res = _post(_req("initialize", _init_params(version)))
    assert res.status_code == 200
    return str(res.headers["mcp-session-id"])


def _call(req_id: int = 1, **arguments: Any) -> dict[str, Any]:
    return _req("tools/call", {"name": "git_status", "arguments": arguments}, req_id)


# ---------------------------------------------------------------------------
# Initialization, sessions, and version negotiation
# ---------------------------------------------------------------------------


def test_initialize_mints_gateway_session(upstream: McpUpstream) -> None:
    """The gateway issues its own session id and hides the upstream one."""
    res = _post(
        _req("initialize", _init_params()), headers={"Authorization": "Bearer x"}
    )
    assert res.status_code == 200
    assert res.json()["result"]["protocolVersion"] == "2025-06-18"
    session = res.headers["mcp-session-id"]
    assert session != UPSTREAM_SESSION
    assert len(session) >= 43
    assert UPSTREAM_SESSION not in res.text
    forwarded = upstream.requests[0]
    assert "authorization" not in forwarded.headers
    assert forwarded.headers.get("mcp-session-id") is None
    assert len(mcp_transport.sessions) == 1


def test_requests_carry_upstream_session_and_version(upstream: McpUpstream) -> None:
    """Later hops use the upstream session id and negotiated version."""
    session = _initialize()
    res = _post(
        _req("tools/list", {}, 2), session, {"MCP-Protocol-Version": "2025-06-18"}
    )
    assert res.status_code == 200
    assert res.json()["result"]["tools"][0]["name"] == "git_status"
    hop = upstream.requests[-1].headers
    assert hop["mcp-session-id"] == UPSTREAM_SESSION
    assert hop["mcp-protocol-version"] == "2025-06-18"


def test_initialize_unsupported_upstream_version(upstream: McpUpstream) -> None:
    """An unsupported negotiated version creates no session."""
    upstream.version = "1999-01-01"
    res = _post(_req("initialize", _init_params()))
    assert res.json()["error"]["code"] == UPSTREAM_ERROR
    assert "mcp-session-id" not in res.headers
    assert len(mcp_transport.sessions) == 0


def test_initialize_upstream_error_is_relayed(upstream: McpUpstream) -> None:
    """An upstream JSON-RPC error is relayed without creating a session."""
    upstream.responder = lambda body: httpx.Response(
        200,
        json={
            "jsonrpc": "2.0",
            "id": body["id"],
            "error": {"code": -1, "message": "x"},
        },
    )
    res = _post(_req("initialize", _init_params()))
    assert res.json()["error"]["code"] == -1
    assert "mcp-session-id" not in res.headers


@pytest.mark.parametrize(
    "responder", [lambda body: httpx.Response(500), _raise_connect_error]
)
def test_initialize_upstream_failure(
    upstream: McpUpstream, responder: Responder
) -> None:
    """Upstream HTTP/network failures become -32004 with the request id."""
    upstream.responder = responder
    res = _post(_req("initialize", _init_params(), req_id="init"))
    assert res.status_code == 200
    assert res.json() == {
        "jsonrpc": "2.0",
        "id": "init",
        "error": {"code": UPSTREAM_ERROR, "message": "Upstream MCP server error."},
    }


def test_initialize_without_upstream_is_rejected(upstream: McpUpstream) -> None:
    """An unconfigured server yields -32004 before anything is forwarded."""
    jsonrpc_gateway.set_upstreams({})
    res = _post(_req("initialize", _init_params()))
    assert res.json()["error"]["code"] == UPSTREAM_ERROR
    assert upstream.requests == []


@pytest.mark.parametrize(
    ("payload", "headers"),
    [
        (_req("initialize", _init_params()), {"X-Aegis-MCP-Server": ""}),
        ({"jsonrpc": "2.0", "method": "initialize"}, {}),
        ([_req("initialize", _init_params())], {}),
    ],
)
def test_initialize_validation_errors(
    upstream: McpUpstream, payload: Any, headers: dict[str, str]
) -> None:
    """Bad routing, a notification initialize, or a batched one are 400s."""
    res = _post(payload, headers=headers)
    assert res.status_code == 400
    assert res.json()["error"]["code"] == INVALID_REQUEST
    assert upstream.requests == []


def test_session_header_is_required(upstream: McpUpstream) -> None:
    """Non-initialize requests without a session are rejected."""
    res = _post(_req("tools/list", {}))
    assert res.status_code == 400
    assert "Mcp-Session-Id" in res.json()["error"]["message"]


@pytest.mark.parametrize(
    ("unknown", "headers"),
    [
        (True, {}),
        (False, {"X-Aegis-Agent-Id": "intruder"}),
        (False, {"X-Aegis-MCP-Server": "other-mcp"}),
    ],
)
def test_foreign_or_unknown_sessions_are_not_found(
    upstream: McpUpstream, unknown: bool, headers: dict[str, str]
) -> None:
    """Sessions are bound to their agent and server (404 otherwise)."""
    session = _initialize()
    res = _post(_req("tools/list", {}), "unknown" if unknown else session, headers)
    assert res.status_code == 404


def test_mismatched_protocol_version_is_rejected(upstream: McpUpstream) -> None:
    """A header disagreeing with the negotiated version is a 400."""
    session = _initialize()
    res = _post(_req("tools/list", {}), session, {"MCP-Protocol-Version": "2025-03-26"})
    assert res.status_code == 400


def test_upstream_404_expires_the_session(upstream: McpUpstream) -> None:
    """An expired upstream session forces the client to re-initialize."""
    session = _initialize()
    upstream.responder = lambda body: httpx.Response(404)
    res = _post(_req("tools/list", {}), session)
    assert res.json()["error"]["code"] == UPSTREAM_ERROR
    assert _post(_req("tools/list", {}), session).status_code == 404


def test_upstream_404_without_upstream_session_keeps_session(
    upstream: McpUpstream,
) -> None:
    """Without an upstream session a 404 is a plain upstream error."""
    upstream.session_header = None
    session = _initialize()
    upstream.responder = lambda body: httpx.Response(404)
    body = _post(_req("tools/list", {}), session).json()
    assert body["error"]["code"] == UPSTREAM_ERROR
    upstream.responder = None
    assert "result" in _post(_req("tools/list", {}), session).json()


def test_mcp_routing_prefers_token_identity() -> None:
    """In OAuth mode the self-declared agent header is ignored."""
    request = Request(
        {
            "type": "http",
            "headers": [
                (b"x-aegis-agent-id", b"spoofed"),
                (b"x-aegis-mcp-server", b"s"),
            ],
        }
    )
    principal = Principal("oauth-agent", "sub", None, frozenset(), {})
    assert mcp_routing(principal, request)["agent_id"] == "oauth-agent"
    assert mcp_routing(None, request) == {
        "agent_id": "spoofed",
        "server_name": "s",
        "environment": None,
    }


# ---------------------------------------------------------------------------
# HTTP-level validation and Origin (DNS rebinding)
# ---------------------------------------------------------------------------


def test_disallowed_origin_is_forbidden(upstream: McpUpstream) -> None:
    """Browser origins outside the allowlist get 403 on every method."""
    evil = {"Origin": "https://evil.example"}
    assert _post(_req("initialize", _init_params()), headers=evil).status_code == 403
    assert client.get("/mcp", headers={**BASE, **evil}).status_code == 403
    assert client.delete("/mcp", headers={**BASE, **evil}).status_code == 403
    assert upstream.requests == []


def test_allowed_origin_is_accepted(upstream: McpUpstream) -> None:
    """Allowlisted origins pass."""
    res = _post(
        _req("initialize", _init_params()), headers={"Origin": "https://app.example"}
    )
    assert res.status_code == 200


@pytest.mark.parametrize(
    ("content", "headers", "status", "code"),
    [
        (b"{}", {"Accept": "text/html"}, 406, INVALID_REQUEST),
        (b"{}", {"Content-Type": "text/plain"}, 415, INVALID_REQUEST),
        (b"{not json", {}, 400, PARSE_ERROR),
        (b"[]", {}, 400, INVALID_REQUEST),
        (b" " * (MAX_REQUEST_BYTES + 1), {}, 413, INVALID_REQUEST),
    ],
)
def test_http_level_rejections(
    upstream: McpUpstream,
    content: bytes,
    headers: dict[str, str],
    status: int,
    code: int,
) -> None:
    """Accept, Content-Type, parse, empty batch, and size are HTTP errors."""
    merged = {**BASE, "Content-Type": "application/json", **headers}
    res = client.post("/mcp", content=content, headers=merged)
    assert res.status_code == status
    assert res.json()["error"]["code"] == code
    assert res.json()["id"] is None


def test_missing_accept_defaults_to_json(upstream: McpUpstream) -> None:
    """Clients that send no Accept header get JSON."""
    res = client.post(
        "/mcp",
        json=_req("initialize", _init_params()),
        headers={"X-Aegis-MCP-Server": "git-mcp", "Accept": ""},
    )
    assert res.status_code == 406
    raw = TestClient(app)
    raw.headers.pop("accept", None)
    res = raw.post(
        "/mcp",
        json=_req("initialize", _init_params()),
        headers={"X-Aegis-MCP-Server": "git-mcp"},
    )
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/json"


@pytest.mark.parametrize(
    ("header", "media_type", "expected"),
    [
        (None, "application/json", True),
        (None, "text/event-stream", False),
        ("*/*", "text/event-stream", True),
        ("text/*;q=0.5", "text/event-stream", True),
        ("application/xml", "application/json", False),
    ],
)
def test_accepts(header: str | None, media_type: str, expected: bool) -> None:
    """Accept parsing honours wildcards and parameters."""
    headers = {} if header is None else {"accept": header}
    assert accepts(headers, media_type) is expected


@pytest.mark.parametrize(
    ("message", "kind"),
    [
        ({"jsonrpc": "2.0", "id": 1, "method": "m"}, "request"),
        ({"jsonrpc": "2.0", "method": "m"}, "notification"),
        ({"jsonrpc": "2.0", "id": 1, "result": {}}, "response"),
        ({"jsonrpc": "2.0", "id": 1, "error": {}}, "response"),
        ({"jsonrpc": "2.0", "id": 1}, "invalid"),
        ({"jsonrpc": "1.0", "method": "m"}, "invalid"),
        ([], "invalid"),
    ],
)
def test_message_kind(message: Any, kind: str) -> None:
    """Messages are classified by JSON-RPC shape."""
    assert message_kind(message) == kind


# ---------------------------------------------------------------------------
# Requests: firewall pipeline, DLP, ledger session binding
# ---------------------------------------------------------------------------


def test_tool_call_is_inspected_redacted_and_ledger_bound(
    upstream: McpUpstream,
) -> None:
    """Calls run the firewall, are redacted both ways, and bind the session."""
    session = _initialize()
    res = _post(_call(5, token=SECRET), session, {"Accept": "application/json"})
    assert res.status_code == 200
    assert res.json()["id"] == 5
    assert EMAIL not in res.text
    assert SECRET not in json.dumps(upstream.bodies()[-1])
    entry = firewall.list_audit_entries()[-1]
    assert entry.session_id == session
    assert entry.hash_version == 2
    assert entry.decision == "SANITIZED"
    assert firewall.verify_chain().valid


def test_blocked_request_never_reaches_upstream(upstream: McpUpstream) -> None:
    """Threat rules block with -32003 and the event is session-bound."""
    session = _initialize()
    before = len(upstream.requests)
    body = _post(_req("resources/read", {"uri": TRAVERSAL}, 9), session).json()
    assert body["error"]["code"] == POLICY_BLOCKED
    assert body["id"] == 9
    assert len(upstream.requests) == before
    assert firewall.list_audit_entries()[-1].session_id == session


def test_unknown_method_is_rejected(upstream: McpUpstream) -> None:
    """Methods outside the allowlist return -32601."""
    session = _initialize()
    body = _post(_req("sampling/createMessage", {}), session).json()
    assert body["error"]["code"] == METHOD_NOT_FOUND


def test_deeply_nested_request_is_rejected(upstream: McpUpstream) -> None:
    """Pathological nesting yields -32600 instead of crashing."""
    session = _initialize()
    nested = "[" * 5_000 + "]" * 5_000
    raw = (
        '{"jsonrpc":"2.0","id":3,"method":"tools/call",'
        '"params":{"name":"t","arguments":{"a":' + nested + "}}}"
    )
    headers = {**BASE, "Content-Type": "application/json", "Mcp-Session-Id": session}
    res = client.post("/mcp", content=raw.encode(), headers=headers)
    assert res.json()["error"]["code"] == INVALID_REQUEST
    assert res.json()["id"] == 3


def test_sse_reply_is_relayed_with_per_event_dlp(upstream: McpUpstream) -> None:
    """SSE events are redacted one by one; strays and garbage are dropped."""
    session = _initialize()
    upstream.sse = True
    res = _post(_call(7), session)
    events = _events(res)
    assert [message.get("method") for message, _ in events] == [
        "notifications/progress",
        None,
    ]
    assert events[0][1] == "ev-0"
    final = events[-1][0]
    assert final["id"] == 7
    assert "result" in final
    assert EMAIL not in res.text
    assert "[REDACTED_EMAIL]" in res.text


def test_sse_reply_is_collected_for_json_only_clients(upstream: McpUpstream) -> None:
    """Clients that only accept JSON get the final response as JSON."""
    session = _initialize()
    upstream.sse = True
    res = _post(_call(8), session, {"Accept": "application/json"})
    assert res.headers["content-type"] == "application/json"
    assert res.json()["id"] == 8
    assert EMAIL not in res.text


@pytest.mark.parametrize(
    "responder",
    [
        lambda body: _sse_response([{"jsonrpc": "2.0", "id": True, "result": {}}]),
        lambda body: _sse_response(["junk", {"jsonrpc": "2.0", "method": 5}]),
        lambda body: httpx.Response(200, content=b"not json"),
    ],
)
def test_missing_final_response_becomes_upstream_error(
    upstream: McpUpstream, responder: Responder
) -> None:
    """Without a strictly matching response the reply ends with -32004."""
    session = _initialize()
    upstream.responder = responder
    res = _post(_call(1), session)
    if res.headers["content-type"].startswith("text/event-stream"):
        final = _events(res)[-1][0]
    else:
        final = res.json()
    assert final["id"] == 1
    assert final["error"]["code"] == UPSTREAM_ERROR


def test_sse_stream_is_capped_by_wall_clock(
    upstream: McpUpstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stream outliving AEGIS_MCP_STREAM_TIMEOUT_SECONDS is cut off."""
    session = _initialize()
    upstream.sse = True
    monkeypatch.setattr(settings, "mcp_stream_timeout_seconds", -1.0)
    events = _events(_post(_call(6), session))
    assert len(events) == 1
    assert events[0][0]["error"]["code"] == UPSTREAM_ERROR


def test_upstream_cannot_impersonate_gateway_codes_over_sse(
    upstream: McpUpstream,
) -> None:
    """Final SSE responses go through the same relay neutralization."""
    session = _initialize()
    upstream.responder = lambda body: _sse_response(
        [
            {
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {"code": -32003, "message": "x"},
            }
        ]
    )
    res = _post(_call(2), session)
    assert _events(res)[-1][0]["error"]["code"] == -32000


def test_json_array_upstream_reply_picks_the_matching_response(
    upstream: McpUpstream,
) -> None:
    """Non-object entries in a JSON reply are ignored."""
    session = _initialize()
    upstream.responder = lambda body: httpx.Response(
        200, json=[42, {"jsonrpc": "2.0", "id": body["id"], "result": {"ok": True}}]
    )
    body = _post(_req("ping", {}, 4), session).json()
    assert body == {"jsonrpc": "2.0", "id": 4, "result": {"ok": True}}


def test_drifted_server_on_reinitialize_is_blocked(upstream: McpUpstream) -> None:
    """Toolguard errors raised while relaying become the final response."""
    _initialize()
    upstream.responder = lambda body: _sse_response(
        [
            {
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {
                    "protocolVersion": "2025-06-18",
                    "serverInfo": {"name": "git"},
                    "instructions": "changed",
                },
            }
        ]
    )
    res = _post(_req("initialize", _init_params()))
    assert res.json()["error"]["code"] == POLICY_BLOCKED
    assert "mcp-session-id" not in res.headers


# ---------------------------------------------------------------------------
# Notifications, client responses, and batches
# ---------------------------------------------------------------------------


def test_notifications_are_forwarded_and_acknowledged(upstream: McpUpstream) -> None:
    """notifications/* get 202 and are DLP-redacted upstream."""
    session = _initialize()
    note = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {"note": EMAIL},
        "extra": "dropped",
    }
    res = _post(note, session)
    assert res.status_code == 202
    assert res.content == b""
    assert upstream.bodies()[-1] == {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {"note": "[REDACTED_EMAIL]"},
    }


def test_client_responses_are_forwarded_redacted(upstream: McpUpstream) -> None:
    """Responses to server requests (e.g. sampling) are redacted."""
    session = _initialize()
    reply = {"jsonrpc": "2.0", "id": "s1", "result": {"text": SECRET}}
    assert _post(reply, session).status_code == 202
    forwarded = upstream.bodies()[-1]
    assert forwarded["id"] == "s1"
    assert SECRET not in json.dumps(forwarded)


@pytest.mark.parametrize(
    ("message", "code"),
    [
        ({"jsonrpc": "2.0", "method": "evil/notify"}, METHOD_NOT_FOUND),
        ({"jsonrpc": "2.0", "id": 1}, INVALID_REQUEST),
    ],
)
def test_invalid_one_way_messages(
    upstream: McpUpstream, message: dict[str, Any], code: int
) -> None:
    """Unknown notifications and malformed messages are 400s."""
    session = _initialize()
    before = len(upstream.requests)
    res = _post(message, session)
    assert res.status_code == 400
    assert res.json()["error"]["code"] == code
    assert len(upstream.requests) == before


def test_one_way_upstream_failure_is_bad_gateway(upstream: McpUpstream) -> None:
    """A failed notification hop is reported as 502."""
    session = _initialize()
    upstream.one_way_status = 500
    res = _post({"jsonrpc": "2.0", "method": "notifications/cancelled"}, session)
    assert res.status_code == 502
    assert res.json()["error"]["code"] == UPSTREAM_ERROR


def test_batches_require_the_2025_03_26_revision(upstream: McpUpstream) -> None:
    """Revisions without batching reject arrays."""
    session = _initialize()
    assert _post([_req("ping", {})], session).status_code == 400


def test_batches_are_processed_member_by_member(upstream: McpUpstream) -> None:
    """Requests reply in an array; one-way members produce no entry."""
    upstream.version = "2025-03-26"
    session = _initialize("2025-03-26")
    upstream.one_way_status = 500
    batch = [
        _req("tools/list", {}, 1),
        {"jsonrpc": "2.0", "method": "notifications/progress"},
        {"jsonrpc": "2.0", "method": "bogus/notify"},
        "garbage",
        _req("resources/read", {"uri": TRAVERSAL}, 2),
    ]
    res = _post(batch, session)
    assert res.status_code == 200
    replies = res.json()
    assert [reply["id"] for reply in replies] == [1, None, 2]
    assert "result" in replies[0]
    assert replies[1]["error"]["code"] == INVALID_REQUEST
    assert replies[2]["error"]["code"] == POLICY_BLOCKED
    methods = [body.get("method") for body in upstream.bodies()]
    assert methods == ["initialize", "tools/list", "notifications/progress"]


def test_batch_of_notifications_is_accepted(upstream: McpUpstream) -> None:
    """A batch without requests is acknowledged with 202."""
    upstream.version = "2025-03-26"
    session = _initialize("2025-03-26")
    res = _post([{"jsonrpc": "2.0", "method": "notifications/progress"}], session)
    assert res.status_code == 202


# ---------------------------------------------------------------------------
# GET stream and DELETE
# ---------------------------------------------------------------------------


def _get(session: str, **headers: str) -> httpx.Response:
    merged = {**BASE, "Mcp-Session-Id": session, **headers}
    response: httpx.Response = client.get("/mcp", headers=merged)
    return response


def _delete(session: str) -> httpx.Response:
    merged = {**BASE, "Mcp-Session-Id": session}
    response: httpx.Response = client.delete("/mcp", headers=merged)
    return response


def test_get_relays_server_stream_with_dlp(upstream: McpUpstream) -> None:
    """Server-initiated requests are redacted; responses are dropped."""
    session = _initialize()
    sampling = {
        "jsonrpc": "2.0",
        "id": "srv-1",
        "method": "sampling/createMessage",
        "params": {"messages": [{"content": {"text": EMAIL}}]},
        "smuggled": True,
    }
    upstream.get_response = _sse_response(
        [sampling, {"jsonrpc": "2.0", "id": 1, "result": {}}], prefix="data: [x\n\n"
    )
    res = _get(session, **{"Last-Event-ID": "ev-41"})
    assert res.status_code == 200
    events = _events(res)
    assert len(events) == 1
    message, event_id = events[0]
    assert event_id == "ev-0"
    assert message["method"] == "sampling/createMessage"
    assert "smuggled" not in message
    assert EMAIL not in res.text
    hop = upstream.requests[-1]
    assert hop.method == "GET"
    assert hop.headers["last-event-id"] == "ev-41"
    assert hop.headers["accept"] == "text/event-stream"
    assert hop.headers["mcp-session-id"] == UPSTREAM_SESSION


def test_get_drops_unsafe_last_event_id(upstream: McpUpstream) -> None:
    """Header-unsafe resumption ids are not forwarded."""
    session = _initialize()
    _get(session, **{"Last-Event-ID": "bad id with spaces"})
    assert "last-event-id" not in upstream.requests[-1].headers


@pytest.mark.parametrize(
    ("response", "status"),
    [
        (httpx.Response(405), 405),
        (httpx.Response(500), 502),
        (httpx.Response(200, json={}), 502),
    ],
)
def test_get_upstream_failures(
    upstream: McpUpstream, response: httpx.Response, status: int
) -> None:
    """405 is passed through; other upstream problems are 502."""
    session = _initialize()
    upstream.get_response = response
    assert _get(session).status_code == status


def test_get_requires_event_stream_accept(upstream: McpUpstream) -> None:
    """GET without text/event-stream in Accept is 406."""
    session = _initialize()
    assert _get(session, Accept="application/json").status_code == 406


def test_get_without_upstream_is_bad_gateway(upstream: McpUpstream) -> None:
    """A server removed from configuration yields 502."""
    session = _initialize()
    jsonrpc_gateway.set_upstreams({})
    assert _get(session).status_code == 502


def test_delete_terminates_both_sessions(upstream: McpUpstream) -> None:
    """DELETE ends the gateway session and the upstream one."""
    session = _initialize()
    assert _delete(session).status_code == 204
    hop = upstream.requests[-1]
    assert hop.method == "DELETE"
    assert hop.headers["mcp-session-id"] == UPSTREAM_SESSION
    assert _post(_req("ping", {}), session).status_code == 404


def test_delete_tolerates_upstream_failure(upstream: McpUpstream) -> None:
    """Upstream termination is best effort."""
    session = _initialize()
    jsonrpc_gateway.set_upstreams({})
    assert _delete(session).status_code == 204


def test_delete_without_upstream_session_skips_upstream(
    upstream: McpUpstream,
) -> None:
    """Nothing is sent upstream when it never issued a session."""
    upstream.session_header = None
    session = _initialize()
    before = len(upstream.requests)
    assert _delete(session).status_code == 204
    assert len(upstream.requests) == before


def test_delete_unknown_session(upstream: McpUpstream) -> None:
    """Unknown sessions are 404."""
    assert _delete("nope").status_code == 404


# ---------------------------------------------------------------------------
# Units: session store and server messages
# ---------------------------------------------------------------------------


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _session(session_id: str) -> McpSession:
    context = CallContext("agent", "server", "prod", session_id)
    return McpSession(session_id, context, "2025-06-18", None)


def test_session_store_ttl_is_sliding() -> None:
    """Access extends the lifetime; idle sessions expire."""
    clock = FakeClock()
    store = SessionStore(ttl_seconds=10, capacity=5, clock=clock)
    store.add(_session("a"))
    clock.now = 8
    assert store.get("a") is not None
    clock.now = 16
    assert store.get("a") is not None
    clock.now = 27
    assert store.get("a") is None
    assert len(store) == 0
    store.remove("missing")


def test_session_store_capacity_purges_expired_first() -> None:
    """Full tables reject with 503 unless expired entries can be purged."""
    clock = FakeClock()
    store = SessionStore(ttl_seconds=10, capacity=1, clock=clock)
    store.add(_session("a"))
    with pytest.raises(TransportError) as excinfo:
        store.add(_session("b"))
    assert excinfo.value.status == 503
    clock.now = 11
    store.add(_session("b"))
    assert store.get("b") is not None


def test_session_capacity_exhaustion_is_service_unavailable(
    upstream: McpUpstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full session table answers initialize with 503."""
    monkeypatch.setattr(mcp_transport.sessions, "capacity", 1)
    _initialize()
    res = _post(_req("initialize", _init_params()))
    assert res.status_code == 503


def test_server_message_filters_non_messages() -> None:
    """Only objects with a string method are relayed."""
    assert server_message(["x"]) is None
    assert server_message({"jsonrpc": "2.0", "method": 1}) is None
    assert server_message({"method": "notifications/message"}) == {
        "jsonrpc": "2.0",
        "method": "notifications/message",
    }


# ---------------------------------------------------------------------------
# End to end: the poisoning scanner speaks to the gateway's /mcp endpoint
# ---------------------------------------------------------------------------


def test_scanner_discovers_through_the_gateway(
    upstream: McpUpstream, capsys: pytest.CaptureFixture[str]
) -> None:
    """scripts/scan_mcp_server.py completes a handshake against /mcp."""
    argv = [
        "--url",
        "http://testserver/mcp",
        "--header",
        "X-Aegis-MCP-Server: git-mcp",
        "--header",
        "X-Aegis-Agent-Id: scanner",
    ]
    assert scan_mcp_server.main(argv, TestClient(app)) == scan_mcp_server.EXIT_CLEAN
    assert "No poisoning indicators found." in capsys.readouterr().out
    methods = [body.get("method") for body in upstream.bodies()]
    assert methods == ["initialize", "notifications/initialized", "tools/list"]
