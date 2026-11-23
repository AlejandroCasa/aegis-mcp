"""JSON-RPC 2.0 MCP wire-protocol gateway with bidirectional DLP redaction.

Request pipeline for ``POST /api/v1/mcp/jsonrpc``:

1. Parse and validate a single JSON-RPC 2.0 request envelope (batches and
   notifications are rejected).
2. Resolve the MCP method (``tools/call``, ``resources/read``,
   ``prompts/get``) and validate its params.
3. Run ``MCPFirewall.inspect`` (threat rules, RBAC matrix, inbound DLP,
   SHA-256 audit ledger). Blocked calls return ``-32003``.
4. Forward the sanitized envelope to the server-configured upstream (never a
   caller-supplied URL) on a fresh request carrying no caller credentials
   (no token passthrough / confused-deputy mitigation), then DLP-redact the
   upstream ``result``/``error`` before relaying it with the caller's
   original ``id``.

RBAC ``tool_name`` mapping: ``tools/call`` uses ``params.name``; the other
methods use the method name itself (``resources/read``, ``prompts/get``).

Discovery methods (``initialize``, ``ping``, ``tools/list``,
``resources/list``, ``resources/templates/list``, ``prompts/list``) are
forwarded with DLP-redacted params; their results pass through the toolguard
(``app/toolguard.py``): every definition is fingerprinted and pinned (TOFU),
drifted definitions are filtered and audited as ``tool_definition_drift``, and
``tools/list`` only advertises tools the RBAC matrix authorizes for the agent
(least-privilege discovery). Any other method is rejected (``-32601``).
"""

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.auth import strip_credentials
from app.config import settings
from app.firewall import MCPFirewall
from app.metrics import metrics_registry
from app.redactor import redact_payload, redact_text
from app.schemas import Environment, MCPInspectionResponse, MCPToolCallRequest
from app.toolguard import (
    DRIFT_VIOLATION,
    LIST_METHODS,
    TOOLGUARD_RISK_SCORE,
    PinKind,
    ToolGuard,
)

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
POLICY_BLOCKED = -32003
UPSTREAM_ERROR = -32004
GENERIC_SERVER_ERROR = -32000
RESERVED_GATEWAY_CODES = frozenset({POLICY_BLOCKED, UPSTREAM_ERROR})

MAX_REQUEST_BYTES = 1_048_576
MAX_UPSTREAM_BYTES = 5_242_880
MAX_IDENTIFIER_LENGTH = 256

RequestId = str | int | None

_ENVIRONMENTS: dict[str, Environment] = {
    "dev": "dev",
    "staging": "staging",
    "prod": "prod",
}


class JsonRpcError(Exception):
    """A JSON-RPC 2.0 error object raised during request processing."""

    def __init__(
        self, code: int, message: str, data: dict[str, Any] | None = None
    ) -> None:
        """Store the JSON-RPC error code, message, and optional data."""
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def to_object(self) -> dict[str, Any]:
        """Serialize to a JSON-RPC 2.0 error object."""
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        return error


@dataclass(frozen=True)
class CallContext:
    """Caller routing metadata taken from ``X-Aegis-*`` headers."""

    agent_id: str
    server_name: str
    environment: Environment


@dataclass(frozen=True)
class Envelope:
    """A validated JSON-RPC 2.0 request envelope."""

    req_id: str | int
    method: str
    params: Any


def error_response(req_id: RequestId, error: dict[str, Any]) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response."""
    return {"jsonrpc": "2.0", "id": req_id, "error": error}


def success_response(req_id: RequestId, result: Any) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 success response."""
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _upstream_failure() -> JsonRpcError:
    """Return a generic upstream error that never leaks transport details."""
    return JsonRpcError(UPSTREAM_ERROR, "Upstream MCP server error.")


def _is_valid_id(value: Any) -> bool:
    """JSON-RPC ids must be integers or bounded strings (no bool/null)."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, str) and len(value) <= MAX_IDENTIFIER_LENGTH


def extract_id(payload: Any) -> RequestId:
    """Return the request id if present and valid, otherwise None."""
    if isinstance(payload, dict) and _is_valid_id(payload.get("id")):
        req_id: str | int = payload["id"]
        return req_id
    return None


def parse_body(raw: bytes) -> Any:
    """Decode a size-bounded JSON request body."""
    if len(raw) > MAX_REQUEST_BYTES:
        raise JsonRpcError(INVALID_REQUEST, "Request body too large.")
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise JsonRpcError(PARSE_ERROR, "Parse error.") from exc


def parse_envelope(payload: Any) -> Envelope:
    """Validate a single JSON-RPC 2.0 request object."""
    if not isinstance(payload, dict):
        raise JsonRpcError(
            INVALID_REQUEST, "Expected a single JSON-RPC 2.0 request object."
        )
    if payload.get("jsonrpc") != "2.0" or not isinstance(payload.get("method"), str):
        raise JsonRpcError(INVALID_REQUEST, "Invalid JSON-RPC 2.0 request.")
    if not _is_valid_id(payload.get("id")):
        raise JsonRpcError(
            INVALID_REQUEST, "Request id must be an integer or string (<=256 chars)."
        )
    return Envelope(payload["id"], payload["method"], payload.get("params", {}))


def build_context(
    agent_id: str | None, server_name: str | None, environment: str | None
) -> CallContext:
    """Validate ``X-Aegis-*`` routing headers into a CallContext."""
    agent = agent_id or "default-agent"
    env = _ENVIRONMENTS.get(environment or "prod")
    if (
        env is None
        or not server_name
        or len(server_name) > MAX_IDENTIFIER_LENGTH
        or len(agent) > MAX_IDENTIFIER_LENGTH
    ):
        raise JsonRpcError(INVALID_REQUEST, "Invalid X-Aegis-* routing headers.")
    return CallContext(agent_id=agent, server_name=server_name, environment=env)


def _require_name(params: dict[str, Any]) -> str:
    """Validate the mandatory ``name`` param."""
    name = params.get("name")
    if not isinstance(name, str) or not 0 < len(name) <= MAX_IDENTIFIER_LENGTH:
        raise JsonRpcError(
            INVALID_PARAMS, "params.name must be a non-empty string (<=256 chars)."
        )
    if settings.enable_dlp_redaction and redact_text(name)[1]:
        raise JsonRpcError(
            INVALID_PARAMS, "params.name must not contain sensitive data."
        )
    return name


def _require_arguments_object(params: dict[str, Any]) -> None:
    """Validate the optional ``arguments`` param is an object."""
    if not isinstance(params.get("arguments", {}), dict):
        raise JsonRpcError(INVALID_PARAMS, "params.arguments must be an object.")


def _tools_call(params: dict[str, Any]) -> str:
    """Validate ``tools/call`` params; the tool name is the RBAC subject."""
    name = _require_name(params)
    _require_arguments_object(params)
    return name


def _resources_read(params: dict[str, Any]) -> str:
    """Validate ``resources/read`` params."""
    uri = params.get("uri")
    if not isinstance(uri, str) or not uri:
        raise JsonRpcError(INVALID_PARAMS, "params.uri must be a non-empty string.")
    return "resources/read"


def _prompts_get(params: dict[str, Any]) -> str:
    """Validate ``prompts/get`` params."""
    _require_name(params)
    _require_arguments_object(params)
    return "prompts/get"


METHOD_HANDLERS: dict[str, Callable[[dict[str, Any]], str]] = {
    "tools/call": _tools_call,
    "resources/read": _resources_read,
    "prompts/get": _prompts_get,
}

CALL_KINDS: dict[str, PinKind] = {
    "tools/call": "tool",
    "resources/read": "resource",
    "prompts/get": "prompt",
}

DISCOVERY_METHODS = frozenset(
    {
        "initialize",
        "ping",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
    }
)


def resolve_call(envelope: Envelope) -> tuple[str | None, dict[str, Any]]:
    """Return the RBAC tool name (None for discovery) and the params dict."""
    handler = METHOD_HANDLERS.get(envelope.method)
    if handler is None and envelope.method not in DISCOVERY_METHODS:
        raise JsonRpcError(METHOD_NOT_FOUND, "Method not found.")
    if not isinstance(envelope.params, dict):
        raise JsonRpcError(INVALID_PARAMS, "params must be an object.")
    return (handler(envelope.params) if handler else None), envelope.params


def _drift_error(violations: list[str], audit_hash: str) -> JsonRpcError:
    """Build the -32003 error for a drifted server definition."""
    return JsonRpcError(
        POLICY_BLOCKED,
        "Request blocked by Aegis-MCP security policy.",
        data={
            "decision": "BLOCKED",
            "risk_score": TOOLGUARD_RISK_SCORE,
            "violations": violations,
            "audit_hash": audit_hash,
        },
    )


def redact_value(value: Any) -> Any:
    """DLP-redact any JSON value when enabled, counting categories in metrics."""
    if not settings.enable_dlp_redaction:
        return value
    sanitized, categories = redact_payload({"value": value})
    metrics_registry.record_redactions(categories)
    return sanitized["value"]


def _reject_constant(token: str) -> Any:
    """Reject non-standard JSON constants (NaN, Infinity) from upstreams."""
    raise ValueError(f"Non-standard JSON constant: {token}")


def _neutralize_error(error: dict[str, Any]) -> dict[str, Any]:
    """Stop upstreams from impersonating gateway-reserved error codes."""
    if error["code"] in RESERVED_GATEWAY_CODES:
        return {**error, "code": GENERIC_SERVER_ERROR}
    return error


def validate_upstreams(upstreams: Mapping[str, str]) -> dict[str, str]:
    """Accept only absolute http(s) upstream URLs from server configuration."""
    for server_name, url in upstreams.items():
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(
                f"Invalid upstream URL for MCP server {server_name!r}: "
                "only absolute http(s) URLs are allowed."
            )
    return dict(upstreams)


def _read_capped(response: httpx.Response, deadline: float) -> bytes:
    """Stream an upstream body within the size cap and wall-clock deadline."""
    buffer = bytearray()
    for chunk in response.iter_bytes():
        buffer.extend(chunk)
        if len(buffer) > MAX_UPSTREAM_BYTES or time.monotonic() > deadline:
            raise _upstream_failure()
    return bytes(buffer)


def _is_error_object(error: Any) -> bool:
    """Return True for a structurally valid JSON-RPC error object."""
    return (
        isinstance(error, dict)
        and isinstance(error.get("code"), int)
        and isinstance(error.get("message"), str)
    )


def build_default_client() -> httpx.Client:
    """Build the hardened upstream HTTP client (no redirects, no env proxies)."""
    return httpx.Client(
        timeout=settings.upstream_timeout_seconds,
        follow_redirects=False,
        trust_env=False,
        headers={"Accept": "application/json"},
    )


class JsonRpcGateway:
    """Firewalled JSON-RPC 2.0 MCP proxy with bidirectional DLP redaction."""

    def __init__(
        self,
        firewall: MCPFirewall,
        upstreams: Mapping[str, str] | None = None,
        client: httpx.Client | None = None,
        toolguard: ToolGuard | None = None,
    ) -> None:
        """Bind the firewall, upstream map, HTTP client, and pin store."""
        self.firewall = firewall
        self.upstreams = validate_upstreams(
            settings.mcp_upstreams if upstreams is None else upstreams
        )
        self.client = client or build_default_client()
        self.toolguard = toolguard or ToolGuard(
            firewall.db_path, require_approval=settings.toolguard_require_approval
        )

    def set_upstreams(self, upstreams: Mapping[str, str]) -> None:
        """Atomically replace the validated server-name to URL mapping."""
        self.upstreams = validate_upstreams(upstreams)

    def handle(self, raw: bytes, routing: Mapping[str, str | None]) -> dict[str, Any]:
        """Process one raw JSON-RPC request body and return the response."""
        payload: Any = None
        try:
            payload = parse_body(raw)
            envelope = parse_envelope(payload)
            context = build_context(
                routing.get("agent_id"),
                routing.get("server_name"),
                routing.get("environment"),
            )
            tool_name, params = resolve_call(envelope)
            return self._process(envelope, context, tool_name, params)
        except JsonRpcError as exc:
            return error_response(extract_id(payload), exc.to_object())
        except RecursionError:
            error = JsonRpcError(INVALID_REQUEST, "Request nesting too deep.")
            return error_response(extract_id(payload), error.to_object())

    def _process(
        self,
        envelope: Envelope,
        context: CallContext,
        tool_name: str | None,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Inspect, forward, and redact a validated MCP call."""
        url = self._upstream_url(context)
        outbound = self.prepare(envelope, context, tool_name, params)
        upstream = self._forward(url, envelope, outbound)
        try:
            return self.relay(envelope, context, upstream)
        except RecursionError as exc:
            raise _upstream_failure() from exc

    def prepare(
        self,
        envelope: Envelope,
        context: CallContext,
        tool_name: str | None,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Return the outbound params: inspected calls or redacted discovery."""
        if tool_name is None:
            return dict(redact_value(params))
        report = self._inspect(context, envelope.method, tool_name, params)
        return dict(report.sanitized_arguments)

    def _upstream_url(self, context: CallContext) -> str:
        """Resolve the configured upstream before any inspection or auditing."""
        url = self.upstreams.get(context.server_name)
        if url is None:
            raise JsonRpcError(
                UPSTREAM_ERROR, "No upstream is configured for this MCP server."
            )
        return url

    def _call_denials(
        self, context: CallContext, method: str, params: dict[str, Any]
    ) -> list[str]:
        """Return toolguard violations (drift / unapproved) for a call."""
        kind = CALL_KINDS[method]
        key = params.get("uri" if kind == "resource" else "name")
        if not isinstance(key, str):
            return []
        return self.toolguard.call_violations(context.server_name, kind, key)

    def _inspect(
        self,
        context: CallContext,
        method: str,
        tool_name: str,
        params: dict[str, Any],
    ) -> MCPInspectionResponse:
        """Run threat rules, RBAC, ABAC, toolguard, inbound DLP, and the ledger.

        Argument constraints see the tool/prompt ``params.arguments`` object
        (``resources/read`` exposes ``params`` itself, i.e. its ``uri``).
        """
        nested = params.get("arguments")
        report = self.firewall.inspect(
            MCPToolCallRequest(
                agent_id=context.agent_id,
                server_name=context.server_name,
                tool_name=tool_name,
                arguments=params,
                environment=context.environment,
            ),
            constraint_arguments=nested if isinstance(nested, dict) else params,
            denials=self._call_denials(context, method, params),
        )
        metrics_registry.record_inspection(
            server_name=context.server_name,
            decision=report.decision,
            violations=report.violations,
            redacted_categories=report.redacted_categories,
            would_block=report.would_block,
        )
        if not report.allowed:
            raise JsonRpcError(
                POLICY_BLOCKED,
                "Request blocked by Aegis-MCP security policy.",
                data={
                    "decision": report.decision,
                    "risk_score": report.risk_score,
                    "violations": report.violations,
                    "audit_hash": report.audit_hash,
                },
            )
        return report

    def _audit_violation(
        self, context: CallContext, subject: str, violations: list[str]
    ) -> tuple[bool, str]:
        """Ledger a discovery-time violation; return ``(blocking, audit_hash)``."""
        decision, audit_hash = self.firewall.record_event(
            (context.agent_id, context.server_name, subject, context.environment),
            violations,
        )
        metrics_registry.record_inspection(
            server_name=context.server_name,
            decision=decision,
            violations=violations,
            redacted_categories=[],
            would_block=True,
        )
        return decision == "BLOCKED", audit_hash

    def screen_result(self, method: str, context: CallContext, result: Any) -> Any:
        """Apply toolguard screening to discovery results (others unchanged)."""
        if not isinstance(result, dict):
            return result
        if method == "initialize":
            self._screen_initialize(context, result)
        elif method in LIST_METHODS:
            return self._screen_listing(method, context, result)
        return result

    def _screen_initialize(self, context: CallContext, result: dict[str, Any]) -> None:
        """Pin the server identity + ``instructions``; block on drift."""
        info = result.get("serverInfo")
        definition = {
            "name": "initialize",
            "serverName": info.get("name") if isinstance(info, dict) else None,
            "instructions": result.get("instructions"),
        }
        observation = self.toolguard.observe(context.server_name, "server", definition)
        if observation is not None and observation.verdict == "drifted":
            blocking, audit_hash = self._audit_violation(
                context, "server:initialize", [DRIFT_VIOLATION]
            )
            if blocking:
                raise _drift_error([DRIFT_VIOLATION], audit_hash)

    def _screen_listing(
        self, method: str, context: CallContext, result: dict[str, Any]
    ) -> dict[str, Any]:
        """Filter a ``*/list`` page to pinned, non-drifted, authorized items."""
        kind, field = LIST_METHODS[method]
        items = result.get(field)
        if not isinstance(items, list):
            return result
        kept = [item for item in items if self._admit(context, kind, item)]
        return {**result, field: kept}

    def _admit(self, context: CallContext, kind: PinKind, item: Any) -> bool:
        """Return True if a listed definition may be advertised to the agent."""
        observation = self.toolguard.observe(context.server_name, kind, item)
        if observation is None:
            return False
        if observation.verdict == "drifted":
            blocking, _ = self._audit_violation(
                context, f"{kind}:{observation.name}", [DRIFT_VIOLATION]
            )
            return not blocking
        if settings.policy_mode == "monitor":
            return True
        if self.toolguard.needs_approval(kind, observation.verdict):
            return False
        if kind != "tool":
            return True
        return self.firewall.policy_engine.is_allowed(
            context.agent_id, context.server_name, observation.name, context.environment
        )

    def _forward(
        self, url: str, envelope: Envelope, params: dict[str, Any]
    ) -> dict[str, Any]:
        """POST the sanitized envelope to the configured upstream."""
        deadline = time.monotonic() + settings.upstream_timeout_seconds
        outbound = {
            "jsonrpc": "2.0",
            "id": envelope.req_id,
            "method": envelope.method,
            "params": params,
        }
        try:
            request = self.client.build_request("POST", url, json=outbound)
            strip_credentials(request.headers)
            response = self.client.send(request, stream=True)
            try:
                if response.status_code != httpx.codes.OK:
                    raise _upstream_failure()
                body = _read_capped(response, deadline)
            finally:
                response.close()
            payload = json.loads(body, parse_constant=_reject_constant)
        except (httpx.HTTPError, ValueError, RecursionError) as exc:
            raise _upstream_failure() from exc
        if not isinstance(payload, dict):
            raise _upstream_failure()
        return payload

    def relay(
        self, envelope: Envelope, context: CallContext, upstream: dict[str, Any]
    ) -> dict[str, Any]:
        """Screen + redact the upstream result/error, bound to the caller's id."""
        req_id = envelope.req_id
        if "result" in upstream:
            result = self.screen_result(envelope.method, context, upstream["result"])
            return success_response(req_id, redact_value(result))
        error = upstream.get("error")
        if _is_error_object(error):
            return error_response(req_id, _neutralize_error(redact_value(error)))
        raise _upstream_failure()
