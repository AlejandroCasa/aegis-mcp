"""Native MCP Streamable HTTP transport (``POST``/``GET``/``DELETE /mcp``).

A firewalled implementation of the MCP Streamable HTTP transport (spec
revisions ``2025-03-26`` and later) in front of the configured upstreams:

* **Origin validation** (DNS-rebinding defense): a request carrying an
  ``Origin`` header outside ``AEGIS_MCP_ALLOWED_ORIGINS`` gets ``403``
  (non-browser clients send no ``Origin`` and are allowed).
* **Sessions**: a successful ``initialize`` mints a gateway
  ``Mcp-Session-Id`` (256-bit random) bound to the caller's agent identity,
  MCP server, and environment. The upstream's own session id stays
  server-side and is never exposed. Every later request needs the header
  (``400`` if missing, ``404`` if unknown, expired, or owned by another
  agent/server); ``DELETE`` terminates the session (and, best effort, the
  upstream one). An upstream ``404`` expires the gateway session so the
  client re-initializes.
* **Version negotiation**: the upstream's negotiated ``protocolVersion``
  must be supported or no session is created; later requests carrying a
  different ``MCP-Protocol-Version`` get ``400``. The negotiated version is
  forwarded upstream.
* **Messages**: requests run the ``POST /api/v1/mcp/jsonrpc`` pipeline
  (threat rules, RBAC/ABAC, toolguard, DLP, ledger entries bound to the
  session id). ``notifications/*`` and client responses to server requests
  are DLP-redacted, forwarded, and acknowledged with ``202``. JSON-RPC batches
  are accepted only for sessions that negotiated ``2025-03-26`` (the one
  revision defining them); each request is forwarded individually and the
  replies are returned as a JSON array.
* **Streaming**: when the client accepts ``text/event-stream`` and the
  upstream answers with SSE, events are relayed one by one; each event is
  parsed and DLP-redacted, the final response is toolguard-screened and
  bound to the caller's id, malformed events are dropped, and a missing
  final response becomes ``-32004``. ``GET`` relays the upstream's
  server-initiated stream with the same per-event DLP. Streams are capped by
  ``AEGIS_MCP_STREAM_TIMEOUT_SECONDS``.
"""

import contextlib
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

import httpx

from app.auth import strip_credentials
from app.config import settings
from app.jsonrpc import (
    INVALID_REQUEST,
    MAX_REQUEST_BYTES,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    UPSTREAM_ERROR,
    CallContext,
    Envelope,
    JsonRpcError,
    JsonRpcGateway,
    build_context,
    error_response,
    extract_id,
    parse_envelope,
    read_capped,
    redact_value,
    reject_constant,
    resolve_call,
    upstream_failure,
)
from app.sse import SseError, format_sse, iter_sse_events, safe_event_id

SUPPORTED_PROTOCOL_VERSIONS = frozenset(
    {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}
)
BATCH_PROTOCOL_VERSIONS = frozenset({"2025-03-26"})
SESSION_HEADER = "Mcp-Session-Id"
VERSION_HEADER = "MCP-Protocol-Version"
JSON_MEDIA_TYPE = "application/json"
SSE_MEDIA_TYPE = "text/event-stream"
UPSTREAM_ACCEPT = f"{JSON_MEDIA_TYPE}, {SSE_MEDIA_TYPE}"
SESSION_ID_PATTERN = re.compile(r"[\x21-\x7e]{1,1024}")
RELAY_FAILURES: tuple[type[BaseException], ...] = (
    JsonRpcError,
    SseError,
    ValueError,
    RecursionError,
    httpx.HTTPError,
)

Headers = Mapping[str, str]
Routing = Mapping[str, str | None]


class TransportError(Exception):
    """An HTTP-level rejection: status plus a JSON-RPC error body (no id)."""

    def __init__(self, status: int, message: str, code: int = INVALID_REQUEST) -> None:
        """Store the HTTP status, message, and JSON-RPC error code."""
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code

    def reply(self) -> "TransportReply":
        """Render the rejection as a transport reply."""
        body = error_response(None, {"code": self.code, "message": self.message})
        return TransportReply(self.status, body)


class UpstreamStatusError(JsonRpcError):
    """The upstream answered with a non-2xx HTTP status."""

    def __init__(self, status: int) -> None:
        """Keep the upstream status for transport-level mapping."""
        super().__init__(UPSTREAM_ERROR, "Upstream MCP server error.")
        self.status = status


@dataclass(frozen=True)
class TransportReply:
    """Framework-neutral HTTP reply: JSON ``body``, SSE ``stream``, or empty."""

    status: int
    body: Any = None
    stream: Iterator[bytes] | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class McpSession:
    """A gateway session bound to one caller, server, and protocol version."""

    session_id: str
    context: CallContext
    protocol_version: str
    upstream_session_id: str | None


class SessionStore:
    """Thread-safe in-memory session table with sliding TTL and capacity."""

    def __init__(
        self,
        ttl_seconds: float,
        capacity: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Configure the lifetime, capacity, and clock of the table."""
        self.ttl_seconds = ttl_seconds
        self.capacity = capacity
        self._clock = clock
        self._lock = threading.Lock()
        self._sessions: dict[str, tuple[McpSession, float]] = {}

    def __len__(self) -> int:
        """Number of stored (possibly expired) sessions."""
        return len(self._sessions)

    def add(self, session: McpSession) -> None:
        """Store ``session``; ``503`` when the table is full of live sessions."""
        with self._lock:
            now = self._clock()
            self._sessions = {
                key: entry for key, entry in self._sessions.items() if entry[1] > now
            }
            if len(self._sessions) >= self.capacity:
                raise TransportError(503, "MCP session capacity exhausted.")
            self._sessions[session.session_id] = (session, now + self.ttl_seconds)

    def get(self, session_id: str) -> McpSession | None:
        """Return a live session and extend its lifetime, else None."""
        with self._lock:
            now = self._clock()
            entry = self._sessions.get(session_id)
            if entry is None or entry[1] <= now:
                self._sessions.pop(session_id, None)
                return None
            self._sessions[session_id] = (entry[0], now + self.ttl_seconds)
            return entry[0]

    def remove(self, session_id: str) -> None:
        """Forget a session (no-op if unknown)."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def clear(self) -> None:
        """Forget every session."""
        with self._lock:
            self._sessions.clear()


def check_origin(headers: Headers) -> None:
    """Reject browser origins outside the allowlist (DNS rebinding)."""
    origin = headers.get("origin")
    if origin is not None and origin not in settings.mcp_allowed_origins:
        raise TransportError(403, "Origin not allowed.")


def accepts(headers: Headers, media_type: str) -> bool:
    """Return True if the ``Accept`` header admits ``media_type``.

    A missing ``Accept`` header is treated as ``application/json`` only.
    """
    accept = headers.get("accept")
    if accept is None:
        return media_type == JSON_MEDIA_TYPE
    ranges = {part.split(";")[0].strip().lower() for part in accept.split(",")}
    major = media_type.split("/")[0]
    return bool(ranges & {media_type, f"{major}/*", "*/*"})


def _media_type(value: str | None) -> str:
    """Return the bare, lower-cased media type of a Content-Type value."""
    return (value or "").split(";")[0].strip().lower()


def _check_post_headers(headers: Headers) -> bool:
    """Validate ``Accept``/``Content-Type``; return True if SSE is accepted."""
    stream_ok = accepts(headers, SSE_MEDIA_TYPE)
    if not (stream_ok or accepts(headers, JSON_MEDIA_TYPE)):
        raise TransportError(
            406, "Accept must include application/json or text/event-stream."
        )
    if _media_type(headers.get("content-type")) != JSON_MEDIA_TYPE:
        raise TransportError(415, "Content-Type must be application/json.")
    return stream_ok


def parse_messages(body: bytes) -> tuple[list[Any], bool]:
    """Decode a POST body into ``(messages, batched)``."""
    if len(body) > MAX_REQUEST_BYTES:
        raise TransportError(413, "Request body too large.")
    try:
        payload = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise TransportError(400, "Parse error.", PARSE_ERROR) from exc
    if not isinstance(payload, list):
        return [payload], False
    if not payload:
        raise TransportError(400, "Empty JSON-RPC batch.")
    return payload, True


def message_kind(message: Any) -> str:
    """Classify a message: request, notification, response, or invalid."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return "invalid"
    if "method" in message:
        return "request" if "id" in message else "notification"
    if "id" in message and ("result" in message or "error" in message):
        return "response"
    return "invalid"


def _is_initialize(messages: list[Any], batched: bool) -> bool:
    """Return True for a lone ``initialize`` (it must never be batched)."""
    flags = [isinstance(m, dict) and m.get("method") == "initialize" for m in messages]
    if batched and any(flags):
        raise TransportError(400, "initialize must not be part of a JSON-RPC batch.")
    return not batched and flags[0]


def _owns(session: McpSession, routing: Routing) -> bool:
    """Return True if the caller is the agent/server the session is bound to."""
    agent = routing.get("agent_id") or "default-agent"
    server = routing.get("server_name")
    context = session.context
    return agent == context.agent_id and server in (None, context.server_name)


def _negotiated_version(reply: dict[str, Any]) -> str | None:
    """Return the supported ``protocolVersion`` of an initialize result."""
    result = reply.get("result")
    version = result.get("protocolVersion") if isinstance(result, dict) else None
    return version if version in SUPPORTED_PROTOCOL_VERSIONS else None


def _upstream_headers(session: McpSession | None, accept: str) -> dict[str, str]:
    """Headers for an upstream hop carrying the upstream session/version."""
    headers = {"Accept": accept}
    if session is not None:
        headers[VERSION_HEADER] = session.protocol_version
        if session.upstream_session_id:
            headers[SESSION_HEADER] = session.upstream_session_id
    return headers


def _upstream_session(response: httpx.Response) -> str | None:
    """Return the upstream ``Mcp-Session-Id`` if it is well-formed."""
    value = response.headers.get(SESSION_HEADER)
    if isinstance(value, str) and SESSION_ID_PATTERN.fullmatch(value):
        return value
    return None


def _stream_timeout() -> httpx.Timeout:
    """Connect/write within the upstream timeout; reads may idle longer."""
    return httpx.Timeout(
        settings.upstream_timeout_seconds, read=settings.mcp_stream_timeout_seconds
    )


def is_event_stream(response: httpx.Response) -> bool:
    """Return True if the upstream answered with ``text/event-stream``."""
    return _media_type(response.headers.get("content-type")) == SSE_MEDIA_TYPE


def _deadline_lines(response: httpx.Response, deadline: float) -> Iterator[str]:
    """Yield body lines until the wall-clock deadline passes."""
    for line in response.iter_lines():
        if time.monotonic() > deadline:
            raise upstream_failure()
        yield line


def _sse_messages(
    response: httpx.Response, deadline: float
) -> Iterator[tuple[Any, str | None]]:
    """Yield ``(message, event_id)`` per SSE event; malformed data is dropped."""
    for event in iter_sse_events(_deadline_lines(response, deadline)):
        try:
            message = json.loads(event.data, parse_constant=reject_constant)
        except (ValueError, RecursionError):
            continue
        yield message, event.event_id


def upstream_messages(response: httpx.Response) -> Iterator[tuple[Any, str | None]]:
    """Yield the JSON-RPC messages of a JSON or SSE upstream body."""
    if is_event_stream(response):
        deadline = time.monotonic() + settings.mcp_stream_timeout_seconds
        yield from _sse_messages(response, deadline)
        return
    deadline = time.monotonic() + settings.upstream_timeout_seconds
    payload = json.loads(
        read_capped(response, deadline), parse_constant=reject_constant
    )
    for message in payload if isinstance(payload, list) else [payload]:
        yield message, None


def server_message(message: Any) -> dict[str, Any] | None:
    """DLP-redact a server-initiated request/notification (else None)."""
    if not isinstance(message, dict) or not isinstance(message.get("method"), str):
        return None
    fields = {key: message[key] for key in ("id", "method", "params") if key in message}
    return dict(redact_value({"jsonrpc": "2.0", **fields}))


def _one_way_message(message: dict[str, Any]) -> dict[str, Any]:
    """Rebuild a notification or client response with only standard fields."""
    keys = ("method", "params") if "method" in message else ("id", "result", "error")
    fields = {key: message[key] for key in keys if key in message}
    return dict(redact_value({"jsonrpc": "2.0", **fields}))


def _is_reply_to(message: dict[str, Any], envelope: Envelope) -> bool:
    """Return True if ``message`` is the response to ``envelope`` (strict id)."""
    reply_id = message.get("id")
    return type(reply_id) is type(envelope.req_id) and reply_id == envelope.req_id


class StreamableHttpTransport:
    """MCP Streamable HTTP endpoint on top of the firewalled gateway."""

    def __init__(
        self, gateway: JsonRpcGateway, sessions: SessionStore | None = None
    ) -> None:
        """Bind the gateway (pipeline + HTTP client) and the session table."""
        self.gateway = gateway
        self.sessions = sessions or SessionStore(
            settings.mcp_session_ttl_seconds, settings.mcp_max_sessions
        )

    # -- HTTP methods -------------------------------------------------------

    def post(self, headers: Headers, body: bytes, routing: Routing) -> TransportReply:
        """Handle ``POST /mcp``: one message or a batch."""
        try:
            check_origin(headers)
            stream_ok = _check_post_headers(headers)
            messages, batched = parse_messages(body)
            if _is_initialize(messages, batched):
                return self._initialize(messages[0], routing)
            session = self._session(headers, routing)
            return self._dispatch(session, messages, batched, stream_ok)
        except TransportError as exc:
            return exc.reply()

    def get(self, headers: Headers, routing: Routing) -> TransportReply:
        """Handle ``GET /mcp``: relay the server-initiated SSE stream."""
        try:
            check_origin(headers)
            if not accepts(headers, SSE_MEDIA_TYPE):
                raise TransportError(406, "Accept must include text/event-stream.")
            session = self._session(headers, routing)
            response = self._open_server_stream(session, headers)
        except TransportError as exc:
            return exc.reply()
        return TransportReply(200, stream=self._server_stream(response))

    def delete(self, headers: Headers, routing: Routing) -> TransportReply:
        """Handle ``DELETE /mcp``: terminate the session."""
        try:
            check_origin(headers)
            session = self._session(headers, routing)
        except TransportError as exc:
            return exc.reply()
        self.sessions.remove(session.session_id)
        self._terminate_upstream(session)
        return TransportReply(204)

    # -- Sessions -----------------------------------------------------------

    def _session(self, headers: Headers, routing: Routing) -> McpSession:
        """Resolve and authorize the caller's session and protocol version."""
        session_id = headers.get("mcp-session-id")
        if not session_id:
            raise TransportError(400, "Missing Mcp-Session-Id header.")
        session = self.sessions.get(session_id)
        if session is None or not _owns(session, routing):
            raise TransportError(404, "MCP session not found.")
        version = headers.get("mcp-protocol-version")
        if version is not None and version != session.protocol_version:
            raise TransportError(400, "Unsupported or mismatched MCP-Protocol-Version.")
        return session

    def _initialize(self, message: Any, routing: Routing) -> TransportReply:
        """Run ``initialize`` upstream and mint a gateway session on success."""
        try:
            envelope = parse_envelope(message)
            context = build_context(
                routing.get("agent_id"),
                routing.get("server_name"),
                routing.get("environment"),
            )
        except JsonRpcError as exc:
            raise TransportError(400, exc.message, exc.code) from exc
        context = replace(context, session_id=secrets.token_urlsafe(32))
        try:
            reply, upstream_session_id = self._initialize_upstream(envelope, context)
        except JsonRpcError as exc:
            return TransportReply(200, error_response(envelope.req_id, exc.to_object()))
        return self._open_session(envelope, context, reply, upstream_session_id)

    def _initialize_upstream(
        self, envelope: Envelope, context: CallContext
    ) -> tuple[dict[str, Any], str | None]:
        """Forward the redacted ``initialize``; return (reply, upstream sid)."""
        _, params = resolve_call(envelope)
        url = self.gateway.upstream_url(context)
        outbound = self.gateway.prepare(envelope, context, None, params)
        response = self._post_upstream(url, _request(envelope, outbound), None)
        upstream_session_id = _upstream_session(response)
        return self._collect(context, envelope, response), upstream_session_id

    def _open_session(
        self,
        envelope: Envelope,
        context: CallContext,
        reply: dict[str, Any],
        upstream_session_id: str | None,
    ) -> TransportReply:
        """Register the session if the upstream negotiated a supported version."""
        if "error" in reply:
            return TransportReply(200, reply)
        version = _negotiated_version(reply)
        if version is None:
            error = {
                "code": UPSTREAM_ERROR,
                "message": "Upstream negotiated an unsupported MCP protocol version.",
            }
            return TransportReply(200, error_response(envelope.req_id, error))
        session = McpSession(context.session_id, context, version, upstream_session_id)
        self.sessions.add(session)
        return TransportReply(200, reply, headers={SESSION_HEADER: session.session_id})

    # -- POST dispatch ------------------------------------------------------

    def _dispatch(
        self,
        session: McpSession,
        messages: list[Any],
        batched: bool,
        stream_ok: bool,
    ) -> TransportReply:
        """Route a single message or a batch within an established session."""
        if batched:
            if session.protocol_version not in BATCH_PROTOCOL_VERSIONS:
                raise TransportError(
                    400, "JSON-RPC batches are not supported by this protocol version."
                )
            return self._batch(session, messages)
        message = messages[0]
        kind = message_kind(message)
        if kind == "request":
            return self._request(session, message, stream_ok)
        if kind == "invalid":
            raise TransportError(400, "Invalid JSON-RPC 2.0 message.")
        try:
            self._one_way(session, message)
        except JsonRpcError as exc:
            status = 502 if exc.code == UPSTREAM_ERROR else 400
            raise TransportError(status, exc.message, exc.code) from exc
        return TransportReply(202)

    def _batch(self, session: McpSession, messages: list[Any]) -> TransportReply:
        """Process each batch member; reply with the responses (or ``202``)."""
        replies = [
            reply
            for reply in (self._batch_member(session, m) for m in messages)
            if reply is not None
        ]
        return TransportReply(200, replies) if replies else TransportReply(202)

    def _batch_member(self, session: McpSession, message: Any) -> Any:
        """Return a member's response (None for notifications/responses)."""
        kind = message_kind(message)
        if kind == "request":
            return self._request(session, message, stream_ok=False).body
        if kind == "invalid":
            error = {
                "code": INVALID_REQUEST,
                "message": "Invalid JSON-RPC 2.0 message.",
            }
            return error_response(None, error)
        # One-way members have no response slot; failures are not reportable.
        with contextlib.suppress(JsonRpcError):
            self._one_way(session, message)
        return None

    def _request(
        self, session: McpSession, message: dict[str, Any], stream_ok: bool
    ) -> TransportReply:
        """Inspect, forward, and relay one request as JSON or SSE."""
        context = session.context
        try:
            envelope = parse_envelope(message)
            tool_name, params = resolve_call(envelope)
            url = self.gateway.upstream_url(context)
            outbound = self.gateway.prepare(envelope, context, tool_name, params)
            response = self._post_upstream(url, _request(envelope, outbound), session)
        except JsonRpcError as exc:
            return TransportReply(
                200, error_response(extract_id(message), exc.to_object())
            )
        except RecursionError:
            error = JsonRpcError(INVALID_REQUEST, "Request nesting too deep.")
            return TransportReply(
                200, error_response(extract_id(message), error.to_object())
            )
        if stream_ok and is_event_stream(response):
            events = self._relay_events(context, envelope, response)
            stream = (format_sse(event, event_id) for event, event_id in events)
            return TransportReply(200, stream=stream)
        return TransportReply(200, self._collect(context, envelope, response))

    def _one_way(self, session: McpSession, message: dict[str, Any]) -> None:
        """Forward a redacted ``notifications/*`` or client response."""
        method = message.get("method", "notifications/")
        if not isinstance(method, str) or not method.startswith("notifications/"):
            raise JsonRpcError(METHOD_NOT_FOUND, "Method not found.")
        url = self.gateway.upstream_url(session.context)
        self._post_upstream(url, _one_way_message(message), session).close()

    # -- Upstream I/O -------------------------------------------------------

    def _post_upstream(
        self, url: str, message: dict[str, Any], session: McpSession | None
    ) -> httpx.Response:
        """POST one message upstream and return the open streamed response."""
        request = self.gateway.client.build_request(
            "POST",
            url,
            json=message,
            headers=_upstream_headers(session, UPSTREAM_ACCEPT),
            timeout=_stream_timeout(),
        )
        return self._send(request, session)

    def _send(
        self, request: httpx.Request, session: McpSession | None
    ) -> httpx.Response:
        """Send without caller credentials; non-2xx raises UpstreamStatusError."""
        strip_credentials(request.headers)
        try:
            response = self.gateway.client.send(request, stream=True)
        except httpx.HTTPError as exc:
            raise upstream_failure() from exc
        if response.is_success:
            return response
        response.close()
        if response.status_code == 404 and session and session.upstream_session_id:
            self.sessions.remove(session.session_id)
        raise UpstreamStatusError(response.status_code)

    def _relay_events(
        self, context: CallContext, envelope: Envelope, response: httpx.Response
    ) -> Iterator[tuple[dict[str, Any], str | None]]:
        """Yield screened messages, always ending with one final response."""
        try:
            with contextlib.suppress(*RELAY_FAILURES):
                for message, event_id in upstream_messages(response):
                    relayed, final = self._screen(context, envelope, message)
                    if relayed is not None:
                        yield relayed, event_id
                    if final:
                        return
        finally:
            response.close()
        yield error_response(envelope.req_id, upstream_failure().to_object()), None

    def _screen(
        self, context: CallContext, envelope: Envelope, message: Any
    ) -> tuple[dict[str, Any] | None, bool]:
        """Return ``(message to relay or None, is_final_response)``."""
        if isinstance(message, dict) and "method" in message:
            return server_message(message), False
        if not isinstance(message, dict) or not _is_reply_to(message, envelope):
            return None, False
        try:
            return self.gateway.relay(envelope, context, message), True
        except JsonRpcError as exc:
            return error_response(envelope.req_id, exc.to_object()), True

    def _collect(
        self, context: CallContext, envelope: Envelope, response: httpx.Response
    ) -> dict[str, Any]:
        """Drain the upstream reply and return only the final response."""
        final: dict[str, Any] = {}
        for message, _ in self._relay_events(context, envelope, response):
            final = message
        return final

    def _open_server_stream(
        self, session: McpSession, headers: Headers
    ) -> httpx.Response:
        """Open the upstream GET stream (``405`` when it offers none)."""
        request_headers = _upstream_headers(session, SSE_MEDIA_TYPE)
        last_event_id = safe_event_id(headers.get("last-event-id"))
        if last_event_id is not None:
            request_headers["Last-Event-ID"] = last_event_id
        try:
            url = self.gateway.upstream_url(session.context)
            request = self.gateway.client.build_request(
                "GET", url, headers=request_headers, timeout=_stream_timeout()
            )
            response = self._send(request, session)
        except UpstreamStatusError as exc:
            status = 405 if exc.status == 405 else 502
            raise TransportError(status, exc.message, exc.code) from exc
        except JsonRpcError as exc:
            raise TransportError(502, exc.message, exc.code) from exc
        if not is_event_stream(response):
            response.close()
            raise TransportError(
                502, "Upstream did not return an event stream.", UPSTREAM_ERROR
            )
        return response

    @staticmethod
    def _server_stream(response: httpx.Response) -> Iterator[bytes]:
        """Relay server-initiated messages with per-event DLP."""
        try:
            with contextlib.suppress(*RELAY_FAILURES):
                for message, event_id in upstream_messages(response):
                    relayed = server_message(message)
                    if relayed is not None:
                        yield format_sse(relayed, event_id)
        finally:
            response.close()

    def _terminate_upstream(self, session: McpSession) -> None:
        """Best-effort ``DELETE`` of the upstream session."""
        if not session.upstream_session_id:
            return
        with contextlib.suppress(JsonRpcError, httpx.HTTPError):
            url = self.gateway.upstream_url(session.context)
            request = self.gateway.client.build_request(
                "DELETE", url, headers=_upstream_headers(session, JSON_MEDIA_TYPE)
            )
            self._send(request, None).close()


def _request(envelope: Envelope, params: dict[str, Any]) -> dict[str, Any]:
    """Build the sanitized outbound request bound to the caller's id."""
    return {
        "jsonrpc": "2.0",
        "id": envelope.req_id,
        "method": envelope.method,
        "params": params,
    }
