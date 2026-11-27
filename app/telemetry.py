"""OpenTelemetry tracing, request correlation, and structured JSON logging.

Spans follow the OpenTelemetry GenAI / MCP semantic conventions
(``gen_ai.system``, ``gen_ai.operation.name``, ``mcp.method.name``,
``mcp.server.name``, ``mcp.tool.name``) plus Aegis attributes
(``aegis.decision``, ``aegis.risk_score``, ``aegis.session.id``). Session
identifiers are bearer-like, so spans only carry a truncated SHA-256
pseudonym; agent identities, arguments and payloads are never recorded.

Tracing is a no-op until a ``TracerProvider`` is installed, either from
settings (OTLP/HTTP exporter) or explicitly (tests use an in-memory
exporter). Every log line of the ``aegis_mcp`` logger namespace is scrubbed
by the DLP redactor and carries ``trace_id``/``span_id``/``request_id``.
"""

import hashlib
import json
import logging
import re
import sys
import uuid
from collections.abc import Mapping
from contextvars import ContextVar
from datetime import UTC, datetime
from time import perf_counter
from typing import Any, Final

from opentelemetry import propagate, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.util.types import AttributeValue
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import Settings
from app.redactor import redact_text

__all__ = [
    "GEN_AI_SYSTEM",
    "JsonLogFormatter",
    "ObservabilityMiddleware",
    "configure_logging",
    "current_request_id",
    "get_tracer",
    "install_tracer_provider",
    "session_ref",
    "setup_tracing",
]

INSTRUMENTATION_NAME: Final = "aegis_mcp"
GEN_AI_SYSTEM: Final = "mcp"
REQUEST_ID_HEADER: Final = "x-request-id"
OTLP_TRACES_PATH: Final = "/v1/traces"
LOGGER_NAMESPACE: Final = "aegis_mcp"

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")
_request_id: ContextVar[str | None] = ContextVar("aegis_request_id", default=None)

# Structured fields copied from ``logging`` ``extra=`` into JSON lines.
LOG_FIELDS: Final = (
    "event",
    "decision",
    "risk_score",
    "violations",
    "server_name",
    "tool_name",
    "method",
    "route",
    "status_code",
    "duration_ms",
)

_tracer: trace.Tracer = trace.NoOpTracer()

access_logger = logging.getLogger("aegis_mcp.http")


# --------------------------------------------------------------------------
# Tracing
# --------------------------------------------------------------------------


def get_tracer() -> trace.Tracer:
    """Return the Aegis tracer (no-op unless a provider is installed)."""
    return _tracer


def install_tracer_provider(provider: TracerProvider | None) -> None:
    """Route Aegis spans to ``provider`` (``None`` restores the no-op tracer)."""
    global _tracer
    _tracer = (
        provider.get_tracer(INSTRUMENTATION_NAME)
        if provider is not None
        else trace.NoOpTracer()
    )


def otlp_traces_url(endpoint: str) -> str:
    """Normalize a collector base URL to its OTLP/HTTP traces endpoint."""
    base = endpoint.rstrip("/")
    return base if base.endswith(OTLP_TRACES_PATH) else base + OTLP_TRACES_PATH


def build_tracer_provider(config: Settings) -> TracerProvider:
    """Build an OTLP/HTTP-exporting provider for ``config``."""
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )

    resource = Resource.create(
        {
            "service.name": config.otel_service_name,
            "deployment.environment.name": config.environment,
        }
    )
    provider = TracerProvider(resource=resource)
    endpoint = otlp_traces_url(config.otel_endpoint) if config.otel_endpoint else None
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint)))
    return provider


def setup_tracing(config: Settings) -> TracerProvider | None:
    """Install the OTLP provider when tracing is active; return it."""
    if not config.otel_active():
        return None
    provider = build_tracer_provider(config)
    install_tracer_provider(provider)
    return provider


def session_ref(session_id: str | None) -> str:
    """Pseudonymous, correlatable reference to a session (never the raw id)."""
    if not session_id:
        return ""
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]


def mcp_attributes(
    server_name: str | None,
    session_id: str | None = None,
    **extra: AttributeValue | None,
) -> dict[str, AttributeValue]:
    """GenAI/MCP span attributes (``None`` values are omitted)."""
    attributes: dict[str, AttributeValue | None] = {
        "gen_ai.system": GEN_AI_SYSTEM,
        "mcp.server.name": server_name,
        "aegis.session.id": session_ref(session_id) or None,
        **extra,
    }
    return {key: value for key, value in attributes.items() if value is not None}


def decision_attributes(
    tool_name: str, decision: str, risk_score: int, violations: list[str]
) -> dict[str, AttributeValue]:
    """Verdict attributes for an inspected tool call."""
    return {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": tool_name,
        "mcp.tool.name": tool_name,
        "aegis.decision": decision,
        "aegis.risk_score": risk_score,
        "aegis.violations": violations,
    }


def annotate_current_span(attributes: Mapping[str, AttributeValue]) -> None:
    """Attach attributes to the active span (no-op when not recording)."""
    trace.get_current_span().set_attributes(dict(attributes))


# --------------------------------------------------------------------------
# Request correlation and structured logging
# --------------------------------------------------------------------------


def current_request_id() -> str | None:
    """Request id of the HTTP request being served (if any)."""
    return _request_id.get()


def resolve_request_id(candidate: str | None) -> str:
    """Accept a well-formed client ``X-Request-Id``, else mint a new one."""
    if candidate and _REQUEST_ID_PATTERN.fullmatch(candidate):
        return candidate
    return uuid.uuid4().hex


def sanitize_log_value(value: object) -> str:
    """Strip CR/LF and ASCII control chars to prevent log injection (CWE-117)."""
    cleaned = str(value).replace("\r", "").replace("\n", "")
    return "".join(ch if ord(ch) >= 32 and ord(ch) != 127 else "_" for ch in cleaned)


def _scrub(value: Any) -> Any:
    """DLP-redact strings (recursively through lists); keep other scalars."""
    if isinstance(value, str):
        return redact_text(value)[0]
    if isinstance(value, list | tuple):
        return [_scrub(item) for item in value]
    if isinstance(value, bool | int | float) or value is None:
        return value
    return redact_text(str(value))[0]


def trace_context() -> dict[str, str | None]:
    """``trace_id``/``span_id`` of the active span (``None`` when absent)."""
    context = trace.get_current_span().get_span_context()
    if not context.is_valid:
        return {"trace_id": None, "span_id": None}
    return {
        "trace_id": trace.format_trace_id(context.trace_id),
        "span_id": trace.format_span_id(context.span_id),
    }


class JsonLogFormatter(logging.Formatter):
    """One DLP-scrubbed JSON object per line with trace correlation."""

    def format(self, record: logging.LogRecord) -> str:
        """Serialize ``record`` (message, whitelisted extras, trace ids)."""
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": _scrub(record.getMessage()),
            "request_id": current_request_id(),
            **trace_context(),
        }
        for field in LOG_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                entry[field] = _scrub(value)
        if record.exc_info and record.exc_info[0] is not None:
            # Exception type only: tracebacks/messages may echo payloads.
            entry["exception"] = record.exc_info[0].__name__
        return json.dumps(entry, ensure_ascii=False, default=str)


class RedactingTextFormatter(logging.Formatter):
    """Human-readable formatter with DLP scrubbing and correlation ids."""

    def __init__(self) -> None:
        """Use a fixed ``timestamp level logger message`` layout."""
        super().__init__("%(asctime)s %(levelname)s %(name)s %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        """Format, append ``request_id``/``trace_id``, then scrub."""
        line = super().format(record)
        suffix = f" request_id={current_request_id() or '-'}"
        suffix += f" trace_id={trace_context()['trace_id'] or '-'}"
        return str(redact_text(line + suffix)[0])


class AegisLogHandler(logging.Handler):
    """Write to the *current* ``sys.stderr`` (survives stream swapping)."""

    def emit(self, record: logging.LogRecord) -> None:
        """Format and write one record."""
        try:
            sys.stderr.write(self.format(record) + "\n")
        except Exception:  # pragma: no cover - logging must never raise
            self.handleError(record)


def configure_logging(log_format: str, level: int = logging.INFO) -> AegisLogHandler:
    """Install (or replace) the ``aegis_mcp`` handler for ``log_format``."""
    logger = logging.getLogger(LOGGER_NAMESPACE)
    for handler in list(logger.handlers):
        if isinstance(handler, AegisLogHandler):
            logger.removeHandler(handler)
    installed = AegisLogHandler()
    installed.setFormatter(
        JsonLogFormatter() if log_format == "json" else RedactingTextFormatter()
    )
    logger.addHandler(installed)
    logger.setLevel(level)
    return installed


# --------------------------------------------------------------------------
# ASGI middleware
# --------------------------------------------------------------------------


def _route_template(scope: Scope) -> str:
    """Matched route template (bounded), else a constant placeholder."""
    route = scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) else "unmatched"


class ObservabilityMiddleware:
    """Server span, ``X-Request-Id`` correlation, and JSON access logs.

    Pure ASGI (no response buffering) so SSE streams are unaffected. The
    W3C ``traceparent`` of the caller is honored as the parent context.
    """

    def __init__(self, app: ASGIApp) -> None:
        """Wrap ``app``."""
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Trace and correlate one HTTP request."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        request_id = resolve_request_id(headers.get(REQUEST_ID_HEADER))
        token = _request_id.set(request_id)
        response = {"status": 500}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                response["status"] = int(message["status"])
                extra = (REQUEST_ID_HEADER.encode(), request_id.encode())
                message = {**message, "headers": [*message.get("headers", []), extra]}
            await send(message)

        method = str(scope.get("method", "GET"))
        start = perf_counter()
        try:
            with get_tracer().start_as_current_span(
                f"HTTP {method}",
                context=propagate.extract(dict(headers.items())),
                kind=trace.SpanKind.SERVER,
                attributes={"http.request.method": method},
            ) as span:
                try:
                    await self.app(scope, receive, send_wrapper)
                finally:
                    _finish_request(span, scope, method, response["status"], start)
        finally:
            _request_id.reset(token)


def _finish_request(
    span: trace.Span, scope: Scope, method: str, status: int, start: float
) -> None:
    """Name the server span after its route and emit the access log line."""
    route = _route_template(scope)
    span.update_name(f"{method} {route}")
    span.set_attributes({"http.route": route, "http.response.status_code": status})
    access_logger.info(
        "http request",
        extra={
            "event": "http.request",
            "method": method,
            "route": route,
            "status_code": status,
            "duration_ms": round((perf_counter() - start) * 1000, 3),
        },
    )
