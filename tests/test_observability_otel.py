"""TDD suite for OpenTelemetry spans, SLO histograms, JSON logs and dashboards."""

import asyncio
import io
import json
import logging
import re
import sqlite3
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient
from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from starlette.types import Message, Receive, Scope, Send

from app.config import Settings, settings
from app.ledger import AuditLedger
from app.main import app, firewall, jsonrpc_gateway, mcp_transport, policy_engine
from app.merkle import CheckpointSigner, TreeHead
from app.metrics import (
    INSPECTION_BUCKETS,
    MAX_LABEL_VALUES,
    OVERFLOW_LABEL,
    Histogram,
    LabelLimiter,
    metrics_registry,
)
from app.schemas import MCPToolCallRequest
from app.telemetry import (
    GEN_AI_SYSTEM,
    AegisLogHandler,
    JsonLogFormatter,
    ObservabilityMiddleware,
    RedactingTextFormatter,
    configure_logging,
    current_request_id,
    get_tracer,
    install_tracer_provider,
    otlp_traces_url,
    resolve_request_id,
    session_ref,
    setup_tracing,
)

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = ROOT / "deploy" / "grafana" / "aegis-mcp.json"
RULES = ROOT / "deploy" / "prometheus" / "aegis-mcp-rules.yaml"

client = TestClient(app)

SECRET = "sk-" + "c" * 24
EMAIL = "bob" + "@" + "example.com"
DANGEROUS = "rm" + " -rf /"
UPSTREAM_URL = "http://git-mcp.internal:9000/mcp"
TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"
REQUIRED_SPAN_KEYS = {
    "gen_ai.system",
    "mcp.server.name",
    "mcp.tool.name",
    "aegis.decision",
    "aegis.risk_score",
}


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    """Route Aegis spans to an in-memory exporter (no collector needed)."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    install_tracer_provider(provider)
    yield exporter
    install_tracer_provider(None)
    provider.shutdown()


@pytest.fixture(autouse=True)
def clean_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Isolate ledger, metrics, policy and upstream wiring."""
    monkeypatch.setattr(settings, "api_key", None)
    monkeypatch.setattr(settings, "policy_mode", "enforce")
    monkeypatch.setattr(settings, "enable_dlp_redaction", True)
    original = jsonrpc_gateway.client
    firewall.reset()
    jsonrpc_gateway.toolguard.reset()
    metrics_registry.reset()
    policy_engine.reset()
    mcp_transport.sessions.clear()
    yield
    jsonrpc_gateway.client = original
    jsonrpc_gateway.set_upstreams({})
    jsonrpc_gateway.toolguard.reset()
    mcp_transport.sessions.clear()


@pytest.fixture
def json_logs() -> Iterator[io.StringIO]:
    """Capture ``aegis_mcp`` log lines rendered by the JSON formatter."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonLogFormatter())
    logger = logging.getLogger("aegis_mcp")
    logger.addHandler(handler)
    yield stream
    logger.removeHandler(handler)


def _lines(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


def _by_name(exporter: InMemorySpanExporter, name: str) -> ReadableSpan:
    matches = [span for span in exporter.get_finished_spans() if span.name == name]
    assert matches, [span.name for span in exporter.get_finished_spans()]
    return matches[-1]


def _upstream(request: httpx.Request) -> httpx.Response:
    if request.method == "GET":
        return httpx.Response(
            200, content=b"", headers={"Content-Type": "text/event-stream"}
        )
    if request.method == "DELETE":
        return httpx.Response(200)
    body = json.loads(request.content)
    if "id" not in body:
        return httpx.Response(202)
    result: dict[str, Any] = {"content": [{"type": "text", "text": "ok"}]}
    if body["method"] == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "git"},
            "capabilities": {"tools": {}},
        }
    return httpx.Response(
        200,
        json={"jsonrpc": "2.0", "id": body["id"], "result": result},
        headers={"Mcp-Session-Id": "upstream-1"},
    )


def _wire_upstream() -> None:
    jsonrpc_gateway.set_upstreams({"git-mcp": UPSTREAM_URL})
    jsonrpc_gateway.client = httpx.Client(transport=httpx.MockTransport(_upstream))


def _request(**overrides: Any) -> MCPToolCallRequest:
    fields: dict[str, Any] = {
        "agent_id": "agent-otel",
        "server_name": "git-mcp",
        "tool_name": "git_status",
        "arguments": {"path": "."},
    }
    return MCPToolCallRequest(**{**fields, **overrides})


async def _noop_receive() -> Message:
    return {"type": "lifespan.startup"}


async def _noop_send(message: Message) -> None:
    return None


# ---------------------------------------------------------------------------
# GenAI / MCP spans
# ---------------------------------------------------------------------------


def test_firewall_inspect_span_has_genai_mcp_attributes(
    spans: InMemorySpanExporter,
) -> None:
    """``MCPFirewall.inspect`` emits one span with the verdict attributes."""
    report = firewall.inspect(
        _request(arguments={"cmd": DANGEROUS}), session_id="sess-123"
    )
    span = _by_name(spans, "aegis.firewall.inspect")
    attributes = dict(span.attributes or {})
    assert attributes.keys() >= REQUIRED_SPAN_KEYS
    assert attributes["gen_ai.system"] == GEN_AI_SYSTEM
    assert attributes["gen_ai.operation.name"] == "execute_tool"
    assert attributes["mcp.server.name"] == "git-mcp"
    assert attributes["mcp.tool.name"] == "git_status"
    assert attributes["aegis.decision"] == report.decision == "BLOCKED"
    assert attributes["aegis.risk_score"] == report.risk_score
    assert "command_injection" in str(attributes["aegis.violations"])


def test_session_id_is_pseudonymized_and_payloads_never_recorded(
    spans: InMemorySpanExporter,
) -> None:
    """Spans carry a session pseudonym, never the raw id, agent or arguments."""
    firewall.inspect(_request(arguments={"token": SECRET}), session_id="sess-raw")
    attributes = dict(_by_name(spans, "aegis.firewall.inspect").attributes or {})
    assert attributes["aegis.session.id"] == session_ref("sess-raw")
    assert re.fullmatch(r"[0-9a-f]{16}", str(attributes["aegis.session.id"]))
    rendered = json.dumps({key: str(value) for key, value in attributes.items()})
    for leaked in ("sess-raw", SECRET, "agent-otel"):
        assert leaked not in rendered
    assert session_ref("") == ""
    assert session_ref(None) == ""


def test_http_server_span_honors_traceparent_and_parents_inspection(
    spans: InMemorySpanExporter,
) -> None:
    """The inspect endpoint joins the caller trace; inspection is a child span."""
    res = client.post(
        "/api/v1/mcp/inspect",
        json=_request().model_dump(mode="json"),
        headers={"traceparent": TRACEPARENT, "X-Request-Id": "req-abc.1"},
    )
    assert res.status_code == 200
    assert res.headers["x-request-id"] == "req-abc.1"
    server = _by_name(spans, "POST /api/v1/mcp/inspect")
    inspect = _by_name(spans, "aegis.firewall.inspect")
    assert server.kind == trace.SpanKind.SERVER
    assert server.context is not None and inspect.context is not None
    assert trace.format_trace_id(server.context.trace_id) == TRACE_ID
    assert inspect.context.trace_id == server.context.trace_id
    assert inspect.parent is not None
    assert inspect.parent.span_id == server.context.span_id
    server_attributes = dict(server.attributes or {})
    assert server_attributes["http.route"] == "/api/v1/mcp/inspect"
    assert server_attributes["http.response.status_code"] == 200


def test_unmatched_routes_use_a_bounded_span_name(
    spans: InMemorySpanExporter,
) -> None:
    """Unknown paths never leak into span names (cardinality)."""
    assert client.get("/no/such/path/12345").status_code == 404
    assert _by_name(spans, "GET unmatched")


def test_jsonrpc_proxy_span_carries_mcp_verdict(spans: InMemorySpanExporter) -> None:
    """The JSON-RPC proxy span is annotated with method, tool and decision."""
    _wire_upstream()
    envelope = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "git_status", "arguments": {"cmd": DANGEROUS}},
    }
    res = client.post(
        "/api/v1/mcp/jsonrpc",
        json=envelope,
        headers={
            "X-Aegis-Agent-Id": "coder-1",
            "X-Aegis-MCP-Server": "git-mcp",
            "X-Aegis-Session-Id": "proxy-session",
        },
    )
    assert "error" in res.json()
    proxy = _by_name(spans, "mcp.proxy jsonrpc")
    attributes = dict(proxy.attributes or {})
    assert attributes.keys() >= REQUIRED_SPAN_KEYS
    assert attributes["mcp.method.name"] == "tools/call"
    assert attributes["aegis.decision"] == "BLOCKED"
    assert attributes["aegis.session.id"] == session_ref("proxy-session")
    inspect = _by_name(spans, "aegis.firewall.inspect")
    assert inspect.parent is not None and proxy.context is not None
    assert inspect.parent.span_id == proxy.context.span_id


def test_streamable_http_spans_carry_session_and_verdict(
    spans: InMemorySpanExporter,
) -> None:
    """``/mcp`` POST/GET/DELETE spans carry the MCP session pseudonym."""
    _wire_upstream()
    headers = {
        "X-Aegis-Agent-Id": "coder-1",
        "X-Aegis-MCP-Server": "git-mcp",
        "Accept": "application/json, text/event-stream",
    }
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"},
        },
    }
    session = client.post("/mcp", json=init, headers=headers).headers["mcp-session-id"]
    session_headers = {
        **headers,
        "Mcp-Session-Id": session,
        "MCP-Protocol-Version": "2025-06-18",
    }
    call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "git_status", "arguments": {"path": "."}},
    }
    assert client.post("/mcp", json=call, headers=session_headers).status_code == 200
    post = _by_name(spans, "mcp.streamable_http POST")
    attributes = dict(post.attributes or {})
    assert attributes.keys() >= REQUIRED_SPAN_KEYS
    assert attributes["aegis.session.id"] == session_ref(session)
    assert attributes["mcp.protocol.version"] == "2025-06-18"
    assert attributes["aegis.decision"] == "ALLOWED"
    get_headers = {**session_headers, "Accept": "text/event-stream"}
    assert client.get("/mcp", headers=get_headers).status_code == 200
    assert _by_name(spans, "mcp.streamable_http GET")
    assert client.delete("/mcp", headers=session_headers).status_code < 300
    assert _by_name(spans, "mcp.streamable_http DELETE")


# ---------------------------------------------------------------------------
# SLO histogram and bounded metrics
# ---------------------------------------------------------------------------


def test_inspection_duration_histogram_exposes_slo_buckets() -> None:
    """Every inspection lands in ``aegis_mcp_inspection_duration_seconds``."""
    firewall.inspect(_request())
    firewall.inspect(_request(arguments={"cmd": DANGEROUS}))
    text = client.get("/metrics").text
    name = "aegis_mcp_inspection_duration_seconds"
    assert f"# TYPE {name} histogram" in text
    assert INSPECTION_BUCKETS == (
        0.001,
        0.0025,
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
    )
    for decision in ("ALLOWED", "BLOCKED"):
        for bound in [*map(repr, INSPECTION_BUCKETS), "+Inf"]:
            assert f'{name}_bucket{{decision="{decision}",le="{bound}"}}' in text
        assert f'{name}_count{{decision="{decision}"}} 1.0' in text
        assert f'{name}_sum{{decision="{decision}"}}' in text


def test_histogram_buckets_are_cumulative() -> None:
    """Bucket counts are cumulative and ``+Inf`` equals the sample count."""
    histogram = Histogram(INSPECTION_BUCKETS)
    for value in (0.0005, 0.003, 0.003, 0.2, 2.0):
        histogram.observe("ALLOWED", value)
    lines = histogram.lines("h", "decision")
    samples = {
        line.split(" ")[0]: float(line.split(" ")[1])
        for line in lines
        if "_bucket" in line
    }
    assert samples['h_bucket{decision="ALLOWED",le="0.001"}'] == 1.0
    assert samples['h_bucket{decision="ALLOWED",le="0.005"}'] == 3.0
    assert samples['h_bucket{decision="ALLOWED",le="0.25"}'] == 4.0
    assert samples['h_bucket{decision="ALLOWED",le="0.5"}'] == 4.0
    assert samples['h_bucket{decision="ALLOWED",le="+Inf"}'] == 5.0
    assert 'h_count{decision="ALLOWED"} 5.0' in lines
    histogram.clear()
    assert histogram.lines("h", "decision") == []


def test_metric_label_cardinality_is_bounded_and_injection_safe() -> None:
    """Client-controlled labels are capped and sanitized; no identity labels."""
    for index in range(MAX_LABEL_VALUES * 3):
        metrics_registry.record_inspection(
            server_name=f"srv-{index}",
            decision="ALLOWED",
            violations=[f"rule_{index}"],
            redacted_categories=[f"cat_{index}"],
            would_block=True,
        )
    metrics_registry.record_inspection(
        server_name='evil"} 1\nfake_metric{a="',
        decision="ALLOWED",
        violations=[],
        redacted_categories=[],
    )
    text = metrics_registry.generate_prometheus_exposition()
    families = {
        "server": r'aegis_mcp_requests_total\{[^}]*server="([^"]*)"',
        "rule": r'aegis_mcp_blocked_total\{rule="([^"]*)"',
        "category": r'aegis_mcp_redactions_total\{category="([^"]*)"',
        "shadow": r'aegis_mcp_shadow_would_block_total\{server="([^"]*)"',
    }
    for pattern in families.values():
        values = set(re.findall(pattern, text))
        assert len(values) == MAX_LABEL_VALUES + 1
        assert OVERFLOW_LABEL in values
    assert not any(line.startswith("fake_metric") for line in text.splitlines())
    for forbidden in ("agent_id", "session_id", "agent=", "session="):
        assert forbidden not in text


def test_label_limiter_sanitizes_and_overflows() -> None:
    """The limiter keeps admitted values stable and collapses the rest."""
    limiter = LabelLimiter(max_values=2)
    assert limiter("a b") == "a_b"
    assert limiter("") == "unknown"
    assert limiter("third") == OVERFLOW_LABEL
    assert limiter("a b") == "a_b"
    limiter.clear()
    assert limiter("third") == "third"


def test_chain_tampering_increments_ledger_error_metric(
    json_logs: io.StringIO,
) -> None:
    """A failed ``verify_chain`` is counted for the tamper alert and logged."""
    firewall.inspect(_request())
    firewall.inspect(_request())
    assert firewall.verify_chain().valid
    with sqlite3.connect(firewall.db_path) as conn:
        conn.execute(
            "UPDATE audit_ledger SET risk_score = 99 "
            "WHERE id = (SELECT MAX(id) FROM audit_ledger)"
        )
        conn.commit()
    assert not firewall.verify_chain().valid
    text = metrics_registry.generate_prometheus_exposition()
    assert 'aegis_mcp_ledger_errors_total{kind="chain_tampered"} 1.0' in text
    events = [line.get("event") for line in _lines(json_logs)]
    assert "ledger.chain_tampered" in events


class _FailingSigner(CheckpointSigner):
    """Signer whose key is unavailable (e.g. HSM outage)."""

    def sign(self, head: TreeHead) -> Any:
        raise RuntimeError("signing key unavailable")


def test_checkpoint_signing_failure_increments_ledger_error_metric(
    tmp_path: Path,
) -> None:
    """Checkpoint failures are counted and still propagate (fail closed)."""
    ledger = AuditLedger(str(tmp_path / "ledger.db"), signer=_FailingSigner.generate())
    ledger.init()
    with pytest.raises(RuntimeError):
        ledger.create_checkpoint()
    text = metrics_registry.generate_prometheus_exposition()
    assert 'aegis_mcp_ledger_errors_total{kind="checkpoint_error"} 1.0' in text
    with pytest.raises(ValueError, match="Unknown ledger error kind"):
        metrics_registry.record_ledger_error("agent-42")


# ---------------------------------------------------------------------------
# Structured JSON logs
# ---------------------------------------------------------------------------


def test_inspection_log_line_is_json_with_trace_and_request_ids(
    spans: InMemorySpanExporter, json_logs: io.StringIO
) -> None:
    """Each inspection logs decision/risk with trace, span and request ids."""
    res = client.post(
        "/api/v1/mcp/inspect",
        json=_request(arguments={"note": f"mail {EMAIL} key {SECRET}"}).model_dump(
            mode="json"
        ),
        headers={"X-Request-Id": "req-log-1", "traceparent": TRACEPARENT},
    )
    assert res.json()["decision"] == "SANITIZED"
    entries = _lines(json_logs)
    inspection = next(e for e in entries if e.get("event") == "mcp.inspection")
    assert inspection["decision"] == "SANITIZED"
    assert inspection["risk_score"] == res.json()["risk_score"]
    assert inspection["request_id"] == "req-log-1"
    assert inspection["trace_id"] == TRACE_ID
    span = _by_name(spans, "aegis.firewall.inspect")
    assert span.context is not None
    assert inspection["span_id"] == trace.format_span_id(span.context.span_id)
    access = next(e for e in entries if e.get("event") == "http.request")
    assert access["route"] == "/api/v1/mcp/inspect"
    assert access["status_code"] == 200
    assert access["request_id"] == "req-log-1"
    rendered = json_logs.getvalue()
    assert EMAIL not in rendered
    assert SECRET not in rendered


def test_json_formatter_scrubs_secrets_and_omits_tracebacks() -> None:
    """Messages and extras are DLP-redacted; exceptions log their type only."""
    logger = logging.getLogger("aegis_mcp.test")
    try:
        raise ValueError(f"leaked {SECRET}")
    except ValueError:
        record = logger.makeRecord(
            "aegis_mcp.test",
            logging.ERROR,
            __file__,
            1,
            "contact %s",
            (EMAIL,),
            exc_info=sys.exc_info(),
            extra={
                "tool_name": f"t {SECRET}",
                "violations": [EMAIL],
                "risk_score": 3.5,
                "route": object(),
                "x": 1,
            },
        )
    entry = json.loads(JsonLogFormatter().format(record))
    assert entry["level"] == "ERROR"
    assert entry["exception"] == "ValueError"
    assert entry["trace_id"] is None and entry["span_id"] is None
    assert entry["request_id"] is None
    assert entry["risk_score"] == 3.5
    assert entry["route"].startswith("<object")
    assert "x" not in entry
    rendered = json.dumps(entry)
    assert SECRET not in rendered and EMAIL not in rendered
    assert "Traceback" not in rendered


def test_text_formatter_redacts_and_correlates() -> None:
    """``AEGIS_LOG_FORMAT=text`` lines are scrubbed and carry correlation ids."""
    record = logging.LogRecord(
        "aegis_mcp.t", logging.INFO, __file__, 1, f"key {SECRET}", None, None
    )
    line = RedactingTextFormatter().format(record)
    assert SECRET not in line
    assert "request_id=-" in line and "trace_id=-" in line


def test_configure_logging_is_idempotent_and_writes_to_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reconfiguring replaces the Aegis handler instead of stacking it."""
    logger = logging.getLogger("aegis_mcp")
    try:
        configure_logging("text")
        handler = configure_logging("json")
        ours = [h for h in logger.handlers if isinstance(h, AegisLogHandler)]
        assert ours == [handler]
        logging.getLogger("aegis_mcp.t").info("hello %s", EMAIL)
        line = capsys.readouterr().err.strip().splitlines()[-1]
        entry = json.loads(line)
        assert entry["message"].startswith("hello ")
        assert EMAIL not in line
    finally:
        configure_logging(settings.log_format)


def test_request_id_validation() -> None:
    """Malformed client request ids are replaced with a fresh one."""
    assert resolve_request_id("abc-123_X.y") == "abc-123_X.y"
    for bad in (None, "", "has space", "x" * 129, "inj\nected"):
        assert re.fullmatch(r"[0-9a-f]{32}", resolve_request_id(bad))
    res = client.get("/healthz", headers={"X-Request-Id": "bad id"})
    assert re.fullmatch(r"[0-9a-f]{32}", res.headers["x-request-id"])
    assert current_request_id() is None


# ---------------------------------------------------------------------------
# ASGI middleware edge cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scope_type", ["lifespan", "websocket"])
def test_middleware_passes_through_non_http_scopes(scope_type: str) -> None:
    """Non-HTTP scopes reach the app untouched."""
    seen: list[str] = []

    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(scope["type"])

    middleware = ObservabilityMiddleware(inner)
    asyncio.run(middleware({"type": scope_type}, _noop_receive, _noop_send))
    assert seen == [scope_type]


def test_middleware_records_500_when_app_raises(
    spans: InMemorySpanExporter, json_logs: io.StringIO
) -> None:
    """An unhandled error still closes the span and logs status 500."""

    async def boom(scope: Scope, receive: Receive, send: Send) -> None:
        raise RuntimeError("upstream exploded")

    scope: Scope = {"type": "http", "method": "POST", "headers": [], "path": "/x"}
    with pytest.raises(RuntimeError):
        asyncio.run(ObservabilityMiddleware(boom)(scope, _noop_receive, _noop_send))
    span = _by_name(spans, "POST unmatched")
    assert dict(span.attributes or {})["http.response.status_code"] == 500
    assert span.status.status_code == trace.StatusCode.ERROR
    access = [e for e in _lines(json_logs) if e.get("event") == "http.request"]
    assert access[-1]["status_code"] == 500


# ---------------------------------------------------------------------------
# Configuration and exporter wiring
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("enabled", "endpoint", "active"),
    [
        (None, None, False),
        (None, "http://otel-collector:4318", True),
        (False, "http://otel-collector:4318", False),
        (True, None, True),
    ],
)
def test_otel_enabled_follows_endpoint_unless_explicit(
    enabled: bool | None, endpoint: str | None, active: bool
) -> None:
    """Tracing defaults off and turns on once a collector is configured."""
    config = Settings(otel_enabled=enabled, otel_endpoint=endpoint)
    assert config.otel_active() is active
    assert config.otel_service_name == "aegis-mcp"
    assert config.log_format == "json"


def test_log_format_rejects_unknown_values() -> None:
    """``AEGIS_LOG_FORMAT`` only accepts ``json`` or ``text``."""
    with pytest.raises(ValueError):
        Settings(log_format="xml")  # type: ignore[arg-type]


def test_otlp_traces_url_normalization() -> None:
    """Collector base URLs gain the OTLP/HTTP traces path exactly once."""
    assert otlp_traces_url("http://c:4318") == "http://c:4318/v1/traces"
    assert otlp_traces_url("http://c:4318/") == "http://c:4318/v1/traces"
    assert otlp_traces_url("http://c:4318/v1/traces") == "http://c:4318/v1/traces"


def test_setup_tracing_installs_otlp_provider_only_when_active() -> None:
    """``setup_tracing`` is a no-op when disabled and builds OTLP otherwise."""
    assert setup_tracing(Settings(otel_enabled=False)) is None
    assert isinstance(get_tracer(), trace.NoOpTracer)
    config = Settings(
        otel_endpoint="http://127.0.0.1:4318",
        otel_service_name="aegis-test",
        environment="staging",
    )
    provider = setup_tracing(config)
    assert provider is not None
    try:
        resource = dict(provider.resource.attributes)
        assert resource["service.name"] == "aegis-test"
        assert resource["deployment.environment.name"] == "staging"
        assert not isinstance(get_tracer(), trace.NoOpTracer)
    finally:
        install_tracer_provider(None)
        provider.shutdown()
    assert isinstance(get_tracer(), trace.NoOpTracer)


# ---------------------------------------------------------------------------
# Grafana dashboard and PrometheusRule
# ---------------------------------------------------------------------------


def _exported_families() -> set[str]:
    firewall.inspect(_request())
    text = metrics_registry.generate_prometheus_exposition()
    return set(re.findall(r"^# TYPE (\S+) ", text, flags=re.MULTILINE))


def _referenced_families(text: str) -> set[str]:
    names = set(re.findall(r"\baegis_mcp_[a-z_]+", text))
    return {re.sub(r"_(bucket|sum|count)$", "", name) for name in names}


def test_grafana_dashboard_is_valid_and_covers_slo_views() -> None:
    """The dashboard is valid JSON with the required SLO/security panels."""
    dashboard = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    assert dashboard["uid"] == "aegis-mcp"
    panels = dashboard["panels"]
    ids = [panel["id"] for panel in panels]
    assert len(ids) == len(set(ids))
    titles = " ".join(panel["title"] for panel in panels).lower()
    for needle in ("p99", "slo", "block", "sanitize", "dlp", "hitl", "taint"):
        assert needle in titles
    exprs = [target["expr"] for panel in panels for target in panel["targets"]]
    joined = "\n".join(exprs)
    assert "histogram_quantile(0.99" in joined
    assert "vector(0.01)" in joined
    assert "toxic_flow_exfiltration" in joined and "hitl_" in joined
    assert _referenced_families(joined) <= _exported_families()
    for panel in panels:
        assert panel["datasource"]["uid"] == "${datasource}"


def test_prometheus_rule_is_valid_and_alerts_on_slo_and_security() -> None:
    """The PrometheusRule parses and alerts on latency, flows and integrity."""
    document = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    assert document["apiVersion"] == "monitoring.coreos.com/v1"
    assert document["kind"] == "PrometheusRule"
    rules = [rule for group in document["spec"]["groups"] for rule in group["rules"]]
    alerts = {rule["alert"]: rule for rule in rules if "alert" in rule}
    for rule in alerts.values():
        assert rule["labels"]["severity"] in {"warning", "critical"}
        assert rule["annotations"]["summary"]
    recorded = {rule["record"]: rule["expr"] for rule in rules if "record" in rule}
    p99 = recorded["aegis_mcp:inspection_duration_seconds:p99_5m"]
    assert "histogram_quantile(0.99" in p99
    assert alerts["AegisMcpInspectionLatencyP99High"]["expr"].endswith("> 0.01")
    toxic = alerts["AegisMcpToxicFlowExfiltrationSpike"]["expr"]
    assert "toxic_flow_exfiltration" in toxic
    assert "tool_definition_drift" in alerts["AegisMcpToolDefinitionDrift"]["expr"]
    assert "chain_tampered" in alerts["AegisMcpAuditChainTampered"]["expr"]
    assert "checkpoint_error" in alerts["AegisMcpCheckpointSigningErrors"]["expr"]
    joined = "\n".join(rule["expr"] for rule in rules)
    assert _referenced_families(joined) <= _exported_families()
