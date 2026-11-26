"""FastAPI application entrypoint and HTTP endpoints for Aegis-MCP."""

import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    Security,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import APIKeyHeader
from opentelemetry.util.types import AttributeValue
from starlette.concurrency import run_in_threadpool

from app.approvals import (
    MAX_LIST_LIMIT,
    ApprovalConflictError,
    ApprovalNotFoundError,
)
from app.auth import (
    WELL_KNOWN_PATH,
    AuthError,
    AuthUnavailableError,
    Principal,
    build_resource_server,
)
from app.config import settings
from app.firewall import MCPFirewall
from app.jsonrpc import MAX_REQUEST_BYTES, JsonRpcGateway
from app.merkle import SignedTreeHead
from app.metrics import metrics_registry
from app.ocsf import NDJSON_MEDIA_TYPE, ocsf_lines
from app.policy import build_policy_engine
from app.schemas import (
    ApprovalResolution,
    ApprovalStatus,
    AuditEntry,
    ChainVerificationResponse,
    HitlApproval,
    InclusionProofResponse,
    MCPInspectionResponse,
    MCPToolCallRequest,
    PolicyDocument,
    PolicyStatus,
    SessionTaintStatus,
    SignedCheckpoint,
    ToolApproval,
    ToolPin,
)
from app.streamable import StreamableHttpTransport, TransportReply
from app.telemetry import (
    ObservabilityMiddleware,
    configure_logging,
    get_tracer,
    mcp_attributes,
    setup_tracing,
)
from app.toolguard import FingerprintMismatchError, PinNotFoundError

logger = logging.getLogger("aegis_mcp.policy")

configure_logging(settings.log_format)
tracer_provider = setup_tracing(settings)

policy_engine = build_policy_engine(settings.policy_path, settings.environment)
firewall = MCPFirewall(policy_engine=policy_engine)
jsonrpc_gateway = JsonRpcGateway(firewall=firewall)
mcp_transport = StreamableHttpTransport(jsonrpc_gateway)
resource_server = build_resource_server(settings.auth_mode, settings.oauth_config)


@asynccontextmanager
async def lifespan(app_instance: FastAPI) -> AsyncIterator[None]:
    """Manage startup, graceful SQLite draining and span flushing on shutdown."""
    firewall._init_db()
    yield
    firewall.close()
    if tracer_provider is not None:
        tracer_provider.shutdown()


app = FastAPI(
    title="Aegis-MCP",
    description=(
        "Zero-Trust Firewall, DLP Redactor & Tamper-Evident Cryptographic "
        "Audit Proxy for Model Context Protocol (MCP) Servers."
    ),
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(ObservabilityMiddleware)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(api_key: str | None = Security(api_key_header)) -> str | None:
    """Validate X-API-Key header against configured application secret."""
    if settings.api_key is not None and api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key authentication header.",
        )
    return api_key


def authenticate(
    api_key: str | None = Security(api_key_header),
    authorization: str | None = Header(default=None),
) -> Principal | None:
    """Authenticate a data-plane caller according to ``AEGIS_AUTH_MODE``.

    ``api_key`` mode keeps the local-development X-API-Key check and returns
    ``None`` (identity is self-declared). ``oauth`` mode requires a valid
    Bearer JWT and returns the claims-derived Principal; failures yield ``401``
    with an RFC 6750 / RFC 9728 ``WWW-Authenticate`` challenge.
    """
    if not resource_server.enabled:
        verify_api_key(api_key)
        return None
    try:
        return resource_server.authenticate(authorization)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=exc.description,
            headers={"WWW-Authenticate": resource_server.challenge(exc)},
        ) from exc
    except AuthUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorization server signing keys are unavailable.",
        ) from exc


AuthenticatedPrincipal = Annotated[Principal | None, Depends(authenticate)]
SessionIdHeader = Annotated[
    str | None, Header(max_length=1024, pattern=r"^[\x21-\x7e]+$")
]


def require_admin_api_key(
    api_key: str | None = Security(api_key_header),
) -> None:
    """Require a configured X-API-Key for privileged policy administration.

    Unlike read endpoints, policy mutation fails closed when no API key is
    configured so an unauthenticated caller can never disable RBAC.
    """
    if settings.api_key is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Policy administration requires AEGIS_API_KEY to be configured.",
        )
    if api_key is None or not secrets.compare_digest(
        api_key.encode("utf-8"), settings.api_key.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key authentication header.",
        )


@app.get("/healthz", tags=["Health"])
def health_check() -> dict[str, str]:
    """Return liveness and readiness status for Kubernetes orchestration."""
    return {"status": "ok"}


@app.get(
    "/metrics",
    tags=["Observability"],
    response_class=Response,
    responses={
        200: {
            "content": {"text/plain; version=0.0.4; charset=utf-8": {}},
            "description": "Prometheus text exposition format.",
        }
    },
)
def get_metrics() -> Response:
    """Export application metrics in standard Prometheus exposition format."""
    payload = metrics_registry.generate_prometheus_exposition()
    return Response(
        content=payload,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.get(WELL_KNOWN_PATH, tags=["OAuth"])
@app.get(WELL_KNOWN_PATH + "/{resource_path:path}", tags=["OAuth"])
def protected_resource_metadata(request: Request) -> JSONResponse:
    """Serve RFC 9728 OAuth 2.0 Protected Resource Metadata (OAuth mode only)."""
    if not resource_server.serves_metadata_path(request.url.path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return JSONResponse(
        resource_server.metadata(),
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.post(
    "/api/v1/mcp/inspect",
    response_model=MCPInspectionResponse,
    tags=["MCP Firewall"],
)
def inspect_mcp_tool_call(
    request: MCPToolCallRequest,
    principal: AuthenticatedPrincipal,
    x_aegis_session_id: SessionIdHeader = None,
) -> MCPInspectionResponse:
    """Inspect an MCP tool call, redact sensitive fields, and record in hash chain.

    ``X-Aegis-Session-Id`` (or the body ``session_id``) opts the call into
    toxic-flow taint tracking.
    """
    if principal is not None:
        request = request.model_copy(update={"agent_id": principal.agent_id})
    report = firewall.inspect(request, session_id=x_aegis_session_id or "")
    metrics_registry.record_inspection(
        server_name=request.server_name,
        decision=report.decision,
        violations=report.violations,
        redacted_categories=report.redacted_categories,
        would_block=report.would_block,
    )
    return report


@app.get(
    "/api/v1/audit",
    response_model=list[AuditEntry],
    dependencies=[Depends(authenticate)],
    tags=["Audit Ledger"],
)
def list_audit_trail(agent_id: str | None = None) -> list[AuditEntry]:
    """Return the tamper-evident audit ledger entries."""
    return firewall.list_audit_entries(agent_id=agent_id)


@app.get(
    "/api/v1/audit/verify",
    response_model=ChainVerificationResponse,
    dependencies=[Depends(authenticate)],
    tags=["Audit Ledger"],
)
def verify_audit_chain() -> ChainVerificationResponse:
    """Verify the cryptographic integrity of the SHA-256 hash chain."""
    return firewall.verify_chain()


def _checkpoint_model(checkpoint: SignedTreeHead) -> SignedCheckpoint:
    """API representation of a Signed Tree Head."""
    return SignedCheckpoint(**checkpoint.as_dict())


@app.get(
    "/api/v1/audit/proof/{entry_id}",
    response_model=InclusionProofResponse,
    dependencies=[Depends(authenticate)],
    tags=["Audit Ledger"],
    responses={404: {"description": "Ledger entry not found."}},
)
def get_inclusion_proof(
    entry_id: Annotated[int, Path(ge=1)],
) -> InclusionProofResponse:
    """Return an RFC 6962 Merkle inclusion proof for one ledger entry.

    The proof targets the latest Ed25519 Signed Tree Head (signed on demand
    when it does not cover the entry yet and a signing key is configured).
    """
    bundle = firewall.ledger.inclusion_proof(entry_id)
    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Ledger entry not found.",
        )
    return InclusionProofResponse(
        entry_id=bundle.entry_id,
        leaf_index=bundle.leaf_index,
        tree_size=bundle.tree_size,
        entry_hash=bundle.entry_hash,
        root_hash=bundle.root_hash,
        audit_path=bundle.audit_path,
        checkpoint=(
            _checkpoint_model(bundle.checkpoint) if bundle.checkpoint else None
        ),
    )


@app.get(
    "/api/v1/audit/checkpoints",
    response_model=list[SignedCheckpoint],
    dependencies=[Depends(authenticate)],
    tags=["Audit Ledger"],
)
def list_checkpoints() -> list[SignedCheckpoint]:
    """Return every Ed25519 Signed Tree Head (oldest first)."""
    return [_checkpoint_model(item) for item in firewall.ledger.list_checkpoints()]


@app.post(
    "/api/v1/audit/checkpoints",
    response_model=SignedCheckpoint,
    dependencies=[Depends(require_admin_api_key)],
    tags=["Audit Ledger"],
    responses={409: {"description": "Checkpoint signing is not configured."}},
)
def create_checkpoint() -> SignedCheckpoint:
    """Manually sign a checkpoint over the current ledger tree."""
    checkpoint = firewall.ledger.create_checkpoint()
    if checkpoint is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Checkpoint signing is not configured.",
        )
    return _checkpoint_model(checkpoint)


@app.get(
    "/api/v1/audit/export/ocsf",
    dependencies=[Depends(authenticate)],
    tags=["Audit Ledger"],
    response_class=StreamingResponse,
    responses={
        200: {
            "content": {NDJSON_MEDIA_TYPE: {}},
            "description": "OCSF 1.3.0 API Activity events as JSON Lines.",
        }
    },
)
def export_ocsf(agent_id: str | None = None) -> StreamingResponse:
    """Export ledger events as OCSF JSON Lines for SIEM ingestion.

    Each event carries hash-chain/Merkle integrity evidence and EU AI Act
    Art. 12 / ISO/IEC 42001 A.6.2.8 record-keeping metadata.
    """
    lines = ocsf_lines(
        firewall.list_audit_entries(),
        firewall.ledger.list_checkpoints(),
        agent_id,
    )
    return StreamingResponse(
        lines,
        media_type=NDJSON_MEDIA_TYPE,
        headers={"Content-Disposition": 'attachment; filename="aegis-ocsf.jsonl"'},
    )


@app.get(
    "/api/v1/sessions/{session_id}/taint",
    response_model=SessionTaintStatus,
    dependencies=[Depends(authenticate)],
    tags=["Taint Tracking"],
)
def get_session_taint(
    session_id: Annotated[str, Path(min_length=1, max_length=1024)],
) -> SessionTaintStatus:
    """Return a session's toxic-flow taint labels and lethal-trifecta state."""
    return firewall.taint.status(session_id)


@app.get(
    "/api/v1/policies",
    response_model=PolicyDocument,
    dependencies=[Depends(require_admin_api_key)],
    tags=["RBAC Policy"],
)
def get_policies() -> PolicyDocument:
    """Return the active declarative RBAC policy matrix."""
    return policy_engine.document


@app.post(
    "/api/v1/policies",
    response_model=PolicyDocument,
    dependencies=[Depends(require_admin_api_key)],
    tags=["RBAC Policy"],
)
def replace_policies(document: PolicyDocument) -> PolicyDocument:
    """Atomically replace the active RBAC policy matrix."""
    policy_engine.load(document)
    logger.warning(
        "RBAC policy matrix replaced: default_action=%s rules=%d version=%s",
        document.default_action,
        len(document.rules),
        policy_engine.version,
    )
    return policy_engine.document


@app.get(
    "/api/v1/policies/status",
    response_model=PolicyStatus,
    dependencies=[Depends(require_admin_api_key)],
    tags=["RBAC Policy"],
)
def get_policy_status() -> PolicyStatus:
    """Return the active policy version, mode, and fail-closed state."""
    _, version, fail_closed = policy_engine.snapshot()
    return PolicyStatus(
        policy_version=version,
        policy_mode=settings.policy_mode,
        environment=settings.environment,
        fail_closed=fail_closed,
    )


@app.get(
    "/api/v1/toolguard/pins",
    response_model=list[ToolPin],
    dependencies=[Depends(require_admin_api_key)],
    tags=["Toolguard"],
)
def list_tool_pins(server_name: str | None = None) -> list[ToolPin]:
    """Return pinned MCP definition fingerprints (pending/approved/drifted)."""
    return jsonrpc_gateway.toolguard.list_pins(server_name)


@app.post(
    "/api/v1/toolguard/approve",
    response_model=ToolPin,
    dependencies=[Depends(require_admin_api_key)],
    tags=["Toolguard"],
)
def approve_tool_pin(approval: ToolApproval) -> ToolPin:
    """Approve the pinned or drifted fingerprint of an MCP definition."""
    try:
        pin = jsonrpc_gateway.toolguard.approve(
            approval.server_name, approval.kind, approval.name, approval.fingerprint
        )
    except PinNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Definition is not pinned."
        ) from exc
    except FingerprintMismatchError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Fingerprint matches neither the pinned nor the drifted definition.",
        ) from exc
    logger.warning(
        "Toolguard approval: server=%s kind=%s name=%s fingerprint=%s",
        pin.server_name,
        pin.kind,
        pin.name,
        pin.fingerprint,
    )
    return pin


def require_approver(
    api_key: str | None = Security(api_key_header),
    authorization: str | None = Header(default=None),
) -> str:
    """Authorize a HITL operator and return its identity for the audit trail.

    ``oauth`` mode requires a valid Bearer token carrying
    ``AEGIS_HITL_APPROVER_SCOPE``; ``api_key`` mode requires the configured
    admin X-API-Key (fail-closed when none is configured).
    """
    if not resource_server.enabled:
        require_admin_api_key(api_key)
        return "api-key-admin"
    principal = authenticate(api_key, authorization)
    if principal is None or settings.hitl_approver_scope not in principal.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Approvals require the '{settings.hitl_approver_scope}' scope.",
        )
    return principal.agent_id


Approver = Annotated[str, Depends(require_approver)]


@app.get(
    "/api/v1/approvals",
    response_model=list[HitlApproval],
    tags=["HITL Approvals"],
)
def list_approvals(
    _approver: Approver,
    approval_status: Annotated[ApprovalStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIST_LIMIT)] = 100,
) -> list[HitlApproval]:
    """Return HITL approval requests (newest first), optionally by status."""
    return firewall.approvals.list_requests(approval_status, limit)


@app.post(
    "/api/v1/approvals/{approval_id}",
    response_model=HitlApproval,
    tags=["HITL Approvals"],
)
def resolve_approval(
    approval_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
    resolution: ApprovalResolution,
    approver: Approver,
) -> HitlApproval:
    """Approve or deny a pending request and ledger the decision."""
    try:
        approval = firewall.approvals.resolve(
            approval_id, resolution.status, approver, resolution.reason
        )
    except ApprovalNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Approval request not found.",
        ) from exc
    except ApprovalConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Approval request is already {exc}.",
        ) from exc
    firewall.record_approval_event(approval)
    logger.warning(
        "HITL approval %s %s by %s (tool=%s server=%s)",
        approval.id,
        approval.status,
        approver,
        approval.tool_name,
        approval.server_name,
    )
    return approval


async def read_body_capped(request: Request, limit: int) -> bytes:
    """Read at most ``limit + 1`` bytes so oversized bodies are never buffered."""
    buffer = bytearray()
    async for chunk in request.stream():
        buffer.extend(chunk)
        if len(buffer) > limit:
            break
    return bytes(buffer)


@app.post(
    "/api/v1/mcp/jsonrpc",
    tags=["MCP Firewall"],
    response_class=JSONResponse,
)
async def mcp_jsonrpc_proxy(
    request: Request,
    principal: AuthenticatedPrincipal,
    x_aegis_agent_id: str | None = Header(default=None),
    x_aegis_mcp_server: str | None = Header(default=None),
    x_aegis_environment: str | None = Header(default=None),
    x_aegis_session_id: str | None = Header(default=None),
) -> JSONResponse:
    """Firewall, audit, and proxy a JSON-RPC 2.0 MCP request to its upstream.

    In OAuth mode the agent identity comes only from the validated token; a
    self-declared ``X-Aegis-Agent-Id`` header is ignored.
    """
    raw = await read_body_capped(request, MAX_REQUEST_BYTES)
    routing = {
        "agent_id": principal.agent_id if principal else x_aegis_agent_id,
        "server_name": x_aegis_mcp_server,
        "environment": x_aegis_environment,
        "session_id": x_aegis_session_id,
    }
    with get_tracer().start_as_current_span(
        "mcp.proxy jsonrpc",
        attributes=mcp_attributes(
            x_aegis_mcp_server, x_aegis_session_id, **{"network.transport": "http"}
        ),
    ):
        payload = await run_in_threadpool(jsonrpc_gateway.handle, raw, routing)
    return JSONResponse(payload)


def mcp_routing(principal: Principal | None, request: Request) -> dict[str, str | None]:
    """Caller routing for ``/mcp``: identity is token-derived in OAuth mode."""
    headers = request.headers
    return {
        "agent_id": (
            principal.agent_id if principal else headers.get("x-aegis-agent-id")
        ),
        "server_name": headers.get("x-aegis-mcp-server"),
        "environment": headers.get("x-aegis-environment"),
    }


def streamable_span_attributes(request: Request) -> dict[str, AttributeValue]:
    """GenAI/MCP attributes of one Streamable HTTP exchange."""
    headers = request.headers
    return mcp_attributes(
        headers.get("x-aegis-mcp-server"),
        headers.get("mcp-session-id"),
        **{
            "network.transport": "http",
            "mcp.protocol.version": headers.get("mcp-protocol-version"),
        },
    )


def transport_response(reply: TransportReply) -> Response:
    """Render a transport reply as JSON, an SSE stream, or an empty body."""
    if reply.stream is not None:
        return StreamingResponse(
            reply.stream,
            status_code=reply.status,
            media_type="text/event-stream",
            headers={**reply.headers, "Cache-Control": "no-cache"},
        )
    if reply.body is None:
        return Response(status_code=reply.status, headers=reply.headers)
    return JSONResponse(reply.body, status_code=reply.status, headers=reply.headers)


@app.post("/mcp", tags=["MCP Streamable HTTP"], response_class=Response)
async def mcp_streamable_post(
    request: Request, principal: AuthenticatedPrincipal
) -> Response:
    """MCP Streamable HTTP: send JSON-RPC messages (JSON or SSE replies)."""
    raw = await read_body_capped(request, MAX_REQUEST_BYTES)
    with get_tracer().start_as_current_span(
        "mcp.streamable_http POST", attributes=streamable_span_attributes(request)
    ):
        reply = await run_in_threadpool(
            mcp_transport.post, request.headers, raw, mcp_routing(principal, request)
        )
    return transport_response(reply)


@app.get("/mcp", tags=["MCP Streamable HTTP"], response_class=Response)
async def mcp_streamable_get(
    request: Request, principal: AuthenticatedPrincipal
) -> Response:
    """MCP Streamable HTTP: open the server-initiated SSE stream."""
    with get_tracer().start_as_current_span(
        "mcp.streamable_http GET", attributes=streamable_span_attributes(request)
    ):
        reply = await run_in_threadpool(
            mcp_transport.get, request.headers, mcp_routing(principal, request)
        )
    return transport_response(reply)


@app.delete("/mcp", tags=["MCP Streamable HTTP"], response_class=Response)
async def mcp_streamable_delete(
    request: Request, principal: AuthenticatedPrincipal
) -> Response:
    """MCP Streamable HTTP: terminate the session."""
    with get_tracer().start_as_current_span(
        "mcp.streamable_http DELETE", attributes=streamable_span_attributes(request)
    ):
        reply = await run_in_threadpool(
            mcp_transport.delete, request.headers, mcp_routing(principal, request)
        )
    return transport_response(reply)
