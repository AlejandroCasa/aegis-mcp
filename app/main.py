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
    Request,
    Response,
    Security,
    status,
)
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from starlette.concurrency import run_in_threadpool

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
from app.metrics import metrics_registry
from app.policy import build_policy_engine
from app.schemas import (
    AuditEntry,
    ChainVerificationResponse,
    MCPInspectionResponse,
    MCPToolCallRequest,
    PolicyDocument,
    PolicyStatus,
    ToolApproval,
    ToolPin,
)
from app.toolguard import FingerprintMismatchError, PinNotFoundError

logger = logging.getLogger("aegis_mcp.policy")

policy_engine = build_policy_engine(settings.policy_path, settings.environment)
firewall = MCPFirewall(policy_engine=policy_engine)
jsonrpc_gateway = JsonRpcGateway(firewall=firewall)
resource_server = build_resource_server(settings.auth_mode, settings.oauth_config)


@asynccontextmanager
async def lifespan(app_instance: FastAPI) -> AsyncIterator[None]:
    """Manage application startup and graceful SQLite draining on shutdown."""
    firewall._init_db()
    yield
    firewall.close()


app = FastAPI(
    title="Aegis-MCP",
    description=(
        "Zero-Trust Firewall, DLP Redactor & Tamper-Evident Cryptographic "
        "Audit Proxy for Model Context Protocol (MCP) Servers."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

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
) -> MCPInspectionResponse:
    """Inspect an MCP tool call, redact sensitive fields, and record in hash chain."""
    if principal is not None:
        request = request.model_copy(update={"agent_id": principal.agent_id})
    report = firewall.inspect(request)
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
    }
    payload = await run_in_threadpool(jsonrpc_gateway.handle, raw, routing)
    return JSONResponse(payload)
