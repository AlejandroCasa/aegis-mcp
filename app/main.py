"""FastAPI application entrypoint and HTTP endpoints for Aegis-MCP."""

import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

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

from app.config import settings
from app.firewall import MCPFirewall
from app.jsonrpc import MAX_REQUEST_BYTES, JsonRpcGateway
from app.metrics import metrics_registry
from app.policy import PolicyEngine
from app.schemas import (
    AuditEntry,
    ChainVerificationResponse,
    MCPInspectionResponse,
    MCPToolCallRequest,
    PolicyDocument,
)

logger = logging.getLogger("aegis_mcp.policy")

policy_engine = PolicyEngine.from_path(settings.policy_path)
if settings.policy_path is None:
    logger.warning("AEGIS_POLICY_PATH is not set: RBAC matrix defaults to allow-all.")
firewall = MCPFirewall(policy_engine=policy_engine)
jsonrpc_gateway = JsonRpcGateway(firewall=firewall)


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


@app.post(
    "/api/v1/mcp/inspect",
    response_model=MCPInspectionResponse,
    dependencies=[Depends(verify_api_key)],
    tags=["MCP Firewall"],
)
def inspect_mcp_tool_call(request: MCPToolCallRequest) -> MCPInspectionResponse:
    """Inspect an MCP tool call, redact sensitive fields, and record in hash chain."""
    report = firewall.inspect(request)
    metrics_registry.record_inspection(
        server_name=request.server_name,
        decision=report.decision,
        violations=report.violations,
        redacted_categories=report.redacted_categories,
    )
    return report


@app.get(
    "/api/v1/audit",
    response_model=list[AuditEntry],
    dependencies=[Depends(verify_api_key)],
    tags=["Audit Ledger"],
)
def list_audit_trail(agent_id: str | None = None) -> list[AuditEntry]:
    """Return the tamper-evident audit ledger entries."""
    return firewall.list_audit_entries(agent_id=agent_id)


@app.get(
    "/api/v1/audit/verify",
    response_model=ChainVerificationResponse,
    dependencies=[Depends(verify_api_key)],
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
        "RBAC policy matrix replaced: default_action=%s rules=%d",
        document.default_action,
        len(document.rules),
    )
    return policy_engine.document


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
    dependencies=[Depends(verify_api_key)],
    tags=["MCP Firewall"],
    response_class=JSONResponse,
)
async def mcp_jsonrpc_proxy(
    request: Request,
    x_aegis_agent_id: str | None = Header(default=None),
    x_aegis_mcp_server: str | None = Header(default=None),
    x_aegis_environment: str | None = Header(default=None),
) -> JSONResponse:
    """Firewall, audit, and proxy a JSON-RPC 2.0 MCP request to its upstream."""
    raw = await read_body_capped(request, MAX_REQUEST_BYTES)
    routing = {
        "agent_id": x_aegis_agent_id,
        "server_name": x_aegis_mcp_server,
        "environment": x_aegis_environment,
    }
    payload = await run_in_threadpool(jsonrpc_gateway.handle, raw, routing)
    return JSONResponse(payload)
