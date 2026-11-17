"""FastAPI application entrypoint and HTTP endpoints for Aegis-MCP."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Response, Security, status
from fastapi.security import APIKeyHeader

from app.config import settings
from app.firewall import MCPFirewall
from app.metrics import metrics_registry
from app.schemas import (
    AuditEntry,
    ChainVerificationResponse,
    MCPInspectionResponse,
    MCPToolCallRequest,
)

firewall = MCPFirewall()


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
