"""Runtime configuration settings for Aegis-MCP validated via pydantic-settings."""

import os
import tempfile
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.auth import AuthMode, OAuthConfig
from app.schemas import Environment, PolicyMode


def _default_db_path() -> str:
    """Return a writable temporary database path for read-only containers."""
    return os.path.join(tempfile.gettempdir(), "aegis_mcp.db")


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_prefix="AEGIS_", extra="ignore")

    api_key: str | None = None
    db_path: str = Field(default_factory=_default_db_path)
    block_threshold_score: int = 70
    enable_dlp_redaction: bool = True
    # Optional HMAC-SHA256 key for referential DLP tokens: when set, redacted
    # values become ``[REDACTED_<LABEL>#<6hex>]`` so identical values stay
    # correlatable without exposing them. Unset/empty emits static placeholders.
    dlp_hmac_key: str | None = None
    # Shannon-entropy detection of unlabelled secrets in explicit secret
    # contexts (``password=...`` assignments and sensitive dictionary keys).
    dlp_entropy_enabled: bool = True
    policy_path: str | None = None
    # Deployment environment of this gateway: ``prod`` fails closed (deny-all)
    # when no valid policy is loaded at startup.
    environment: Environment = "dev"
    # ``enforce`` blocks; ``monitor`` (shadow mode) evaluates and audits
    # ``would_block`` without blocking, for progressive production rollouts.
    policy_mode: PolicyMode = "enforce"
    # Tool manifest pinning: require operator approval before pinned (TOFU)
    # tools/prompts may be called. Drifted definitions are always blocked.
    toolguard_require_approval: bool = False
    # Tool poisoning / cross-server shadowing scan of discovered definitions:
    # findings scoring >= block_threshold_score hide the definition (and strip
    # poisoned ``instructions``) and block calls in enforce mode.
    toolguard_scan_poisoning: bool = True
    # Toxic-flow ("lethal trifecta") session taint tracking: deny egress sinks
    # once a session has seen both untrusted content and private data.
    # ``taint_default_heuristics`` adds built-in tool/server classification
    # on top of the policy's declarative ``taint_rules``.
    enable_taint_tracking: bool = True
    taint_default_heuristics: bool = True
    # Behavioral rate limiting: a token bucket per ``(agent, server, tool)``
    # (``rate_limit_exceeded``, risk 75) and a sliding-window exfiltration
    # velocity detector per ``(session, agent)`` counting sensitive reads
    # such as ``resources/read`` / ``query_db`` / ``read_file``
    # (``exfiltration_velocity_anomaly``, risk 90). Both block in enforce mode
    # and set ``would_block`` in monitor mode; policy ``rate_limits`` override.
    rate_limit_enabled: bool = True
    rate_limit_capacity: float = Field(default=60.0, gt=0, le=1_000_000)
    rate_limit_refill_per_sec: float = Field(default=5.0, ge=0, le=1_000_000)
    velocity_window_seconds: float = Field(default=60.0, gt=0, le=3600)
    velocity_max_reads: int = Field(default=30, ge=1, le=4096)
    rate_limit_max_keys: int = Field(default=10_000, ge=1)
    mcp_upstreams: dict[str, str] = Field(default_factory=dict)
    upstream_timeout_seconds: float = 10.0

    # Native MCP Streamable HTTP transport (``/mcp``): browser ``Origin``
    # allowlist (DNS-rebinding defense; requests without Origin are allowed),
    # session lifetime/capacity, and the wall-clock cap of one SSE stream.
    mcp_allowed_origins: list[str] = Field(default_factory=list)
    mcp_session_ttl_seconds: int = 3600
    mcp_max_sessions: int = 10_000
    mcp_stream_timeout_seconds: float = 300.0

    # Human-in-the-loop approval gate (``require_approval`` policy action):
    # pending requests (and granted, single-use approvals) expire after
    # ``hitl_timeout_seconds``; a gated call may block up to
    # ``hitl_wait_seconds`` polling for a decision before failing closed.
    # In ``oauth`` mode resolvers need ``hitl_approver_scope``.
    hitl_timeout_seconds: int = Field(default=900, ge=1, le=86_400)
    hitl_wait_seconds: float = Field(default=0.0, ge=0.0, le=300.0)
    hitl_approver_scope: str = "aegis:approve"

    # Security webhook (approval requests and high-severity BLOCKED incidents):
    # HTTPS only (plain http to localhost outside prod); in prod the target
    # must not resolve to private, loopback, link-local or metadata addresses.
    webhook_url: str | None = None
    webhook_cooldown_seconds: float = Field(default=300.0, ge=0.0)
    webhook_timeout_seconds: float = Field(default=3.0, gt=0.0, le=30.0)

    # Audit ledger: SQLite write-ahead logging (concurrent readers never
    # block the single chain writer).
    ledger_wal: bool = True

    # RFC 6962 Merkle checkpoints: every ``checkpoint_interval`` appended
    # events (0 = only on demand) the ledger signs an Ed25519 Signed Tree
    # Head with the PKCS#8 PEM key at ``signing_key_path``. Without a key,
    # ``prod`` fails closed at startup unless ``checkpoint_signing`` is
    # disabled; elsewhere ``signing_key_ephemeral`` opts into a throwaway
    # in-memory key (dev/test only), otherwise checkpoints are disabled.
    checkpoint_signing: bool = True
    checkpoint_interval: int = Field(default=50, ge=0)
    signing_key_path: str | None = None
    signing_key_ephemeral: bool = False

    # Authentication: ``api_key`` (local development, X-API-Key + self-declared
    # X-Aegis-Agent-Id) or ``oauth`` (OAuth 2.1 resource server, identity from
    # validated JWT claims only).
    auth_mode: AuthMode = "api_key"
    oauth_issuer: str | None = None
    oauth_audience: str | None = None
    oauth_jwks_url: str | None = None
    oauth_algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    oauth_authorization_servers: list[str] = Field(default_factory=list)
    oauth_scopes_supported: list[str] = Field(default_factory=list)
    oauth_leeway_seconds: int = 30
    oauth_jwks_cache_seconds: int = 300

    # Observability: OpenTelemetry traces are exported over OTLP/HTTP when
    # ``otel_enabled`` is true; left unset it follows ``otel_endpoint`` (off
    # in dev/test, on as soon as a collector endpoint is configured). Logs of
    # the ``aegis_mcp`` namespace are DLP-scrubbed ``json`` lines or ``text``.
    otel_enabled: bool | None = None
    otel_endpoint: str | None = None
    otel_service_name: str = "aegis-mcp"
    log_format: Literal["json", "text"] = "json"

    def otel_active(self) -> bool:
        """Effective tracing switch (explicit flag, else endpoint presence)."""
        if self.otel_enabled is not None:
            return self.otel_enabled
        return bool(self.otel_endpoint)

    def oauth_config(self) -> OAuthConfig:
        """Build the validated OAuth config (raises ValueError when incomplete)."""
        return OAuthConfig(
            issuer=self.oauth_issuer or "",
            resource=self.oauth_audience or "",
            jwks_url=self.oauth_jwks_url or "",
            algorithms=tuple(self.oauth_algorithms),
            authorization_servers=tuple(self.oauth_authorization_servers),
            scopes_supported=tuple(self.oauth_scopes_supported),
            leeway_seconds=self.oauth_leeway_seconds,
            jwks_cache_seconds=self.oauth_jwks_cache_seconds,
        )


settings = Settings()
