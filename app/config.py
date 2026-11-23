"""Runtime configuration settings for Aegis-MCP validated via pydantic-settings."""

import os
import tempfile

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
    policy_path: str | None = None
    # Deployment environment of this gateway: ``prod`` fails closed (deny-all)
    # when no valid policy is loaded at startup.
    environment: Environment = "dev"
    # ``enforce`` blocks; ``monitor`` (shadow mode) evaluates and audits
    # ``would_block`` without blocking, for progressive production rollouts.
    policy_mode: PolicyMode = "enforce"
    mcp_upstreams: dict[str, str] = Field(default_factory=dict)
    upstream_timeout_seconds: float = 10.0

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
