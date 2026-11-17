"""Runtime configuration settings for Aegis-MCP validated via pydantic-settings."""

import os
import tempfile

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    mcp_upstreams: dict[str, str] = Field(default_factory=dict)
    upstream_timeout_seconds: float = 10.0


settings = Settings()
