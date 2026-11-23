"""Pydantic v2 data contracts for Aegis-MCP inspection and cryptographic auditing."""

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

Environment = Literal["dev", "staging", "prod"]
PolicyMode = Literal["enforce", "monitor"]
Decision = Literal["ALLOWED", "SANITIZED", "BLOCKED"]

GlobPattern = Annotated[str, StringConstraints(min_length=1, max_length=256)]
"""Case-sensitive ``fnmatch`` glob (``*``, ``?``, ``[seq]``) for RBAC matching."""


def _all_environments() -> list[Environment]:
    """Return every deployment environment (default RBAC rule scope)."""
    return ["dev", "staging", "prod"]


class MCPToolCallRequest(BaseModel):
    """Represents an incoming Model Context Protocol (MCP) tool invocation."""

    agent_id: str = Field(
        default="default-agent",
        min_length=1,
        max_length=256,
        description="Identifier of the calling AI agent or orchestrator.",
    )
    server_name: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Target MCP server identifier (e.g. postgres-mcp, filesystem-mcp).",
    )
    tool_name: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Name of the MCP tool being invoked (e.g. query_db, read_file).",
    )
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON arguments passed to the MCP tool call.",
    )
    environment: Environment = Field(
        default="prod",
        description="Execution environment context.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of the tool invocation.",
    )


class MCPInspectionResponse(BaseModel):
    """Represents the Zero-Trust firewall decision and sanitized payload."""

    allowed: bool = Field(
        ...,
        description="True if the MCP tool call is permitted to execute.",
    )
    decision: Literal["ALLOWED", "SANITIZED", "BLOCKED"] = Field(
        ...,
        description="Policy decision outcome.",
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Computed risk score from 0 (benign) to 100 (critical threat).",
    )
    violations: list[str] = Field(
        default_factory=list,
        description="List of triggered security rules or threat categories.",
    )
    redacted_categories: list[str] = Field(
        default_factory=list,
        description="Categories of sensitive data scrubbed by the DLP redactor.",
    )
    sanitized_arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments with PII and secrets scrubbed for safe forwarding.",
    )
    audit_hash: str = Field(
        ...,
        description="SHA-256 tamper-evident hash of this audit ledger record.",
    )
    prev_hash: str = Field(
        ...,
        description="SHA-256 hash of the preceding record in the ledger chain.",
    )
    timestamp: datetime = Field(
        ...,
        description="UTC timestamp of the firewall evaluation.",
    )
    would_block: bool = Field(
        default=False,
        description="True if enforce mode would block the call (shadow signal).",
    )
    policy_mode: PolicyMode = Field(
        default="enforce",
        description="Policy mode that produced the decision (enforce|monitor).",
    )
    policy_version: str = Field(
        default="",
        description="SHA-256 (RFC 8785 JCS) of the policy document that decided.",
    )


class AuditEntry(BaseModel):
    """Represents a persisted tamper-evident record in the SQLite audit ledger."""

    id: int = Field(..., description="Sequential ledger entry ID.")
    agent_id: str = Field(..., description="Calling AI agent identifier.")
    server_name: str = Field(..., description="Target MCP server name.")
    tool_name: str = Field(..., description="Invoked MCP tool name.")
    environment: str = Field(..., description="Deployment environment.")
    decision: Literal["ALLOWED", "SANITIZED", "BLOCKED"] = Field(
        ...,
        description="Recorded firewall decision.",
    )
    risk_score: int = Field(..., description="Evaluated risk score (0-100).")
    violations: list[str] = Field(
        default_factory=list,
        description="Triggered threat violation codes.",
    )
    redacted_categories: list[str] = Field(
        default_factory=list,
        description="Scrubbed DLP categories.",
    )
    prev_hash: str = Field(..., description="Previous entry SHA-256 hash.")
    entry_hash: str = Field(..., description="Current entry SHA-256 hash.")
    timestamp: str = Field(..., description="ISO-8601 UTC timestamp.")
    would_block: bool = Field(
        default=False, description="Shadow signal: enforce mode would block."
    )
    policy_mode: str = Field(default="enforce", description="enforce|monitor.")
    policy_version: str = Field(
        default="", description="SHA-256 of the deciding policy document."
    )


class ChainVerificationResponse(BaseModel):
    """Represents the cryptographic integrity status of the SQLite audit ledger."""

    valid: bool = Field(
        ...,
        description="True if every SHA-256 link in the audit chain is intact.",
    )
    total_entries: int = Field(
        ...,
        ge=0,
        description="Total number of audit records verified.",
    )
    head_hash: str = Field(
        ...,
        description="Latest SHA-256 entry hash at the tip of the ledger.",
    )
    corrupted_entry_id: int | None = Field(
        default=None,
        description="ID of the first tampered record if integrity verification fails.",
    )


class PolicyRule(BaseModel):
    """A single RBAC matrix row scoped by agent, server, and environment.

    A rule applies when ``agent_id`` and ``server_name`` glob-match the call and
    the call's environment is listed. ``deny_tools`` always win; a non-empty
    ``allow_tools`` turns the rule into an allowlist for the matched scope.
    """

    model_config = ConfigDict(extra="forbid")

    agent_id: GlobPattern = Field(
        default="*",
        description="Glob matched against the calling agent_id.",
    )
    server_name: GlobPattern = Field(
        default="*",
        description="Glob matched against the target MCP server name.",
    )
    environments: list[Environment] = Field(
        default_factory=_all_environments,
        min_length=1,
        max_length=3,
        description="Environments in which this rule applies.",
    )
    allow_tools: list[GlobPattern] = Field(
        default_factory=list,
        max_length=512,
        description="Tool-name globs authorized for the matched scope.",
    )
    deny_tools: list[GlobPattern] = Field(
        default_factory=list,
        max_length=512,
        description="Tool-name globs always denied for the matched scope.",
    )

    @model_validator(mode="after")
    def _require_effect(self) -> "PolicyRule":
        """Reject no-op rules (e.g. a typo leaving both tool lists empty)."""
        if not self.allow_tools and not self.deny_tools:
            raise ValueError("RBAC rule must declare allow_tools or deny_tools.")
        return self


ArgumentName = Annotated[str, StringConstraints(min_length=1, max_length=128)]
"""Top-level tool argument key inspected by an argument constraint."""

AllowedPath = Annotated[str, StringConstraints(min_length=1, max_length=4096)]
"""Absolute filesystem root; canonicalized with ``realpath`` at evaluation."""

DomainPattern = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=253,
        pattern=r"^(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$",
    ),
]
"""Egress host: exact ``example.com`` or any subdomain via ``*.example.com``."""

MAX_CONSTRAINT_BYTES = 67_108_864


def _default_path_args() -> list[str]:
    """Argument keys treated as filesystem paths by default."""
    return ["path", "paths", "file", "file_path", "filename", "directory"]


def _default_sql_args() -> list[str]:
    """Argument keys treated as SQL statements by default."""
    return ["query", "sql", "statement"]


def _default_url_args() -> list[str]:
    """Argument keys treated as outbound URLs by default."""
    return ["url", "uri", "endpoint", "href"]


class ToolConstraint(BaseModel):
    """Argument-level ABAC constraint for tools matched by scope globs.

    Every matching constraint applies (logical AND). Constrained argument keys
    holding a non-string value fail closed.
    """

    model_config = ConfigDict(extra="forbid")

    agent_id: GlobPattern = Field(default="*", description="Agent glob.")
    server_name: GlobPattern = Field(default="*", description="Server glob.")
    tool_name: GlobPattern = Field(default="*", description="Tool-name glob.")
    environments: list[Environment] = Field(
        default_factory=_all_environments, min_length=1, max_length=3
    )
    path_allow: list[AllowedPath] = Field(
        default_factory=list,
        max_length=64,
        description="Allowed roots; paths are realpath-canonicalized (anti-symlink).",
    )
    path_args: list[ArgumentName] = Field(
        default_factory=_default_path_args, max_length=64
    )
    sql_mode: Literal["read_only"] | None = Field(
        default=None, description="``read_only`` allows a single SELECT/WITH."
    )
    sql_args: list[ArgumentName] = Field(
        default_factory=_default_sql_args, max_length=64
    )
    egress_allow: list[DomainPattern] = Field(
        default_factory=list,
        max_length=256,
        description="Allowed http(s) destination hosts for URL arguments.",
    )
    url_args: list[ArgumentName] = Field(
        default_factory=_default_url_args, max_length=64
    )
    max_bytes: int | None = Field(
        default=None, ge=1, le=MAX_CONSTRAINT_BYTES, description="Serialized cap."
    )
    max_items: int | None = Field(
        default=None, ge=0, le=1_000_000, description="Max elements per array."
    )

    @model_validator(mode="after")
    def _validate_constraint(self) -> "ToolConstraint":
        """Reject no-op constraints and relative allow roots."""
        if not (
            self.path_allow
            or self.sql_mode
            or self.egress_allow
            or self.max_bytes is not None
            or self.max_items is not None
        ):
            raise ValueError("Tool constraint must declare at least one limit.")
        if not all(root.startswith("/") for root in self.path_allow):
            raise ValueError("path_allow roots must be absolute paths.")
        return self


PinKindName = Literal["server", "tool", "resource", "prompt"]


class ToolPin(BaseModel):
    """A pinned MCP definition fingerprint (TOFU + explicit approval)."""

    server_name: str = Field(..., description="Upstream MCP server name.")
    kind: PinKindName = Field(..., description="Definition kind.")
    name: str = Field(..., description="Tool/prompt name or resource URI.")
    fingerprint: str = Field(..., description="Pinned SHA-256 (RFC 8785 JCS).")
    status: Literal["pending", "approved"] = Field(..., description="Approval.")
    drift_fingerprint: str | None = Field(
        default=None, description="Latest differing fingerprint (sticky drift)."
    )
    first_seen: str = Field(..., description="ISO-8601 UTC first observation.")
    updated_at: str = Field(..., description="ISO-8601 UTC last change.")


class ToolApproval(BaseModel):
    """Operator approval of a pinned or drifted definition fingerprint."""

    model_config = ConfigDict(extra="forbid")

    server_name: str = Field(..., min_length=1, max_length=256)
    kind: PinKindName = Field(default="tool")
    name: str = Field(..., min_length=1, max_length=1024)
    fingerprint: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class PolicyStatus(BaseModel):
    """Operational state of the active policy (version, mode, fail-closed)."""

    policy_version: str = Field(..., description="SHA-256 of the active document.")
    policy_mode: PolicyMode = Field(..., description="enforce|monitor.")
    environment: Environment = Field(..., description="Gateway deployment env.")
    fail_closed: bool = Field(
        ..., description="True while the startup deny-all fallback is active."
    )


class PolicyDocument(BaseModel):
    """Declarative RBAC policy matrix applied to every MCP tool call."""

    model_config = ConfigDict(extra="forbid")

    default_action: Literal["allow", "deny"] = Field(
        default="allow",
        description="Decision applied when no matching rule declares an allowlist.",
    )
    rules: list[PolicyRule] = Field(
        default_factory=list,
        max_length=1024,
        description="Ordered RBAC rules (evaluation is order-independent).",
    )
    tool_constraints: list[ToolConstraint] = Field(
        default_factory=list,
        max_length=1024,
        description="Argument-level ABAC constraints (all matching apply).",
    )
