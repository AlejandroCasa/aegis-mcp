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
TaintRole = Literal["untrusted_content", "private_data", "egress_sink"]
TaintLabel = Literal["untrusted_content", "private_data"]
PolicyAction = Literal["allow", "deny", "require_approval"]
ApprovalStatus = Literal["pending", "approved", "denied", "expired"]
ApprovalId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
"""Opaque HITL approval identifier (UUID4 hex)."""

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
    session_id: str = Field(
        default="",
        max_length=1024,
        description="Optional agent session for toxic-flow taint tracking.",
    )
    approval_id: ApprovalId | None = Field(
        default=None,
        description="HITL approval to redeem for a ``require_approval`` call.",
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
    approval_id: str | None = Field(
        default=None,
        description="HITL approval request bound to this call, if any.",
    )
    approval_status: ApprovalStatus | None = Field(
        default=None,
        description="Status of the bound HITL approval request.",
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
    hash_version: int = Field(
        default=1, description="Link format: 1 legacy, 2 full-payload JCS."
    )
    session_id: str = Field(
        default="", description="Gateway MCP session (Mcp-Session-Id), if any."
    )
    args_digest: str = Field(
        default="", description="JCS SHA-256 of the sanitized arguments (v2)."
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
    legacy_entries: int = Field(
        default=0,
        ge=0,
        description="Entries still linked with the legacy v1 hash format.",
    )


class SignedCheckpoint(BaseModel):
    """Ed25519 Signed Tree Head over the RFC 6962 Merkle tree of the ledger."""

    tree_size: int = Field(..., ge=0, description="Entries committed to.")
    root_hash: str = Field(..., description="RFC 6962 Merkle Tree Hash (hex).")
    timestamp: str = Field(..., description="ISO-8601 UTC signing time.")
    prev_checkpoint_hash: str = Field(
        ..., description="Checkpoint hash of the previous tree head (hex)."
    )
    checkpoint_hash: str = Field(
        ..., description="SHA-256 of the signed canonical tree head (hex)."
    )
    algorithm: Literal["Ed25519"] = "Ed25519"
    signature: str = Field(..., description="Ed25519 signature (hex).")
    public_key: str = Field(..., description="Raw Ed25519 public key (hex).")
    key_fingerprint: str = Field(
        ..., description="SHA-256 fingerprint of the public key (hex)."
    )


class InclusionProofResponse(BaseModel):
    """RFC 6962 Merkle inclusion proof of one audit ledger entry."""

    entry_id: int = Field(..., description="Ledger entry ID.")
    leaf_index: int = Field(..., ge=0, description="0-based Merkle leaf index.")
    tree_size: int = Field(..., ge=1, description="Size of the proven tree.")
    entry_hash: str = Field(..., description="Entry hash used as Merkle leaf.")
    root_hash: str = Field(..., description="Merkle Tree Hash the proof targets.")
    audit_path: list[str] = Field(
        default_factory=list, description="Sibling hashes, leaf to root (hex)."
    )
    checkpoint: SignedCheckpoint | None = Field(
        default=None,
        description="Signed Tree Head of ``tree_size`` (absent when unsigned).",
    )


class PolicyRule(BaseModel):
    """A single RBAC matrix row scoped by agent, server, and environment.

    A rule applies when ``agent_id`` and ``server_name`` glob-match the call and
    the call's environment is listed. ``deny_tools`` always win; a non-empty
    ``allow_tools`` turns the rule into an allowlist for the matched scope.
    ``require_approval_tools`` gate matching tools behind a human-in-the-loop
    approval (and satisfy any allowlist in scope).
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
    require_approval_tools: list[GlobPattern] = Field(
        default_factory=list,
        max_length=512,
        description="Tool-name globs requiring human approval in the scope.",
    )

    @model_validator(mode="after")
    def _require_effect(self) -> "PolicyRule":
        """Reject no-op rules (e.g. a typo leaving every tool list empty)."""
        if not (self.allow_tools or self.deny_tools or self.require_approval_tools):
            raise ValueError(
                "RBAC rule must declare allow_tools, deny_tools or "
                "require_approval_tools."
            )
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


class ToolTaintRule(BaseModel):
    """Declarative toxic-flow taint classification for matching tools.

    Every matching rule contributes its ``roles`` (union); explicit rules are
    combined with the built-in heuristics unless those are disabled.
    """

    model_config = ConfigDict(extra="forbid")

    server_name: GlobPattern = Field(default="*", description="Server glob.")
    tool_name: GlobPattern = Field(default="*", description="Tool-name glob.")
    environments: list[Environment] = Field(
        default_factory=_all_environments, min_length=1, max_length=3
    )
    roles: list[TaintRole] = Field(
        ...,
        min_length=1,
        max_length=3,
        description="untrusted_content | private_data | egress_sink.",
    )


class SessionTaintStatus(BaseModel):
    """Toxic-flow taint state of one agent session (observability)."""

    session_id: str = Field(..., description="Agent / MCP session identifier.")
    labels: list[TaintLabel] = Field(
        default_factory=list, description="Taint labels held by the session."
    )
    lethal_trifecta_armed: bool = Field(
        ..., description="True when any egress sink would now be denied."
    )
    sources: list[str] = Field(
        default_factory=list,
        description="Bounded provenance (``<tool>:<label>``), oldest first.",
    )


class PolicyDocument(BaseModel):
    """Declarative RBAC policy matrix applied to every MCP tool call."""

    model_config = ConfigDict(extra="forbid")

    default_action: PolicyAction = Field(
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
    taint_rules: list[ToolTaintRule] = Field(
        default_factory=list,
        max_length=1024,
        description="Toxic-flow taint classification (lethal trifecta defense).",
    )


class HitlApproval(BaseModel):
    """A human-in-the-loop approval request for a ``require_approval`` call."""

    id: str = Field(..., description="Approval identifier (UUID4 hex).")
    agent_id: str = Field(..., description="Requesting agent.")
    server_name: str = Field(..., description="Target MCP server.")
    tool_name: str = Field(..., description="Gated tool.")
    environment: str = Field(..., description="Deployment environment.")
    arguments_hash: str = Field(..., description="JCS SHA-256 of the arguments.")
    sanitized_arguments: dict[str, Any] = Field(
        default_factory=dict, description="DLP-redacted arguments for review."
    )
    session_id: str = Field(default="", description="Agent session, if any.")
    status: ApprovalStatus = Field(..., description="Lifecycle status.")
    created_at: str = Field(..., description="ISO-8601 UTC creation time.")
    expires_at: str = Field(..., description="ISO-8601 UTC expiry (TTL bound).")
    resolved_by: str | None = Field(default=None, description="Resolver identity.")
    resolved_at: str | None = Field(default=None, description="Resolution time.")
    reason: str | None = Field(default=None, description="Resolution reason.")
    consumed_at: str | None = Field(
        default=None, description="Single-use redemption time of an approval."
    )


class ApprovalResolution(BaseModel):
    """Operator decision on a pending HITL approval request."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["approved", "denied"] = Field(..., description="Decision.")
    reason: str | None = Field(default=None, max_length=1024)
