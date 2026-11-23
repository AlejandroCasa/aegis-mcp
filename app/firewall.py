"""Zero-Trust MCP Firewall and SHA-256 hash-chained SQLite audit ledger."""

import json
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from app.config import settings
from app.constraints import evaluate_constraints
from app.ledger import (
    GENESIS_HASH,
    AuditLedger,
    LedgerRecord,
    compute_entry_hash,
    compute_entry_hash_v2,
    digest_arguments,
)
from app.normalize import detection_views
from app.policy import (
    FAIL_CLOSED_VIOLATION,
    RBAC_RISK_SCORE,
    RBAC_VIOLATION,
    PolicyEngine,
    build_policy_engine,
    evaluate_policy,
)
from app.redactor import redact_payload
from app.schemas import (
    AuditEntry,
    ChainVerificationResponse,
    Decision,
    MCPInspectionResponse,
    MCPToolCallRequest,
)

__all__ = [
    "GENESIS_HASH",
    "LedgerRecord",
    "MCPFirewall",
    "compute_entry_hash",
    "compute_entry_hash_v2",
    "evaluate_threats",
]

OBFUSCATION_VIOLATION = "obfuscated_payload"
DECODE_BUDGET_VIOLATION = "decode_budget_exceeded"
DECODE_BUDGET_RISK_SCORE = 50

THREAT_RULES: tuple[tuple[str, int, re.Pattern[str]], ...] = (
    (
        "prompt_injection",
        90,
        re.compile(
            r"(?:ignore\s+(?:all\s+)?previous\s+instructions|"
            r"system\s+prompt\s*:|<\|im_start\|>|override\s+security\s+policy)",
            re.IGNORECASE,
        ),
    ),
    (
        "path_traversal",
        85,
        re.compile(
            r"(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|\.ssh/id_rsa|\.env\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "destructive_sql",
        80,
        re.compile(
            r"(?:\bDROP\s+TABLE\b|\bTRUNCATE\s+TABLE\b|"
            r"\bDELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1)",
            re.IGNORECASE,
        ),
    ),
    (
        "command_injection",
        95,
        re.compile(
            r"(?:\brm\s+-rf\b|;\s*(?:curl|wget|bash|sh)\b|"
            r"\|\s*(?:bash|sh)\b|\$\([^)]+\))",
            re.IGNORECASE,
        ),
    ),
)


def _match_rule(pattern: re.Pattern[str], views: list[str]) -> tuple[bool, bool]:
    """Return ``(matched, hidden)``: hidden means no match in the raw view."""
    if pattern.search(views[0]):
        return True, False
    hidden = any(pattern.search(view) for view in views[1:])
    return hidden, hidden


def evaluate_threats(payload_text: str) -> tuple[int, list[str]]:
    """Scan tool arguments against Zero-Trust threat rules after canonicalization.

    Rules run on every detection view (raw, Unicode-folded, percent/HTML
    decoded, recursively Base64/hex decoded; see ``app/normalize.py``). A
    match that only exists in a transformed view adds ``obfuscated_payload``;
    running out of decode budget adds the advisory ``decode_budget_exceeded``.
    """
    analysis = detection_views(payload_text)
    violations: list[str] = []
    max_score = 0
    obfuscated = False

    for rule_name, score, pattern in THREAT_RULES:
        matched, hidden = _match_rule(pattern, analysis.views)
        if matched:
            violations.append(rule_name)
            max_score = max(max_score, score)
            obfuscated = obfuscated or hidden

    if obfuscated:
        violations.append(OBFUSCATION_VIOLATION)
    if analysis.exhausted:
        violations.append(DECODE_BUDGET_VIOLATION)
        max_score = max(max_score, DECODE_BUDGET_RISK_SCORE)
    return max_score, violations


class MCPFirewall:
    """Inspects MCP tool calls, applies DLP redaction, and maintains a hash chain."""

    def __init__(
        self,
        db_path: str | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        """Initialize SQLite audit ledger and the RBAC policy engine.

        Without an explicit engine the startup policy is built fail-closed:
        ``AEGIS_ENVIRONMENT=prod`` with no valid policy denies every call.
        """
        self.db_path = db_path or settings.db_path
        self.policy_engine = policy_engine or build_policy_engine(
            settings.policy_path, settings.environment
        )
        self.ledger = AuditLedger(self.db_path, wal=settings.ledger_wal)
        self._init_db()

    def _apply_policy(
        self,
        request: MCPToolCallRequest,
        violations: list[str],
        constraint_arguments: dict[str, Any] | None,
    ) -> tuple[bool, str]:
        """Evaluate RBAC and argument ABAC against one atomic policy snapshot.

        Appends ``rbac_policy_denied`` (plus ``policy_fail_closed`` under the
        startup deny-all fallback) and any ``argument_*`` constraint codes;
        returns ``(denied, policy_version)``.
        """
        document, version, fail_closed = self.policy_engine.snapshot()
        scope = (
            request.agent_id,
            request.server_name,
            request.tool_name,
            request.environment,
        )
        rbac_denied = not evaluate_policy(document, *scope)
        if rbac_denied:
            violations.append(RBAC_VIOLATION)
            if fail_closed:
                violations.append(FAIL_CLOSED_VIOLATION)
        subject = (
            request.arguments if constraint_arguments is None else constraint_arguments
        )
        argument_violations = evaluate_constraints(document, scope, subject)
        violations.extend(argument_violations)
        return rbac_denied or bool(argument_violations), version

    @staticmethod
    def _decide(
        risk_score: int, denied: bool, redacted: bool
    ) -> tuple[bool, Decision, bool]:
        """Map the evaluation to ``(allowed, decision, would_block)``.

        In ``monitor`` (shadow) mode nothing is blocked: the call keeps its
        ALLOWED/SANITIZED decision and ``would_block`` records the verdict
        enforce mode would have reached.
        """
        would_block = denied or risk_score >= settings.block_threshold_score
        if would_block and settings.policy_mode == "enforce":
            return False, "BLOCKED", True
        return True, "SANITIZED" if redacted else "ALLOWED", would_block

    def _init_db(self) -> None:
        """Create/migrate the audit ledger (WAL, additive v1 -> v2 columns)."""
        self.ledger.init()

    def inspect(
        self,
        request: MCPToolCallRequest,
        constraint_arguments: dict[str, Any] | None = None,
        denials: Sequence[str] = (),
        session_id: str = "",
    ) -> MCPInspectionResponse:
        """Inspect an MCP tool call, redact PII/secrets, and append to hash ledger.

        ``constraint_arguments`` selects the object argument constraints apply
        to when ``request.arguments`` wraps it (e.g. JSON-RPC ``tools/call``
        params carry the tool arguments under ``params.arguments``); threat
        rules and DLP always scan the full ``request.arguments``.
        ``denials`` are gateway-level violations (e.g. ``tool_definition_drift``)
        that deny the call exactly like an RBAC denial. ``session_id`` (the
        gateway ``Mcp-Session-Id``) and the JCS digest of the sanitized
        arguments are bound into the v2 ledger hash.
        """
        raw_serialized = json.dumps(
            request.arguments, sort_keys=True, ensure_ascii=False
        )
        risk_score, violations = evaluate_threats(raw_serialized)
        violations.extend(denials)
        policy_denied, version = self._apply_policy(
            request, violations, constraint_arguments
        )
        policy_denied = policy_denied or bool(denials)
        if policy_denied:
            risk_score = RBAC_RISK_SCORE

        sanitized_args: dict[str, Any] = dict(request.arguments)
        redacted_categories: list[str] = []
        if settings.enable_dlp_redaction:
            sanitized_args, redacted_categories = redact_payload(request.arguments)
            if redacted_categories and risk_score < 25:
                risk_score = 25

        allowed, decision, would_block = self._decide(
            risk_score, policy_denied, bool(redacted_categories)
        )
        record = LedgerRecord(
            agent_id=request.agent_id,
            server_name=request.server_name,
            tool_name=request.tool_name,
            environment=request.environment,
            decision=decision,
            risk_score=risk_score,
            violations=violations,
            redacted_categories=redacted_categories,
            timestamp=request.timestamp.isoformat(),
            would_block=would_block,
            policy_mode=settings.policy_mode,
            policy_version=version,
            session_id=session_id,
            args_digest=digest_arguments(sanitized_args),
        )
        prev_hash, entry_hash = self._append(record)

        return MCPInspectionResponse(
            allowed=allowed,
            decision=decision,
            risk_score=risk_score,
            violations=violations,
            redacted_categories=redacted_categories,
            sanitized_arguments=sanitized_args if allowed else {},
            audit_hash=entry_hash,
            prev_hash=prev_hash,
            timestamp=request.timestamp,
            would_block=would_block,
            policy_mode=record.policy_mode,
            policy_version=version,
        )

    def record_event(
        self,
        scope: tuple[str, str, str, str],
        violations: list[str],
        risk_score: int = RBAC_RISK_SCORE,
        session_id: str = "",
    ) -> tuple[Decision, str]:
        """Append a blocking gateway event (e.g. tool drift) to the hash chain.

        ``scope`` is ``(agent_id, server_name, tool_name, environment)``. The
        decision is ``BLOCKED`` in enforce mode and ``ALLOWED`` (with
        ``would_block``) in monitor mode; returns ``(decision, entry_hash)``.
        """
        agent_id, server_name, tool_name, environment = scope
        decision: Decision = (
            "BLOCKED" if settings.policy_mode == "enforce" else "ALLOWED"
        )
        record = LedgerRecord(
            agent_id=agent_id,
            server_name=server_name,
            tool_name=tool_name,
            environment=environment,
            decision=decision,
            risk_score=risk_score,
            violations=list(violations),
            redacted_categories=[],
            timestamp=datetime.now(UTC).isoformat(),
            would_block=True,
            policy_mode=settings.policy_mode,
            policy_version=self.policy_engine.version,
            session_id=session_id,
            args_digest=digest_arguments({}),
        )
        return decision, self._append(record)[1]

    def _append(self, record: LedgerRecord) -> tuple[str, str]:
        """Link ``record`` (v2) to the chain head; ``(prev_hash, entry_hash)``."""
        return self.ledger.append(record)

    def list_audit_entries(self, agent_id: str | None = None) -> list[AuditEntry]:
        """Return persisted audit entries, optionally filtered by agent_id."""
        return self.ledger.list_entries(agent_id)

    def verify_chain(self) -> ChainVerificationResponse:
        """Verify every link (legacy v1 and full-payload v2) of the ledger."""
        return self.ledger.verify()

    def close(self) -> None:
        """Graceful shutdown hook (connections are per-operation)."""

    def reset(self) -> None:
        """Clear audit ledger table for deterministic test isolation."""
        self.ledger.reset()
