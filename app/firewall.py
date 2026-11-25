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
    PolicyDocument,
    TaintLabel,
)
from app.taint import (
    TOXIC_FLOW_VIOLATION,
    SessionTaintTracker,
    TaintCall,
    TaintVerdict,
    classify,
    evaluate_flow,
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
        taint: SessionTaintTracker | None = None,
    ) -> None:
        """Initialize SQLite audit ledger, RBAC policy engine, and taint tracker.

        Without an explicit engine the startup policy is built fail-closed:
        ``AEGIS_ENVIRONMENT=prod`` with no valid policy denies every call.
        """
        self.db_path = db_path or settings.db_path
        self.policy_engine = policy_engine or build_policy_engine(
            settings.policy_path, settings.environment
        )
        self.taint = taint or SessionTaintTracker(
            settings.mcp_session_ttl_seconds, settings.mcp_max_sessions
        )
        self.ledger = AuditLedger(self.db_path, wal=settings.ledger_wal)
        self._init_db()

    def _apply_policy(
        self,
        snapshot: tuple[PolicyDocument, str, bool],
        request: MCPToolCallRequest,
        violations: list[str],
        constraint_arguments: dict[str, Any] | None,
    ) -> bool:
        """Evaluate RBAC and argument ABAC against one atomic policy snapshot.

        Appends ``rbac_policy_denied`` (plus ``policy_fail_closed`` under the
        startup deny-all fallback) and any ``argument_*`` constraint codes;
        returns True if the call is denied.
        """
        document, _, fail_closed = snapshot
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
        return rbac_denied or bool(argument_violations)

    def _taint_flow(
        self,
        document: PolicyDocument,
        request: MCPToolCallRequest,
        session_id: str,
        redacted: bool,
    ) -> TaintVerdict:
        """Evaluate the call against the session's toxic-flow taint state."""
        if not settings.enable_taint_tracking:
            return TaintVerdict(toxic=False, carried=frozenset())
        call = TaintCall(
            request.server_name,
            request.tool_name,
            request.environment,
            request.arguments,
        )
        roles = classify(document, call, settings.taint_default_heuristics)
        return evaluate_flow(self.taint.labels(session_id), roles, call, redacted)

    def taint_session(
        self, session_id: str, subject: str, labels: frozenset[TaintLabel]
    ) -> None:
        """Attach taint labels to a session (e.g. outbound DLP promotion)."""
        if settings.enable_taint_tracking:
            self.taint.record(session_id, subject, labels)

    @staticmethod
    def _redact(arguments: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        """Inbound DLP: ``(sanitized_arguments, redacted_categories)``."""
        if not settings.enable_dlp_redaction:
            return dict(arguments), []
        return redact_payload(arguments)

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
        gateway ``Mcp-Session-Id``, else ``request.session_id``) and the JCS
        digest of the sanitized arguments are bound into the v2 ledger hash.

        Session-bound calls run toxic-flow taint analysis: an egress sink in
        a session holding both ``untrusted_content`` and ``private_data`` is
        denied with ``toxic_flow_exfiltration``; an allowed call adds its own
        taint labels to the session.
        """
        session_id = session_id or request.session_id
        raw_serialized = json.dumps(
            request.arguments, sort_keys=True, ensure_ascii=False
        )
        risk_score, violations = evaluate_threats(raw_serialized)
        violations.extend(denials)
        snapshot = self.policy_engine.snapshot()
        version = snapshot[1]
        policy_denied = self._apply_policy(
            snapshot, request, violations, constraint_arguments
        )
        sanitized_args, redacted_categories = self._redact(request.arguments)
        flow = self._taint_flow(
            snapshot[0], request, session_id, bool(redacted_categories)
        )
        if flow.toxic:
            violations.append(TOXIC_FLOW_VIOLATION)
        if policy_denied or denials or flow.toxic:
            policy_denied = True
            risk_score = RBAC_RISK_SCORE
        elif redacted_categories:
            risk_score = max(risk_score, 25)

        allowed, decision, would_block = self._decide(
            risk_score, policy_denied, bool(redacted_categories)
        )
        if allowed:
            self.taint_session(session_id, request.tool_name, flow.carried)
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
        """Clear audit ledger and session taint for deterministic isolation."""
        self.ledger.reset()
        self.taint.reset()
