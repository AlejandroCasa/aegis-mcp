"""Zero-Trust MCP Firewall and SHA-256 hash-chained SQLite audit ledger."""

import json
import logging
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from time import perf_counter
from typing import Any

from app.approvals import (
    HITL_DENIED_RISK_SCORE,
    HITL_DENIED_VIOLATION,
    HITL_GRANTED_EVENT,
    ApprovalKey,
    ApprovalQueue,
    HitlOutcome,
    gate_outcome,
    monitor_outcome,
)
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
from app.merkle import load_signer
from app.metrics import metrics_registry
from app.normalize import detection_views
from app.policy import (
    FAIL_CLOSED_VIOLATION,
    RBAC_RISK_SCORE,
    RBAC_VIOLATION,
    PolicyEngine,
    build_policy_engine,
    evaluate_action,
)
from app.rate_limit import (
    RATE_ANOMALY_KINDS,
    VELOCITY_VIOLATION,
    BehaviorRateLimiter,
    LimiterConfig,
    RateScope,
    RateVerdict,
)
from app.redactor import redact_payload
from app.schemas import (
    AuditEntry,
    ChainVerificationResponse,
    Decision,
    HitlApproval,
    MCPInspectionResponse,
    MCPToolCallRequest,
    PolicyDocument,
    TaintLabel,
    TokenBucketLimit,
    VelocityLimit,
)
from app.taint import (
    TOXIC_FLOW_VIOLATION,
    SessionTaintTracker,
    TaintCall,
    TaintVerdict,
    classify,
    evaluate_flow,
)
from app.telemetry import (
    decision_attributes,
    get_tracer,
    mcp_attributes,
    sanitize_log_value,
)
from app.webhooks import Incident, WebhookDispatcher

__all__ = [
    "GENESIS_HASH",
    "LedgerRecord",
    "MCPFirewall",
    "compute_entry_hash",
    "compute_entry_hash_v2",
    "evaluate_threats",
]

logger = logging.getLogger("aegis_mcp.inspection")

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


def limiter_config_from_settings() -> LimiterConfig:
    """Build the rate limiter defaults from ``AEGIS_RATE_LIMIT_*`` settings."""
    return LimiterConfig(
        enabled=settings.rate_limit_enabled,
        bucket=TokenBucketLimit(
            capacity=settings.rate_limit_capacity,
            refill_per_sec=settings.rate_limit_refill_per_sec,
        ),
        velocity=VelocityLimit(
            window_seconds=settings.velocity_window_seconds,
            max_reads=settings.velocity_max_reads,
        ),
        max_keys=settings.rate_limit_max_keys,
    )


class MCPFirewall:
    """Inspects MCP tool calls, applies DLP redaction, and maintains a hash chain."""

    def __init__(
        self,
        db_path: str | None = None,
        policy_engine: PolicyEngine | None = None,
        taint: SessionTaintTracker | None = None,
        approvals: ApprovalQueue | None = None,
        webhooks: WebhookDispatcher | None = None,
        rate_limiter: BehaviorRateLimiter | None = None,
    ) -> None:
        """Initialize ledger, RBAC engine, taint, rate limits, HITL and webhooks.

        Without an explicit engine the startup policy is built fail-closed:
        ``AEGIS_ENVIRONMENT=prod`` with no valid policy denies every call.
        An invalid ``AEGIS_WEBHOOK_URL`` raises ``WebhookConfigError``; a
        missing/invalid checkpoint signing key in prod raises
        ``SigningKeyError`` (fail-closed).
        """
        self.db_path = db_path or settings.db_path
        self.policy_engine = policy_engine or build_policy_engine(
            settings.policy_path, settings.environment
        )
        self.taint = taint or SessionTaintTracker(
            settings.mcp_session_ttl_seconds, settings.mcp_max_sessions
        )
        self.rate_limiter = rate_limiter or BehaviorRateLimiter(
            limiter_config_from_settings()
        )
        self.ledger = AuditLedger(
            self.db_path,
            wal=settings.ledger_wal,
            signer=load_signer(
                settings.checkpoint_signing,
                settings.signing_key_path,
                settings.signing_key_ephemeral,
                settings.environment,
            ),
            checkpoint_interval=settings.checkpoint_interval,
        )
        self._init_db()
        self.approvals = approvals or ApprovalQueue(
            self.db_path, settings.hitl_timeout_seconds
        )
        self.webhooks = webhooks or WebhookDispatcher(
            settings.webhook_url,
            settings.environment,
            settings.webhook_cooldown_seconds,
            settings.webhook_timeout_seconds,
        )

    def _apply_policy(
        self,
        snapshot: tuple[PolicyDocument, str, bool],
        request: MCPToolCallRequest,
        violations: list[str],
        subject: dict[str, Any],
    ) -> tuple[bool, bool]:
        """Evaluate RBAC and argument ABAC against one atomic policy snapshot.

        Appends ``rbac_policy_denied`` (plus ``policy_fail_closed`` under the
        startup deny-all fallback) and any ``argument_*`` constraint codes;
        returns ``(denied, requires_approval)``.
        """
        document, _, fail_closed = snapshot
        scope = (
            request.agent_id,
            request.server_name,
            request.tool_name,
            request.environment,
        )
        action = evaluate_action(document, *scope)
        rbac_denied = action == "deny"
        if rbac_denied:
            violations.append(RBAC_VIOLATION)
            if fail_closed:
                violations.append(FAIL_CLOSED_VIOLATION)
        argument_violations = evaluate_constraints(document, scope, subject)
        violations.extend(argument_violations)
        return rbac_denied or bool(argument_violations), action == "require_approval"

    def _hitl_gate(
        self,
        request: MCPToolCallRequest,
        subject: dict[str, Any],
        sanitized: dict[str, Any],
        session_id: str,
    ) -> HitlOutcome:
        """Fail-closed human-in-the-loop gate for ``require_approval`` calls.

        Monitor mode only audits ``hitl_approval_required``. Enforce mode
        redeems a matching single-use approval (or the explicit
        ``approval_id``), else registers/reuses a pending request and polls up
        to ``AEGIS_HITL_WAIT_SECONDS`` for an operator decision.
        """
        if settings.policy_mode != "enforce":
            return monitor_outcome()
        key = ApprovalKey(
            request.agent_id,
            request.server_name,
            request.tool_name,
            request.environment,
            digest_arguments(subject),
        )
        approval = self.approvals.claim(key, request.approval_id)
        created = False
        if approval is None:
            approval, created = self.approvals.submit(key, sanitized, session_id)
        wait = settings.hitl_wait_seconds
        if approval.status != "pending" or wait <= 0:
            return gate_outcome(approval, created, waited=False)
        resolved = self.approvals.wait(key, approval.id, wait) or approval
        return gate_outcome(resolved, created, waited=True)

    def _gate_if_clean(
        self,
        state: tuple[bool, bool, int],
        request: MCPToolCallRequest,
        subject: dict[str, Any],
        sanitized: dict[str, Any],
        session_id: str,
    ) -> HitlOutcome:
        """Run the HITL gate for a ``require_approval`` call not yet blocked.

        ``state`` is ``(requires_approval, denied, threat_risk_score)``. A
        denied or threat-blocked call never opens an approval request, so an
        operator is never asked to green-light e.g. a prompt-injection payload.
        """
        requires_approval, denied, risk_score = state
        if not requires_approval or denied:
            return HitlOutcome()
        if risk_score >= settings.block_threshold_score:
            return HitlOutcome()
        return self._hitl_gate(request, subject, sanitized, session_id)

    @staticmethod
    def _risk(risk_score: int, denied: bool, redacted: bool, hitl: HitlOutcome) -> int:
        """Final risk: 100 when denied, else the max of threat, DLP and HITL."""
        if denied:
            return RBAC_RISK_SCORE
        return max(risk_score, 25 if redacted else 0, hitl.risk_score)

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

    def _rate_check(
        self, document: PolicyDocument, request: MCPToolCallRequest, session_id: str
    ) -> RateVerdict:
        """Token-bucket and exfiltration-velocity verdict (counted in metrics)."""
        verdict = self.rate_limiter.check(
            document,
            RateScope(
                request.agent_id,
                request.server_name,
                request.tool_name,
                request.environment,
                session_id,
            ),
        )
        enforced = settings.policy_mode == "enforce"
        for code in RATE_ANOMALY_KINDS.intersection(verdict.violations):
            metrics_registry.record_rate_anomaly(code, enforced)
        return verdict

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
        """Inspect an MCP tool call inside an ``aegis.firewall.inspect`` span.

        See ``_evaluate`` for the inspection semantics. The span carries the
        GenAI/MCP attributes and verdict; the latency is observed in the
        ``aegis_mcp_inspection_duration_seconds`` SLO histogram and one
        structured (DLP-scrubbed) ``mcp.inspection`` log line is emitted.
        """
        session_id = session_id or request.session_id
        start = perf_counter()
        with get_tracer().start_as_current_span(
            "aegis.firewall.inspect",
            attributes=mcp_attributes(request.server_name, session_id),
        ) as span:
            report = self._evaluate(request, constraint_arguments, denials, session_id)
            span.set_attributes(
                decision_attributes(
                    request.tool_name,
                    report.decision,
                    report.risk_score,
                    report.violations,
                )
            )
            elapsed = perf_counter() - start
            metrics_registry.observe_inspection(report.decision, elapsed)
            logger.info(
                "mcp tool call inspected",
                extra={
                    "event": "mcp.inspection",
                    "decision": sanitize_log_value(report.decision),
                    "risk_score": report.risk_score,
                    "violations": [sanitize_log_value(v) for v in report.violations],
                    "server_name": sanitize_log_value(request.server_name),
                    "tool_name": sanitize_log_value(request.tool_name),
                    "duration_ms": round(elapsed * 1000, 3),
                },
            )
        return report

    def _evaluate(
        self,
        request: MCPToolCallRequest,
        constraint_arguments: dict[str, Any] | None,
        denials: Sequence[str],
        session_id: str,
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
        raw_serialized = json.dumps(
            request.arguments, sort_keys=True, ensure_ascii=False
        )
        risk_score, violations = evaluate_threats(raw_serialized)
        violations.extend(denials)
        snapshot = self.policy_engine.snapshot()
        version = snapshot[1]
        subject = (
            constraint_arguments
            if constraint_arguments is not None
            else request.arguments
        )
        policy_denied, requires_approval = self._apply_policy(
            snapshot, request, violations, subject
        )
        sanitized_args, redacted_categories = self._redact(request.arguments)
        flow = self._taint_flow(
            snapshot[0], request, session_id, bool(redacted_categories)
        )
        if flow.toxic:
            violations.append(TOXIC_FLOW_VIOLATION)
        rate = self._rate_check(snapshot[0], request, session_id)
        violations.extend(rate.violations)
        denied = policy_denied or bool(denials) or flow.toxic
        hitl = self._gate_if_clean(
            (requires_approval, any((denied, rate.blocking)), risk_score),
            request,
            subject,
            sanitized_args,
            session_id,
        )
        violations.extend(hitl.violations)
        risk_score = self._risk(
            max(risk_score, rate.risk_score), denied, bool(redacted_categories), hitl
        )

        allowed, decision, would_block = self._decide(
            risk_score,
            any((denied, hitl.blocking, rate.blocking)),
            bool(redacted_categories),
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
        self._notify(record, entry_hash, hitl)

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
            **hitl.response_fields(),
        )

    def _notify(self, record: LedgerRecord, entry_hash: str, hitl: HitlOutcome) -> None:
        """Fire-and-forget webhooks: approval requests and security incidents.

        Incidents are BLOCKED calls plus exfiltration velocity anomalies,
        which are announced even when monitor mode lets the call through.
        """
        if hitl.created and hitl.approval is not None:
            self.webhooks.notify_approval(hitl.approval)
        if record.decision == "BLOCKED" or VELOCITY_VIOLATION in record.violations:
            self.webhooks.notify_incident(
                Incident(
                    agent_id=record.agent_id,
                    server_name=record.server_name,
                    tool_name=record.tool_name,
                    environment=record.environment,
                    risk_score=record.risk_score,
                    violations=tuple(record.violations),
                    audit_hash=entry_hash,
                    timestamp=record.timestamp,
                )
            )

    def record_approval_event(self, approval: HitlApproval) -> str:
        """Append an operator HITL resolution to the hash chain; entry hash.

        ``approved`` is ledgered as ``ALLOWED`` with ``hitl_approval_granted``;
        ``denied`` as ``BLOCKED`` with ``hitl_approval_denied`` (risk 100).
        """
        granted = approval.status == "approved"
        decision: Decision = "ALLOWED" if granted else "BLOCKED"
        record = LedgerRecord(
            agent_id=approval.agent_id,
            server_name=approval.server_name,
            tool_name=approval.tool_name,
            environment=approval.environment,
            decision=decision,
            risk_score=0 if granted else HITL_DENIED_RISK_SCORE,
            violations=[HITL_GRANTED_EVENT if granted else HITL_DENIED_VIOLATION],
            redacted_categories=[],
            timestamp=approval.resolved_at or datetime.now(UTC).isoformat(),
            would_block=not granted,
            policy_mode=settings.policy_mode,
            policy_version=self.policy_engine.version,
            session_id=approval.session_id,
            args_digest=digest_arguments(approval.sanitized_arguments),
        )
        return self._append(record)[1]

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
        """Verify every link (legacy v1 and full-payload v2) of the ledger.

        A broken chain increments ``aegis_mcp_ledger_errors_total``
        (``kind="chain_tampered"``) for alerting.
        """
        result = self.ledger.verify()
        if not result.valid:
            metrics_registry.record_ledger_error("chain_tampered")
            logger.error(
                "audit chain verification failed",
                extra={"event": "ledger.chain_tampered"},
            )
        return result

    def close(self) -> None:
        """Graceful shutdown: drain and stop the webhook worker pool."""
        self.webhooks.close()

    def reset(self) -> None:
        """Clear ledger, taint, rate limits, HITL and webhook state (isolation)."""
        self.ledger.reset()
        self.taint.reset()
        self.rate_limiter.reset()
        self.approvals.reset()
        self.webhooks.reset()
