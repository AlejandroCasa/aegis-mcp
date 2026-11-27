"""Human-in-the-loop approval gate, security webhooks, and ledger integration."""

import ipaddress
import json
import logging
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import app.main as main
import app.webhooks as webhooks
from app.approvals import (
    HITL_DENIED_RISK_SCORE,
    HITL_DENIED_VIOLATION,
    HITL_GRANTED_EVENT,
    HITL_REQUIRED_VIOLATION,
    HITL_RISK_SCORE,
    HITL_TIMEOUT_VIOLATION,
    ApprovalConflictError,
    ApprovalKey,
    ApprovalNotFoundError,
    ApprovalQueue,
    gate_outcome,
)
from app.auth import Principal
from app.config import settings
from app.firewall import MCPFirewall
from app.policy import RBAC_VIOLATION, PolicyEngine, evaluate_action, evaluate_policy
from app.schemas import MCPToolCallRequest, PolicyDocument, PolicyRule
from app.webhooks import (
    APPROVAL_EVENT,
    INCIDENT_EVENT,
    Incident,
    WebhookConfigError,
    WebhookDispatcher,
    ensure_public_destination,
    is_forbidden_address,
    validate_webhook_url,
)

ADMIN_KEY = "admin-" + "k" * 20
HOOK_URL = "https://hooks.example.com/aegis"
EMAIL = "jane.doe@example.com"
DESTRUCTIVE = "rm" + " -rf /var/lib"
GATED_POLICY = PolicyDocument(
    rules=[
        PolicyRule(
            allow_tools=["read_*"],
            deny_tools=["drop_*"],
            require_approval_tools=["transfer_*", "drop_*"],
        )
    ]
)

client = TestClient(main.app)


@dataclass
class Recorder:
    """Captures webhook deliveries made through an ``httpx.MockTransport``."""

    status: int = 204
    payloads: list[dict[str, Any]] = field(default_factory=list)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.payloads.append(json.loads(request.content))
        return httpx.Response(self.status)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


class Clock:
    """Mutable UTC clock for deterministic TTL expiry."""

    def __init__(self) -> None:
        self.now = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture(autouse=True)
def isolate(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Enforce mode, no waiting, and a clean shared app firewall per test."""
    monkeypatch.setattr(settings, "policy_mode", "enforce")
    monkeypatch.setattr(settings, "block_threshold_score", 70)
    monkeypatch.setattr(settings, "enable_dlp_redaction", True)
    monkeypatch.setattr(settings, "hitl_wait_seconds", 0.0)
    monkeypatch.setattr(settings, "api_key", ADMIN_KEY)
    main.firewall.reset()
    yield
    main.firewall.reset()
    main.policy_engine.reset()


def _dispatcher(recorder: Recorder, **kwargs: Any) -> WebhookDispatcher:
    return WebhookDispatcher(HOOK_URL, client=recorder.client(), **kwargs)


def _firewall(
    tmp_path: Path,
    recorder: Recorder | None = None,
    clock: Clock | None = None,
    ttl: int = 900,
) -> MCPFirewall:
    db = str(tmp_path / "ledger.db")
    return MCPFirewall(
        db_path=db,
        policy_engine=PolicyEngine(GATED_POLICY),
        approvals=ApprovalQueue(db, ttl, clock=clock),
        webhooks=_dispatcher(recorder or Recorder()),
    )


def _call(
    tool: str = "transfer_funds",
    arguments: dict[str, Any] | None = None,
    approval_id: str | None = None,
) -> MCPToolCallRequest:
    return MCPToolCallRequest(
        agent_id="payments-agent",
        server_name="bank-mcp",
        tool_name=tool,
        arguments=arguments if arguments is not None else {"amount": 100},
        environment="prod",
        approval_id=approval_id,
    )


def _admin() -> dict[str, str]:
    return {"X-API-Key": ADMIN_KEY}


# --------------------------------------------------------------------------
# Policy action evaluation
# --------------------------------------------------------------------------


def test_evaluate_action_precedence() -> None:
    """deny > require_approval > allowlist > default_action."""
    scope = ("payments-agent", "bank-mcp")
    assert evaluate_action(GATED_POLICY, *scope, "drop_table", "prod") == "deny"
    assert (
        evaluate_action(GATED_POLICY, *scope, "transfer_funds", "prod")
        == "require_approval"
    )
    assert evaluate_action(GATED_POLICY, *scope, "read_ledger", "prod") == "allow"
    assert evaluate_action(GATED_POLICY, *scope, "list_users", "prod") == "deny"
    gated_default = PolicyDocument(default_action="require_approval")
    assert evaluate_action(gated_default, *scope, "x", "dev") == "require_approval"
    assert evaluate_policy(GATED_POLICY, *scope, "transfer_funds", "prod") is True
    assert evaluate_policy(GATED_POLICY, *scope, "drop_table", "prod") is False


def test_rule_with_only_require_approval_tools_is_valid() -> None:
    """A rule may consist solely of approval-gated tools; empty rules fail."""
    rule = PolicyRule(require_approval_tools=["wire_*"])
    assert rule.require_approval_tools == ["wire_*"]
    with pytest.raises(ValidationError, match="require_approval_tools"):
        PolicyRule()


def test_require_approval_changes_policy_version() -> None:
    """Gated rules are bound into the policy version hash."""
    plain = PolicyDocument(rules=[PolicyRule(allow_tools=["read_*"])])
    gated = PolicyDocument(
        rules=[PolicyRule(allow_tools=["read_*"], require_approval_tools=["w"])]
    )
    assert PolicyEngine(plain).version != PolicyEngine(gated).version


# --------------------------------------------------------------------------
# Firewall gate: request, approval, denial, single use
# --------------------------------------------------------------------------


def test_gated_call_blocks_and_queues_pending_request(tmp_path: Path) -> None:
    """First invocation fails closed and announces the request once."""
    recorder = Recorder()
    fw = _firewall(tmp_path, recorder)
    report = fw.inspect(_call(arguments={"amount": 100, "note": EMAIL}))
    assert report.allowed is False
    assert report.decision == "BLOCKED"
    assert report.violations == [HITL_REQUIRED_VIOLATION]
    assert report.risk_score == HITL_RISK_SCORE
    assert report.approval_status == "pending"
    assert report.approval_id is not None
    assert report.sanitized_arguments == {}

    again = fw.inspect(_call(arguments={"amount": 100, "note": EMAIL}))
    assert again.approval_id == report.approval_id
    fw.webhooks.drain()
    approvals = [p for p in recorder.payloads if p["event"] == APPROVAL_EVENT]
    assert len(approvals) == 1
    assert approvals[0]["approval_id"] == report.approval_id
    assert EMAIL not in json.dumps(approvals[0])

    stored = fw.approvals.get(report.approval_id)
    assert stored is not None
    assert EMAIL not in json.dumps(stored.sanitized_arguments)
    assert fw.verify_chain().valid is True


def test_approval_is_single_use_and_bound_to_arguments(tmp_path: Path) -> None:
    """An approval redeems exactly one identical call."""
    fw = _firewall(tmp_path)
    pending = fw.inspect(_call())
    assert pending.approval_id is not None
    fw.approvals.resolve(pending.approval_id, "approved", "alice", "ok")

    other = fw.inspect(_call(arguments={"amount": 999_999}))
    assert other.allowed is False
    assert other.approval_id != pending.approval_id

    granted = fw.inspect(_call())
    assert granted.allowed is True
    assert granted.decision == "ALLOWED"
    assert granted.approval_status == "approved"
    assert granted.violations == []
    assert granted.risk_score == 0

    replay = fw.inspect(_call())
    assert replay.allowed is False
    assert replay.violations == [HITL_REQUIRED_VIOLATION]
    consumed = fw.approvals.get(pending.approval_id)
    assert consumed is not None and consumed.consumed_at is not None


def test_explicit_approval_id_redeems_and_reports_denial(tmp_path: Path) -> None:
    """A caller may redeem by approval_id; a denial blocks with risk 100."""
    fw = _firewall(tmp_path)
    first = fw.inspect(_call())
    assert first.approval_id is not None
    fw.approvals.resolve(first.approval_id, "approved", "alice")
    redeemed = fw.inspect(_call(approval_id=first.approval_id))
    assert redeemed.allowed is True

    second = fw.inspect(_call())
    assert second.approval_id is not None
    fw.approvals.resolve(second.approval_id, "denied", "bob", "too large")
    denied = fw.inspect(_call(approval_id=second.approval_id))
    assert denied.allowed is False
    assert denied.violations == [HITL_DENIED_VIOLATION]
    assert denied.risk_score == HITL_DENIED_RISK_SCORE
    assert denied.approval_status == "denied"


def test_redeemed_explicit_approval_cannot_be_replayed(tmp_path: Path) -> None:
    """Re-sending a consumed approval_id opens a fresh pending request."""
    fw = _firewall(tmp_path)
    first = fw.inspect(_call())
    assert first.approval_id is not None
    fw.approvals.resolve(first.approval_id, "approved", "alice")
    assert fw.inspect(_call(approval_id=first.approval_id)).allowed is True
    replay = fw.inspect(_call(approval_id=first.approval_id))
    assert replay.allowed is False
    assert replay.approval_id != first.approval_id


def test_deny_rules_and_threats_win_over_approval(tmp_path: Path) -> None:
    """Denied or threat-blocked calls never open an approval request."""
    fw = _firewall(tmp_path)
    denied = fw.inspect(_call(tool="drop_table"))
    assert denied.violations == [RBAC_VIOLATION]
    assert denied.approval_id is None

    threat = fw.inspect(_call(arguments={"cmd": DESTRUCTIVE}))
    assert threat.allowed is False
    assert "command_injection" in threat.violations
    assert HITL_REQUIRED_VIOLATION not in threat.violations
    assert threat.approval_id is None
    assert fw.approvals.list_requests() == []


def test_allowlisted_tool_bypasses_gate(tmp_path: Path) -> None:
    """Non-gated tools are unaffected by the HITL queue."""
    fw = _firewall(tmp_path)
    report = fw.inspect(_call(tool="read_ledger"))
    assert report.allowed is True
    assert report.approval_id is None


# --------------------------------------------------------------------------
# Fail-closed timeout
# --------------------------------------------------------------------------


def test_pending_request_expires_fail_closed(tmp_path: Path) -> None:
    """A pending request past its TTL is expired and the call times out."""
    clock = Clock()
    fw = _firewall(tmp_path, clock=clock, ttl=60)
    first = fw.inspect(_call())
    assert first.approval_id is not None
    clock.advance(61)
    timed_out = fw.inspect(_call(approval_id=first.approval_id))
    assert timed_out.allowed is False
    assert timed_out.violations == [HITL_TIMEOUT_VIOLATION]
    assert timed_out.approval_status == "expired"
    with pytest.raises(ApprovalConflictError, match="expired"):
        fw.approvals.resolve(first.approval_id, "approved", "alice")


def test_unredeemed_approval_expires(tmp_path: Path) -> None:
    """Granted approvals are TTL-bound tokens, not standing permissions."""
    clock = Clock()
    fw = _firewall(tmp_path, clock=clock, ttl=60)
    first = fw.inspect(_call())
    assert first.approval_id is not None
    fw.approvals.resolve(first.approval_id, "approved", "alice")
    clock.advance(61)
    report = fw.inspect(_call())
    assert report.allowed is False
    assert report.approval_id != first.approval_id
    assert fw.approvals.list_requests(status="expired")[0].id == first.approval_id


def test_wait_window_times_out_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a wait window and no decision the call fails closed (timeout)."""
    monkeypatch.setattr(settings, "hitl_wait_seconds", 0.1)
    fw = _firewall(tmp_path)
    started = time.monotonic()
    report = fw.inspect(_call())
    assert time.monotonic() - started >= 0.1
    assert report.allowed is False
    assert report.violations == [HITL_TIMEOUT_VIOLATION]
    assert report.approval_status == "pending"


def test_wait_window_picks_up_operator_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A decision arriving while the call waits is honored immediately."""
    monkeypatch.setattr(settings, "hitl_wait_seconds", 5.0)
    fw = _firewall(tmp_path)

    def approve_when_pending() -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            pending = fw.approvals.list_requests(status="pending")
            if pending:
                fw.approvals.resolve(pending[0].id, "approved", "alice")
                return
            time.sleep(0.02)

    worker = threading.Thread(target=approve_when_pending)
    worker.start()
    report = fw.inspect(_call())
    worker.join()
    assert report.allowed is True
    assert report.approval_status == "approved"


def test_gate_outcome_mapping() -> None:
    """Status -> verdict mapping covers each lifecycle state."""
    queue_approval = _sample_approval("pending")
    assert gate_outcome(queue_approval, True, waited=False).violations == (
        HITL_REQUIRED_VIOLATION,
    )
    assert gate_outcome(queue_approval, False, waited=True).violations == (
        HITL_TIMEOUT_VIOLATION,
    )
    expired = gate_outcome(_sample_approval("expired"), False, waited=False)
    assert expired.violations == (HITL_TIMEOUT_VIOLATION,)
    assert gate_outcome(_sample_approval("approved"), False, False).blocking is False


def _sample_approval(status: str) -> Any:
    from app.schemas import HitlApproval

    return HitlApproval(
        id="a" * 32,
        agent_id="a",
        server_name="s",
        tool_name="t",
        environment="dev",
        arguments_hash="h",
        status=status,  # type: ignore[arg-type]
        created_at="c",
        expires_at="e",
    )


# --------------------------------------------------------------------------
# Monitor (shadow) mode
# --------------------------------------------------------------------------


def test_monitor_mode_flags_would_block_without_queueing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Monitor mode allows the call, records would_block and never queues."""
    monkeypatch.setattr(settings, "policy_mode", "monitor")
    recorder = Recorder()
    fw = _firewall(tmp_path, recorder)
    report = fw.inspect(_call())
    assert report.allowed is True
    assert report.decision == "ALLOWED"
    assert report.would_block is True
    assert report.violations == [HITL_REQUIRED_VIOLATION]
    assert report.risk_score == HITL_RISK_SCORE
    assert report.approval_id is None
    assert fw.approvals.list_requests() == []
    entry = fw.list_audit_entries()[-1]
    assert entry.would_block is True
    assert entry.policy_mode == "monitor"
    fw.webhooks.drain()
    assert recorder.payloads == []


# --------------------------------------------------------------------------
# Approval queue store
# --------------------------------------------------------------------------


def test_queue_resolution_errors_and_listing(tmp_path: Path) -> None:
    """Unknown ids, double resolution, filtering, limits and reason DLP."""
    queue = ApprovalQueue(str(tmp_path / "q.db"))
    key = ApprovalKey("a", "s", "t", "dev", "h")
    approval, created = queue.submit(key, {"x": 1}, "sess")
    assert created is True
    with pytest.raises(ApprovalNotFoundError):
        queue.resolve("f" * 32, "approved", "alice")
    resolved = queue.resolve(approval.id, "denied", "alice", f"mail {EMAIL}")
    assert resolved.resolved_by == "alice"
    assert resolved.reason is not None and EMAIL not in resolved.reason
    with pytest.raises(ApprovalConflictError):
        queue.resolve(approval.id, "approved", "alice")
    queue.submit(ApprovalKey("a", "s", "t", "dev", "h2"), {}, "")
    assert len(queue.list_requests(limit=0)) == 1
    assert len(queue.list_requests(limit=10)) == 2
    assert [a.status for a in queue.list_requests(status="denied")] == ["denied"]
    assert queue.get("0" * 32) is None
    assert queue.claim(ApprovalKey("z", "s", "t", "dev", "h")) is None
    assert queue.wait(ApprovalKey("z", "s", "t", "dev", "h"), "0" * 32, 0.01) is None


def test_queue_rolls_back_on_error(tmp_path: Path) -> None:
    """A failing transaction leaves the store untouched."""
    queue = ApprovalQueue(str(tmp_path / "q.db"))
    queue.submit(ApprovalKey("a", "s", "t", "dev", "h"), {}, "")
    with pytest.raises(RuntimeError), queue._transaction() as cursor:
        cursor.execute("DELETE FROM hitl_approvals")
        raise RuntimeError("boom")
    assert len(queue.list_requests()) == 1


# --------------------------------------------------------------------------
# Ledger integration
# --------------------------------------------------------------------------


def test_resolution_events_are_hash_chained(tmp_path: Path) -> None:
    """Approve/deny decisions are appended to the verifiable SHA-256 chain."""
    fw = _firewall(tmp_path)
    first = fw.inspect(_call())
    assert first.approval_id is not None
    approved = fw.approvals.resolve(first.approval_id, "approved", "alice")
    fw.record_approval_event(approved)
    second = fw.inspect(_call(arguments={"amount": 5}))
    assert second.approval_id is not None
    denied = fw.approvals.resolve(second.approval_id, "denied", "bob")
    entry_hash = fw.record_approval_event(denied)

    entries = fw.list_audit_entries()
    granted_entry = entries[1]
    assert granted_entry.violations == [HITL_GRANTED_EVENT]
    assert granted_entry.decision == "ALLOWED"
    denied_entry = entries[-1]
    assert denied_entry.entry_hash == entry_hash
    assert denied_entry.decision == "BLOCKED"
    assert denied_entry.violations == [HITL_DENIED_VIOLATION]
    assert denied_entry.risk_score == HITL_DENIED_RISK_SCORE
    assert fw.verify_chain().valid is True


# --------------------------------------------------------------------------
# REST API
# --------------------------------------------------------------------------


def _pending_via_api() -> str:
    main.policy_engine.load(GATED_POLICY)
    response = client.post(
        "/api/v1/mcp/inspect",
        json=_call().model_dump(mode="json", exclude={"approval_id"}),
        headers=_admin(),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["approval_status"] == "pending"
    return str(body["approval_id"])


def test_api_approve_flow_is_audited() -> None:
    """GET lists pending requests; POST approves and ledgers the decision."""
    approval_id = _pending_via_api()
    listed = client.get("/api/v1/approvals?status=pending", headers=_admin())
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [approval_id]

    resolved = client.post(
        f"/api/v1/approvals/{approval_id}",
        json={"status": "approved", "reason": "change ticket 42"},
        headers=_admin(),
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "approved"
    assert resolved.json()["resolved_by"] == "api-key-admin"

    entries = main.firewall.list_audit_entries()
    assert entries[-1].violations == [HITL_GRANTED_EVENT]
    assert client.get("/api/v1/audit/verify", headers=_admin()).json()["valid"]

    retried = client.post(
        "/api/v1/mcp/inspect",
        json=_call().model_dump(mode="json", exclude={"approval_id"}),
        headers=_admin(),
    )
    assert retried.json()["allowed"] is True

    conflict = client.post(
        f"/api/v1/approvals/{approval_id}",
        json={"status": "denied"},
        headers=_admin(),
    )
    assert conflict.status_code == 409


def test_api_deny_flow_and_errors() -> None:
    """Denial is ledgered; unknown ids 404; malformed ids/bodies 422."""
    approval_id = _pending_via_api()
    denied = client.post(
        f"/api/v1/approvals/{approval_id}",
        json={"status": "denied"},
        headers=_admin(),
    )
    assert denied.status_code == 200
    assert main.firewall.list_audit_entries()[-1].violations == [HITL_DENIED_VIOLATION]
    missing = client.post(
        f"/api/v1/approvals/{'f' * 32}", json={"status": "denied"}, headers=_admin()
    )
    assert missing.status_code == 404
    malformed = client.post(
        "/api/v1/approvals/not-an-id", json={"status": "denied"}, headers=_admin()
    )
    assert malformed.status_code == 422
    bad_status = client.post(
        f"/api/v1/approvals/{approval_id}", json={"status": "maybe"}, headers=_admin()
    )
    assert bad_status.status_code == 422


def test_api_requires_admin_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Approval endpoints fail closed without a valid admin key."""
    assert client.get("/api/v1/approvals").status_code == 401
    wrong = client.get("/api/v1/approvals", headers={"X-API-Key": "nope"})
    assert wrong.status_code == 401
    monkeypatch.setattr(settings, "api_key", None)
    unconfigured = client.post(
        f"/api/v1/approvals/{'f' * 32}", json={"status": "approved"}
    )
    assert unconfigured.status_code == 403


@dataclass
class StubResourceServer:
    """Minimal OAuth resource server double for approver scope checks."""

    principal: Principal
    enabled: bool = True

    def authenticate(self, authorization: str | None) -> Principal:
        return self.principal


def _principal(scopes: frozenset[str]) -> Principal:
    return Principal(
        agent_id="soc-operator",
        subject="soc-operator",
        client_id=None,
        scopes=scopes,
        claims={},
    )


def test_oauth_approver_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """OAuth mode requires the approver scope and records the operator."""
    approval_id = _pending_via_api()
    monkeypatch.setattr(
        main, "resource_server", StubResourceServer(_principal(frozenset()))
    )
    forbidden = client.get("/api/v1/approvals")
    assert forbidden.status_code == 403

    scoped = StubResourceServer(_principal(frozenset({"aegis:approve"})))
    monkeypatch.setattr(main, "resource_server", scoped)
    resolved = client.post(
        f"/api/v1/approvals/{approval_id}", json={"status": "approved"}
    )
    assert resolved.status_code == 200
    assert resolved.json()["resolved_by"] == "soc-operator"


# --------------------------------------------------------------------------
# Webhooks: SSRF validation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "environment"),
    [
        ("http://hooks.example.com/x", "dev"),
        ("ftp://hooks.example.com/x", "dev"),
        ("https://user:pw@hooks.example.com/x", "dev"),
        ("https:///nohost", "dev"),
        ("https://169.254.169.254/latest", "dev"),
        ("https://metadata.google.internal/", "dev"),
        ("http://localhost:8080/hook", "prod"),
        ("https://localhost/hook", "prod"),
        ("https://10.0.0.5/hook", "prod"),
        ("https://[::ffff:127.0.0.1]/hook", "prod"),
    ],
)
def test_webhook_url_rejections(url: str, environment: Any) -> None:
    """Scheme, credentials, metadata and private targets are rejected."""
    with pytest.raises(WebhookConfigError):
        validate_webhook_url(url, environment)


@pytest.mark.parametrize(
    ("url", "environment"),
    [
        (HOOK_URL, "prod"),
        ("https://8.8.8.8/hook", "prod"),
        ("http://localhost:9000/hook", "dev"),
        ("http://127.0.0.1:9000/hook", "staging"),
        ("https://10.0.0.5/hook", "dev"),
    ],
)
def test_webhook_url_acceptances(url: str, environment: Any) -> None:
    """Public https (and local http outside prod) are accepted."""
    assert validate_webhook_url(url, environment) == url


def test_invalid_webhook_url_fails_firewall_startup(tmp_path: Path) -> None:
    """A bad URL raises at construction rather than silently disabling alerts."""
    with pytest.raises(WebhookConfigError):
        WebhookDispatcher("http://hooks.example.com/x")


def test_resolved_destination_checks() -> None:
    """DNS answers must be exclusively public."""
    ensure_public_destination("hooks.example.com", lambda _h: ["93.184.216.34"])
    ensure_public_destination("8.8.8.8")
    with pytest.raises(WebhookConfigError, match="non-public"):
        ensure_public_destination("evil.example", lambda _h: ["8.8.8.8", "10.0.0.1"])
    with pytest.raises(WebhookConfigError, match="non-public"):
        ensure_public_destination("evil.example", lambda _h: ["fe80::1%eth0"])
    with pytest.raises(WebhookConfigError, match="non-public"):
        ensure_public_destination("empty.example", lambda _h: [])

    def broken(_host: str) -> list[str]:
        raise OSError("nxdomain")

    with pytest.raises(WebhookConfigError, match="does not resolve"):
        ensure_public_destination("missing.example", broken)
    assert is_forbidden_address(ipaddress.ip_address("::ffff:192.168.0.1"))
    assert is_forbidden_address(ipaddress.ip_address("224.0.0.1"))
    assert not is_forbidden_address(ipaddress.ip_address("1.1.1.1"))


def test_resolve_host_uses_system_resolver() -> None:
    """The default resolver returns literal addresses for IP hosts."""
    assert "127.0.0.1" in webhooks.resolve_host("127.0.0.1")


def test_prod_delivery_blocks_rebinding_to_private(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """In prod a DNS name resolving to a private address is never contacted."""
    recorder = Recorder()
    dispatcher = WebhookDispatcher(
        HOOK_URL,
        "prod",
        client=recorder.client(),
        resolver=lambda _h: ["192.168.1.10"],
    )
    with caplog.at_level(logging.WARNING, logger="aegis_mcp.webhooks"):
        assert dispatcher.notify_approval(_sample_approval("pending")) is True
        dispatcher.drain()
    assert recorder.payloads == []
    assert "delivery failed" in caplog.text

    public = WebhookDispatcher(
        HOOK_URL, "prod", client=recorder.client(), resolver=lambda _h: ["1.1.1.1"]
    )
    public.notify_approval(_sample_approval("pending"))
    public.drain()
    assert len(recorder.payloads) == 1
    public.close()
    dispatcher.close()


# --------------------------------------------------------------------------
# Webhooks: anti-spam cooldown and delivery
# --------------------------------------------------------------------------


def _incident(violations: tuple[str, ...] = ("command_injection",)) -> Incident:
    return Incident(
        agent_id="payments-agent",
        server_name="bank-mcp",
        tool_name="run",
        environment="prod",
        risk_score=95,
        violations=violations,
        audit_hash="ab" * 32,
        timestamp="2026-11-26T12:00:00+00:00",
    )


def test_incident_cooldown_suppresses_duplicates() -> None:
    """Identical incidents are throttled; new violation codes still alert."""
    recorder = Recorder()
    dispatcher = _dispatcher(recorder, cooldown_seconds=300.0)
    assert dispatcher.notify_incident(_incident()) is True
    assert dispatcher.notify_incident(_incident()) is False
    assert dispatcher.notify_incident(_incident(("path_traversal",))) is True
    assert dispatcher.notify_incident(_incident(())) is True
    assert dispatcher.notify_incident(_incident(())) is False
    low = Incident(**{**_incident().__dict__, "risk_score": 79})
    assert dispatcher.notify_incident(low) is False
    dispatcher.reset()
    assert dispatcher.notify_incident(_incident()) is True
    dispatcher.drain()
    assert [p["event"] for p in recorder.payloads] == [INCIDENT_EVENT] * 4
    assert recorder.payloads[0]["audit_hash"] == "ab" * 32
    dispatcher.close()


def test_zero_cooldown_and_disabled_dispatcher() -> None:
    """Cooldown 0 never throttles; no URL means nothing is sent."""
    recorder = Recorder()
    dispatcher = _dispatcher(recorder, cooldown_seconds=0.0)
    assert dispatcher.notify_incident(_incident()) is True
    assert dispatcher.notify_incident(_incident()) is True
    dispatcher.close()
    disabled = WebhookDispatcher(None)
    assert disabled.enabled is False
    assert disabled.notify_incident(_incident()) is False
    assert disabled.notify_approval(_sample_approval("pending")) is False
    disabled.close()


def test_cooldown_memory_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Expired keys are pruned; a saturated table is cleared."""
    monkeypatch.setattr(webhooks, "MAX_COOLDOWN_KEYS", 2)
    dispatcher = _dispatcher(Recorder(), cooldown_seconds=300.0)
    for code in ("a", "b", "c", "d"):
        assert dispatcher.notify_incident(_incident((code,))) is True
    assert len(dispatcher._last_sent) <= 2
    dispatcher.close()


def test_saturated_queue_drops(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Bounded in-flight deliveries: excess notifications are dropped."""
    monkeypatch.setattr(webhooks, "MAX_INFLIGHT", 0)
    dispatcher = _dispatcher(Recorder())
    with caplog.at_level(logging.WARNING, logger="aegis_mcp.webhooks"):
        assert dispatcher.notify_approval(_sample_approval("pending")) is False
    assert "saturated" in caplog.text


def test_delivery_failures_are_logged_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """HTTP errors and 4xx/5xx replies never propagate to the firewall."""
    rejecting = Recorder(status=500)
    dispatcher = _dispatcher(rejecting)

    def explode(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    failing = WebhookDispatcher(
        HOOK_URL, client=httpx.Client(transport=httpx.MockTransport(explode))
    )
    with caplog.at_level(logging.WARNING, logger="aegis_mcp.webhooks"):
        dispatcher.notify_incident(_incident())
        failing.notify_incident(_incident())
        dispatcher.drain()
        failing.drain()
    assert "HTTP 500" in caplog.text
    assert "delivery failed" in caplog.text
    dispatcher.close()
    failing.close()


def test_default_http_client_is_hardened() -> None:
    """The lazily built client never follows redirects or trusts env proxies."""
    dispatcher = WebhookDispatcher(HOOK_URL, timeout_seconds=1.5)
    built = dispatcher._http()
    assert built.follow_redirects is False
    assert built.timeout.connect == 1.5
    built.close()


def test_drain_respects_timeout() -> None:
    """drain() returns once its deadline passes even if work is in flight."""
    gate = threading.Event()

    def slow(request: httpx.Request) -> httpx.Response:
        gate.wait(2)
        return httpx.Response(204)

    dispatcher = WebhookDispatcher(
        HOOK_URL, client=httpx.Client(transport=httpx.MockTransport(slow))
    )
    dispatcher.notify_approval(_sample_approval("pending"))
    started = time.monotonic()
    dispatcher.drain(timeout=0.05)
    assert time.monotonic() - started < 1.0
    dispatcher.drain(timeout=0.0)
    gate.set()
    dispatcher.close()


def test_payloads_are_dlp_redacted_and_truncated() -> None:
    """Approval summaries are redacted and bounded in size."""
    approval = _sample_approval("pending").model_copy(
        update={
            "agent_id": EMAIL,
            "sanitized_arguments": {"note": EMAIL, "blob": "x" * 2_000},
        }
    )
    payload = webhooks.approval_payload(approval)
    assert EMAIL not in json.dumps(payload)
    assert payload["summary"].endswith("[truncated]")
    assert len(payload["summary"]) <= webhooks.MAX_SUMMARY_CHARS + 20


def test_firewall_blocked_incident_triggers_webhook(tmp_path: Path) -> None:
    """A high-severity BLOCKED decision posts one incident bound to its hash."""
    recorder = Recorder()
    fw = _firewall(tmp_path, recorder)
    report = fw.inspect(_call(tool="read_x", arguments={"cmd": DESTRUCTIVE}))
    fw.inspect(_call(tool="read_x", arguments={"cmd": DESTRUCTIVE}))
    fw.webhooks.drain()
    incidents = [p for p in recorder.payloads if p["event"] == INCIDENT_EVENT]
    assert len(incidents) == 1
    assert incidents[0]["audit_hash"] == report.audit_hash
    assert "command_injection" in incidents[0]["violations"]
    fw.close()


def test_hitl_pending_block_is_not_an_incident(tmp_path: Path) -> None:
    """A pending-approval block (risk 50) only emits the approval event."""
    recorder = Recorder()
    fw = _firewall(tmp_path, recorder)
    fw.inspect(_call())
    fw.webhooks.drain()
    assert [p["event"] for p in recorder.payloads] == [APPROVAL_EVENT]
