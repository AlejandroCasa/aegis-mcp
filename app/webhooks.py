"""Security webhook dispatcher (HITL approval requests and BLOCKED incidents).

Notifications are fire-and-forget: payloads are queued on a small bounded
thread pool and POSTed with a hard timeout, so a slow or dead receiver never
delays the firewall decision. Delivery failures are logged, never raised.

* **SSRF defense**: the URL must be ``https`` (plain ``http`` is accepted only
  for ``localhost``/loopback outside ``prod``), carry no userinfo, and never
  target a cloud metadata endpoint. In ``prod`` the host must resolve
  exclusively to public addresses (checked at startup for IP literals and
  again before every delivery, narrowing DNS-rebinding windows); redirects
  are never followed.
* **Anti-spam**: high-severity incidents (``risk_score >= 80``) are throttled
  per ``(agent_id, server_name, tool_name, violation)`` for the cooldown.
* **DLP**: identity fields and argument summaries are re-redacted with
  ``redact_payload`` so raw PII/secrets never leave the gateway.
"""

import ipaddress
import json
import logging
import socket
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import CancelledError, Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.redactor import redact_payload
from app.schemas import Environment, HitlApproval

APPROVAL_EVENT = "hitl.approval_requested"
INCIDENT_EVENT = "security.blocked"
INCIDENT_MIN_RISK_SCORE = 80
MAX_SUMMARY_CHARS = 512
MAX_COOLDOWN_KEYS = 10_000
MAX_INFLIGHT = 256
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "fd00:ec2::254",
        "100.100.100.200",
        "metadata",
        "metadata.google.internal",
        "metadata.azure.internal",
    }
)

logger = logging.getLogger("aegis_mcp.webhooks")

Resolver = Callable[[str], list[str]]
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class WebhookConfigError(ValueError):
    """Raised when a webhook URL fails scheme / host / SSRF validation."""


def resolve_host(host: str) -> list[str]:
    """Resolve ``host`` to every TCP address it maps to."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


def is_forbidden_address(address: IPAddress) -> bool:
    """True for private, loopback, link-local, reserved or metadata targets."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return not address.is_global or address.is_multicast


def _literal_address(host: str) -> IPAddress | None:
    """Return ``host`` as an IP address, or None for DNS names."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def ensure_public_destination(host: str, resolver: Resolver = resolve_host) -> None:
    """Raise unless ``host`` (literal or resolved) is publicly routable."""
    literal = _literal_address(host)
    if literal is not None:
        candidates = [literal]
    else:
        try:
            resolved = resolver(host)
        except OSError as exc:
            raise WebhookConfigError(f"Webhook host does not resolve: {exc}") from exc
        candidates = [ipaddress.ip_address(item.split("%")[0]) for item in resolved]
    if not candidates or any(is_forbidden_address(item) for item in candidates):
        raise WebhookConfigError("Webhook host resolves to a non-public address.")


def _checked_host(
    hostname: str | None, username: str | None, password: str | None
) -> str:
    """Normalized host; reject missing hosts, userinfo and metadata targets."""
    host = (hostname or "").lower().rstrip(".")
    if not host or username is not None or password is not None:
        raise WebhookConfigError("Webhook URL needs a host and no credentials.")
    if host in METADATA_HOSTS:
        raise WebhookConfigError("Webhook URL targets a metadata endpoint.")
    return host


def validate_webhook_url(url: str, environment: Environment) -> str:
    """Statically validate a webhook URL (scheme, userinfo, metadata, IP).

    ``prod`` additionally rejects non-public IP literals; DNS names are
    re-checked against private ranges before each delivery.
    """
    parts = urlsplit(url)
    host = _checked_host(parts.hostname, parts.username, parts.password)
    local = host in LOCAL_HOSTS
    if parts.scheme == "http" and local and environment != "prod":
        return url
    if parts.scheme != "https":
        raise WebhookConfigError("Webhook URL must use https.")
    literal = _literal_address(host)
    if environment == "prod" and (local or (literal and is_forbidden_address(literal))):
        raise WebhookConfigError("Webhook URL targets a non-public address in prod.")
    return url


@dataclass(frozen=True)
class Incident:
    """A ledgered BLOCKED decision considered for SOC notification."""

    agent_id: str
    server_name: str
    tool_name: str
    environment: str
    risk_score: int
    violations: Sequence[str]
    audit_hash: str
    timestamp: str


def _redacted(fields: dict[str, Any]) -> dict[str, Any]:
    """Run DLP redaction over webhook fields that may carry user data."""
    return redact_payload(fields)[0]


def _summary(arguments: dict[str, Any]) -> str:
    """Bounded, DLP-redacted JSON summary of tool arguments."""
    redacted, _ = redact_payload(arguments)
    text = json.dumps(redacted, sort_keys=True, ensure_ascii=False, default=str)
    if len(text) <= MAX_SUMMARY_CHARS:
        return text
    return text[:MAX_SUMMARY_CHARS] + " [truncated]"


def approval_payload(approval: HitlApproval) -> dict[str, Any]:
    """Webhook body announcing a new pending approval request."""
    identity = _redacted(
        {
            "agent_id": approval.agent_id,
            "server_name": approval.server_name,
            "tool_name": approval.tool_name,
        }
    )
    return {
        "event": APPROVAL_EVENT,
        "approval_id": approval.id,
        **identity,
        "environment": approval.environment,
        "summary": _summary(approval.sanitized_arguments),
        "created_at": approval.created_at,
        "expires_at": approval.expires_at,
    }


def incident_payload(incident: Incident) -> dict[str, Any]:
    """Webhook body describing a high-severity BLOCKED incident."""
    identity = _redacted(
        {
            "agent_id": incident.agent_id,
            "server_name": incident.server_name,
            "tool_name": incident.tool_name,
        }
    )
    return {
        "event": INCIDENT_EVENT,
        **identity,
        "environment": incident.environment,
        "risk_score": incident.risk_score,
        "violations": list(incident.violations),
        "audit_hash": incident.audit_hash,
        "timestamp": incident.timestamp,
    }


class WebhookDispatcher:
    """Non-blocking, bounded-timeout webhook sender with incident cooldown."""

    def __init__(
        self,
        url: str | None,
        environment: Environment = "dev",
        cooldown_seconds: float = 300.0,
        timeout_seconds: float = 3.0,
        client: httpx.Client | None = None,
        resolver: Resolver = resolve_host,
    ) -> None:
        """Validate ``url`` (raising ``WebhookConfigError``) and configure."""
        self.url = validate_webhook_url(url, environment) if url else None
        self.environment = environment
        self.cooldown_seconds = cooldown_seconds
        self.timeout_seconds = timeout_seconds
        self._client = client
        self._resolver = resolver
        self._lock = threading.Lock()
        self._last_sent: dict[tuple[str, str, str, str], float] = {}
        self._inflight: set[Future[None]] = set()
        self._executor: ThreadPoolExecutor | None = None

    @property
    def enabled(self) -> bool:
        """True when a webhook URL is configured."""
        return self.url is not None

    def notify_approval(self, approval: HitlApproval) -> bool:
        """Announce a new pending approval request (never throttled)."""
        return self._submit(approval_payload(approval))

    def notify_incident(self, incident: Incident) -> bool:
        """Announce a high-severity incident unless every key is cooling down."""
        if not self.enabled or incident.risk_score < INCIDENT_MIN_RISK_SCORE:
            return False
        if not self._admit(incident):
            return False
        return self._submit(incident_payload(incident))

    def _admit(self, incident: Incident) -> bool:
        """Apply the per ``(agent, server, tool, violation)`` cooldown."""
        scope = (incident.agent_id, incident.server_name, incident.tool_name)
        keys = [(*scope, code) for code in incident.violations] or [(*scope, "")]
        now = time.monotonic()
        with self._lock:
            fresh = [
                key
                for key in keys
                if now - self._last_sent.get(key, float("-inf"))
                >= self.cooldown_seconds
            ]
            if not fresh:
                return False
            self._prune(now)
            for key in keys:
                self._last_sent[key] = now
        return True

    def _prune(self, now: float) -> None:
        """Bound cooldown memory (caller holds the lock)."""
        if len(self._last_sent) < MAX_COOLDOWN_KEYS:
            return
        self._last_sent = {
            key: sent
            for key, sent in self._last_sent.items()
            if now - sent < self.cooldown_seconds
        }
        if len(self._last_sent) >= MAX_COOLDOWN_KEYS:
            self._last_sent.clear()

    def _submit(self, payload: dict[str, Any]) -> bool:
        """Queue one delivery; False when disabled or saturated."""
        if self.url is None:
            return False
        with self._lock:
            if len(self._inflight) >= MAX_INFLIGHT:
                logger.warning("Webhook queue saturated: dropping %s", payload["event"])
                return False
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=2, thread_name_prefix="aegis-webhook"
                )
            future = self._executor.submit(self._deliver, self.url, payload)
            self._inflight.add(future)
        future.add_done_callback(self._discard)
        return True

    def _discard(self, future: Future[None]) -> None:
        """Forget a finished delivery."""
        with self._lock:
            self._inflight.discard(future)

    def _http(self) -> httpx.Client:
        """Return the (lazily built) no-redirect, bounded-timeout client."""
        if self._client is None:
            self._client = httpx.Client(
                timeout=self.timeout_seconds, follow_redirects=False, trust_env=False
            )
        return self._client

    def _deliver(self, url: str, payload: dict[str, Any]) -> None:
        """POST one payload; log (never raise) on any failure."""
        try:
            if self.environment == "prod":
                ensure_public_destination(urlsplit(url).hostname or "", self._resolver)
            response = self._http().post(
                url, json=payload, timeout=self.timeout_seconds
            )
            if response.status_code >= 400:
                logger.warning(
                    "Webhook %s rejected with HTTP %d",
                    payload["event"],
                    response.status_code,
                )
        except (httpx.HTTPError, WebhookConfigError, ValueError) as exc:
            logger.warning("Webhook %s delivery failed: %s", payload["event"], exc)

    def drain(self, timeout: float = 5.0) -> None:
        """Wait (bounded) for in-flight deliveries (tests / shutdown)."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                pending = list(self._inflight)
            remaining = deadline - time.monotonic()
            if not pending or remaining <= 0:
                return
            try:
                pending[0].exception(timeout=remaining)
            except (TimeoutError, CancelledError):
                return
            self._discard(pending[0])

    def reset(self) -> None:
        """Forget cooldown state (test isolation)."""
        with self._lock:
            self._last_sent.clear()

    def close(self) -> None:
        """Drain briefly, then stop the worker pool."""
        self.drain(timeout=self.timeout_seconds)
        with self._lock:
            executor, self._executor = self._executor, None
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
