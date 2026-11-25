"""Stateful per-session toxic-flow taint analysis ("lethal trifecta" defense).

Stateless argument rules cannot see a multi-step indirect prompt injection
exfiltration: an agent reads **untrusted content** (web page, issue, email),
also touches **private data** (database row, file, secret, any DLP hit), and
finally calls an **external communication sink** (HTTP POST, email, git
push). Each step is benign in isolation; the combination is the exfiltration.

This module classifies every inspected call into taint *roles*:

* ``untrusted_content`` and ``private_data`` are *labels*: once a call
  carrying them is allowed, the label sticks to the calling session.
* ``egress_sink`` is checked before execution: when the session already
  holds **both** labels (a ``private_data`` label carried by the sink call
  itself also counts), the call completes the trifecta and is denied with
  ``toxic_flow_exfiltration``.

Roles come from the policy's declarative ``taint_rules`` unioned with
built-in name heuristics (``AEGIS_TAINT_DEFAULT_HEURISTICS``). Name
heuristics compare case-insensitively so ``Send_Email`` cannot dodge
``send_*``. Any call whose arguments hold an ``http(s)://`` URL is also an
egress sink. A DLP redaction on a session-bound call (inbound arguments or
upstream reply) promotes the session to ``private_data``.

Calls without a session id (``""``) are evaluated statelessly: taint is
never shared across unrelated callers.
"""

import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

from app.schemas import (
    PolicyDocument,
    SessionTaintStatus,
    TaintLabel,
    TaintRole,
    ToolTaintRule,
)

__all__ = [
    "SOURCE_LABELS",
    "TOXIC_FLOW_VIOLATION",
    "SessionTaintTracker",
    "TaintCall",
    "TaintLabel",
    "TaintRole",
    "TaintVerdict",
    "carries_url",
    "classify",
    "evaluate_flow",
]

TOXIC_FLOW_VIOLATION = "toxic_flow_exfiltration"
SOURCE_LABELS: frozenset[TaintLabel] = frozenset({"untrusted_content", "private_data"})
MAX_SOURCES = 16
URL_SCHEMES = ("http://", "https://")

UNTRUSTED_TOOLS = (
    "web_*",
    "fetch*",
    "browse*",
    "http_get*",
    "read_email*",
    "list_issues*",
    "get_issue*",
    "get_pull_request*",
    "search_web*",
)
UNTRUSTED_SERVERS = ("*web*", "*browser*", "*fetch*", "*mail*", "*github*")
PRIVATE_TOOLS = (
    "resources/read",
    "query*",
    "*sql*",
    "read_file*",
    "get_secret*",
    "get_customer*",
    "db_*",
)
PRIVATE_SERVERS = (
    "*postgres*",
    "*db*",
    "*sql*",
    "*filesystem*",
    "*vault*",
    "*secrets*",
)
EGRESS_TOOLS = (
    "send_*",
    "post_*",
    "webhook*",
    "upload*",
    "git_push*",
    "create_issue*",
    "create_comment*",
    "http_post*",
    "http_put*",
    "curl*",
)


@dataclass(frozen=True)
class TaintCall:
    """The subject of one taint evaluation."""

    server_name: str
    tool_name: str
    environment: str
    arguments: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TaintVerdict:
    """Outcome: ``toxic`` denies the call; ``carried`` labels stick if allowed."""

    toxic: bool
    carried: frozenset[TaintLabel]


def _matches(name: str, patterns: Iterable[str]) -> bool:
    """Case-insensitive glob match (heuristics only)."""
    lowered = name.lower()
    return any(fnmatchcase(lowered, pattern) for pattern in patterns)


def heuristic_roles(server_name: str, tool_name: str) -> set[TaintRole]:
    """Built-in classification from tool and server names.

    Server-name patterns only label *reading* tools: ``send_email`` on a
    mail server is an egress sink, not a source of untrusted content.
    """
    roles: set[TaintRole] = set()
    egress = _matches(tool_name, EGRESS_TOOLS)
    if egress:
        roles.add("egress_sink")
    if _matches(tool_name, UNTRUSTED_TOOLS) or (
        not egress and _matches(server_name, UNTRUSTED_SERVERS)
    ):
        roles.add("untrusted_content")
    if _matches(tool_name, PRIVATE_TOOLS) or (
        not egress and _matches(server_name, PRIVATE_SERVERS)
    ):
        roles.add("private_data")
    return roles


def _rule_applies(rule: ToolTaintRule, call: TaintCall) -> bool:
    """Case-sensitive scope match, consistent with the RBAC matrix."""
    return (
        call.environment in rule.environments
        and fnmatchcase(call.server_name, rule.server_name)
        and fnmatchcase(call.tool_name, rule.tool_name)
    )


def classify(
    document: PolicyDocument, call: TaintCall, heuristics: bool
) -> frozenset[TaintRole]:
    """Union of matching declarative ``taint_rules`` (and heuristics)."""
    roles: set[TaintRole] = (
        heuristic_roles(call.server_name, call.tool_name) if heuristics else set()
    )
    for rule in document.taint_rules:
        if _rule_applies(rule, call):
            roles.update(rule.roles)
    return frozenset(roles)


def carries_url(arguments: Any) -> bool:
    """Return True if any string value (at any depth) is an http(s) URL."""
    stack: list[Any] = [arguments]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            if node.strip().lower().startswith(URL_SCHEMES):
                return True
        elif isinstance(node, Mapping):
            stack.extend(node.values())
        elif isinstance(node, list | tuple):
            stack.extend(node)
    return False


@dataclass
class _SessionTaint:
    """Mutable per-session state (guarded by the tracker lock)."""

    labels: frozenset[TaintLabel]
    sources: deque[str]
    expires_at: float


class SessionTaintTracker:
    """Thread-safe per-session taint labels with sliding TTL and LRU capacity."""

    def __init__(
        self,
        ttl_seconds: float,
        capacity: int,
        clock: Callable[[], float] = time.monotonic,
        max_sources: int = MAX_SOURCES,
    ) -> None:
        """Configure lifetime, capacity (LRU eviction), clock, and provenance."""
        self.ttl_seconds = ttl_seconds
        self.capacity = max(1, capacity)
        self.max_sources = max_sources
        self._clock = clock
        self._lock = threading.Lock()
        self._sessions: OrderedDict[str, _SessionTaint] = OrderedDict()

    def __len__(self) -> int:
        """Number of stored (possibly expired) sessions."""
        return len(self._sessions)

    def _live(self, session_id: str, now: float) -> _SessionTaint | None:
        """Return the live entry (expired entries are dropped)."""
        entry = self._sessions.get(session_id)
        if entry is not None and entry.expires_at <= now:
            del self._sessions[session_id]
            return None
        return entry

    def _touch(self, session_id: str, entry: _SessionTaint, now: float) -> None:
        """Slide the TTL and mark the session most recently used."""
        entry.expires_at = now + self.ttl_seconds
        self._sessions.move_to_end(session_id)

    def labels(self, session_id: str) -> frozenset[TaintLabel]:
        """Return (and keep alive) the labels a session currently holds."""
        if not session_id:
            return frozenset()
        with self._lock:
            now = self._clock()
            entry = self._live(session_id, now)
            if entry is None:
                return frozenset()
            self._touch(session_id, entry, now)
            return entry.labels

    def record(
        self, session_id: str, subject: str, labels: Iterable[TaintLabel]
    ) -> None:
        """Add ``labels`` (with ``subject`` provenance) to a session."""
        new = frozenset(labels)
        if not session_id or not new:
            return
        with self._lock:
            now = self._clock()
            entry = self._live(session_id, now) or self._create(session_id, now)
            entry.labels = entry.labels | new
            for label in sorted(new):
                source = f"{subject}:{label}"
                if source not in entry.sources:
                    entry.sources.append(source)
            self._touch(session_id, entry, now)

    def _create(self, session_id: str, now: float) -> _SessionTaint:
        """Insert an empty entry, purging expired ones and evicting LRU."""
        for key in [k for k, e in self._sessions.items() if e.expires_at <= now]:
            del self._sessions[key]
        while len(self._sessions) >= self.capacity:
            self._sessions.popitem(last=False)
        entry = _SessionTaint(
            frozenset(), deque(maxlen=self.max_sources), now + self.ttl_seconds
        )
        self._sessions[session_id] = entry
        return entry

    def status(self, session_id: str) -> SessionTaintStatus:
        """Read-only snapshot for operators (does not extend the TTL)."""
        with self._lock:
            entry = self._live(session_id, self._clock())
            labels = entry.labels if entry else frozenset()
            sources = list(entry.sources) if entry else []
        return SessionTaintStatus(
            session_id=session_id,
            labels=sorted(labels),
            lethal_trifecta_armed=labels >= SOURCE_LABELS,
            sources=sources,
        )

    def clear_session(self, session_id: str) -> None:
        """Forget a session's taint (session termination / expiry)."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def reset(self) -> None:
        """Forget every session (deterministic test isolation)."""
        with self._lock:
            self._sessions.clear()


def evaluate_flow(
    held: frozenset[TaintLabel],
    roles: frozenset[TaintRole],
    call: TaintCall,
    redacted: bool,
) -> TaintVerdict:
    """Decide whether a call completes the lethal trifecta.

    ``held`` are the session's existing labels; ``roles`` the call's
    classification; ``redacted`` whether DLP scrubbed the call's arguments
    (which makes the call itself carry ``private_data``).
    """
    carried: set[TaintLabel] = {label for label in SOURCE_LABELS if label in roles}
    if redacted:
        carried.add("private_data")
    exposure = held | (carried & {"private_data"})
    toxic = exposure >= SOURCE_LABELS and (
        "egress_sink" in roles or carries_url(call.arguments)
    )
    return TaintVerdict(toxic=toxic, carried=frozenset(carried))
