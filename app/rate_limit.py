"""Behavioral tool-call rate limiting and exfiltration velocity detection.

Stateless argument rules cannot see *automated data harvesting*: an agent
(possibly steered by an indirect prompt injection) that walks a database or
resource tree one innocuous ``resources/read`` / ``query_db`` at a time. Two
bounded, thread-safe detectors run on every inspected call:

* **Token bucket** per ``(agent_id, server_name, tool_name)``: each call
  spends one token; tokens refill continuously at ``refill_per_sec`` up to
  ``capacity``. An empty bucket yields ``rate_limit_exceeded`` (risk 75).
* **Exfiltration velocity** per ``(session_id, agent_id)``: a sliding window
  of *sensitive read* timestamps. A sensitive read arriving when the window
  already holds ``max_reads`` reads yields ``exfiltration_velocity_anomaly``
  (risk 90, high enough for the security webhook). Anomalous reads are not
  recorded, so each window stores at most ``max_reads`` timestamps. Calls
  without a session id share one per-agent window, so dropping the
  ``Mcp-Session-Id`` header cannot be used to dodge accounting.

Sensitive reads come from built-in, case-insensitive tool-name heuristics
(``SENSITIVE_READ_TOOLS``) unless the first matching policy ``rate_limits``
rule says otherwise; that rule may also override the bucket and window.

Memory is bounded: both maps are LRU-capped at ``max_keys`` entries, and
emptied velocity windows are dropped.
"""

import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatchcase

from app.schemas import (
    PolicyDocument,
    RateLimitStats,
    TokenBucketLimit,
    ToolRateLimit,
    VelocityLimit,
)

__all__ = [
    "RATE_ANOMALY_KINDS",
    "RATE_LIMIT_RISK_SCORE",
    "RATE_LIMIT_VIOLATION",
    "SENSITIVE_READ_TOOLS",
    "VELOCITY_RISK_SCORE",
    "VELOCITY_VIOLATION",
    "BehaviorRateLimiter",
    "LimiterConfig",
    "RateScope",
    "RateVerdict",
    "is_sensitive_read",
    "match_rule",
]

RATE_LIMIT_VIOLATION = "rate_limit_exceeded"
RATE_LIMIT_RISK_SCORE = 75
VELOCITY_VIOLATION = "exfiltration_velocity_anomaly"
VELOCITY_RISK_SCORE = 90
RATE_ANOMALY_KINDS = frozenset({RATE_LIMIT_VIOLATION, VELOCITY_VIOLATION})

SENSITIVE_READ_TOOLS = (
    "resources/read",
    "read_file*",
    "read_resource*",
    "read_multiple_files*",
    "query*",
    "*_query",
    "*sql*",
    "db_*",
    "get_secret*",
    "get_customer*",
    "get_record*",
    "fetch_record*",
    "list_records*",
    "search_records*",
    "export_*",
    "dump_*",
)


@dataclass(frozen=True)
class LimiterConfig:
    """Global defaults (``AEGIS_RATE_LIMIT_*`` / ``AEGIS_VELOCITY_*``)."""

    enabled: bool
    bucket: TokenBucketLimit
    velocity: VelocityLimit
    max_keys: int = 10_000


@dataclass(frozen=True)
class RateScope:
    """The subject of one rate evaluation."""

    agent_id: str
    server_name: str
    tool_name: str
    environment: str
    session_id: str = ""


@dataclass(frozen=True)
class RateVerdict:
    """Outcome: any violation blocks (enforce) or sets ``would_block``."""

    violations: tuple[str, ...] = ()
    risk_score: int = 0

    @property
    def blocking(self) -> bool:
        """True when the call tripped a rate or velocity limit."""
        return bool(self.violations)


@dataclass
class _Bucket:
    """Token-bucket state (guarded by the limiter lock)."""

    tokens: float
    updated: float


@dataclass
class _Counters:
    """Lifetime anomaly counters (cleared by ``reset``)."""

    rate_limited: int = 0
    velocity_anomalies: int = 0


@dataclass(frozen=True)
class _Limits:
    """Effective limits for one call."""

    bucket: TokenBucketLimit
    velocity: VelocityLimit
    sensitive: bool


def match_rule(document: PolicyDocument, scope: RateScope) -> ToolRateLimit | None:
    """First policy ``rate_limits`` rule matching the call (case-sensitive)."""
    for rule in document.rate_limits:
        if (
            scope.environment in rule.environments
            and fnmatchcase(scope.server_name, rule.server_name)
            and fnmatchcase(scope.tool_name, rule.tool_name)
        ):
            return rule
    return None


def is_sensitive_read(rule: ToolRateLimit | None, tool_name: str) -> bool:
    """Policy decision first, else the case-insensitive name heuristics."""
    if rule is not None and rule.sensitive_read is not None:
        return rule.sensitive_read
    if rule is not None and rule.velocity_limit is not None:
        return True
    lowered = tool_name.lower()
    return any(fnmatchcase(lowered, pattern) for pattern in SENSITIVE_READ_TOOLS)


class BehaviorRateLimiter:
    """Thread-safe, LRU-bounded token buckets plus velocity windows."""

    def __init__(
        self, config: LimiterConfig, clock: Callable[[], float] = time.monotonic
    ) -> None:
        """Configure defaults, capacity bound and the (injectable) clock."""
        self.config = config
        self.max_keys = max(1, config.max_keys)
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: OrderedDict[tuple[str, str, str], _Bucket] = OrderedDict()
        self._windows: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()
        self._counters = _Counters()

    def _limits(self, document: PolicyDocument, scope: RateScope) -> _Limits:
        """Resolve the effective bucket, window and sensitivity of a call."""
        rule = match_rule(document, scope)
        if rule is None:
            return _Limits(
                self.config.bucket,
                self.config.velocity,
                is_sensitive_read(None, scope.tool_name),
            )
        return _Limits(
            rule.rate_limit or self.config.bucket,
            rule.velocity_limit or self.config.velocity,
            is_sensitive_read(rule, scope.tool_name),
        )

    def check(self, document: PolicyDocument, scope: RateScope) -> RateVerdict:
        """Spend a token and account a sensitive read; return the verdict."""
        if not self.config.enabled:
            return RateVerdict()
        limits = self._limits(document, scope)
        violations: list[str] = []
        with self._lock:
            now = self._clock()
            if not self._take_token(scope, limits.bucket, now):
                violations.append(RATE_LIMIT_VIOLATION)
                self._counters.rate_limited += 1
            if limits.sensitive and not self._admit_read(scope, limits.velocity, now):
                violations.append(VELOCITY_VIOLATION)
                self._counters.velocity_anomalies += 1
        return RateVerdict(tuple(violations), _score(violations))

    def _take_token(
        self, scope: RateScope, limit: TokenBucketLimit, now: float
    ) -> bool:
        """Refill then spend one token; False when the bucket is empty."""
        key = (scope.agent_id, scope.server_name, scope.tool_name)
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(limit.capacity, now)
            _insert_lru(self._buckets, key, bucket, self.max_keys)
        elapsed = max(0.0, now - bucket.updated)
        bucket.tokens = min(
            limit.capacity, bucket.tokens + elapsed * limit.refill_per_sec
        )
        bucket.updated = now
        self._buckets.move_to_end(key)
        if bucket.tokens < 1.0:
            return False
        bucket.tokens -= 1.0
        return True

    def _admit_read(self, scope: RateScope, limit: VelocityLimit, now: float) -> bool:
        """Slide the window; record the read unless it exceeds ``max_reads``."""
        key = (scope.session_id, scope.agent_id)
        window = self._windows.get(key)
        if window is None:
            window = deque()
            _insert_lru(self._windows, key, window, self.max_keys)
        cutoff = now - limit.window_seconds
        while window and window[0] <= cutoff:
            window.popleft()
        self._windows.move_to_end(key)
        if len(window) >= limit.max_reads:
            return False
        window.append(now)
        return True

    def stats(self) -> RateLimitStats:
        """Operator snapshot of configuration, tracked keys and anomalies."""
        with self._lock:
            buckets, sessions = len(self._buckets), len(self._windows)
            counters = _Counters(**vars(self._counters))
        return RateLimitStats(
            enabled=self.config.enabled,
            capacity=self.config.bucket.capacity,
            refill_per_sec=self.config.bucket.refill_per_sec,
            velocity_window_seconds=self.config.velocity.window_seconds,
            velocity_max_reads=self.config.velocity.max_reads,
            tracked_buckets=buckets,
            tracked_sessions=sessions,
            rate_limited_total=counters.rate_limited,
            velocity_anomalies_total=counters.velocity_anomalies,
        )

    def reset(self) -> None:
        """Forget every bucket, window and counter (test isolation)."""
        with self._lock:
            self._buckets.clear()
            self._windows.clear()
            self._counters = _Counters()


def _insert_lru[K, V](store: OrderedDict[K, V], key: K, value: V, cap: int) -> None:
    """Insert ``key`` evicting least-recently-used entries beyond ``cap``."""
    while len(store) >= cap:
        store.popitem(last=False)
    store[key] = value


_RISK_SCORES = {
    RATE_LIMIT_VIOLATION: RATE_LIMIT_RISK_SCORE,
    VELOCITY_VIOLATION: VELOCITY_RISK_SCORE,
}


def _score(violations: list[str]) -> int:
    """Highest risk of the tripped detectors (0 when clean)."""
    return max((_RISK_SCORES[code] for code in violations), default=0)
