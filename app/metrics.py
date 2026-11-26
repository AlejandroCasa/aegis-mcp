"""Prometheus metrics registry and text exposition formatter for Aegis-MCP.

Every label value is bounded: values are sanitized to a safe character set
(no exposition injection via quotes/newlines) and each label keeps at most
``MAX_LABEL_VALUES`` distinct values, after which new values collapse into
``OVERFLOW_LABEL``. Identity labels (``agent_id``, ``session_id``) are never
exported; per-call detail belongs in traces and the audit ledger.
"""

import re
import threading
from collections import Counter
from collections.abc import Callable, Hashable
from typing import Final, cast

LabelFormatter = Callable[[Hashable], str]

MAX_LABEL_VALUES: Final = 64
MAX_LABEL_LENGTH: Final = 64
OVERFLOW_LABEL: Final = "other"
_UNSAFE_LABEL_CHARS = re.compile(r"[^A-Za-z0-9_.:\-]")

# Tight SLO buckets (seconds) around the 10 ms p99 inspection objective.
INSPECTION_BUCKETS: Final[tuple[float, ...]] = (
    0.001,
    0.0025,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
)

LEDGER_ERROR_KINDS: Final = frozenset({"chain_tampered", "checkpoint_error"})


class LabelLimiter:
    """Sanitize label values and cap their distinct count (caller holds lock)."""

    def __init__(self, max_values: int = MAX_LABEL_VALUES) -> None:
        """Create an empty limiter admitting at most ``max_values`` values."""
        self.max_values = max_values
        self._seen: set[str] = set()

    def __call__(self, value: str) -> str:
        """Return the bounded, exposition-safe form of ``value``."""
        clean = _UNSAFE_LABEL_CHARS.sub("_", value)[:MAX_LABEL_LENGTH] or "unknown"
        if clean in self._seen:
            return clean
        if len(self._seen) >= self.max_values:
            return OVERFLOW_LABEL
        self._seen.add(clean)
        return clean

    def clear(self) -> None:
        """Forget admitted values."""
        self._seen.clear()


def _counter_lines(
    name: str, help_text: str, counter: Counter[Hashable], labels: LabelFormatter
) -> list[str]:
    """Render one counter family (zero sample when no series exist)."""
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} counter"]
    if not counter:
        lines.append(f"{name} 0.0")
    for key, count in sorted(counter.items(), key=lambda item: str(item[0])):
        lines.append(f"{name}{{{labels(key)}}} {float(count)}")
    return lines


def _request_labels(key: Hashable) -> str:
    """Format ``(server, decision)`` labels."""
    server, decision = cast(tuple[str, str], key)
    return f'decision="{decision}",server="{server}"'


class Histogram:
    """Cumulative fixed-bucket histogram series keyed by one label value."""

    def __init__(self, buckets: tuple[float, ...]) -> None:
        """Create an empty histogram with sorted upper ``buckets``."""
        self.buckets = tuple(sorted(buckets))
        self._counts: dict[str, list[int]] = {}
        self._sums: dict[str, float] = {}

    def observe(self, label: str, value: float) -> None:
        """Record one observation for ``label``."""
        counts = self._counts.setdefault(label, [0] * (len(self.buckets) + 1))
        index = next(
            (i for i, bound in enumerate(self.buckets) if value <= bound),
            len(self.buckets),
        )
        counts[index] += 1
        self._sums[label] = self._sums.get(label, 0.0) + value

    def lines(self, name: str, label_name: str) -> list[str]:
        """Render ``_bucket``/``_sum``/``_count`` samples for every series."""
        bounds = [*map(repr, self.buckets), "+Inf"]
        lines: list[str] = []
        for label in sorted(self._counts):
            cumulative = 0
            for bound, count in zip(bounds, self._counts[label], strict=True):
                cumulative += count
                lines.append(
                    f'{name}_bucket{{{label_name}="{label}",le="{bound}"}} '
                    f"{float(cumulative)}"
                )
            lines.append(f'{name}_sum{{{label_name}="{label}"}} {self._sums[label]}')
            lines.append(f'{name}_count{{{label_name}="{label}"}} {float(cumulative)}')
        return lines

    def clear(self) -> None:
        """Drop every series."""
        self._counts.clear()
        self._sums.clear()


class MetricsRegistry:
    """Thread-safe in-memory metrics registry for Prometheus 0.0.4 exposition."""

    def __init__(self) -> None:
        """Initialize counters, histograms, label limiters and the lock."""
        self._lock = threading.Lock()
        self._requests_total: Counter[Hashable] = Counter()
        self._blocked_total: Counter[Hashable] = Counter()
        self._redactions_total: Counter[Hashable] = Counter()
        self._shadow_total: Counter[Hashable] = Counter()
        self._ledger_errors_total: Counter[Hashable] = Counter()
        self._inspection_duration = Histogram(INSPECTION_BUCKETS)
        self._limiters = {
            name: LabelLimiter()
            for name in ("server", "decision", "rule", "category", "shadow")
        }

    def record_inspection(
        self,
        server_name: str,
        decision: str,
        violations: list[str],
        redacted_categories: list[str],
        would_block: bool = False,
    ) -> None:
        """Record an MCP inspection event, blocked violations, and DLP redactions.

        ``would_block`` on a non-BLOCKED decision is a shadow-mode (monitor)
        verdict and is counted per server in ``aegis_mcp_shadow_would_block``.
        """
        with self._lock:
            server = self._limiters["server"](server_name)
            label = self._limiters["decision"](decision)
            self._requests_total[(server, label)] += 1
            for violation in violations:
                self._blocked_total[self._limiters["rule"](violation)] += 1
            self._count_redactions(redacted_categories)
            if would_block and decision != "BLOCKED":
                self._shadow_total[self._limiters["shadow"](server_name)] += 1

    def _count_redactions(self, redacted_categories: list[str]) -> None:
        """Count DLP categories (caller holds the lock)."""
        for category in redacted_categories:
            self._redactions_total[self._limiters["category"](category)] += 1

    def record_redactions(self, redacted_categories: list[str]) -> None:
        """Record DLP redactions applied outside an inspection (e.g. responses)."""
        with self._lock:
            self._count_redactions(redacted_categories)

    def observe_inspection(self, decision: str, duration_seconds: float) -> None:
        """Record one firewall inspection latency under its decision."""
        with self._lock:
            label = self._limiters["decision"](decision)
            self._inspection_duration.observe(label, max(duration_seconds, 0.0))

    def record_ledger_error(self, kind: str) -> None:
        """Count an audit-integrity failure (see ``LEDGER_ERROR_KINDS``)."""
        if kind not in LEDGER_ERROR_KINDS:
            raise ValueError(f"Unknown ledger error kind: {kind}")
        with self._lock:
            self._ledger_errors_total[kind] += 1

    def _histogram_lines(self) -> list[str]:
        """Render the inspection latency histogram family."""
        name = "aegis_mcp_inspection_duration_seconds"
        return [
            f"# HELP {name} Firewall inspection latency (SLO: p99 < 10ms).",
            f"# TYPE {name} histogram",
            *self._inspection_duration.lines(name, "decision"),
        ]

    def generate_prometheus_exposition(self) -> str:
        """Serialize registered metrics to Prometheus text exposition format (0.0.4)."""
        with self._lock:
            lines = [
                *_counter_lines(
                    "aegis_mcp_requests_total",
                    "Total MCP tool calls inspected.",
                    self._requests_total,
                    _request_labels,
                ),
                *_counter_lines(
                    "aegis_mcp_blocked_total",
                    "Total MCP threats blocked by rule.",
                    self._blocked_total,
                    lambda rule: f'rule="{rule}"',
                ),
                *_counter_lines(
                    "aegis_mcp_redactions_total",
                    "Total sensitive fields redacted.",
                    self._redactions_total,
                    lambda category: f'category="{category}"',
                ),
                *_counter_lines(
                    "aegis_mcp_shadow_would_block_total",
                    "Calls monitor mode let through that enforce mode would block.",
                    self._shadow_total,
                    lambda server: f'server="{server}"',
                ),
                *_counter_lines(
                    "aegis_mcp_ledger_errors_total",
                    "Audit ledger integrity failures (tampering, checkpoint signing).",
                    self._ledger_errors_total,
                    lambda kind: f'kind="{kind}"',
                ),
                *self._histogram_lines(),
                "",
            ]
            return "\n".join(lines)

    def reset(self) -> None:
        """Clear all metric series and label limiters for test isolation."""
        with self._lock:
            self._requests_total.clear()
            self._blocked_total.clear()
            self._redactions_total.clear()
            self._shadow_total.clear()
            self._ledger_errors_total.clear()
            self._inspection_duration.clear()
            for limiter in self._limiters.values():
                limiter.clear()


metrics_registry = MetricsRegistry()
