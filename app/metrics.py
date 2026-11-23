"""Prometheus metrics registry and text exposition formatter for Aegis-MCP."""

import threading
from collections import Counter
from collections.abc import Callable, Hashable
from typing import cast

LabelFormatter = Callable[[Hashable], str]


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


class MetricsRegistry:
    """Thread-safe in-memory metrics registry for Prometheus 0.0.4 exposition."""

    def __init__(self) -> None:
        """Initialize counters and thread synchronization lock."""
        self._lock = threading.Lock()
        self._requests_total: Counter[Hashable] = Counter()
        self._blocked_total: Counter[Hashable] = Counter()
        self._redactions_total: Counter[Hashable] = Counter()
        self._shadow_total: Counter[Hashable] = Counter()

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
            self._requests_total[(server_name, decision)] += 1
            for violation in violations:
                self._blocked_total[violation] += 1
            for category in redacted_categories:
                self._redactions_total[category] += 1
            if would_block and decision != "BLOCKED":
                self._shadow_total[server_name] += 1

    def record_redactions(self, redacted_categories: list[str]) -> None:
        """Record DLP redactions applied outside an inspection (e.g. responses)."""
        with self._lock:
            for category in redacted_categories:
                self._redactions_total[category] += 1

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
                "",
            ]
            return "\n".join(lines)

    def reset(self) -> None:
        """Clear all metric counters for test isolation."""
        with self._lock:
            self._requests_total.clear()
            self._blocked_total.clear()
            self._redactions_total.clear()
            self._shadow_total.clear()


metrics_registry = MetricsRegistry()
