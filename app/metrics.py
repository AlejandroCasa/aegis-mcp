"""Prometheus metrics registry and text exposition formatter for Aegis-MCP."""

import threading
from collections import Counter


class MetricsRegistry:
    """Thread-safe in-memory metrics registry for Prometheus 0.0.4 exposition."""

    def __init__(self) -> None:
        """Initialize counters and thread synchronization lock."""
        self._lock = threading.Lock()
        self._requests_total: Counter[tuple[str, str]] = Counter()
        self._blocked_total: Counter[str] = Counter()
        self._redactions_total: Counter[str] = Counter()

    def record_inspection(
        self,
        server_name: str,
        decision: str,
        violations: list[str],
        redacted_categories: list[str],
    ) -> None:
        """Record an MCP inspection event, blocked violations, and DLP redactions."""
        with self._lock:
            self._requests_total[(server_name, decision)] += 1
            for violation in violations:
                self._blocked_total[violation] += 1
            for category in redacted_categories:
                self._redactions_total[category] += 1

    def generate_prometheus_exposition(self) -> str:
        """Serialize registered metrics to Prometheus text exposition format (0.0.4)."""
        with self._lock:
            lines: list[str] = [
                "# HELP aegis_mcp_requests_total Total MCP tool calls inspected.",
                "# TYPE aegis_mcp_requests_total counter",
            ]
            if self._requests_total:
                for (server, decision), count in sorted(self._requests_total.items()):
                    labels = f'decision="{decision}",server="{server}"'
                    lines.append(f"aegis_mcp_requests_total{{{labels}}} {float(count)}")
            else:
                lines.append("aegis_mcp_requests_total 0.0")

            lines.append(
                "# HELP aegis_mcp_blocked_total Total MCP threats blocked by rule."
            )
            lines.append("# TYPE aegis_mcp_blocked_total counter")
            if self._blocked_total:
                for rule, count in sorted(self._blocked_total.items()):
                    lines.append(
                        f'aegis_mcp_blocked_total{{rule="{rule}"}} {float(count)}'
                    )
            else:
                lines.append("aegis_mcp_blocked_total 0.0")

            lines.append(
                "# HELP aegis_mcp_redactions_total Total sensitive fields redacted."
            )
            lines.append("# TYPE aegis_mcp_redactions_total counter")
            if self._redactions_total:
                for category, count in sorted(self._redactions_total.items()):
                    lines.append(
                        f'aegis_mcp_redactions_total{{category="{category}"}} '
                        f"{float(count)}"
                    )
            else:
                lines.append("aegis_mcp_redactions_total 0.0")

            lines.append("")
            return "\n".join(lines)

    def reset(self) -> None:
        """Clear all metric counters for test isolation."""
        with self._lock:
            self._requests_total.clear()
            self._blocked_total.clear()
            self._redactions_total.clear()


metrics_registry = MetricsRegistry()
