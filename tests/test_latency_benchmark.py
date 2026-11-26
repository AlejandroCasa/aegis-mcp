"""Tests for the reproducible latency benchmark and its CI p99 gate."""

import json
from pathlib import Path

import pytest

from scripts import benchmark_latency as bench
from scripts.evaluate_detection import percentile


def _stats(suite: str, scenario: str, p99: float) -> bench.LatencyStats:
    return bench.LatencyStats(suite, scenario, 10, p99, p99, p99, p99, 100.0)


def _parse_json(stdout: str) -> dict[str, object]:
    """The JSON report precedes the blank line and the Markdown table."""
    payload, _, _ = stdout.partition("\n\n| Suite")
    return dict(json.loads(payload))


# ---------------------------------------------------------------------------
# Percentiles and summaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pct", "expected"),
    [(50, 50.0), (95, 95.0), (99, 99.0), (100, 100.0)],
)
def test_percentile_nearest_rank(pct: float, expected: float) -> None:
    """Nearest-rank percentiles over 1..100 are exact and order-independent."""
    values = [float(v) for v in range(100, 0, -1)]
    assert percentile(values, pct) == expected


def test_percentile_small_and_empty_samples() -> None:
    """Tiny samples round up to the next rank; empty samples are 0."""
    assert percentile([3.0, 1.0, 2.0], 50) == 2.0
    assert percentile([3.0, 1.0, 2.0], 99) == 3.0
    assert percentile([], 99) == 0.0


def test_summarize_computes_distribution_and_throughput() -> None:
    """p50/p95/p99/max and rps derive from the raw samples and wall time."""
    samples = [float(v) for v in range(1, 101)]
    stats = bench.summarize("inspect", "benign", samples, wall_seconds=0.5)
    assert (stats.p50_ms, stats.p95_ms, stats.p99_ms) == (50.0, 95.0, 99.0)
    assert stats.max_ms == 100.0
    assert stats.iterations == 100
    assert stats.throughput_rps == 200.0


def test_summarize_zero_wall_time_and_empty_samples() -> None:
    """Degenerate runs never divide by zero."""
    stats = bench.summarize("inspect", "benign", [], wall_seconds=0.0)
    assert stats.throughput_rps == 0.0
    assert stats.max_ms == 0.0


def test_measure_runs_warmup_then_timed_iterations() -> None:
    """Warmup calls are untimed; every timed call yields one sample."""
    calls: list[int] = []
    stats = bench.measure("inspect", "x", lambda: calls.append(1), 7, 3)
    assert len(calls) == 10
    assert stats.iterations == 7
    assert stats.p99_ms >= stats.p50_ms >= 0.0


# ---------------------------------------------------------------------------
# Workload sanity
# ---------------------------------------------------------------------------


def test_workload_scenarios_exercise_intended_paths() -> None:
    """Benign passes, DLP-heavy redacts, obfuscated and blocked are blocked."""
    with bench.bench_firewall() as firewall:
        verdicts = {
            name: firewall.inspect(bench.build_request(name))
            for name in bench.INSPECT_SCENARIOS
        }
        assert firewall.verify_chain().valid
    assert not verdicts["benign"].would_block
    assert not verdicts["benign"].redacted_categories
    assert len(verdicts["dlp_heavy"].redacted_categories) >= 3
    assert verdicts["obfuscated"].would_block
    assert verdicts["blocked"].would_block


def test_asgi_suite_measures_both_endpoints() -> None:
    """The HTTP suite hits /inspect and /jsonrpc and restores app globals."""
    import app.main as main

    original = (main.firewall, main.jsonrpc_gateway)
    results = bench.run_asgi_suite(iterations=3, warmup=1)
    assert [r.scenario for r in results] == [
        "POST /api/v1/mcp/inspect",
        "POST /api/v1/mcp/jsonrpc",
    ]
    assert all(r.suite == "asgi" and r.iterations == 3 for r in results)
    assert (main.firewall, main.jsonrpc_gateway) == original


def test_asgi_post_raises_on_http_error() -> None:
    """A non-200 response aborts the benchmark instead of timing errors."""
    with bench.asgi_client() as client:
        operation = bench._post(client, "/api/v1/does-not-exist", {})
        with pytest.raises(RuntimeError, match="HTTP 404"):
            operation()


def test_http_headers_forward_configured_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``AEGIS_API_KEY`` is configured the benchmark authenticates."""
    from app.config import settings

    monkeypatch.setattr(settings, "api_key", "bench-key")
    assert bench._http_headers()["X-API-Key"] == "bench-key"
    monkeypatch.setattr(settings, "api_key", None)
    assert "X-API-Key" not in bench._http_headers()


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


def test_gate_uses_worst_inspect_scenario_and_ignores_asgi() -> None:
    """HTTP numbers never fail the gate; the worst inspect p99 does."""
    results = [
        _stats("inspect", "benign", 1.0),
        _stats("inspect", "dlp_heavy", 4.0),
        _stats("asgi", "POST /api/v1/mcp/inspect", 500.0),
    ]
    gate = bench.check_gate(results, max_p99_ms=5.0, enforced=True)
    assert gate.passed
    assert (gate.worst_scenario, gate.observed_p99_ms) == ("dlp_heavy", 4.0)
    failing = bench.check_gate(results, max_p99_ms=3.0, enforced=True)
    assert not failing.passed


def test_gate_without_inspect_results_passes() -> None:
    """An empty inspect suite reports 0 ms and passes."""
    gate = bench.check_gate([], max_p99_ms=1.0, enforced=False)
    assert gate.passed
    assert gate.worst_scenario == ""


def test_markdown_table_lists_every_scenario_and_verdict() -> None:
    """The Markdown summary has one row per scenario plus the verdict."""
    results = [_stats("inspect", "benign", 1.0), _stats("asgi", "POST /x", 2.0)]
    gate = bench.check_gate(results, max_p99_ms=0.5, enforced=False)
    table = bench.format_markdown(results, gate)
    assert "| inspect | benign | 10 |" in table
    assert "| asgi | POST /x | 10 |" in table
    assert "FAIL" in table


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_pass_threshold_emits_json_and_markdown(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A generous budget passes with exit 0 and a complete JSON report."""
    out = tmp_path / "bench.json"
    argv = ["--iterations", "5", "--warmup", "1", "--max-p99-ms", "10000"]
    code = bench.main([*argv, "--fail-on-regression", "--json-out", str(out)])
    assert code == 0
    stdout = capsys.readouterr().out
    report = _parse_json(stdout)
    assert json.loads(out.read_text(encoding="utf-8")) == report
    assert report["config"] == {"iterations": 5, "warmup": 1, "ledger": "sqlite-wal"}
    gate = report["gate"]
    assert isinstance(gate, dict) and gate["passed"] and gate["enforced"]
    results = report["results"]
    assert isinstance(results, list)
    suites = {(r["suite"], r["scenario"]) for r in results}
    assert {("inspect", name) for name in bench.INSPECT_SCENARIOS} <= suites
    assert ("asgi", "POST /api/v1/mcp/jsonrpc") in suites
    for row in results:
        assert set(row) >= {"p50_ms", "p95_ms", "p99_ms", "max_ms", "throughput_rps"}
    assert "| Suite | Scenario |" in stdout
    assert "PASS" in stdout


def test_cli_fail_on_regression_exits_non_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An impossible budget with ``--fail-on-regression`` exits 1."""
    argv = ["--iterations", "3", "--warmup", "0", "--max-p99-ms", "0", "--skip-asgi"]
    assert bench.main([*argv, "--fail-on-regression"]) == 1
    captured = capsys.readouterr()
    assert "Latency regression" in captured.err
    gate = _parse_json(captured.out)["gate"]
    assert isinstance(gate, dict) and not gate["passed"]


def test_cli_regression_is_report_only_without_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Without ``--fail-on-regression`` an exceeded budget still exits 0."""
    argv = ["--iterations", "3", "--warmup", "0", "--max-p99-ms", "0", "--skip-asgi"]
    assert bench.main(argv) == 0
    report = _parse_json(capsys.readouterr().out)
    results = report["results"]
    assert isinstance(results, list)
    assert {r["suite"] for r in results} == {"inspect"}


def test_cli_defaults_and_argument_validation() -> None:
    """Defaults match the documented budget; invalid counts are rejected."""
    args = bench.build_parser().parse_args([])
    assert (args.iterations, args.warmup, args.max_p99_ms) == (500, 50, 10.0)
    assert not args.fail_on_regression
    with pytest.raises(SystemExit):
        bench.build_parser().parse_args(["--iterations", "0"])
    with pytest.raises(SystemExit):
        bench.build_parser().parse_args(["--warmup", "-1"])
