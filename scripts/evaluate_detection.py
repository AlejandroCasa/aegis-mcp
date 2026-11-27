"""Detection benchmark evaluator and CI quality gate.

Loads every ``benchmarks/corpus/*.jsonl`` case, runs it deterministically
against Aegis-MCP in memory (temporary audit ledger, per-case policy and
session taint isolation) and reports the confusion matrix, precision,
recall, F1, false positive rate, latency, and per-category / per-taxonomy
breakdowns.

A case is *flagged* when:

* ``inspect``: ``MCPFirewall.inspect`` would block the call (``would_block``)
  or DLP redacted at least one category;
* ``tool_definition``: ``scan_definition`` reports a finding scoring at
  least the gateway block threshold (``AEGIS_BLOCK_THRESHOLD_SCORE``);
* ``session_flow``: any step of the session would be blocked (toxic-flow
  taint, RBAC/ABAC, or threat rules).

Exit codes: ``0`` all gates pass, ``1`` a KPI gate failed, ``2`` the corpus
is invalid. Usage::

    uv run python -m scripts.evaluate_detection --min-recall 0.95 \
        --max-fpr 0.02 --min-cases 300 [--json]
"""

import argparse
import base64
import hashlib
import json
import re
import sys
import tempfile
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.config import settings
from app.firewall import MCPFirewall
from app.poisoning import scan_definition
from app.policy import PolicyEngine
from app.schemas import MCPToolCallRequest, PolicyDocument

DEFAULT_CORPUS_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "corpus"

CATEGORIES = frozenset(
    {
        "benign",
        "prompt_injection",
        "command_injection",
        "destructive_sql",
        "path_traversal",
        "evasion_obfuscated",
        "tool_poisoning",
        "abac_constraint",
        "toxic_flow",
        "dlp_redaction",
    }
)
KINDS = frozenset({"inspect", "tool_definition", "session_flow"})
DEFINITION_KINDS = frozenset({"server", "tool", "prompt", "resource"})
TAXONOMY_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("owasp_llm_2025", re.compile(r"^LLM(?:0[1-9]|10):2025 \S.*$")),
    ("owasp_agentic", re.compile(r"^ASI(?:0[1-9]|1[0-5]) \S.*$")),
    ("mitre_atlas", re.compile(r"^AML\.T\d{4}(?:\.\d{3})? \S.*$")),
)
ID_PATTERN = re.compile(r"^[A-Z]{3}-\d{3,}$")
MACRO_PATTERN = re.compile(r"\{\{(SYNTH_[A-Z0-9_]+)\}\}")


class CorpusError(ValueError):
    """Raised when a corpus file or record violates the schema."""


# ---------------------------------------------------------------------------
# Synthetic secret macros (assembled from fragments, never stored literally)
# ---------------------------------------------------------------------------


def _material(label: str, length: int, alphabet: str) -> str:
    """Deterministic pseudo-random characters derived from ``label``."""
    out: list[str] = []
    counter = 0
    while len(out) < length:
        digest = hashlib.sha256(f"{label}:{counter}".encode()).digest()
        out.extend(alphabet[byte % len(alphabet)] for byte in digest)
        counter += 1
    return "".join(out[:length])


_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _b64url_json(data: dict[str, Any]) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _synthetic_pem() -> str:
    dashes = "-" * 5
    label = " ".join(["RSA", "PRIVATE", "KEY"])
    body = _material("pem", 64, _ALNUM)
    return f"{dashes}BEGIN {label}{dashes}\n{body}\n{dashes}END {label}{dashes}"


def _synthetic_jwt() -> str:
    header = _b64url_json({"alg": "HS256", "typ": "JWT"})
    claims = _b64url_json({"sub": "bench-user", "iat": 1764065730})
    return ".".join([header, claims, _material("jwt", 43, _ALNUM)])


def build_macros() -> dict[str, str]:
    """Return the ``SYNTH_*`` macro table (deterministic synthetic secrets)."""
    return {
        "SYNTH_OPENAI_KEY": "".join(
            ["sk", "-", "proj", "-", _material("oa", 40, _ALNUM)]
        ),
        "SYNTH_GITHUB_PAT": "".join(["gh", "p", "_", _material("gh", 36, _ALNUM)]),
        "SYNTH_AWS_KEY": "".join(["AK", "IA", _material("aws", 16, _UPPER)]),
        "SYNTH_SLACK_TOKEN": "-".join(
            ["xox" + "b", "1029384756", "5647382910", _material("sl", 24, _ALNUM)]
        ),
        "SYNTH_STRIPE_KEY": "_".join(["sk", "live", _material("st", 24, _ALNUM)]),
        "SYNTH_GOOGLE_KEY": "".join(["AI", "za", _material("gg", 35, _ALNUM)]),
        "SYNTH_PEM_KEY": _synthetic_pem(),
        "SYNTH_JWT": _synthetic_jwt(),
        "SYNTH_HIGH_ENTROPY": _material("entropy", 32, _ALNUM + "+/!#%"),
    }


MACROS = build_macros()


def expand_macros(node: Any) -> Any:
    """Recursively replace ``{{SYNTH_*}}`` placeholders in strings."""
    if isinstance(node, str):
        return MACRO_PATTERN.sub(_macro_value, node)
    if isinstance(node, dict):
        return {key: expand_macros(value) for key, value in node.items()}
    if isinstance(node, list):
        return [expand_macros(item) for item in node]
    return node


def _macro_value(match: re.Match[str]) -> str:
    name = match.group(1)
    if name not in MACROS:
        raise CorpusError(f"Unknown corpus macro: {name}")
    return MACROS[name]


# ---------------------------------------------------------------------------
# Corpus schema
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BenchmarkCase:
    """One labeled, executable benchmark case."""

    id: str
    category: str
    expected_flagged: bool
    owasp_llm_2025: str
    owasp_agentic: str
    mitre_atlas: str
    kind: str
    payload: dict[str, Any]
    source: str = ""

    def taxonomy(self) -> dict[str, str]:
        """Return the taxonomy tags keyed by field name."""
        return {
            "owasp_llm_2025": self.owasp_llm_2025,
            "owasp_agentic": self.owasp_agentic,
            "mitre_atlas": self.mitre_atlas,
        }


def _require_str(record: dict[str, Any], key: str, where: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise CorpusError(f"{where}: '{key}' must be a non-empty string")
    return value


def _validate_taxonomy(record: dict[str, Any], benign: bool, where: str) -> None:
    for key, pattern in TAXONOMY_FIELDS:
        value = _require_str(record, key, where)
        if benign and value != "N/A":
            raise CorpusError(f"{where}: benign case must tag '{key}' as N/A")
        if not benign and not pattern.fullmatch(value):
            raise CorpusError(f"{where}: invalid '{key}' tag {value!r}")


def _validate_payload(kind: str, record: dict[str, Any], where: str) -> None:
    if kind == "inspect" and not isinstance(record.get("request"), dict):
        raise CorpusError(f"{where}: inspect case needs a 'request' object")
    if kind == "session_flow":
        steps = record.get("steps")
        if not isinstance(steps, list) or not steps:
            raise CorpusError(f"{where}: session_flow needs non-empty 'steps'")
    if kind == "tool_definition":
        if not isinstance(record.get("definition"), dict):
            raise CorpusError(f"{where}: tool_definition needs 'definition'")
        if record.get("definition_kind", "tool") not in DEFINITION_KINDS:
            raise CorpusError(f"{where}: invalid 'definition_kind'")
    policy = record.get("policy")
    if policy is not None and not isinstance(policy, dict):
        raise CorpusError(f"{where}: 'policy' must be an object")


def parse_case(record: Any, source: str = "") -> BenchmarkCase:
    """Validate one JSONL record and return a :class:`BenchmarkCase`."""
    if not isinstance(record, dict):
        raise CorpusError(f"{source}: record must be a JSON object")
    where = f"{source}:{record.get('id', '?')}"
    case_id = _require_str(record, "id", where)
    if not ID_PATTERN.fullmatch(case_id):
        raise CorpusError(f"{where}: id must look like 'BEN-001'")
    category = _require_str(record, "category", where)
    if category not in CATEGORIES:
        raise CorpusError(f"{where}: unknown category {category!r}")
    expected = record.get("expected_flagged")
    if not isinstance(expected, bool) or expected != (category != "benign"):
        raise CorpusError(f"{where}: expected_flagged must be bool and match label")
    kind = _require_str(record, "kind", where)
    if kind not in KINDS:
        raise CorpusError(f"{where}: unknown kind {kind!r}")
    _validate_taxonomy(record, category == "benign", where)
    _validate_payload(kind, record, where)
    return BenchmarkCase(
        id=case_id,
        category=category,
        expected_flagged=expected,
        owasp_llm_2025=record["owasp_llm_2025"],
        owasp_agentic=record["owasp_agentic"],
        mitre_atlas=record["mitre_atlas"],
        kind=kind,
        payload=record,
        source=source,
    )


def _iter_lines(path: Path) -> Iterator[tuple[int, str]]:
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            yield number, line


def load_corpus(directory: Path = DEFAULT_CORPUS_DIR) -> list[BenchmarkCase]:
    """Load and validate every ``*.jsonl`` file (IDs must be unique)."""
    files = sorted(directory.glob("*.jsonl"))
    if not files:
        raise CorpusError(f"No *.jsonl corpus files found in {directory}")
    cases: list[BenchmarkCase] = []
    seen: set[str] = set()
    for path in files:
        for number, line in _iter_lines(path):
            source = f"{path.name}:{number}"
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CorpusError(f"{source}: invalid JSON ({exc.msg})") from exc
            case = parse_case(record, source)
            if case.id in seen:
                raise CorpusError(f"{source}: duplicate case id {case.id}")
            seen.add(case.id)
            cases.append(case)
    return cases


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaseResult:
    """Outcome of one executed case."""

    case: BenchmarkCase
    flagged: bool
    latency_ms: float
    signals: tuple[str, ...]

    @property
    def correct(self) -> bool:
        """True when the verdict matches the label."""
        return self.flagged == self.case.expected_flagged


class DetectionHarness:
    """Runs cases against an isolated in-memory Aegis-MCP firewall."""

    def __init__(self, db_path: str) -> None:
        """Bind a firewall to a throwaway audit ledger."""
        self.firewall = MCPFirewall(db_path=db_path, policy_engine=PolicyEngine())

    def _prepare(self, case: BenchmarkCase) -> None:
        policy = case.payload.get("policy") or {}
        self.firewall.policy_engine.load(PolicyDocument.model_validate(policy))
        self.firewall.taint.reset()
        self.firewall.rate_limiter.reset()

    def _inspect(self, request: dict[str, Any], session_id: str) -> list[str]:
        call = MCPToolCallRequest.model_validate(expand_macros(request))
        response = self.firewall.inspect(call, session_id=session_id)
        signals = list(response.violations)
        signals.extend(f"redacted:{name}" for name in response.redacted_categories)
        if response.would_block:
            signals.append("would_block")
        return signals

    def _run_definition(self, case: BenchmarkCase) -> list[str]:
        payload = case.payload
        findings = scan_definition(
            str(payload.get("server", "benchmark")),
            str(payload.get("definition_kind", "tool")),
            expand_macros(payload["definition"]),
            frozenset(payload.get("foreign_tools", [])),
        )
        threshold = settings.block_threshold_score
        return [f"{f.rule}:{f.score}" for f in findings if f.score >= threshold]

    def _run_flow(self, case: BenchmarkCase) -> list[str]:
        signals: list[str] = []
        for index, step in enumerate(case.payload["steps"]):
            step_signals = self._inspect(step, session_id=f"bench-{case.id}")
            if "would_block" in step_signals:
                signals.extend(f"step{index}:{s}" for s in step_signals)
        return signals

    @staticmethod
    def _is_flagged(case: BenchmarkCase, signals: list[str]) -> bool:
        if case.kind == "inspect":
            return any(s == "would_block" or s.startswith("redacted:") for s in signals)
        return bool(signals)

    def run(self, case: BenchmarkCase) -> CaseResult:
        """Execute one case and time it."""
        self._prepare(case)
        start = time.perf_counter()
        if case.kind == "tool_definition":
            signals = self._run_definition(case)
        elif case.kind == "session_flow":
            signals = self._run_flow(case)
        else:
            signals = self._inspect(case.payload["request"], session_id="")
        elapsed = (time.perf_counter() - start) * 1000.0
        flagged = self._is_flagged(case, signals)
        return CaseResult(case, flagged, elapsed, tuple(signals))


@contextmanager
def harness() -> Iterator[DetectionHarness]:
    """Yield a harness whose audit ledger lives in a temporary directory."""
    with tempfile.TemporaryDirectory(prefix="aegis-bench-") as tmp:
        yield DetectionHarness(str(Path(tmp) / "bench_audit.db"))


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


@dataclass
class Confusion:
    """Binary confusion matrix with derived detection metrics."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def add(self, expected: bool, flagged: bool) -> None:
        """Record one verdict."""
        if expected and flagged:
            self.tp += 1
        elif expected:
            self.fn += 1
        elif flagged:
            self.fp += 1
        else:
            self.tn += 1

    @property
    def total(self) -> int:
        """Number of cases."""
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        """TP / (TP + FP)."""
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        """TP / (TP + FN)."""
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def fpr(self) -> float:
        """FP / (FP + TN)."""
        return _ratio(self.fp, self.fp + self.tn)

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall."""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    def as_dict(self) -> dict[str, Any]:
        """JSON-serializable view."""
        return {
            "total": self.total,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fpr": round(self.fpr, 4),
        }


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile (0 for an empty list)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, -(-len(ordered) * pct // 100))
    return ordered[int(rank) - 1]


@dataclass
class Report:
    """Aggregated evaluation results."""

    results: list[CaseResult]
    overall: Confusion = field(default_factory=Confusion)
    by_category: dict[str, Confusion] = field(default_factory=dict)
    by_taxonomy: dict[str, dict[str, Confusion]] = field(default_factory=dict)
    chain_valid: bool = True

    @property
    def latencies(self) -> list[float]:
        """Per-case latencies in milliseconds."""
        return [result.latency_ms for result in self.results]

    @property
    def misclassified(self) -> list[CaseResult]:
        """Cases whose verdict disagrees with the label."""
        return [result for result in self.results if not result.correct]

    def latency_summary(self) -> dict[str, float]:
        """Total, p50, and p99 latency in milliseconds."""
        values = self.latencies
        return {
            "total_ms": round(sum(values), 3),
            "p50_ms": round(percentile(values, 50), 3),
            "p99_ms": round(percentile(values, 99), 3),
        }


def aggregate(results: Iterable[CaseResult], chain_valid: bool = True) -> Report:
    """Build overall, per-category, and per-taxonomy confusion matrices."""
    report = Report(results=list(results), chain_valid=chain_valid)
    for result in report.results:
        case = result.case
        report.overall.add(case.expected_flagged, result.flagged)
        report.by_category.setdefault(case.category, Confusion()).add(
            case.expected_flagged, result.flagged
        )
        if case.category == "benign":
            continue
        for key, tag in case.taxonomy().items():
            bucket = report.by_taxonomy.setdefault(key, {})
            bucket.setdefault(tag, Confusion()).add(True, result.flagged)
    return report


def evaluate(cases: list[BenchmarkCase]) -> Report:
    """Run every case in an isolated harness and aggregate the results."""
    with harness() as runner:
        results = [runner.run(case) for case in cases]
        chain_valid = runner.firewall.verify_chain().valid
    return aggregate(results, chain_valid)


# ---------------------------------------------------------------------------
# Gates and output
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Thresholds:
    """KPI gate configuration."""

    min_recall: float = 0.95
    max_fpr: float = 0.02
    min_cases: int = 300


def check_thresholds(report: Report, thresholds: Thresholds) -> list[str]:
    """Return human-readable gate failures (empty when all gates pass)."""
    failures: list[str] = []
    overall = report.overall
    if overall.total < thresholds.min_cases:
        failures.append(f"cases {overall.total} < min_cases {thresholds.min_cases}")
    if overall.recall < thresholds.min_recall:
        failures.append(
            f"recall {overall.recall:.4f} < min_recall {thresholds.min_recall}"
        )
    if overall.fpr > thresholds.max_fpr:
        failures.append(f"fpr {overall.fpr:.4f} > max_fpr {thresholds.max_fpr}")
    if not report.chain_valid:
        failures.append("audit hash chain verification failed")
    return failures


def report_to_dict(
    report: Report, thresholds: Thresholds, failures: list[str]
) -> dict[str, Any]:
    """Machine-readable report (``--json``)."""
    return {
        "passed": not failures,
        "failures": failures,
        "thresholds": {
            "min_recall": thresholds.min_recall,
            "max_fpr": thresholds.max_fpr,
            "min_cases": thresholds.min_cases,
        },
        "overall": report.overall.as_dict(),
        "latency": report.latency_summary(),
        "chain_valid": report.chain_valid,
        "by_category": {k: v.as_dict() for k, v in sorted(report.by_category.items())},
        "by_taxonomy": {
            key: {tag: c.as_dict() for tag, c in sorted(tags.items())}
            for key, tags in sorted(report.by_taxonomy.items())
        },
        "misclassified": [
            {
                "id": r.case.id,
                "category": r.case.category,
                "expected_flagged": r.case.expected_flagged,
                "flagged": r.flagged,
                "description": r.case.payload.get("description", ""),
            }
            for r in report.misclassified
        ],
    }


def _row(name: str, c: Confusion) -> str:
    return (
        f"  {name:<44} {c.total:>4} {c.tp:>4} {c.fp:>4} {c.tn:>4} {c.fn:>4} "
        f"{c.precision:>6.3f} {c.recall:>6.3f} {c.fpr:>6.3f}"
    )


def format_text(report: Report, thresholds: Thresholds, failures: list[str]) -> str:
    """Human-readable diagnostic summary."""
    header = f"  {'':<44} {'n':>4} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} "
    header += f"{'prec':>6} {'recall':>6} {'fpr':>6}"
    o = report.overall
    latency = report.latency_summary()
    lines = [
        "Aegis-MCP detection benchmark",
        f"  cases={o.total} TP={o.tp} FP={o.fp} TN={o.tn} FN={o.fn}",
        f"  precision={o.precision:.4f} recall={o.recall:.4f} "
        f"f1={o.f1:.4f} fpr={o.fpr:.4f}",
        f"  latency total={latency['total_ms']:.1f}ms "
        f"p50={latency['p50_ms']:.3f}ms p99={latency['p99_ms']:.3f}ms",
        f"  audit chain valid={report.chain_valid}",
        "",
        "By category:",
        header,
    ]
    lines.extend(_row(k, v) for k, v in sorted(report.by_category.items()))
    for key, tags in sorted(report.by_taxonomy.items()):
        lines.extend(["", f"By {key} (malicious cases):", header])
        lines.extend(_row(tag, c) for tag, c in sorted(tags.items()))
    if report.misclassified:
        lines.extend(["", "Misclassified cases:"])
        lines.extend(
            f"  {r.case.id} [{r.case.category}] expected={r.case.expected_flagged} "
            f"flagged={r.flagged}: {r.case.payload.get('description', '')}"
            for r in report.misclassified
        )
    verdict = "PASS" if not failures else "FAIL: " + "; ".join(failures)
    lines.extend(
        [
            "",
            f"Gate (min_recall={thresholds.min_recall}, max_fpr={thresholds.max_fpr},"
            f" min_cases={thresholds.min_cases}): {verdict}",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """CLI argument parser."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus-dir", type=Path, default=DEFAULT_CORPUS_DIR)
    parser.add_argument("--min-recall", type=float, default=0.95)
    parser.add_argument("--max-fpr", type=float, default=0.02)
    parser.add_argument("--min-cases", type=int, default=300)
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the benchmark gate; returns the process exit code."""
    args = build_parser().parse_args(argv)
    thresholds = Thresholds(args.min_recall, args.max_fpr, args.min_cases)
    try:
        cases = load_corpus(args.corpus_dir)
        report = evaluate(cases)
    except CorpusError as exc:
        print(f"Invalid benchmark corpus: {exc}", file=sys.stderr)
        return 2
    failures = check_thresholds(report, thresholds)
    if args.json:
        print(json.dumps(report_to_dict(report, thresholds, failures), indent=2))
    else:
        print(format_text(report, thresholds, failures))
    return 1 if failures else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
