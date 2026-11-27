"""Tests for the labeled detection benchmark corpus and its CI gate."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from scripts import build_benchmark_corpus as builder
from scripts import evaluate_detection as ev

MALICIOUS_CATEGORIES = ev.CATEGORIES - {"benign"}


@pytest.fixture(scope="module")
def corpus() -> list[ev.BenchmarkCase]:
    """The committed corpus."""
    return ev.load_corpus()


@pytest.fixture(scope="module")
def report(corpus: list[ev.BenchmarkCase]) -> ev.Report:
    """One full evaluation of the committed corpus."""
    return ev.evaluate(corpus)


def _record(case_id: str, category: str, arguments: dict[str, Any]) -> dict[str, Any]:
    benign = category == "benign"
    return {
        "id": case_id,
        "category": category,
        "expected_flagged": not benign,
        "owasp_llm_2025": "N/A" if benign else "LLM01:2025 Prompt Injection",
        "owasp_agentic": "N/A" if benign else "ASI01 Goal Hijack",
        "mitre_atlas": "N/A" if benign else "AML.T0051 LLM Prompt Injection",
        "kind": "inspect",
        "request": {
            "server_name": "notes-mcp",
            "tool_name": "save",
            "arguments": arguments,
        },
    }


def _write(directory: Path, records: list[dict[str, Any]]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    lines = "".join(json.dumps(record) + "\n" for record in records)
    (directory / "mini.jsonl").write_text(lines, encoding="utf-8")
    return directory


LEAK = {"text": "{{SYNTH_AWS_KEY}}"}
CLEAN = {"text": "standup notes"}


# ---------------------------------------------------------------------------
# Committed corpus
# ---------------------------------------------------------------------------


def test_corpus_size_and_category_coverage(corpus: list[ev.BenchmarkCase]) -> None:
    """>= 300 cases spread over every category, benign and malicious."""
    assert len(corpus) >= 320
    counts = Counter(case.category for case in corpus)
    assert set(counts) == ev.CATEGORIES
    assert counts["benign"] >= 150
    assert all(counts[category] >= 15 for category in MALICIOUS_CATEGORIES)
    assert {case.kind for case in corpus} == ev.KINDS


def test_corpus_taxonomy_tags(corpus: list[ev.BenchmarkCase]) -> None:
    """Every malicious case carries OWASP LLM, OWASP Agentic and ATLAS tags."""
    for case in corpus:
        tags = case.taxonomy().values()
        if case.category == "benign":
            assert set(tags) == {"N/A"}
            continue
        assert case.owasp_llm_2025.startswith("LLM")
        assert case.owasp_agentic.startswith("ASI")
        assert case.mitre_atlas.startswith("AML.T")


def test_corpus_matches_generator() -> None:
    """The committed JSONL is exactly what the deterministic generator emits."""
    for name, records in builder.build_corpus().items():
        committed = (ev.DEFAULT_CORPUS_DIR / name).read_text(encoding="utf-8")
        assert committed == builder.serialize(records), name


def test_committed_corpus_meets_kpis(report: ev.Report) -> None:
    """recall >= 0.95, fpr <= 0.02, intact audit chain."""
    assert report.overall.recall >= 0.95
    assert report.overall.fpr <= 0.02
    assert report.chain_valid
    assert not ev.check_thresholds(report, ev.Thresholds())
    misses = {r.case.id for r in report.misclassified}
    described = {
        r.case.id
        for r in report.results
        if str(r.case.payload.get("description", "")).startswith("known gap")
    }
    assert misses <= described


def test_report_breakdowns(report: ev.Report) -> None:
    """Per-category and per-taxonomy matrices cover all malicious cases."""
    malicious = report.overall.tp + report.overall.fn
    for key in ("owasp_llm_2025", "owasp_agentic", "mitre_atlas"):
        assert sum(c.total for c in report.by_taxonomy[key].values()) == malicious
    assert sum(c.total for c in report.by_category.values()) == report.overall.total
    latency = report.latency_summary()
    assert 0 <= latency["p50_ms"] <= latency["p99_ms"] <= latency["total_ms"]


def test_main_passes_on_committed_corpus(capsys: pytest.CaptureFixture[str]) -> None:
    """Default thresholds exit 0 and emit a machine-readable report."""
    assert ev.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True
    assert payload["overall"]["total"] >= 300
    assert set(payload["by_taxonomy"]) == {
        "mitre_atlas",
        "owasp_agentic",
        "owasp_llm_2025",
    }


def test_builder_main_writes_corpus(tmp_path: Path) -> None:
    """The generator CLI materializes the same four files elsewhere."""
    assert builder.main([str(tmp_path)]) == 0
    assert sorted(p.name for p in tmp_path.glob("*.jsonl")) == sorted(builder.FILES)


# ---------------------------------------------------------------------------
# Gate failures on synthetic mini-corpora
# ---------------------------------------------------------------------------


def test_main_fails_on_high_fpr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A benign-labeled case that gets flagged violates max_fpr."""
    corpus_dir = _write(
        tmp_path,
        [_record("BEN-001", "benign", LEAK), _record("BEN-002", "benign", CLEAN)],
    )
    code = ev.main(["--corpus-dir", str(corpus_dir), "--min-cases", "1"])
    assert code == 1
    out = capsys.readouterr().out
    assert "fpr 0.5000 > max_fpr" in out
    assert "BEN-001" in out


def test_main_fails_on_low_recall(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A malicious-labeled case that is missed violates min_recall."""
    corpus_dir = _write(
        tmp_path,
        [
            _record("INJ-001", "prompt_injection", CLEAN),
            _record("INJ-002", "prompt_injection", LEAK),
        ],
    )
    args = ["--corpus-dir", str(corpus_dir), "--min-cases", "1", "--json"]
    assert ev.main(args) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is False
    assert any("recall" in failure for failure in payload["failures"])
    assert payload["misclassified"][0]["id"] == "INJ-001"


def test_main_fails_below_min_cases(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Perfect metrics still fail when the corpus is too small."""
    corpus_dir = _write(tmp_path, [_record("BEN-001", "benign", CLEAN)])
    assert ev.main(["--corpus-dir", str(corpus_dir)]) == 1
    assert "cases 1 < min_cases 300" in capsys.readouterr().out


def test_main_rejects_invalid_corpus(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Schema violations exit 2."""
    bad = _record("BEN-001", "benign", CLEAN)
    bad["expected_flagged"] = True
    corpus_dir = _write(tmp_path, [bad])
    assert ev.main(["--corpus-dir", str(corpus_dir)]) == 2
    assert "expected_flagged" in capsys.readouterr().err


def test_chain_failure_fails_gate() -> None:
    """A broken audit chain fails the gate regardless of KPIs."""
    report = ev.aggregate([], chain_valid=False)
    lenient = ev.Thresholds(min_recall=0.0, max_fpr=1.0, min_cases=0)
    failures = ev.check_thresholds(report, lenient)
    assert failures == ["audit hash chain verification failed"]


# ---------------------------------------------------------------------------
# Schema validation and helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"id": "bad"}, "id must look like"),
        ({"category": "spam"}, "unknown category"),
        ({"kind": "replay"}, "unknown kind"),
        ({"owasp_llm_2025": "LLM99"}, "invalid 'owasp_llm_2025'"),
        ({"mitre_atlas": ""}, "non-empty string"),
        ({"request": None}, "needs a 'request'"),
        ({"policy": []}, "'policy' must be an object"),
    ],
)
def test_parse_case_rejects(mutation: dict[str, Any], message: str) -> None:
    """Each schema rule produces a precise error."""
    record = _record("INJ-001", "prompt_injection", CLEAN)
    record.update(mutation)
    with pytest.raises(ev.CorpusError, match=message):
        ev.parse_case(record, "mini.jsonl:1")


def test_parse_case_rejects_tagged_benign_and_bad_kinds() -> None:
    """Benign cases must use N/A; flows/definitions need their payloads."""
    benign = _record("BEN-001", "benign", CLEAN)
    benign["mitre_atlas"] = "AML.T0051 LLM Prompt Injection"
    with pytest.raises(ev.CorpusError, match="N/A"):
        ev.parse_case(benign)
    flow = _record("TNT-001", "prompt_injection", CLEAN) | {"kind": "session_flow"}
    with pytest.raises(ev.CorpusError, match="non-empty 'steps'"):
        ev.parse_case(flow)
    definition = _record("POI-001", "prompt_injection", CLEAN)
    definition |= {"kind": "tool_definition"}
    with pytest.raises(ev.CorpusError, match="needs 'definition'"):
        ev.parse_case(definition)
    definition["definition"] = {"name": "x"}
    definition["definition_kind"] = "widget"
    with pytest.raises(ev.CorpusError, match="definition_kind"):
        ev.parse_case(definition)
    with pytest.raises(ev.CorpusError, match="JSON object"):
        ev.parse_case([1, 2])


def test_load_corpus_errors(tmp_path: Path) -> None:
    """Missing files, invalid JSON and duplicate IDs are rejected."""
    with pytest.raises(ev.CorpusError, match="No"):
        ev.load_corpus(tmp_path)
    (tmp_path / "a.jsonl").write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(ev.CorpusError, match="invalid JSON"):
        ev.load_corpus(tmp_path)
    record = json.dumps(_record("BEN-001", "benign", CLEAN))
    (tmp_path / "a.jsonl").write_text(f"{record}\n\n{record}\n", encoding="utf-8")
    with pytest.raises(ev.CorpusError, match="duplicate"):
        ev.load_corpus(tmp_path)


def test_macros_expand_deterministically() -> None:
    """Macros expand recursively; unknown macros are corpus errors."""
    expanded = ev.expand_macros({"a": ["{{SYNTH_JWT}}", 3], "b": "x{{SYNTH_AWS_KEY}}"})
    assert expanded["a"][0] == ev.MACROS["SYNTH_JWT"]
    assert expanded["a"][1] == 3
    assert expanded["b"] == "x" + ev.MACROS["SYNTH_AWS_KEY"]
    assert ev.build_macros() == ev.MACROS
    with pytest.raises(ev.CorpusError, match="Unknown corpus macro"):
        ev.expand_macros("{{SYNTH_NOPE}}")


def test_confusion_metrics_and_percentile() -> None:
    """Derived metrics handle empty denominators."""
    empty = ev.Confusion()
    assert (empty.precision, empty.recall, empty.f1, empty.fpr) == (0, 0, 0, 0)
    matrix = ev.Confusion()
    for expected, flagged in [(True, True), (True, False), (False, True)]:
        matrix.add(expected, flagged)
    matrix.add(False, False)
    assert matrix.as_dict() == {
        "total": 4,
        "tp": 1,
        "fp": 1,
        "tn": 1,
        "fn": 1,
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
        "fpr": 0.5,
    }
    assert ev.percentile([], 50) == 0.0
    assert ev.percentile([3.0, 1.0, 2.0], 50) == 2.0
    assert ev.percentile([float(i) for i in range(1, 101)], 99) == 99.0
