"""Consistency checks for the threat model, security policy and README links.

These tests keep ``docs/THREAT-MODEL.md`` and ``SECURITY.md`` from rotting:
every module or script they cite must exist, the framework sections the
control matrix promises must be present, and ``README.md`` must link both
documents without adding new top-level sections.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
THREAT_MODEL = ROOT / "docs" / "THREAT-MODEL.md"
SECURITY = ROOT / "SECURITY.md"
README = ROOT / "README.md"

CODE_PATH = re.compile(r"\b((?:app|scripts)/[a-z_]+\.py)\b")
MARKDOWN_LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)\s]*)?\)")

REQUIRED_MODULES = (
    "app/auth.py",
    "app/policy.py",
    "app/constraints.py",
    "app/toolguard.py",
    "app/poisoning.py",
    "app/normalize.py",
    "app/redactor.py",
    "app/taint.py",
    "app/rate_limit.py",
    "app/approvals.py",
    "app/ledger.py",
    "app/merkle.py",
    "app/ocsf.py",
    "app/stdio_wrap.py",
    "app/streamable.py",
)

FRAMEWORK_HEADINGS = (
    "OWASP Top 10 for LLM Applications 2025",
    "OWASP Agentic AI",
    "MITRE ATLAS",
    "NIST AI Risk Management Framework",
    "EU AI Act",
    "ISO/IEC 42001",
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _project_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        version = tomllib.load(handle)["project"]["version"]
    assert isinstance(version, str)
    return version


def _resolve_link(document: Path, target: str) -> Path:
    if target.startswith("/"):
        return ROOT / target.lstrip("/")
    return document.parent / target


@pytest.mark.parametrize("document", [THREAT_MODEL, SECURITY])
def test_cited_code_paths_exist(document: Path) -> None:
    cited = set(CODE_PATH.findall(_read(document)))
    assert cited, f"{document.name} cites no modules"
    missing = sorted(path for path in cited if not (ROOT / path).is_file())
    assert not missing, f"{document.name} cites missing files: {missing}"


@pytest.mark.parametrize("document", [THREAT_MODEL, SECURITY, README])
def test_relative_links_resolve(document: Path) -> None:
    targets = [
        target
        for target in MARKDOWN_LINK.findall(_read(document))
        if "://" not in target and not target.startswith("mailto:")
    ]
    broken = [t for t in targets if not _resolve_link(document, t).exists()]
    assert not broken, f"{document.name} has broken links: {broken}"


def test_threat_model_covers_every_required_module() -> None:
    text = _read(THREAT_MODEL)
    missing = [module for module in REQUIRED_MODULES if module not in text]
    assert not missing


def test_threat_model_structure() -> None:
    text = _read(THREAT_MODEL)
    assert f"v{_project_version()}" in text.splitlines()[0]
    assert "```mermaid\nflowchart LR" in text
    for letter in "STRIDE":
        assert f"| **{letter}** |" in text, f"STRIDE category {letter} missing"
    for heading in FRAMEWORK_HEADINGS:
        assert re.search(rf"^### 6\.\d .*{re.escape(heading)}", text, re.M), heading
    for article in ("Art. 12", "Art. 14"):
        assert article in text
    assert "Residual Risk Register" in text


def test_security_policy_contents() -> None:
    text = _read(SECURITY)
    supported_line = f"`{_project_version().rsplit('.', 1)[0]}.x`"
    assert supported_line in text
    for required in (
        "Security Advisories",
        "Email",
        "Response targets",
        "scripts.verify_ledger",
        "cosign verify",
        "slsaprovenance",
    ):
        assert required in text, required


def test_readme_links_docs_without_new_sections() -> None:
    text = _read(README)
    assert "](docs/THREAT-MODEL.md)" in text
    assert "](SECURITY.md)" in text
    headings = re.findall(r"^## (.+)$", text, re.M)
    assert not any("security" in h.lower() or "threat" in h.lower() for h in headings)
