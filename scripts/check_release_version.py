"""Release-train consistency gate: tag == pyproject == chart == CHANGELOG.

Run by ``.github/workflows/release.yml`` before any image is built::

    python -m scripts.check_release_version --tag "$GITHUB_REF_NAME"

Without ``--tag`` it only checks that the repository's own version sources
agree with each other (useful before cutting the tag).
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHART_PATH = Path("deploy/helm/aegis-mcp/Chart.yaml")
_CHANGELOG_HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\]", re.MULTILINE)
# Top-level scalar keys of Chart.yaml (stdlib only: runs on a bare runner).
_CHART_KEY = r"^{key}:\s*[\"']?(?P<value>[^\"'\s#]+)[\"']?\s*(?:#.*)?$"


def _chart_field(chart: str, key: str) -> str:
    """Return the top-level ``key`` scalar of a Chart.yaml document."""
    match = re.search(_CHART_KEY.format(key=key), chart, re.MULTILINE)
    return match.group("value") if match else ""


@dataclass(frozen=True)
class ReleaseVersions:
    """Every version string the release train must keep in lockstep."""

    pyproject: str
    chart: str
    app: str
    changelog: tuple[str, ...]


def read_versions(root: Path = ROOT) -> ReleaseVersions:
    """Collect the version declared by each release artifact under ``root``."""
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    chart = (root / CHART_PATH).read_text(encoding="utf-8")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    return ReleaseVersions(
        pyproject=str(project["project"]["version"]),
        chart=_chart_field(chart, "version"),
        app=_chart_field(chart, "appVersion"),
        changelog=tuple(_CHANGELOG_HEADING.findall(changelog)),
    )


def check(versions: ReleaseVersions, tag: str | None = None) -> list[str]:
    """Return human-readable inconsistencies (empty when releasable)."""
    expected = tag.removeprefix("v") if tag else versions.pyproject
    errors = [
        f"{label} is {value!r}, expected {expected!r}"
        for label, value in (
            ("pyproject.toml version", versions.pyproject),
            ("Chart.yaml version", versions.chart),
            ("Chart.yaml appVersion", versions.app),
        )
        if value != expected
    ]
    if expected not in versions.changelog:
        errors.append(f"CHANGELOG.md has no '## [{expected}]' section")
    return errors


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; exit status 1 on any inconsistency."""
    parser = argparse.ArgumentParser(
        description="Check tag, pyproject, Helm chart and CHANGELOG versions agree."
    )
    parser.add_argument("--tag", help="git tag being released, e.g. v0.2.0")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    errors = check(read_versions(args.root), args.tag)
    for error in errors:
        print(f"release-version: {error}", file=sys.stderr)
    if not errors:
        print("release-version: consistent")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
