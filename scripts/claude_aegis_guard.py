"""CLI hook runner connecting Claude Code + ECC lifecycle events to Aegis-MCP."""

import json
import select
import subprocess
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from app.claude_guard import (  # noqa: E402
    evaluate_post_tool_event,
    evaluate_pre_tool_event,
    verify_audit_chain_integrity,
)

QUALITY_GATE_COMMANDS: tuple[tuple[str, list[str]], ...] = (
    ("ruff", ["uv", "run", "--no-sync", "ruff", "check", "."]),
    ("black", ["uv", "run", "--no-sync", "black", "--check", "."]),
    (
        "isort",
        ["uv", "run", "--no-sync", "isort", "--check-only", "--profile", "black", "."],
    ),
    (
        "mypy",
        [
            "uv",
            "run",
            "--no-sync",
            "mypy",
            "--strict",
            "app",
            "tests",
            "fuzz",
            "scripts",
        ],
    ),
    (
        "bandit",
        ["uv", "run", "--no-sync", "bandit", "-c", "pyproject.toml", "-r", "app/"],
    ),
    (
        "xenon",
        [
            "uv",
            "run",
            "--no-sync",
            "xenon",
            "--max-absolute",
            "B",
            "--max-modules",
            "A",
            "--max-average",
            "A",
            "app/",
        ],
    ),
    (
        "pytest",
        [
            "uv",
            "run",
            "--no-sync",
            "pytest",
            "-q",
            "--cov=app",
            "--cov-fail-under=85",
        ],
    ),
)


def _has_stdin_data() -> bool:
    """Return True if stdin has readable data without blocking on open pipes."""
    try:
        fd = sys.stdin.fileno()
    except (AttributeError, OSError, ValueError):
        return True
    try:
        ready, _, _ = select.select([fd], [], [], 0.25)
        return bool(ready)
    except (OSError, ValueError):
        return False


def _read_stdin_json() -> dict[str, Any]:
    """Read and parse JSON hook payload from stdin without hanging on open pipes."""
    if sys.stdin.isatty() or not _has_stdin_data():
        return {}
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def run_stop_gate() -> tuple[int, str]:
    """Run Aegis-MCP chain verification and all CTO Zero-Tolerance Quality Gates."""
    chain_ok, chain_json = verify_audit_chain_integrity()
    if not chain_ok:
        return 2, f"Aegis-MCP SHA-256 Audit Chain Corrupted: {chain_json}"

    for gate_name, cmd in QUALITY_GATE_COMMANDS:
        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return 2, f"[CTO Stop Gate Blocked: {gate_name} timed out after 120s]"
        if proc.returncode != 0:
            details = (proc.stdout + "\n" + proc.stderr).strip()
            return (
                2,
                f"[CTO Stop Gate Blocked: {gate_name} failed]\n{details}",
            )

    report = {"status": "ALL_GATES_PASSED", "chain": json.loads(chain_json)}
    return 0, json.dumps(report)


def main(argv: list[str] | None = None) -> int:
    """Dispatch Claude Code hook event to the corresponding Aegis-MCP handler."""
    args = argv if argv is not None else sys.argv[1:]
    mode = args[0] if args else "pre-tool"

    if mode == "stop-gate":
        code, message = run_stop_gate()
    elif mode == "pre-tool":
        code, message = evaluate_pre_tool_event(_read_stdin_json())
    elif mode == "post-tool":
        code, message = evaluate_post_tool_event(_read_stdin_json())
    else:
        sys.stderr.write(f"Unknown mode: {mode}\n")
        return 2

    if code != 0:
        sys.stderr.write(f"{message}\n")
    else:
        sys.stdout.write(f"{message}\n")
    return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
