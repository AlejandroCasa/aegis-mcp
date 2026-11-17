# CLAUDE.md — Autonomous Execution Manifest (Claude Code + `affaan-m/ECC`)

This repository operates under a **Dual-Harness Agentic Architecture**:
- **Governor & Principal Architect**: **Google Antigravity** (manages Obsidian ADRs, architecture specifications, `BACKLOG.md`, and hardened guardrails).
- **Tactical Autonomous Engine**: **Claude Code + Everything Claude Code (`affaan-m/ECC`)** (executes TDD loops, subagent delegation, and feature implementation inside deterministic Aegis-MCP guardrails).

---

## 1. Using Full `affaan-m/ECC` Power Safely
All `affaan-m/ECC` subagents (`planner`, `architect`, `tdd-guide`, `security-reviewer`, `code-reviewer`, `build-error-resolver`) and on-demand skills are fully enabled.
- Always follow `.claude/rules/00-cto-aegis-override.md` when executing shell commands.
- Use `uv run ...` exclusively for Python execution.
- Maintain **>= 85% test coverage** (surpassing ECC's default 80% threshold) and **Rank A/B cyclomatic complexity** enforced via `xenon`.

## 2. Mandatory Quality Gates (Enforced Automatically by the `Stop` Hook)
Before Claude Code can complete any turn (`Stop` lifecycle hook), `scripts/claude_aegis_guard.py stop-gate` automatically verifies:
1. **Aegis-MCP Cryptographic Ledger**: `MCPFirewall.verify_chain()` confirms `0` tampered records in `.aegis_claude_audit.db`.
2. **Formatting & Linting**: `uv run ruff check .`, `uv run black --check .`, `uv run isort --check-only --profile black .`
3. **Strict Static Typing**: `uv run mypy --strict app tests fuzz scripts`
4. **SAST Security**: `uv run bandit -c pyproject.toml -r app/`
5. **Cyclomatic Complexity**: `uv run xenon --max-absolute B --max-modules A --max-average A app/`
6. **Test Suite & Coverage**: `uv run pytest -q --cov=app --cov-fail-under=85`

## 3. Git & Branching Discipline
- Never commit or push directly to `main` or `master`.
- Always work on a dedicated branch (`feat/<scope>-<slug>`, `fix/<scope>-<slug>`, `refactor/<scope>-<slug>`).
- Use Google Conventional Commits (`feat(rbac): add declarative policy matrix`).
- Never use `--no-verify` or modify `.claude/**` guardrail files.
