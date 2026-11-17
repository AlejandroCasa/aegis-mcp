# CTO Governance Override for Everything Claude Code (`affaan-m/ECC`)

> **Precedence**: `CRITICAL (Priority 00)` — This rule binds all `affaan-m/ECC` subagents (`planner`, `architect`, `tdd-guide`, `code-reviewer`, `security-reviewer`, `build-error-resolver`) and skills to the **Aegis-MCP CTO Zero-Trust Standard**. Do not disable any ECC agent or skill; instead, map their execution primitives to the exact toolchain below.

## 1. ECC Toolchain Binding Matrix (Zero Collision)

Whenever an ECC skill, command (`/tdd`, `/plan`, `/code-review`, `/verify`), or subagent instructs you to run tests, linters, type checks, or package operations, **always translate the generic command to this exact `uv` command**:

| ECC Generic Action | Mandatory Aegis-MCP Command (`uv`) | Gate Requirement |
| :--- | :--- | :--- |
| Install / sync deps | `uv sync --frozen` | Never use `pip`, `pip3`, `poetry`, or unmanaged `venv` |
| Run TDD test cycle | `uv run pytest -v --cov=app --cov-report=term-missing --cov-fail-under=85` | `0` warnings (`filterwarnings = ["error"]`), `>= 85%` coverage |
| Format & sort imports | `uv run black --check . && uv run isort --check-only --profile black .` | 88-char line length, Black profile |
| Fast Linter | `uv run ruff check .` | `0` errors |
| Static Type Check | `uv run mypy --strict app tests fuzz scripts` | 100% type annotations required |
| Complexity Gate | `uv run radon cc app/ -a -nb && uv run xenon --max-absolute B --max-modules A --max-average A app/` | Max function rank `B`, module/average `A` |
| Security SAST | `uv run bandit -c pyproject.toml -r app/ && uv run pip-audit` | `0` vulnerabilities |

## 2. Live Aegis-MCP Dogfooding Enforcement

Every `Bash`, `Edit`, `Write`, and `MultiEdit` invocation in this repository is intercepted in real time by `scripts/claude_aegis_guard.py` and evaluated by `app.firewall.MCPFirewall`:
1. **DLP Redaction**: Any secret, Bearer token, API key, email, or IBAN in tool arguments is scrubbed via `app.redactor.redact_payload`.
2. **Zero-Trust Threat Rules**: Prompt injection, path traversal (`../`, `.env`, `/etc/passwd`), destructive SQL, and command injection (`rm -rf`, `; sh`) are blocked with exit code `2`.
3. **Cryptographic Merkle Audit**: Every tool call is hashed into `.aegis_claude_audit.db` using `SHA-256(prev_hash | timestamp | agent_id | server_name | tool_name | decision | risk_score)`.
4. **Immutable Guardrails**: Attempting to edit `.claude/**`, `.pre-commit-config.yaml`, `AGENTS.md`, `CLAUDE.md`, `app/claude_guard.py`, or `scripts/claude_aegis_guard.py` is blocked by the `PreToolUse` firewall.
5. **Stop Gate Lock**: The `Stop` hook executes all 7 Quality Gates plus `MCPFirewall.verify_chain()`. You cannot finish a task until every gate exits with `0`.
