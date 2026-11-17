# Aegis-MCP — Agentic Engineering Governance (`AGENTS.md`)

This repository follows an **Agentic Engineering** workflow governed by strict architectural principles, automated quality gates, and zero-trust container hardening.

## 1. Repository Architecture & Scope
- **Service**: Zero-Trust Firewall, DLP Redactor & Tamper-Evident Cryptographic Audit Proxy for Model Context Protocol (MCP) Servers (`FastAPI` + `Pydantic v2`).
- **Package Mode**: `uv` in application mode (`[tool.uv] package = false`, Python 3.12+).
- **Source Layout**:
  - `app/config.py`: Runtime configuration validated via `pydantic-settings` (`AEGIS_` env prefix).
  - `app/schemas.py`: Pydantic v2 contracts for MCP `tools/call` inspection (`MCPToolCallRequest`, `MCPInspectionResponse`, `AuditEntry`, `ChainVerificationResponse`).
  - `app/redactor.py`: Deterministic PII & Secret DLP Redactor (`redact_payload`, email, IBAN, credit card, API key/Bearer token scrubbing).
  - `app/firewall.py`: Zero-Trust MCP Firewall & Hash-Chained SQLite Audit Ledger (`MCPFirewall`, prompt injection, SQLi/destructive DDL, path traversal, shell command injection, and SHA-256 Merkle chain verification).
  - `app/metrics.py`: Native zero-dependency Prometheus 0.0.4 text exposition registry (`aegis_mcp_requests_total`, `aegis_mcp_blocked_total`, `aegis_mcp_redactions_total`).
  - `app/main.py`: FastAPI HTTP endpoints (`GET /healthz`, `GET /metrics`, `POST /api/v1/mcp/inspect`, `GET /api/v1/audit`, `GET /api/v1/audit/verify`).
  - `tests/`: Unit, integration, and mutation hardening test suite (`pytest` + `httpx`).
  - `fuzz/fuzz_firewall.py`: Deterministic and Atheris-compatible fuzzing harness.
  - `scripts/simulate_mcp_traffic.py`: Local traffic simulator for benign, PII-leaking, and malicious MCP tool invocations.
  - `BACKLOG.md`: Version-controlled engineering roadmap prioritized by `P0` / `P1` / `P2`.

## 2. Mandatory Quality Gates & CI/CD Standard (Zero-Tolerance Checklist)
No code change may be committed or merged unless **100% of the following gates pass with exit code `0`**:

1. **Dependency Sync**:
   ```bash
   uv sync --frozen
   ```
2. **Formatting, Import Sorting & Linting (`black` + `isort` + `ruff`)**:
   ```bash
   uv run black --check . && uv run isort --check-only --profile black . && uv run ruff check .
   ```
3. **Strict Static Type Checking (`mypy --strict`)**:
   ```bash
   uv run mypy --strict app tests fuzz scripts
   ```
4. **Code Complexity & Maintainability (`radon` + `xenon`)**:
   ```bash
   uv run radon cc app/ -a -nb && uv run xenon --max-absolute B --max-modules A --max-average A app/
   ```
5. **Security SAST & Dependency Audit (`bandit` + `pip-audit`)**:
   ```bash
   uv run bandit -c pyproject.toml -r app/ && uv run pip-audit
   ```
6. **Automated Test Suite (`0` warnings, `>= 85%` coverage)**:
   ```bash
   uv run pytest -v --cov=app --cov-report=term-missing --cov-fail-under=85
   ```
7. **Hardened Container Build**:
   ```bash
   docker build -t aegis-mcp:latest .
   ```
