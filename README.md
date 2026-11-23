# Aegis-MCP 🛡️🔐

A lightweight, cloud-native **Zero-Trust Firewall, DLP Redactor & Cryptographic Audit Proxy** for **Model Context Protocol (MCP)** servers, built with **Python 3.12**, **FastAPI**, **Pydantic v2**, **SQLite**, and **uv**.

Aegis-MCP sits between AI Agents (Claude Desktop, Cursor, autonomous orchestrators) and downstream MCP servers, inspecting every `tools/call` invocation in real time to block **Indirect Prompt Injection**, **Destructive SQL/Shell Execution**, and **Path Traversal**, while automatically scrubbing **PII & Secrets** and recording every decision in a **tamper-evident SHA-256 hash-chained SQLite ledger**.

---

## ✨ Key Capabilities

- **Zero-Trust MCP Tool-Call Inspection (`POST /api/v1/mcp/inspect`)**:
  - Evaluates MCP tool invocations (`agent_id`, `server_name`, `tool_name`, `arguments`, `environment`) against deterministic security policies in `< 2 ms`.
  - **Threat Detection Engine ([`app/firewall.py`](app/firewall.py))**:
    - `prompt_injection`: Blocks instruction override attempts (`ignore previous instructions`, `system prompt:`, `<|im_start|>`).
    - `path_traversal`: Blocks unauthorized filesystem escapes (`../`, `/etc/passwd`, `/etc/shadow`, `.ssh/id_rsa`, `.env`).
    - `destructive_sql`: Blocks destructive SQL/DDL payloads (`DROP TABLE`, `TRUNCATE TABLE`, `DELETE FROM ... WHERE 1=1`).
    - `command_injection`: Blocks shell metacharacter chaining and destructive system commands (`rm -rf`, `; curl`, `| bash`, `` ` ``, `$()`).
- **Real-Time DLP & Secret Redaction ([`app/redactor.py`](app/redactor.py))**:
  - Automatically scrubs sensitive data inside nested tool arguments before forwarding to MCP servers or external LLMs:
    - **Secrets & Tokens**: OpenAI/Anthropic/GitHub keys (`sk-...`, `ghp_...`, `AKIA...`) and `Bearer` tokens $\rightarrow$ `[REDACTED_SECRET]`.
    - **Emails**: Standard email addresses $\rightarrow$ `[REDACTED_EMAIL]`.
    - **IBANs**: European/International bank accounts $\rightarrow$ `[REDACTED_IBAN]`.
- **Tamper-Evident SHA-256 Audit Ledger (`GET /api/v1/audit` & `GET /api/v1/audit/verify`)**:
  - Every inspection decision (`ALLOWED`, `SANITIZED`, `BLOCKED`) is persisted in an embedded SQLite ledger (`sqlite3` stdlib, default `/tmp/aegis_mcp.db` for `readOnlyRootFilesystem: true` compatibility).
  - Each record (hash v2, [`app/ledger.py`](app/ledger.py)) computes `entry_hash` as the SHA-256 of the RFC 8785 (JCS) canonical JSON of the **full** entry (`prev_hash`, timestamp, identity/scope, decision, risk score, violations, DLP categories, sanitized-arguments digest, policy version/mode, `would_block`, MCP session id), forming an immutable chain verifiable via `GET /api/v1/audit/verify`. Legacy v1 links (`SHA256(prev_hash | timestamp | agent_id | server_name | tool_name | decision | risk_score)`) are migrated additively and still verified; a v1 link after a v2 link is rejected as a downgrade.
- **Anti-Evasion Canonicalization ([`app/normalize.py`](app/normalize.py))**: threat rules and DLP also run on NFKC-normalized, zero-width/bidi-stripped (CVE-2021-42574), tag-revealed, homoglyph-folded, percent/HTML-decoded and bounded recursive Base64/hex-decoded views; matches only visible after decoding add `obfuscated_payload`.
- **Prometheus Observability (`GET /metrics`) & Perimeter Auth (`X-API-Key`)**:
  - Zero-dependency Prometheus 0.0.4 text exposition tracking `aegis_mcp_requests_total`, `aegis_mcp_blocked_total`, and `aegis_mcp_redactions_total`.
- **4-Phase Zero-Tolerance CI/CD & Container Hardening**:
  - Multi-stage [`Dockerfile`](Dockerfile) running under `UID 10001` (`appuser`) with Kubernetes manifests ([`k8s/`](k8s/)) and OPA/Rego policies ([`policy/`](policy/)).

---

## ⚙️ Gateway Configuration (`AEGIS_*`)

| Variable | Default | Effect |
| :--- | :--- | :--- |
| `AEGIS_ENVIRONMENT` | `dev` | Deployment environment of the gateway. In `prod`, a missing or invalid `AEGIS_POLICY_PATH` **fails closed** (deny-all, violation `policy_fail_closed`) instead of allow-all. |
| `AEGIS_POLICY_MODE` | `enforce` | `enforce` blocks; `monitor` (shadow mode) evaluates and audits `would_block=true` without blocking, for progressive rollouts (`aegis_mcp_shadow_would_block_total`). |
| `AEGIS_POLICY_PATH` | unset | YAML RBAC/ABAC policy. Every decision records `policy_version` = SHA-256 of the RFC 8785 (JCS) canonical document (`GET /api/v1/policies/status`). |
| `AEGIS_TOOLGUARD_REQUIRE_APPROVAL` | `false` | Only operator-approved (pinned) tools/prompts may be listed or called. Drifted definitions are always blocked. |
| `AEGIS_TOOLGUARD_SCAN_POISONING` | `true` | Scan discovered `instructions` and tool/prompt/resource definitions for poisoning and cross-server shadowing (`app/poisoning.py`); findings scoring `>= AEGIS_BLOCK_THRESHOLD_SCORE` hide the definition, strip poisoned `instructions`, and block calls with `tool_poisoning`. |
| `AEGIS_MCP_ALLOWED_ORIGINS` | `[]` | JSON list of browser `Origin`s allowed on `/mcp` (DNS-rebinding defense); requests without `Origin` are allowed, any other origin gets `403`. |
| `AEGIS_MCP_SESSION_TTL_SECONDS` / `AEGIS_MCP_MAX_SESSIONS` | `3600` / `10000` | Sliding idle lifetime and capacity (`503` when full) of `/mcp` sessions. |
| `AEGIS_MCP_STREAM_TIMEOUT_SECONDS` | `300` | Wall-clock cap of one relayed SSE stream (and the upstream read timeout for streams). |
| `AEGIS_LEDGER_WAL` | `true` | SQLite write-ahead logging for the audit ledger (readers never block the chain writer). |

### Native MCP Streamable HTTP (`POST`/`GET`/`DELETE /mcp`)

Point any Streamable HTTP MCP client at `/mcp` with `X-Aegis-MCP-Server: <server>` (and the usual auth). `initialize` mints a gateway `Mcp-Session-Id` bound to the caller, server and environment (the upstream's session id is never exposed); later requests without it get `400`, unknown/foreign sessions `404`, a mismatched `MCP-Protocol-Version` `400`. Requests run the full firewall pipeline with ledger entries bound to the session; SSE replies are relayed event by event with per-event DLP (the final response is toolguard-screened and bound to the caller's id, a missing one becomes `-32004`); `notifications/*` and client responses are redacted and acknowledged with `202`; `GET` relays the server-initiated stream; `DELETE` ends the session. JSON-RPC batches are accepted for sessions that negotiated `2025-03-26`.

### Poisoning scanner CLI

```bash
uv run python -m scripts.scan_mcp_server --url https://host/mcp --header "Authorization: Bearer <token>" --fail-on high
uv run python -m scripts.scan_mcp_server --manifest servers.json --json   # {"servers": {...}} enables shadowing checks
```

Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` connection/protocol error.

### Argument-level ABAC (`tool_constraints`)

```yaml
default_action: deny
rules:
  - server_name: "postgres-mcp"
    allow_tools: ["query"]
tool_constraints:
  - server_name: "filesystem-mcp"
    path_allow: ["/srv/workspace"]   # realpath-canonicalized: symlink / dot-dot escapes blocked
  - server_name: "postgres-mcp"
    tool_name: "query"
    sql_mode: read_only              # one SELECT/WITH, no write/DDL tokens outside literals
  - tool_name: "fetch"
    egress_allow: ["api.github.com", "*.example.org"]
    max_bytes: 65536
    max_items: 100
```

Violations (`argument_path_not_allowed`, `argument_sql_not_read_only`, `argument_egress_not_allowed`, `argument_max_bytes_exceeded`, `argument_max_items_exceeded`) block with risk `100`. Constrained keys default to `path`/`file`/`file_path`/`filename`/`directory`, `query`/`sql`/`statement` and `url`/`uri`/`endpoint`/`href` (override via `path_args`, `sql_args`, `url_args`).

---

## 🚀 Quick Start & Local Simulation

```bash
# Option A: Run locally with uv
uv run uvicorn app.main:app --reload --port 8000

# Option B: Run MCP security & DLP traffic simulation
uv run python -m scripts.simulate_mcp_traffic --dry-run

# Option C: Build and run hardened production container
docker build -t aegis-mcp:latest .
docker run --rm -p 8000:8000 aegis-mcp:latest
```

---

## 🧪 Quality Gates

```bash
uv run black --check . && uv run isort --check-only --profile black . && uv run ruff check .
uv run mypy --strict app tests fuzz scripts
uv run pytest -v --cov=app --cov-report=term-missing --cov-fail-under=85
uv run python -m fuzz.fuzz_firewall --self-test
```

---

## 🗺️ Architecture Roadmap

See [BACKLOG.md](BACKLOG.md) for the prioritized engineering backlog.
