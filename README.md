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
  - Zero-dependency Prometheus 0.0.4 text exposition tracking `aegis_mcp_requests_total`, `aegis_mcp_blocked_total`, `aegis_mcp_redactions_total`, `aegis_mcp_ledger_errors_total`, and the `aegis_mcp_inspection_duration_seconds` SLO histogram (1 ms–500 ms buckets around the 10 ms p99 objective). Label values are sanitized and capped at 64 per label (overflow → `other`); no `agent_id`/`session_id` labels.
  - OpenTelemetry traces ([`app/telemetry.py`](app/telemetry.py)) over OTLP/HTTP with GenAI/MCP semantic conventions (`gen_ai.system`, `mcp.server.name`, `mcp.tool.name`, `mcp.method.name`, `aegis.decision`, `aegis.risk_score`, pseudonymized `aegis.session.id`) for the HTTP server span, the JSON-RPC proxy, `/mcp` Streamable HTTP and `MCPFirewall.inspect`; W3C `traceparent` is honored.
  - DLP-scrubbed structured JSON logs with `trace_id`, `span_id`, `request_id` (`X-Request-Id`), `decision` and `risk_score`; Grafana dashboard [`deploy/grafana/aegis-mcp.json`](deploy/grafana/aegis-mcp.json) and `PrometheusRule` alerts [`deploy/prometheus/aegis-mcp-rules.yaml`](deploy/prometheus/aegis-mcp-rules.yaml) (p99 > 10 ms, toxic-flow / tool-drift spikes, chain/checkpoint errors).
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
| `AEGIS_RATE_LIMIT_ENABLED` | `true` | Behavioral rate limiting (`app/rate_limit.py`). Both detectors block in `enforce` mode and set `would_block` in `monitor` mode; anomalies are counted in `aegis_mcp_rate_anomalies_total{kind,mode}` and summarized at `GET /api/v1/rate-limits/stats`. |
| `AEGIS_RATE_LIMIT_CAPACITY` / `AEGIS_RATE_LIMIT_REFILL_PER_SEC` | `60` / `5.0` | Token bucket per `(agent_id, server_name, tool_name)`; an empty bucket yields `rate_limit_exceeded` (risk 75). |
| `AEGIS_VELOCITY_WINDOW_SECONDS` / `AEGIS_VELOCITY_MAX_READS` | `60` / `30` | Sliding window of sensitive reads (`resources/read`, `query*`, `read_file*`, `*sql*`, `db_*`, ...) per `(session_id, agent_id)`; exceeding it yields `exfiltration_velocity_anomaly` (risk 90, security webhook even in `monitor` mode). Sessionless calls share one per-agent window. Policy YAML `rate_limits` rules (first match wins) override `rate_limit`, `velocity_limit` and `sensitive_read` per server/tool/environment. |
| `AEGIS_RATE_LIMIT_MAX_KEYS` | `10000` | LRU cap of tracked buckets and velocity windows (bounded memory). |
| `AEGIS_LEDGER_WAL` | `true` | SQLite write-ahead logging for the audit ledger (readers never block the chain writer). |
| `AEGIS_OTEL_ENABLED` | unset | Export OpenTelemetry traces over OTLP/HTTP. Unset follows `AEGIS_OTEL_ENDPOINT` (off in dev/test, on once an endpoint is configured). |
| `AEGIS_OTEL_ENDPOINT` | unset | OTLP/HTTP collector base URL (e.g. `http://otel-collector:4318`; `/v1/traces` is appended). Without it, the standard `OTEL_EXPORTER_OTLP_*` variables apply. |
| `AEGIS_OTEL_SERVICE_NAME` | `aegis-mcp` | `service.name` resource attribute of exported spans. |
| `AEGIS_LOG_FORMAT` | `json` | `json` (one DLP-scrubbed object per line with `trace_id`/`span_id`/`request_id`) or `text`. |

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

### Firewalling local `stdio` MCP servers (Claude Desktop / Cursor / Windsurf)

`app.stdio_wrap` sits between a local MCP host and any `stdio` MCP server subprocess:

```bash
uv run python -m app.stdio_wrap [--server-name NAME] [--agent-id AGENT] \
  [--environment dev|staging|prod] [--policy PATH] [--db-path PATH] -- <command> [args...]
```

Replace the server's `command`/`args` in your host's `mcpServers` config with the wrapper (use absolute paths; `--directory` points `uv` at this checkout):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "uv",
      "args": [
        "run", "--directory", "/opt/aegis-mcp", "python", "-m", "app.stdio_wrap",
        "--server-name", "filesystem-mcp", "--agent-id", "cursor",
        "--policy", "/opt/aegis-mcp/policy/local.yaml",
        "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/srv/workspace"
      ]
    },
    "postgres": {
      "command": "uv",
      "args": [
        "run", "--directory", "/opt/aegis-mcp", "python", "-m", "app.stdio_wrap",
        "--server-name", "postgres-mcp", "--environment", "prod",
        "--policy", "/opt/aegis-mcp/policy/local.yaml",
        "--", "npx", "-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/app"
      ]
    }
  }
}
```

- **Framing**: UTF-8 newline-delimited JSON-RPC 2.0 on `stdin`/`stdout` (lines capped at `1 MiB` from the host and `5 MiB` from the server); the server's `stderr` and wrapper diagnostics go to `stderr` only.
- **Inbound**: `tools/call`, `resources/read` and `prompts/get` run the full `MCPFirewall.inspect` pipeline (threat rules, RBAC, `tool_constraints`, toolguard drift/poisoning, toxic-flow taint, DLP, ledger). Blocked calls are **never forwarded** and are answered with `-32003` (`violations`, `audit_hash`). Discovery requests, `notifications/*` and client responses are DLP-redacted; other methods get `-32601`, client batches `-32600`.
- **Outbound**: replies are matched to their pending request and toolguard-screened (`initialize` pinning, `*/list` TOFU pinning, drift hiding, poisoning hiding, RBAC least-privilege `tools/list`), DLP-redacted (a redaction promotes the session to `private_data` taint), and reserved codes `-32003`/`-32004` are rewritten to `-32000`. Server-initiated messages are DLP-redacted; unsolicited responses are dropped.
- **Session**: one `stdio-<32 hex>` session id per wrapper lifetime binds taint tracking and ledger v2 entries across every call.
- **Secret hygiene**: every `AEGIS_*` variable (e.g. `AEGIS_API_KEY`, `AEGIS_DLP_HMAC_KEY`) is stripped from the server's environment; the server is spawned with `shell=False`.

---

## 🧪 Quality Gates

```bash
uv run black --check . && uv run isort --check-only --profile black . && uv run ruff check .
uv run mypy --strict app tests fuzz scripts
uv run pytest -v --cov=app --cov-report=term-missing --cov-fail-under=85
uv run python -m fuzz.fuzz_firewall --self-test
uv run python -m scripts.evaluate_detection --min-recall 0.95 --max-fpr 0.02 --min-cases 300
uv run python -m scripts.benchmark_latency --iterations 300 --max-p99-ms 10.0 --fail-on-regression
```

---

## Latency Budget & Load Testing

The gateway has a **10 ms p99** latency budget per firewalled call.

### Reproducible benchmark (`make bench`)

`scripts/benchmark_latency.py` runs two suites in-process against a temporary SQLite (WAL) audit ledger:

| Suite | Scenarios |
| :--- | :--- |
| `inspect` | `MCPFirewall.inspect` on `benign`, `dlp_heavy` (synthetic secrets, email, IBAN), `obfuscated` (Base64, full-width and zero-width Unicode injection) and `blocked` (command injection) calls |
| `asgi` | FastAPI end to end: `POST /api/v1/mcp/inspect` and `POST /api/v1/mcp/jsonrpc` (in-memory mock upstream) |

For each scenario it reports p50 / p95 / p99 / max latency in ms and sequential throughput in rps. Output is a JSON report followed by a Markdown table; `--json-out FILE` also saves the JSON. Every run starts with untimed warm-up calls (`--warmup`, default 50) and then times `--iterations` calls (default 500).

```bash
make bench                                      # or: uv run python -m scripts.benchmark_latency
make bench-gate                                 # CI gate: --iterations 300 --fail-on-regression
uv run python -m scripts.benchmark_latency --skip-asgi --json-out bench.json
```

**CI regression gate.** With `--fail-on-regression`, the script exits `1` when the **worst `inspect` scenario p99** is above `--max-p99-ms` (default `10.0`). CI runs this as the `latency-gate` step. Only the pure `inspect` overhead is gated, which catches algorithmic regressions in regex, canonicalization or DLP code. The ASGI numbers are reported but not gated, so CI does not fail on socket and thread-pool scheduling noise on shared runners.

### Load test (k6, `make load`)

`benchmarks/load_k6.js` sends an open-model load (`constant-arrival-rate`) of **500 rps total**, split evenly between `/api/v1/mcp/inspect` and `/api/v1/mcp/jsonrpc`. Its thresholds are `http_req_duration p(99)<10` overall and per endpoint, plus `http_req_failed < 1%`. `benchmarks/mock_upstream.py` is a stdlib-only JSON-RPC echo server that stands in for a real MCP tool server.

```bash
uv run python benchmarks/mock_upstream.py --port 9100 &
AEGIS_MCP_UPSTREAMS='{"bench-mcp":"http://127.0.0.1:9100/mcp"}' \
  uv run uvicorn app.main:app --port 8000 &   # single worker: one SQLite chain writer
make load                     # k6 run benchmarks/load_k6.js (RATE=500 DURATION=60s)
make load RATE=1000 DURATION=2m BASE_URL=http://gateway:8000
```

Pass `API_KEY` (`k6 run -e API_KEY=...`) when `AEGIS_API_KEY` is set. k6 exits non-zero when any threshold is breached.

---

## Detection Benchmark

`benchmarks/corpus/*.jsonl` holds a reproducible, labeled corpus of **348 cases** (154 benign, 194 malicious). It is generated deterministically by `scripts/build_benchmark_corpus.py`. Attack strings and encodings are assembled at runtime, and secret-shaped DLP values are stored as `{{SYNTH_*}}` macros that the evaluator expands in memory, so no real credential is committed. `scripts/evaluate_detection.py` runs every case against Aegis-MCP in-process, using a temporary audit ledger and per-case policy and taint isolation. It enforces the CI gate `recall >= 0.95`, `FPR <= 0.02`, `cases >= 300`, plus an intact audit hash chain. The exit code is `0` on pass, `1` on a failed KPI, and `2` on an invalid corpus.

```bash
uv run python -m scripts.build_benchmark_corpus      # regenerate the corpus
uv run python -m scripts.evaluate_detection --json   # machine-readable report
```

### Corpus schema

Every record has `id`, `category`, `expected_flagged`, `kind`, and three taxonomy tags: `owasp_llm_2025`, `owasp_agentic`, and `mitre_atlas` (`N/A` for benign). Each `kind` selects an engine and its own flagging rule:

| `kind` | Engine | Flagged when |
| :--- | :--- | :--- |
| `inspect` | `MCPFirewall.inspect` (threat rules, RBAC/ABAC `policy`, DLP) | enforce mode would block, or DLP redacted a category |
| `tool_definition` | `app.poisoning.scan_definition` | a finding scores at least the block threshold (70) |
| `session_flow` | `MCPFirewall.inspect` over ordered steps sharing one session | any step would be blocked (e.g. toxic-flow taint) |

Benign cases are realistic developer traffic. They include `SELECT` queries, git operations, workspace file reads, Markdown with code blocks, JSON and Kubernetes payloads, UUIDs, SHA-256 digests, timestamps, Luhn-invalid order IDs, and mod-97-invalid IBAN look-alikes. Multi-step sessions in the benign set are missing one leg of the lethal trifecta.

### Measured results

The figures below are the evaluator's output for the committed corpus. Latency is per case, measured in-process on a developer workstation, and varies by host.

| Metric | Value |
| :--- | :--- |
| Cases | 348 |
| TP / FP / TN / FN | 185 / 0 / 154 / 9 |
| Precision | 1.0000 |
| Recall | 0.9536 |
| F1 | 0.9763 |
| False positive rate | 0.0000 |
| Latency p50 / p99 | 0.63 ms / 4.07 ms |

| Category | Cases | TP | FN | Recall |
| :--- | ---: | ---: | ---: | ---: |
| `prompt_injection` | 25 | 24 | 1 | 0.960 |
| `command_injection` | 22 | 20 | 2 | 0.909 |
| `destructive_sql` | 17 | 15 | 2 | 0.882 |
| `path_traversal` | 20 | 20 | 0 | 1.000 |
| `evasion_obfuscated` | 25 | 24 | 1 | 0.960 |
| `tool_poisoning` | 22 | 20 | 2 | 0.909 |
| `abac_constraint` | 20 | 20 | 0 | 1.000 |
| `toxic_flow` | 17 | 16 | 1 | 0.941 |
| `dlp_redaction` | 26 | 26 | 0 | 1.000 |
| `benign` (TN / FP) | 154 | 154 TN | 0 FP | FPR 0.000 |

### Taxonomy coverage (malicious cases)

| Taxonomy | Tag | Cases | Recall |
| :--- | :--- | ---: | ---: |
| OWASP LLM Top 10 2025 | LLM01:2025 Prompt Injection | 50 | 0.960 |
| OWASP LLM Top 10 2025 | LLM02:2025 Sensitive Information Disclosure | 63 | 0.984 |
| OWASP LLM Top 10 2025 | LLM03:2025 Supply Chain | 22 | 0.909 |
| OWASP LLM Top 10 2025 | LLM05:2025 Improper Output Handling | 22 | 0.909 |
| OWASP LLM Top 10 2025 | LLM06:2025 Excessive Agency | 37 | 0.946 |
| OWASP Agentic AI Threats | ASI01 Goal Hijack | 50 | 0.960 |
| OWASP Agentic AI Threats | ASI02 Tool Misuse | 59 | 0.932 |
| OWASP Agentic AI Threats | ASI03 Identity & Privilege Abuse | 46 | 1.000 |
| OWASP Agentic AI Threats | ASI04 Supply Chain / Tool Poisoning | 22 | 0.909 |
| OWASP Agentic AI Threats | ASI07 Memory & Context Poisoning | 17 | 0.941 |
| MITRE ATLAS | AML.T0010 ML Supply Chain Compromise | 22 | 0.909 |
| MITRE ATLAS | AML.T0048 External Harms / Exfiltration | 17 | 0.941 |
| MITRE ATLAS | AML.T0051 LLM Prompt Injection | 25 | 0.960 |
| MITRE ATLAS | AML.T0053 LLM Plugin Compromise | 59 | 0.932 |
| MITRE ATLAS | AML.T0054 LLM Jailbreak | 25 | 0.960 |
| MITRE ATLAS | AML.T0057 LLM Data Leakage | 46 | 1.000 |

### Known detection gaps

The corpus keeps 9 documented false negatives, each labeled `known gap` in its `description`. The gate asserts that every miss is one of them:

- Prompt injection whose words are separated by newlines or tabs. JSON serialization escapes the control whitespace, so the phrase never reaches the regex in contiguous form.
- Command substitution with backticks, and `&&` chaining to a downloader.
- SQL keywords separated by inline comments, and an unbounded `DELETE` without a tautology. Use `sql_mode: read_only` to cover these.
- `0x`-prefixed hex payloads, which are not decoded.
- An http(s) URL embedded in prose on a non-sink tool. Egress detection only matches values that start with a scheme.
- Medium-severity poisoning signals on their own, such as a context-siphoning parameter name or a bare cross-server name collision. These score 60, below the block threshold.

---

## 🗺️ Architecture Roadmap

See [BACKLOG.md](BACKLOG.md) for the prioritized engineering backlog.
