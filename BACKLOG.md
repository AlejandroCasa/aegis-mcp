# Technical Backlog & Architecture Roadmap — Aegis-MCP

This file tracks prioritized engineering improvements, technical debt, and completed milestones for **Aegis-MCP**.

## 🎯 Prioritized Backlog (Sprint 2026-W48)

### P0 — Core Governance & Policy Engine

### P1 — Threat Intelligence & Observability
- [ ] **[rate-anomaly]** Behavioral Tool-Call Rate Limiting & Exfiltration Velocity Detector: Detect anomalous bursts of `resources/read` or database queries from a single agent session to stop automated data harvesting (Impact: 4/5 | Effort: S)
- [ ] **[ui-cockpit]** Editorial Security & Audit Chain Inspector UI (`GET /`): Minimalist *Taste* web cockpit displaying live MCP tool decisions, DLP redaction counters, and interactive SHA-256 hash-chain verification (Impact: 5/5 | Effort: M)

### P2 — Ecosystem & Alerting
- [ ] **[webhooks]** Real-Time Security Incident Webhook Dispatcher: Push high-severity `BLOCKED` events (`risk_score >= 80`) to SOC/Slack webhooks with anti-spam cooldown (Impact: 4/5 | Effort: S)

---

## ✅ Completed Milestones
- [x] **[core/init]** Project initialization (`v0.1.0`) with Zero-Trust MCP Firewall (`app/firewall.py`), deterministic DLP Redactor (`app/redactor.py`), SHA-256 Hash-Chained SQLite Audit Ledger, Prometheus `/metrics`, Atheris fuzzing harness (`fuzz/fuzz_firewall.py`), traffic simulator (`scripts/simulate_mcp_traffic.py`), hardened multi-stage `Dockerfile` (`UID 10001`), K8s manifests (`k8s/`), OPA/Rego policies (`policy/`), and 4-Phase CI/CD pipeline (`[[ADR-0021-aegis-mcp-zero-trust-firewall-and-hash-chain-audit]]`) — Branch: `main` (`2026-11-17`)
- [x] **[rbac-policy]** Declarative Per-Agent & Per-Server RBAC Policy Matrix (`app/policy.py`): deny-overrides `fnmatch` glob matrix scoped by `agent_id`, `server_name`, and `environment` (`dev`/`staging`/`prod`); fail-closed `yaml.safe_load` loader via `AEGIS_POLICY_PATH`; `GET`/`POST /api/v1/policies` (POST requires a configured `AEGIS_API_KEY`); unauthorized calls `BLOCKED` with `rbac_policy_denied` (risk `100`) in `MCPFirewall.inspect` — Branch: `feat/rbac-policy-matrix` (`2026-11-17`)
- [x] **[jsonrpc-proxy]** Native JSON-RPC 2.0 MCP Wire-Protocol Proxy (`POST /api/v1/mcp/jsonrpc`, `app/jsonrpc.py`): `tools/call`, `resources/read`, `prompts/get` envelopes enforced through `MCPFirewall` threat rules, RBAC `PolicyEngine`, and the SHA-256 ledger; standard `-32700`/`-32600`/`-32601`/`-32602` errors plus `-32003` (policy/security blocked) and `-32004` (upstream error) preserving the request `id`; forwarding only to server-configured `AEGIS_MCP_UPSTREAMS` (http/https, no redirects, 5 MiB cap) with bidirectional DLP redaction of params and `result`/`error` — Branch: `feat/jsonrpc-mcp-proxy` (`2026-11-17`)
