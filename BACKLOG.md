# Technical Backlog & Architecture Roadmap — Aegis-MCP

This file tracks prioritized engineering improvements, technical debt, and completed milestones for **Aegis-MCP**.

## 🎯 Prioritized Backlog (Sprint 2026-W48)

### P0 — Core Governance & Policy Engine
- [ ] **[rbac-policy]** Declarative Per-Agent & Per-Server RBAC Policy Matrix (`POST /api/v1/policies` & YAML loader): Enforce fine-grained tool allowlists/denylists per `agent_id` and `environment` (`dev`/`staging`/`prod`) so untrusted agents cannot invoke write/admin MCP tools (Impact: 5/5 | Effort: S)
- [ ] **[jsonrpc-proxy]** Native JSON-RPC 2.0 MCP Wire-Protocol Envelope Endpoint (`POST /api/v1/mcp/jsonrpc`): Support full JSON-RPC 2.0 `tools/call`, `resources/read`, and `prompts/get` envelopes with bidirectional response DLP redaction (Impact: 5/5 | Effort: M)

### P1 — Threat Intelligence & Observability
- [ ] **[rate-anomaly]** Behavioral Tool-Call Rate Limiting & Exfiltration Velocity Detector: Detect anomalous bursts of `resources/read` or database queries from a single agent session to stop automated data harvesting (Impact: 4/5 | Effort: S)
- [ ] **[ui-cockpit]** Editorial Security & Audit Chain Inspector UI (`GET /`): Minimalist *Taste* web cockpit displaying live MCP tool decisions, DLP redaction counters, and interactive SHA-256 hash-chain verification (Impact: 5/5 | Effort: M)

### P2 — Ecosystem & Alerting
- [ ] **[webhooks]** Real-Time Security Incident Webhook Dispatcher: Push high-severity `BLOCKED` events (`risk_score >= 80`) to SOC/Slack webhooks with anti-spam cooldown (Impact: 4/5 | Effort: S)

---

## ✅ Completed Milestones
- [x] **[core/init]** Project initialization (`v0.1.0`) with Zero-Trust MCP Firewall (`app/firewall.py`), deterministic DLP Redactor (`app/redactor.py`), SHA-256 Hash-Chained SQLite Audit Ledger, Prometheus `/metrics`, Atheris fuzzing harness (`fuzz/fuzz_firewall.py`), traffic simulator (`scripts/simulate_mcp_traffic.py`), hardened multi-stage `Dockerfile` (`UID 10001`), K8s manifests (`k8s/`), OPA/Rego policies (`policy/`), and 4-Phase CI/CD pipeline (`[[ADR-0021-aegis-mcp-zero-trust-firewall-and-hash-chain-audit]]`) — Branch: `main` (`2026-11-17`)
