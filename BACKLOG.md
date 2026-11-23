# Technical Backlog & Architecture Roadmap — Aegis-MCP

This file tracks prioritized engineering improvements, technical debt, and completed milestones for **Aegis-MCP**.

## 🎯 Prioritized Backlog (Sprint 2026-W48)

> Goal: `v0.2.0` industry-grade MCP Security Gateway. Acceptance KPIs: detection recall >= 0.95 and FPR <= 0.02 on a >= 300-case labeled corpus, p99 inspection overhead <= 10 ms at 500 rps, no self-declared identity in `enforce` mode, signed and offline-verifiable audit ledger, coverage >= 90%.

### P0 — Zero-Trust Identity, Protocol Coverage & Evidence Integrity
- [x] **[policy/fail-closed-and-shadow-mode]** `AEGIS_POLICY_MODE=enforce|monitor`, fail-closed (deny-all) in `prod` when no valid policy is loaded (fixes current allow-all default), `policy_version` hash recorded per ledger entry (Impact: 5/5 | Effort: S) — Done: `AEGIS_ENVIRONMENT=prod` with a missing/invalid policy installs a deny-all engine (`policy_fail_closed`); `monitor` audits `would_block` without blocking (`aegis_mcp_shadow_would_block_total`); `policy_version` = SHA-256 of the RFC 8785 JCS document (`app/canonical.py`) stored per ledger row with additive schema migration; `GET /api/v1/policies/status` — Branch: `feat/w48-p0-sprint` (`2026-11-23`)
- [x] **[policy/argument-constraints]** Argument-level ABAC: `realpath`-canonicalized `path_allow`, `sql_mode: read_only`, `egress_allow` domains, `max_bytes`/`max_items` (Impact: 5/5 | Effort: M) — Done: `tool_constraints` in the YAML policy (`app/constraints.py`), scoped by agent/server/tool globs and environment; `path_allow` resolves `file://`, relative, percent-encoded and symlinked paths with `realpath` + `commonpath` (NUL bytes rejected); `sql_mode: read_only` allows one `SELECT`/`WITH` with no write/DDL/session tokens outside comments and literals (blocks data-modifying CTEs, `SELECT INTO`, stacked queries); `egress_allow` matches IDNA hosts exactly or via `*.domain` (userinfo/backslash tricks rejected); `max_bytes`/`max_items`; JSON-RPC `tools/call`/`prompts/get` constrain `params.arguments`, `resources/read` its `uri` — Branch: `feat/w48-p0-sprint` (`2026-11-23`)
- [ ] **[toolguard/manifest-pinning]** Intercept `initialize` and `*/list`; JCS SHA-256 fingerprint pinning of tool definitions (TOFU + explicit approval), `tool_definition_drift` blocking (rug-pull), RBAC-filtered `tools/list` (Impact: 5/5 | Effort: M)
- [ ] **[toolguard/poisoning-scanner]** Tool poisoning and cross-server shadowing scanner for descriptions/schemas plus `scripts/scan_mcp_server` CLI (Impact: 5/5 | Effort: M)
- [ ] **[detection/canonicalization]** Anti-evasion pipeline before rules: NFKC, zero-width/bidi stripping (CVE-2021-42574), confusables folding, percent/HTML decoding, bounded recursive Base64/hex decoding (Impact: 5/5 | Effort: S)
- [ ] **[transport/streamable-http]** Native Streamable HTTP transport (`/mcp`): JSON + SSE streaming with per-event DLP, `Mcp-Session-Id`, `MCP-Protocol-Version` negotiation, `initialize`/`ping`/`notifications/*`, JSON-RPC batches (Impact: 5/5 | Effort: L)
- [ ] **[audit/full-payload-binding]** Ledger hash v2 over the full JCS-canonical entry (violations, categories, sanitized-args digest, policy version, session id), v1 -> v2 migration with backward verification, SQLite WAL (Impact: 5/5 | Effort: M)

### P1 — Threat Intelligence, Observability & Distribution
- [ ] **[dlp/enterprise-detectors]** Credit cards with Luhn (documented in `AGENTS.md` but missing), IBAN mod-97, Spanish DNI/NIE, JWT, PEM keys, Slack/Stripe/GCP/Azure/GitLab tokens, E.164 phones, Shannon-entropy secrets, optional HMAC tokenization (Impact: 5/5 | Effort: M)
- [ ] **[detection/toxic-flow-taint]** Session taint tracking ("lethal trifecta"): block `egress_sink` tools once a session holds both `untrusted_content` and `private_data` (Impact: 5/5 | Effort: M)
- [ ] **[detection/benchmark-corpus]** Labeled corpus mapped to OWASP LLM Top 10 2025 / OWASP Agentic / MITRE ATLAS with precision/recall/FPR CI gate (Impact: 5/5 | Effort: M)
- [ ] **[transport/stdio-wrapper]** `stdio` wrapper to interpose Aegis between local MCP clients and servers (Impact: 4/5 | Effort: M)
- [ ] **[hitl/approval-gate]** `require_approval` policy action with webhook notification and fail-closed timeout; supersedes `[webhooks]` (Impact: 4/5 | Effort: M)
- [ ] **[audit/signed-merkle-checkpoints]** RFC 6962 Merkle tree, Ed25519 signed tree heads, inclusion proofs endpoint, offline verifier, OCSF SIEM export (Impact: 5/5 | Effort: M)
- [ ] **[observability/otel]** OTLP traces (GenAI/MCP semantic conventions), latency histograms, structured JSON logs, Grafana dashboard and `PrometheusRule` alerts (Impact: 4/5 | Effort: M)
- [ ] **[perf/latency-budget]** Reproducible benchmarks, k6/locust load test and p99 regression gate in CI (Impact: 4/5 | Effort: S)
- [ ] **[rate-anomaly]** Behavioral Tool-Call Rate Limiting & Exfiltration Velocity Detector: Detect anomalous bursts of `resources/read` or database queries from a single agent session to stop automated data harvesting (Impact: 4/5 | Effort: S)
- [ ] **[release/helm-and-slsa]** Helm chart as a single-replica `StatefulSet` with a PVC for the SQLite ledger (HPA/PDB shipped disabled via `autoscaling.enabled: false` until `[persistence/postgres-ledger]` exists, since multiple SQLite replicas would fork the hash chain), default-deny egress NetworkPolicy, PSS restricted, multi-arch image, cosign keyless signing, SLSA L3 provenance, attested SBOM, `v0.2.0` release (Impact: 5/5 | Effort: M)
- [ ] **[ui-cockpit]** Editorial Security & Audit Chain Inspector UI (`GET /`): Minimalist *Taste* web cockpit displaying live MCP tool decisions, DLP redaction counters, pinned/drifted tool inventory, HITL approval queue, and interactive hash-chain verification (Impact: 5/5 | Effort: M)
- [ ] **[docs/threat-model-and-compliance]** STRIDE threat model, `SECURITY.md`, control matrix vs. OWASP LLM Top 10 2025, OWASP Agentic, MITRE ATLAS, NIST AI RMF, EU AI Act (Impact: 4/5 | Effort: S)

### P2 — Scale-Out & Ecosystem (stretch)

> **P2 entry criteria** (checked before opening the branch; otherwise the item rolls over to the next sprint untouched):
> 1. All P0 items closed (branch pushed, `AGENTS.md` gates green, ADR written).
> 2. >= 80% of P1 items closed, including the measurable KPIs (recall >= 0.95, FPR <= 0.02, p99 overhead <= 10 ms).
> 3. Zero open regressions on delivered work (coverage >= 90%, no surviving core mutants).
> 4. Remaining sprint days exceed the estimated effort (L ~ 2 days, M ~ 1 day). No half-finished P2 work.
>
> **Per-item triggers** (in addition to the above):
> - `[persistence/postgres-ledger]`: a real need for more than one replica, or `[perf/latency-budget]` proves the SQLite single writer is the cause of exceeding the 10 ms p99 budget; `[audit/full-payload-binding]` and `[audit/signed-merkle-checkpoints]` must be closed first to avoid a double schema migration.
> - `[policy/external-pdp]`: a real consumer already runs OPA/Cedar, or a required rule cannot be expressed in the native YAML ABAC. Otherwise dropped (YAGNI).
> - `[webhooks]`: folded into `[hitl/approval-gate]`; closed without standalone execution.

- [ ] **[persistence/postgres-ledger]** Pluggable ledger backend with PostgreSQL HA option (`pg_advisory_xact_lock` chain serialization) (Impact: 4/5 | Effort: L)
- [ ] **[policy/external-pdp]** Optional OPA REST / Cedar PDP adapter alongside the native YAML engine (Impact: 3/5 | Effort: M)
- [ ] **[webhooks]** Real-Time Security Incident Webhook Dispatcher: Push high-severity `BLOCKED` events (`risk_score >= 80`) to SOC/Slack webhooks with anti-spam cooldown — folded into `[hitl/approval-gate]` (Impact: 4/5 | Effort: S)

---

## ✅ Completed Milestones
- [x] **[core/init]** Project initialization (`v0.1.0`) with Zero-Trust MCP Firewall (`app/firewall.py`), deterministic DLP Redactor (`app/redactor.py`), SHA-256 Hash-Chained SQLite Audit Ledger, Prometheus `/metrics`, Atheris fuzzing harness (`fuzz/fuzz_firewall.py`), traffic simulator (`scripts/simulate_mcp_traffic.py`), hardened multi-stage `Dockerfile` (`UID 10001`), K8s manifests (`k8s/`), OPA/Rego policies (`policy/`), and 4-Phase CI/CD pipeline (`[[ADR-0021-aegis-mcp-zero-trust-firewall-and-hash-chain-audit]]`) — Branch: `main` (`2026-11-17`)
- [x] **[rbac-policy]** Declarative Per-Agent & Per-Server RBAC Policy Matrix (`app/policy.py`): deny-overrides `fnmatch` glob matrix scoped by `agent_id`, `server_name`, and `environment` (`dev`/`staging`/`prod`); fail-closed `yaml.safe_load` loader via `AEGIS_POLICY_PATH`; `GET`/`POST /api/v1/policies` (POST requires a configured `AEGIS_API_KEY`); unauthorized calls `BLOCKED` with `rbac_policy_denied` (risk `100`) in `MCPFirewall.inspect` — Branch: `feat/rbac-policy-matrix` (`2026-11-17`)
- [x] **[jsonrpc-proxy]** Native JSON-RPC 2.0 MCP Wire-Protocol Proxy (`POST /api/v1/mcp/jsonrpc`, `app/jsonrpc.py`): `tools/call`, `resources/read`, `prompts/get` envelopes enforced through `MCPFirewall` threat rules, RBAC `PolicyEngine`, and the SHA-256 ledger; standard `-32700`/`-32600`/`-32601`/`-32602` errors plus `-32003` (policy/security blocked) and `-32004` (upstream error) preserving the request `id`; forwarding only to server-configured `AEGIS_MCP_UPSTREAMS` (http/https, no redirects, 5 MiB cap) with bidirectional DLP redaction of params and `result`/`error` — Branch: `feat/jsonrpc-mcp-proxy` (`2026-11-17`)
- [x] **[authn/oauth-resource-server]** OAuth 2.1 Resource Server per the MCP authorization spec (`app/auth.py`, `AEGIS_AUTH_MODE=oauth`): Bearer JWT validation of `iss`/`aud`/`exp`/`nbf` against a TTL-cached JWKS with rate-limited forced refresh on unknown `kid` (key rotation); explicit asymmetric allow-list (`RS*`/`PS*`/`ES*`/`EdDSA`) rejecting `none` and `HS*` plus JWK `kty`/`crv`/`alg` binding (algorithm-confusion defense); RFC 8707 audience binding; RFC 9728 `GET /.well-known/oauth-protected-resource` and `WWW-Authenticate: Bearer resource_metadata=…` on `401` (`503` on JWKS outage); `agent_id` derived only from validated `sub` → `azp` → `client_id` (self-declared `X-Aegis-Agent-Id` / body `agent_id` ignored); caller credentials (`Authorization`, `Proxy-Authorization`, `Cookie`) stripped on the upstream hop (confused-deputy mitigation); fail-closed OAuth config at startup; `AEGIS_AUTH_MODE=api_key` default retained for local development — Branch: `feat/auth-oauth-resource-server` (`2026-11-23`)
