# Changelog

All notable changes to Aegis-MCP are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Release tags (`vX.Y.Z`) are cut by
the human release train; `.github/workflows/release.yml` refuses a tag whose
version disagrees with `pyproject.toml`, `Chart.yaml` or this file.

## [Unreleased]

## [0.2.0] - 2026-11-27

Sprint 2026-W48: from a single-endpoint firewall to a spec-compliant MCP
security gateway with a signed, verifiable audit trail and a hardened
supply chain.

### Added

- **Release & deployment**
  - Hardened Helm chart `deploy/helm/aegis-mcp` (chart/app `0.2.0`): a
    single-replica `StatefulSet` with a retained `PersistentVolumeClaim` for the
    SQLite ledger (`AEGIS_DB_PATH=/data/aegis.db`), Pod Security Standards
    `restricted` (UID/GID 10001, read-only root filesystem, `/tmp` emptyDir,
    `drop: [ALL]`, `RuntimeDefault` seccomp, no service-account token), a
    default-deny egress `NetworkPolicy` (DNS plus declared MCP upstream and
    OTLP CIDRs only, ingress on port 8000 only), `/healthz` probes and
    `NOTES.txt`. HPA/PDB ship disabled, and the chart refuses
    `replicaCount != 1` because several SQLite writers would fork the hash
    chain.
  - `policy/helm.rego` conftest policy for the rendered chart.
  - `.github/workflows/release.yml`: on `v*` tags it builds a multi-arch
    (`linux/amd64`, `linux/arm64`) image and pushes it to `ghcr.io`, generates
    a CycloneDX SBOM (Syft), signs it with cosign keyless (Sigstore OIDC),
    attests the SBOM (cosign + GitHub attestation), produces SLSA Build L3
    provenance (`slsa-github-generator`), and verifies everything after
    publishing. Jobs get least-privilege `permissions` and actions are pinned
    to exact release tags.
  - `scripts/check_release_version.py` tag/version consistency gate.
- **Gateway & transports**: firewalled JSON-RPC 2.0 MCP proxy, native MCP
  Streamable HTTP transport (`/mcp`) with an `Origin` allowlist, and a
  firewalled stdio wrapper for local MCP servers.
- **Authorization**: OAuth 2.1 resource server per the MCP authorization spec,
  a declarative per-agent/per-server RBAC matrix, argument-level ABAC tool
  constraints, fail-closed `prod` startup and shadow `monitor` mode.
- **Detection**: tool-manifest pinning against rug-pull drift, a tool
  poisoning/shadowing scanner, canonicalization, session taint tracking
  against toxic-flow exfiltration, a token-bucket rate limiter and an
  exfiltration-velocity detector.
- **DLP**: checksum-validated enterprise detectors and HMAC referential
  tokenization.
- **Human-in-the-loop**: `require_approval` policy action and a security
  webhook dispatcher.
- **Audit**: RFC 6962 Merkle checkpoints with Ed25519 Signed Tree Heads,
  inclusion proofs and OCSF export.
- **Observability**: OpenTelemetry MCP spans, SLO latency histograms,
  DLP-scrubbed JSON logs and Grafana alerts.
- **Quality gates**: a labeled OWASP / MITRE ATLAS detection corpus with a
  recall >= 0.95 / FPR <= 0.02 CI gate, and a latency benchmark suite with a
  k6 load script and a p99 <= 10 ms CI gate.
- **UI**: an editorial security cockpit (`GET /`) and audit-chain inspector.

### Changed

- Version bumped to `0.2.0` (`pyproject.toml`, OpenAPI `info.version`, OCSF
  `metadata.product.version`, `k8s/` labels).

### Fixed

- The Claude guard stop-gate no longer hangs on open non-TTY stdin pipes.

## [0.1.0] - 2026-11-17

### Added

- Initial Zero-Trust MCP firewall, deterministic DLP redactor and SHA-256
  hash-chained SQLite audit ledger, Prometheus `/metrics`, Atheris fuzzing
  harness, traffic simulator, hardened multi-stage `Dockerfile` (UID 10001),
  Kubernetes manifests, OPA/Rego policies and a 4-phase CI pipeline.

[Unreleased]: https://github.com/AlejandroCasa/aegis-mcp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/AlejandroCasa/aegis-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/AlejandroCasa/aegis-mcp/releases/tag/v0.1.0
