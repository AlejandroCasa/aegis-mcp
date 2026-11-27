# Security Policy

Aegis-MCP is a security control: it firewalls, redacts and audits Model Context Protocol (MCP) traffic. We take reports against it seriously and welcome coordinated disclosure.

The full STRIDE threat model, residual risk register and regulatory control matrix (OWASP LLM Top 10 2025, OWASP Agentic AI, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO/IEC 42001) are in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

---

## 1. Supported Versions

| Version | Supported | Notes |
| :--- | :---: | :--- |
| `0.2.x` | ✅ | Current release line. Receives security fixes as patch releases. |
| `< 0.2.0` | ❌ | Unsupported. Upgrade to the latest `0.2.x` (ledger v1 → v2 migration is additive and preserves existing evidence). |
| `main` (unreleased) | ⚠️ | Fixed on a best-effort basis before the next tag. Do not run untagged builds in production. |

---

## 2. Reporting a Vulnerability

**Do not open a public issue, discussion or pull request for a suspected vulnerability.**

Report privately through one of these channels:

1. **GitHub Security Advisories (preferred)**: open a draft advisory from the repository's **Security → Advisories → Report a vulnerability** page. This gives us a private workspace and lets us request a CVE.
2. **Email**: `<SECURITY_CONTACT_EMAIL>`, subject line starting with `[aegis-mcp security]`.

Include, where possible:

- the affected version (`0.2.x` tag or commit SHA) and deployment mode (HTTP, Streamable HTTP `/mcp`, or `stdio` wrapper; `api_key` or `oauth` auth mode; `enforce` or `monitor` policy mode);
- the affected component (for example `app/redactor.py` or `app/ledger.py`) and the trust boundary crossed (see [`docs/THREAT-MODEL.md` §2](docs/THREAT-MODEL.md#2-architecture--trust-boundaries));
- a minimal reproduction: request payload, policy YAML and configuration (`AEGIS_*` variables, **with secrets removed**);
- the impact you observed (firewall bypass, DLP leak, ledger tampering that goes undetected, authentication bypass, SSRF, DoS, ...).

Please use synthetic data only. Never send real credentials, personal data or production audit ledgers.

### Response targets

These are targets for a small, maintainer-run project, not contractual guarantees.

| Stage | Target |
| :--- | :--- |
| Acknowledgement of the report | within **3 business days** |
| Initial triage and severity (CVSS v4.0) | within **7 calendar days** |
| Fix or mitigation — Critical | within **14 days** of triage |
| Fix or mitigation — High | within **30 days** of triage |
| Fix or mitigation — Medium / Low | next planned minor or patch release (≤ **90 days**) |
| Public advisory | when the fix is released, or at **90 days** after the report, whichever comes first, unless we agree otherwise |

We will keep you updated at least every 14 days while a report is open, and credit you in the advisory and `CHANGELOG.md` unless you prefer to stay anonymous.

### Scope

**In scope:** everything in this repository: the gateway (`app/`), the `stdio` wrapper, the scripts in `scripts/`, the Helm chart (`deploy/helm/aegis-mcp`), Kubernetes manifests and OPA/Rego policies, the container image, and the release workflow.

Examples of in-scope findings:

- a payload that `MCPFirewall.inspect` should block but forwards, *outside* the gaps listed in README *Known detection gaps*;
- secrets or PII reaching an upstream server, the ledger, logs, spans, metrics or webhooks unredacted;
- an edit to the audit ledger database that `GET /api/v1/audit/verify` or `scripts/verify_ledger.py` does not detect;
- forged or replayable Signed Tree Heads, inclusion proofs or HITL approvals;
- JWT validation bypass, algorithm confusion, audience confusion or `Mcp-Session-Id` hijacking;
- SSRF through webhooks or upstream routing; credential leakage to upstream servers or `stdio` children.

**Out of scope:** the already documented residual risks in [`docs/THREAT-MODEL.md` §5](docs/THREAT-MODEL.md#5-residual-risk-register) (unless you find a way to make them worse); weaknesses in upstream MCP servers, LLMs or MCP host applications; volumetric DoS without an amplification factor; findings that need a compromised host, cluster admin rights, or `monitor` mode in place of `enforce`.

### Safe harbor

We will not pursue or support legal action for good-faith research that follows this policy: test only against your own deployments, avoid privacy violations and service disruption, and give us reasonable time to fix the issue before disclosure.

---

## 3. Security Architecture Highlights

| Layer | Control | Module |
| :--- | :--- | :--- |
| Identity | OAuth 2.1 resource server: asymmetric-only JWT validation, RFC 8707 audience binding, RFC 9728 metadata; constant-time `X-API-Key` comparison | `app/auth.py` |
| Authorization | Default-deny RBAC per agent / server / environment, fail-closed in `prod`; argument-level ABAC (`path_allow`, `sql_mode: read_only`, `egress_allow`, size caps) | `app/policy.py`, `app/constraints.py` |
| Threat detection | Prompt injection, command injection, destructive SQL and path traversal rules over anti-evasion views (NFKC, invisible characters, homoglyphs, recursive Base64/hex) | `app/firewall.py`, `app/normalize.py` |
| Supply chain (MCP) | TOFU tool/prompt/resource pinning with sticky rug-pull drift detection; tool-poisoning and cross-server shadowing scanner | `app/toolguard.py`, `app/poisoning.py` |
| Data protection | Checksum-validated DLP on arguments, replies, SSE events, logs, spans and webhooks; optional HMAC pseudonymous placeholders | `app/redactor.py` |
| Agentic abuse | Per-session "lethal trifecta" toxic-flow taint; token-bucket rate limiting and exfiltration velocity detection | `app/taint.py`, `app/rate_limit.py` |
| Human oversight | Single-use, argument-bound, TTL-limited HITL approvals; cockpit with strict CSP | `app/approvals.py`, `app/cockpit.py` |
| Evidence | v2 RFC 8785 full-payload SHA-256 hash chain, RFC 6962 Merkle tree, chained Ed25519 Signed Tree Heads, OCSF 1.3.0 SIEM export | `app/ledger.py`, `app/merkle.py`, `app/ocsf.py` |
| Transports | Streamable HTTP with `Origin` allow-list and gateway-bound sessions; `stdio` wrapper with `shell=False` and `AEGIS_*` stripping | `app/streamable.py`, `app/stdio_wrap.py` |
| Platform | Non-root `UID 10001`, read-only rootfs, PSS restricted, default-deny NetworkPolicy, single-writer `StatefulSet` | `Dockerfile`, `deploy/helm/aegis-mcp` |
| Engineering | `mypy --strict`, `bandit`, `pip-audit`, CodeQL, fuzzing, detection-benchmark and ≥ 85 % coverage gates | `.github/workflows/` |

---

## 4. Verifying Releases (Cosign & SLSA)

Every `v*` release image at `ghcr.io/alejandrocasa/aegis-mcp` is signed keyless with Sigstore cosign, carries a CycloneDX SBOM attestation, and has SLSA Build L3 provenance from `slsa-framework/slsa-github-generator`. Always verify **by digest**, never by mutable tag. Resolve the digest of the tag first (for example with `crane digest ghcr.io/alejandrocasa/aegis-mcp:v0.2.0` or `docker buildx imagetools inspect`), then:

```bash
TAG=v0.2.0
REF=ghcr.io/alejandrocasa/aegis-mcp@sha256:<digest-of-the-tag>
ISSUER=https://token.actions.githubusercontent.com
IDENTITY="https://github.com/AlejandroCasa/aegis-mcp/.github/workflows/release.yml@refs/tags/${TAG}"

# 1. Image signature
cosign verify "${REF}" \
  --certificate-oidc-issuer "${ISSUER}" --certificate-identity "${IDENTITY}"

# 2. SBOM attestation (CycloneDX)
cosign verify-attestation "${REF}" --type cyclonedx \
  --certificate-oidc-issuer "${ISSUER}" --certificate-identity "${IDENTITY}"

# 3. SLSA L3 provenance
cosign verify-attestation "${REF}" --type slsaprovenance \
  --certificate-oidc-issuer "${ISSUER}" \
  --certificate-identity-regexp '^https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'

# Alternative for step 3
slsa-verifier verify-image "${REF}" \
  --source-uri github.com/AlejandroCasa/aegis-mcp --source-tag "${TAG}"
```

Pin the verified digest in your deployment, and enforce signatures at admission time (for example with Sigstore policy-controller or Kyverno `verifyImages`) so unsigned images are rejected.

---

## 5. Verifying the Audit Ledger

The audit ledger is **tamper-evident**: an attacker with disk access cannot be prevented from editing it, but the edit can be detected.

**Online** (running gateway, authenticated):

```bash
curl -fsS -H "X-API-Key: ${AEGIS_API_KEY}" http://localhost:8000/api/v1/audit/verify
curl -fsS -H "X-API-Key: ${AEGIS_API_KEY}" http://localhost:8000/api/v1/audit/proof/42
```

**Offline** (recommended for audits, incident response and EU AI Act Art. 12 evidence). `scripts/verify_ledger.py` opens a *copy* of the SQLite ledger read-only and trusts only the Ed25519 public key:

```bash
# Derive the public key from the signing key (once, on a trusted host)
openssl pkey -in aegis-signing.pem -pubout -out aegis-signing.pub.pem

# Full hash chain + every Signed Tree Head (signature, chaining, RFC 6962 root)
uv run python -m scripts.verify_ledger --db aegis_mcp.db --pubkey aegis-signing.pub.pem

# Plus the RFC 6962 inclusion proof of one entry, machine-readable
uv run python -m scripts.verify_ledger --db aegis_mcp.db --pubkey aegis-signing.pub.pem \
  --entry-id 42 --json
```

Exit codes: `0` valid, `1` tampering or verification failure, `2` usage or I/O error.

Operational guidance:

- Keep the Ed25519 private key in a Kubernetes Secret, sealed secret or KMS, never next to the ledger. Distribute the **public key** and its fingerprint to auditors out of band.
- Keep `AEGIS_CHECKPOINT_INTERVAL` small and export Signed Tree Heads and OCSF events (`GET /api/v1/audit/export/ocsf`) to an off-host SIEM continuously. Entries after the latest checkpoint are not yet covered by a signature.
- Treat any non-zero exit of `verify_ledger` as a security incident: preserve the database, WAL and SHM files before restarting the gateway.

---

## 6. Hardening Checklist for Operators

- [ ] `AEGIS_ENVIRONMENT=prod` with a valid `AEGIS_POLICY_PATH` (a missing or invalid policy fails closed).
- [ ] `AEGIS_AUTH_MODE=oauth` for multi-tenant deployments, with a separate approver scope (`AEGIS_HITL_APPROVER_SCOPE`).
- [ ] `AEGIS_POLICY_MODE=enforce` (use `monitor` only for time-boxed rollouts).
- [ ] `tool_constraints` declared for every filesystem, SQL and HTTP tool.
- [ ] `AEGIS_TOOLGUARD_REQUIRE_APPROVAL=true` and an Ed25519 checkpoint signing key configured.
- [ ] `AEGIS_MCP_ALLOWED_ORIGINS` set when `/mcp` is reachable from browsers.
- [ ] Release image verified by digest (§4); ledger verified offline on a schedule (§5).
