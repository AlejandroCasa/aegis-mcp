"""Operator Security Cockpit (``GET /``): markup hygiene, assets and backing APIs."""

import json
import re
import shutil
import subprocess
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import main
from app.approvals import ApprovalKey
from app.cockpit import CONTENT_SECURITY_POLICY, STATIC_DIR, TEMPLATE_PATH
from app.config import settings
from app.metrics import metrics_registry
from app.schemas import MCPToolCallRequest

client = TestClient(main.app)

ADMIN_KEY = "cockpit-" + "k" * 24
JS_DIR = STATIC_DIR / "js"
CSS_PATH = STATIC_DIR / "css" / "cockpit.css"
JS_MODULES = sorted(JS_DIR.glob("*.js"))
NODE = shutil.which("node")
requires_node = pytest.mark.skipif(NODE is None, reason="node is not installed")

EMOJI = re.compile(
    "["
    "\U0001f000-\U0001faff"  # pictographs, emoticons, transport, symbols
    "\U00002600-\U000027bf"  # misc symbols and dingbats
    "\U00002b00-\U00002bff"  # arrows and stars
    "\U0000fe0f"  # emoji presentation selector
    "\U0000200d"  # zero-width joiner sequences
    "]"
)
IMPORT_RE = re.compile(r'^import\s+\{([^}]*)\}\s+from\s+"\./([\w-]+\.js)";', re.M)
EXPORT_RE = re.compile(
    r"^export\s+(?:async\s+)?(?:function|const|class)\s+(\w+)", re.MULTILINE
)


class MarkupAudit(HTMLParser):
    """Collect every construct a strict CSP would reject."""

    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[dict[str, str | None]] = []
        self.inline_script_bodies: list[str] = []
        self.style_tags = 0
        self.style_attrs: list[str] = []
        self.handlers: list[str] = []
        self.stylesheets: list[str] = []
        self.ids: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        names = dict(attrs)
        self.handlers += [name for name, _ in attrs if name.startswith("on")]
        if "style" in names:
            self.style_attrs.append(tag)
        if names.get("id"):
            self.ids.append(str(names["id"]))
        if tag == "script":
            self.scripts.append(names)
            self._in_script = True
        elif tag == "style":
            self.style_tags += 1
        elif tag == "link" and names.get("rel") == "stylesheet":
            self.stylesheets.append(names.get("href") or "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script and data.strip():
            self.inline_script_bodies.append(data)


@pytest.fixture(autouse=True)
def isolate(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Admin key configured, clean ledger/pins/approvals/metrics per test."""
    monkeypatch.setattr(settings, "api_key", ADMIN_KEY)
    monkeypatch.setattr(settings, "policy_mode", "enforce")
    main.firewall.reset()
    main.jsonrpc_gateway.toolguard.reset()
    metrics_registry.reset()
    yield
    main.firewall.reset()
    main.jsonrpc_gateway.toolguard.reset()
    metrics_registry.reset()


def _admin() -> dict[str, str]:
    return {"X-API-Key": ADMIN_KEY}


def _audit(page: str) -> MarkupAudit:
    audit = MarkupAudit()
    audit.feed(page)
    audit.close()
    return audit


def _inspect(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    request = MCPToolCallRequest(
        agent_id="research-agent",
        server_name="files-mcp",
        tool_name=tool,
        arguments=arguments,
        environment="dev",
    )
    response = client.post(
        "/api/v1/mcp/inspect", json=request.model_dump(mode="json"), headers=_admin()
    )
    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    return body


def _seed_traffic() -> None:
    _inspect("read_file", {"path": "docs/readme.md"})
    _inspect("send_email", {"to": "jane.doe@example.com", "body": "hello"})
    _inspect("run_shell", {"command": "ls; " + "rm" + " -rf /tmp/x"})


# --------------------------------------------------------------------------
# GET / shell
# --------------------------------------------------------------------------


def test_root_serves_cockpit_html_with_strict_headers() -> None:
    """``GET /`` is public HTML with a strict CSP and anti-framing headers."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert "script-src 'self'" in CONTENT_SECURITY_POLICY
    assert "'unsafe-inline'" not in CONTENT_SECURITY_POLICY
    assert "frame-ancestors 'none'" in CONTENT_SECURITY_POLICY
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert "<title>Aegis-MCP Security Cockpit</title>" in response.text


def test_root_has_no_inline_script_style_or_handlers() -> None:
    """Every script is an external ES module; no inline CSS or on*= handlers."""
    page = client.get("/").text
    audit = _audit(page)
    assert audit.scripts, "cockpit must load its ES module entrypoint"
    for script in audit.scripts:
        assert script.get("type") == "module"
        assert (script.get("src") or "").startswith("/static/js/")
    assert audit.inline_script_bodies == []
    assert audit.style_tags == 0
    assert audit.style_attrs == []
    assert audit.handlers == []
    assert audit.stylesheets == ["/static/css/cockpit.css"]
    assert "javascript:" not in page.lower()


def test_root_markup_exposes_every_cockpit_region() -> None:
    """Semantic landmarks and the element ids main.js binds to all exist."""
    page = client.get("/").text
    audit = _audit(page)
    assert len(audit.ids) == len(set(audit.ids)), "duplicate element ids"
    main_js = (JS_DIR / "main.js").read_text(encoding="utf-8")
    referenced = set(re.findall(r'byId\("([\w-]+)"\)', main_js))
    assert referenced
    assert referenced <= set(audit.ids)
    for landmark in ("<header", "<main", "<footer", "<table", "<dl"):
        assert landmark in page
    for kpi in ("requests", "allowed", "sanitized", "blocked", "redactions", "mode"):
        assert f'data-kpi="{kpi}"' in page
    assert 'type="password"' in page


def test_template_is_served_verbatim() -> None:
    """The response body is exactly the on-disk template (no server templating)."""
    assert client.get("/").text == TEMPLATE_PATH.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "path",
    [TEMPLATE_PATH, CSS_PATH, *JS_MODULES],
    ids=lambda path: path.name,
)
def test_ui_sources_contain_no_emoji(path: Path) -> None:
    """Zero Unicode emoji in UI markup, CSS and ES modules."""
    text = path.read_text(encoding="utf-8")
    assert EMOJI.findall(text) == []
    assert text.isascii(), f"{path.name} must stay pure ASCII"


def test_existing_routes_are_preserved() -> None:
    """Mounting the cockpit keeps health, metrics and API routes intact."""
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/metrics").status_code == 200
    assert client.get("/api/v1/audit/verify", headers=_admin()).status_code == 200


# --------------------------------------------------------------------------
# Static assets
# --------------------------------------------------------------------------


def test_stylesheet_is_served_with_tokens() -> None:
    """The CSS asset is served as text/css and defines the design tokens."""
    response = client.get("/static/css/cockpit.css")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    for token in ("--bg", "--ink", "--accent", "--emerald", "--amber", "--crimson"):
        assert f"{token}:" in response.text
    assert "prefers-color-scheme: dark" in response.text
    assert "@import" not in response.text
    assert "url(" not in response.text


@pytest.mark.parametrize("module", JS_MODULES, ids=lambda path: path.name)
def test_es_modules_are_served_as_javascript(module: Path) -> None:
    """Every ES module is reachable under /static/js with a JS media type."""
    response = client.get(f"/static/js/{module.name}")
    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert response.text == module.read_text(encoding="utf-8")


def test_static_mount_returns_404_for_unknown_assets() -> None:
    """Unknown assets are not found (no directory listing or fallback)."""
    assert client.get("/static/js/missing.js").status_code == 404
    assert client.get("/static/").status_code == 404


@pytest.mark.parametrize("module", JS_MODULES, ids=lambda path: path.name)
def test_es_modules_avoid_unsafe_sinks(module: Path) -> None:
    """No innerHTML/eval sinks; the key is never persisted to localStorage."""
    source = module.read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert sink not in source
    assert not re.search(r"\beval\s*\(|new\s+Function\s*\(", source)
    assert not re.search(r"\blocalStorage\s*\.", source)
    assert not re.search(r"\.on[a-z]+\s*=", source), "use addEventListener"
    assert not re.search(r"https?://", source), "same-origin requests only"


def test_api_key_lives_only_in_session_storage() -> None:
    """The X-API-Key is read/written through sessionStorage exclusively."""
    source = (JS_DIR / "api.js").read_text(encoding="utf-8")
    assert "sessionStorage.setItem" in source
    assert "sessionStorage.removeItem" in source
    assert '"X-API-Key"' in source
    assert ADMIN_KEY not in source


def test_es_module_import_graph_resolves() -> None:
    """Every named import exists as an export of the referenced sibling module."""
    exports = {
        path.name: set(EXPORT_RE.findall(path.read_text(encoding="utf-8")))
        for path in JS_MODULES
    }
    checked = 0
    for path in JS_MODULES:
        for names, target in IMPORT_RE.findall(path.read_text(encoding="utf-8")):
            assert target in exports, f"{path.name} imports missing {target}"
            for name in filter(None, (part.strip() for part in names.split(","))):
                assert name in exports[target], f"{target} lacks export {name}"
                checked += 1
    assert checked > 10
    assert "main.js" in exports


def _node(*args: str, cwd: Path | None = None, stdin: str = "") -> str:
    assert NODE is not None
    result = subprocess.run(
        [NODE, *args],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=cwd,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


@requires_node
@pytest.mark.parametrize("module", JS_MODULES, ids=lambda path: path.name)
def test_es_module_syntax_with_node_check(module: Path, tmp_path: Path) -> None:
    """``node --check`` parses each file as an ES module (.mjs copy)."""
    target = tmp_path / f"{module.stem}.mjs"
    shutil.copyfile(module, target)
    _node("--check", str(target))


# --------------------------------------------------------------------------
# Backing APIs
# --------------------------------------------------------------------------


def test_cockpit_reads_require_api_key_when_configured() -> None:
    """KPIs and the feed are protected exactly like other read endpoints."""
    assert client.get("/api/v1/cockpit/summary").status_code == 401
    assert client.get("/api/v1/audit/entries").status_code == 401


def test_cockpit_summary_reports_posture_kpis() -> None:
    """Totals, decision split, DLP counters and policy state are reported."""
    _seed_traffic()
    metrics_registry.record_rate_anomaly("rate_limit_exceeded", enforced=True)
    metrics_registry.record_rate_anomaly("exfiltration_velocity_anomaly", False)
    body = client.get("/api/v1/cockpit/summary", headers=_admin()).json()
    assert body["requests_total"] == 3
    assert body["decisions"]["BLOCKED"] == 1
    assert sum(body["decisions"].values()) == 3
    assert body["redactions_total"] >= 1
    assert body["redactions"]
    assert body["blocked_rule_hits"] >= 1
    assert body["rate_anomalies_total"] == 2
    assert body["rate_anomalies"] == {
        "rate_limit_exceeded": 1,
        "exfiltration_velocity_anomaly": 1,
    }
    assert body["ledger_entries"] == 3
    assert body["policy_mode"] == "enforce"
    assert body["api_key_required"] is True
    assert body["auth_mode"] == "api_key"
    assert len(body["policy_version"]) == 64


def test_cockpit_summary_is_empty_on_fresh_gateway() -> None:
    """A fresh gateway reports zeroed counters, not errors."""
    body = client.get("/api/v1/cockpit/summary", headers=_admin()).json()
    assert body["requests_total"] == 0
    assert body["decisions"] == {}
    assert body["ledger_entries"] == 0
    assert body["ledger_errors"] == 0


def test_audit_entries_feed_is_newest_first_and_bounded() -> None:
    """``/api/v1/audit/entries`` returns the newest ``limit`` rows first."""
    _seed_traffic()
    rows = client.get("/api/v1/audit/entries?limit=2", headers=_admin()).json()
    assert [row["tool_name"] for row in rows] == ["run_shell", "send_email"]
    assert rows[0]["decision"] == "BLOCKED"
    assert rows[0]["violations"]
    assert rows[0]["id"] > rows[1]["id"]
    assert "policy_version" in rows[0]
    assert "session_id" in rows[0]
    default = client.get("/api/v1/audit/entries", headers=_admin()).json()
    assert len(default) == 3
    for limit in (0, 501):
        bad = client.get(f"/api/v1/audit/entries?limit={limit}", headers=_admin())
        assert bad.status_code == 422


def test_chain_verify_and_checkpoints_back_the_inspector() -> None:
    """The inspector's verify and checkpoint calls succeed end to end."""
    _seed_traffic()
    verdict = client.get("/api/v1/audit/verify", headers=_admin()).json()
    assert verdict["valid"] is True
    assert verdict["total_entries"] == 3
    checkpoints = client.get("/api/v1/audit/checkpoints", headers=_admin())
    assert checkpoints.status_code == 200
    assert isinstance(checkpoints.json(), list)


def test_toolguard_inventory_and_approve_flow() -> None:
    """Pending pins are listed and approvable with the session admin key."""
    main.jsonrpc_gateway.toolguard.observe(
        "files-mcp",
        "tool",
        {"name": "read_file", "description": "Read a file", "inputSchema": {}},
    )
    assert client.get("/api/v1/toolguard/pins").status_code == 401
    pins = client.get("/api/v1/toolguard/pins", headers=_admin()).json()
    assert [(pin["name"], pin["status"]) for pin in pins] == [("read_file", "pending")]
    approved = client.post(
        "/api/v1/toolguard/approve",
        json={
            "server_name": "files-mcp",
            "kind": "tool",
            "name": "read_file",
            "fingerprint": pins[0]["fingerprint"],
        },
        headers=_admin(),
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"


def test_hitl_queue_list_and_resolve_flow() -> None:
    """Pending approvals are listed and resolvable (Approve / Deny)."""
    iban = "DE89370400440532013000"
    approval, created = main.firewall.approvals.submit(
        ApprovalKey("payments-agent", "bank-mcp", "transfer_funds", "prod", "f" * 64),
        {"amount": 10, "iban": iban},
        "",
    )
    assert created
    listed = client.get("/api/v1/approvals", headers=_admin()).json()
    assert [item["id"] for item in listed] == [approval.id]
    assert iban not in json.dumps(listed)
    denied = client.post(
        f"/api/v1/approvals/{approval.id}",
        json={"status": "denied", "reason": "cockpit operator denied"},
        headers=_admin(),
    )
    assert denied.status_code == 200
    assert denied.json()["status"] == "denied"
    assert denied.json()["resolved_by"] == "api-key-admin"


def test_admin_panels_fail_closed_without_configured_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without AEGIS_API_KEY the summary is open but admin panels are 403."""
    monkeypatch.setattr(settings, "api_key", None)
    summary = client.get("/api/v1/cockpit/summary")
    assert summary.status_code == 200
    assert summary.json()["api_key_required"] is False
    assert client.get("/api/v1/toolguard/pins").status_code == 403
    assert client.get("/api/v1/approvals").status_code == 403


def test_inclusion_proofs_exist_for_every_feed_entry() -> None:
    """Every feed entry yields a proof the cockpit can independently check."""
    _seed_traffic()
    for row in client.get("/api/v1/audit/entries", headers=_admin()).json():
        proof = client.get(f"/api/v1/audit/proof/{row['id']}", headers=_admin())
        assert proof.status_code == 200
        assert proof.json()["entry_hash"] == row["entry_hash"]
    assert client.get("/api/v1/audit/proof/999", headers=_admin()).status_code == 404


@requires_node
def test_merkle_module_verifies_server_proofs_in_node(tmp_path: Path) -> None:
    """merkle.js recomputes the server root for every entry; tampering fails."""
    for index in range(7):
        _inspect("read_file", {"path": f"docs/{index}.md"})
    rows = client.get("/api/v1/audit/entries", headers=_admin()).json()
    proofs = [
        client.get(f"/api/v1/audit/proof/{row['id']}", headers=_admin()).json()
        for row in reversed(rows)
    ]
    assert [proof["leaf_index"] for proof in proofs] == list(range(7))
    tampered = {**proofs[3], "entry_hash": "0" * 64}
    shutil.copyfile(JS_DIR / "merkle.js", tmp_path / "merkle.mjs")
    (tmp_path / "run.mjs").write_text(
        'import { verifyInclusionProof } from "./merkle.mjs";\n'
        'import { readFileSync } from "node:fs";\n'
        'const proofs = JSON.parse(readFileSync(0, "utf8"));\n'
        "const out = [];\n"
        "for (const proof of proofs) {\n"
        "  out.push((await verifyInclusionProof(proof)).valid);\n"
        "}\n"
        "console.log(JSON.stringify(out));\n",
        encoding="utf-8",
    )
    output = _node("run.mjs", cwd=tmp_path, stdin=json.dumps([*proofs, tampered]))
    assert json.loads(output) == [True] * 7 + [False]


def test_metrics_snapshot_aggregates_counters() -> None:
    """The registry snapshot sums tuple-keyed series by label."""
    metrics_registry.record_inspection("a", "ALLOWED", [], ["email"])
    metrics_registry.record_inspection("b", "ALLOWED", [], [])
    metrics_registry.record_inspection("a", "SANITIZED", [], [], would_block=True)
    metrics_registry.record_ledger_error("chain_tampered")
    snapshot = metrics_registry.snapshot()
    assert snapshot["decisions"] == {"ALLOWED": 2, "SANITIZED": 1}
    assert snapshot["redactions"] == {"email": 1}
    assert snapshot["totals"]["requests"] == 3
    assert snapshot["totals"]["shadow_would_block"] == 1
    assert snapshot["totals"]["ledger_errors"] == 1
