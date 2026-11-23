"""Argument-level ABAC constraints: paths, read-only SQL, egress, size caps."""

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from app.config import settings
from app.constraints import (
    BYTES_VIOLATION,
    EGRESS_VIOLATION,
    ITEMS_VIOLATION,
    PATH_VIOLATION,
    SQL_VIOLATION,
    egress_allowed,
    evaluate_constraints,
    is_read_only_sql,
    resolve_path,
)
from app.firewall import MCPFirewall
from app.jsonrpc import POLICY_BLOCKED, JsonRpcGateway
from app.policy import PolicyEngine, parse_policy_yaml
from app.schemas import MCPToolCallRequest, PolicyDocument, ToolConstraint

DOTDOT = "." + "."
DROP = "DR" + "OP"
SCOPE = ("agent-1", "fs-mcp", "read_file", "prod")


@pytest.fixture(autouse=True)
def enforce_mode(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin enforce mode and default thresholds for every test."""
    monkeypatch.setattr(settings, "policy_mode", "enforce")
    monkeypatch.setattr(settings, "block_threshold_score", 70)
    monkeypatch.setattr(settings, "enable_dlp_redaction", True)
    yield


def _doc(**limits: Any) -> PolicyDocument:
    return PolicyDocument(tool_constraints=[ToolConstraint(**limits)])


def _violations(document: PolicyDocument, arguments: dict[str, Any]) -> list[str]:
    return evaluate_constraints(document, SCOPE, arguments)


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT * FROM users WHERE id = 1",
        "  with recent as (select 1 as x) select * from recent",
        "SELECT 'update; " + DROP + "' AS s FROM t -- delete everything",
        'SELECT "update" FROM t /* insert; */;',
        "SELECT $$ " + DROP + " $$, `delete` FROM t",
        "select 1;  ",
    ],
)
def test_read_only_sql_accepts_single_select(statement: str) -> None:
    """Keywords hidden in literals/comments/identifiers do not count."""
    assert is_read_only_sql(statement) is True


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE t SET a = 1",
        "SELECT 1; " + DROP + " TABLE t",
        "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
        "SELECT * INTO backup FROM t",
        "SELECT pg_sleep(10)",
        "EXPLAIN ANALYZE SELECT 1",
        "SELECT 'unterminated UPDATE",
        "-- comment only",
        "",
        "SELECT 1; SELECT 2",
    ],
)
def test_read_only_sql_rejects_writes_and_stacking(statement: str) -> None:
    """Writes, data-modifying CTEs, SELECT INTO, and stacked queries fail."""
    assert is_read_only_sql(statement) is False


def test_sql_constraint_on_arguments() -> None:
    """Non-string and write SQL arguments violate ``sql_mode: read_only``."""
    document = _doc(sql_mode="read_only")
    assert _violations(document, {"query": "SELECT 1"}) == []
    assert _violations(document, {"sql": "UPDATE t SET a=1"}) == [SQL_VIOLATION]
    assert _violations(document, {"statement": {"nested": 1}}) == [SQL_VIOLATION]
    assert _violations(document, {"other": "UPDATE t SET a=1"}) == []


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    """Create ``data/`` root with a file, a sibling dir, and an escaping link."""
    root = tmp_path / "data"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "a.txt").write_text("ok", encoding="utf-8")
    (tmp_path / "data-evil").mkdir()
    (tmp_path / "outside.txt").write_text("secret", encoding="utf-8")
    os.symlink(tmp_path / "outside.txt", root / "link.txt")
    return root


def test_path_allow_accepts_paths_inside_root(sandbox: Path) -> None:
    """Absolute, relative, file:// and the root itself are accepted."""
    document = _doc(path_allow=[str(sandbox)])
    for value in (
        str(sandbox / "docs" / "a.txt"),
        "docs/a.txt",
        "file://" + str(sandbox / "docs" / "a.txt"),
        str(sandbox),
        [str(sandbox / "docs"), "docs/new.txt"],
    ):
        assert _violations(document, {"path": value}) == [], value


def test_path_allow_rejects_escapes(sandbox: Path) -> None:
    """Traversal, symlink escape, prefix siblings, encodings, NUL, non-str."""
    document = _doc(path_allow=[str(sandbox)])
    escapes: list[Any] = [
        str(sandbox / DOTDOT / "outside.txt"),
        "docs/" + DOTDOT + "/" + DOTDOT + "/outside.txt",
        str(sandbox / "link.txt"),
        str(sandbox.parent / "data-evil" / "x"),
        "file://" + str(sandbox) + "/%2e%2e/outside.txt",
        str(sandbox / "docs" / "a.txt") + "\x00.png",
        42,
        [str(sandbox / "docs"), "/" + "etc"],
    ]
    for value in escapes:
        assert _violations(document, {"file": value}) == [PATH_VIOLATION], value


def test_resolve_path_rejects_nul() -> None:
    """NUL bytes raise ValueError before touching the filesystem."""
    with pytest.raises(ValueError):
        resolve_path("/srv\x00", "/srv")


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://api.example.com/v1", True),
        ("HTTP://API.EXAMPLE.COM./x", True),
        ("https://deep.cdn.example.org/a", True),
        ("https://example.org/", False),
        ("https://api.example.com.evil.io/", False),
        ("https://api.example.com@evil.io/", False),
        ("https://api.example.com\\@evil.io/", False),
        ("https://api.example.com /", False),
        ("ftp://api.example.com/", False),
        ("https://api.example.com:99999/", False),
        ("https://[::1/", False),
        ("not a url", False),
        ("https://b\U000000fccher.example.de/", True),
    ],
)
def test_egress_allowlist(url: str, allowed: bool) -> None:
    """Exact hosts, ``*.`` subdomains, IDNA; userinfo/backslash tricks fail."""
    patterns = ["api.example.com", "*.example.org", "xn--bcher-kva.example.de"]
    assert egress_allowed(url, patterns) is allowed


def test_egress_constraint_on_arguments() -> None:
    """URL keys are checked; non-strings fail closed."""
    document = _doc(egress_allow=["api.example.com"])
    assert _violations(document, {"url": "https://api.example.com/"}) == []
    assert _violations(document, {"uri": "https://evil.io/"}) == [EGRESS_VIOLATION]
    assert _violations(document, {"href": None}) == [EGRESS_VIOLATION]


def test_max_bytes_and_max_items() -> None:
    """Serialized size and nested array/object element counts are capped."""
    document = _doc(max_bytes=32, max_items=2)
    assert _violations(document, {"a": [1, 2]}) == []
    assert _violations(document, {"a": "x" * 64}) == [BYTES_VIOLATION]
    assert _violations(document, {"a": {"b": [1, 2, 3]}}) == [ITEMS_VIOLATION]
    assert _violations(document, {"a": 1, "b": 2, "c": 3}) == [ITEMS_VIOLATION]


def test_scope_globs_select_constraints() -> None:
    """Constraints apply only to matching agent/server/tool/environment."""
    document = PolicyDocument(
        tool_constraints=[
            ToolConstraint(tool_name="write_*", max_bytes=1),
            ToolConstraint(server_name="db-*", max_bytes=1),
            ToolConstraint(agent_id="intern-*", max_bytes=1),
            ToolConstraint(environments=["dev"], max_bytes=1),
            ToolConstraint(tool_name="read_*", max_items=0),
        ]
    )
    assert _violations(document, {"a": 1}) == [ITEMS_VIOLATION]


@pytest.mark.parametrize(
    "limits",
    [
        {},
        {"path_allow": ["relative/root"]},
        {"egress_allow": ["bad domain"]},
        {"max_bytes": 0},
        {"unknown": True},
    ],
)
def test_constraint_validation(limits: dict[str, Any]) -> None:
    """No-op, relative-root, malformed-domain, and unknown fields are invalid."""
    with pytest.raises(ValidationError):
        ToolConstraint(**limits)


def test_yaml_policy_declares_constraints() -> None:
    """``tool_constraints`` load from YAML alongside RBAC rules."""
    document = parse_policy_yaml(
        "tool_constraints:\n"
        "  - server_name: postgres-mcp\n"
        "    tool_name: query\n"
        "    sql_mode: read_only\n"
        "    max_bytes: 4096\n"
    )
    constraint = document.tool_constraints[0]
    assert (constraint.sql_mode, constraint.max_bytes) == ("read_only", 4096)


def test_firewall_blocks_and_monitor_mode_audits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Constraint violations block with risk 100; monitor only flags them."""
    engine = PolicyEngine(_doc(sql_mode="read_only"))
    firewall = MCPFirewall(db_path=str(tmp_path / "l.db"), policy_engine=engine)
    request = MCPToolCallRequest(
        agent_id="agent-1",
        server_name="db",
        tool_name="query",
        arguments={"query": "UPDATE accounts SET balance = 0"},
    )
    report = firewall.inspect(request)
    assert (report.decision, report.risk_score) == ("BLOCKED", 100)
    assert report.violations == [SQL_VIOLATION]
    monkeypatch.setattr(settings, "policy_mode", "monitor")
    shadow = firewall.inspect(request)
    assert (shadow.allowed, shadow.would_block) == (True, True)


def _gateway(tmp_path: Path, document: PolicyDocument) -> JsonRpcGateway:
    def reply(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": body["id"], "result": {}}
        )

    return JsonRpcGateway(
        firewall=MCPFirewall(
            db_path=str(tmp_path / "gw.db"), policy_engine=PolicyEngine(document)
        ),
        upstreams={"fs-mcp": "http://fs.internal/mcp"},
        client=httpx.Client(transport=httpx.MockTransport(reply)),
    )


def test_jsonrpc_tools_call_constrains_nested_arguments(
    tmp_path: Path, sandbox: Path
) -> None:
    """tools/call constraints read ``params.arguments``; escapes are -32003."""
    gateway = _gateway(tmp_path, _doc(path_allow=[str(sandbox)]))
    routing = {"agent_id": "agent-1", "server_name": "fs-mcp"}

    def call(path: str) -> dict[str, Any]:
        envelope = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": path}},
        }
        return gateway.handle(json.dumps(envelope).encode(), routing)

    assert "result" in call(str(sandbox / "docs" / "a.txt"))
    blocked = call(str(sandbox / "link.txt"))
    assert blocked["error"]["code"] == POLICY_BLOCKED
    assert blocked["error"]["data"]["violations"] == [PATH_VIOLATION]


def test_jsonrpc_resources_read_constrains_uri(tmp_path: Path, sandbox: Path) -> None:
    """resources/read exposes ``params.uri`` to path constraints."""
    gateway = _gateway(tmp_path, _doc(path_allow=[str(sandbox)], path_args=["uri"]))
    envelope = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "resources/read",
        "params": {"uri": "file://" + str(sandbox / "link.txt")},
    }
    response = gateway.handle(
        json.dumps(envelope).encode(), {"agent_id": "a", "server_name": "fs-mcp"}
    )
    assert response["error"]["data"]["violations"] == [PATH_VIOLATION]
