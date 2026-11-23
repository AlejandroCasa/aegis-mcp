"""Scan an MCP server for tool poisoning and cross-server shadowing.

Usage::

    uv run python -m scripts.scan_mcp_server --url https://host/mcp \\
        --header "Authorization: Bearer <token>" --fail-on high
    uv run python -m scripts.scan_mcp_server --manifest servers.json --json

``--url`` speaks MCP Streamable HTTP: ``initialize`` (capturing
``Mcp-Session-Id``), ``notifications/initialized`` and every paginated
``*/list`` the server advertises, accepting JSON or SSE responses.
``--manifest`` scans offline JSON: either one manifest
(``{"instructions": ..., "tools": [...], "prompts": [...], ...}``) or
``{"servers": {"<name>": <manifest>, ...}}`` (enables cross-server checks).

Exit codes: ``0`` clean (nothing at or above ``--fail-on``), ``1`` findings
at or above ``--fail-on``, ``2`` usage, connection, or protocol error.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import httpx

from app.poisoning import SEVERITY_ORDER, ScanReport, Severity, scan_servers
from app.sse import iter_sse_events

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "aegis-mcp-scanner", "version": "0.2.0"}
ACCEPT = "application/json, text/event-stream"
MAX_PAGES = 50
LIST_METHODS: tuple[tuple[str, str, str], ...] = (
    ("tools/list", "tools", "tools"),
    ("prompts/list", "prompts", "prompts"),
    ("resources/list", "resources", "resources"),
    ("resources/templates/list", "resourceTemplates", "resources"),
)
EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


class ScanError(Exception):
    """A connection or protocol error while talking to the MCP server."""


def _match_response(message: Any, req_id: int) -> dict[str, Any] | None:
    """Return ``message`` if it is the JSON-RPC response to ``req_id``."""
    if not isinstance(message, dict) or message.get("id") != req_id:
        return None
    return message if "result" in message or "error" in message else None


class McpHttpClient:
    """Minimal MCP Streamable HTTP client used for discovery."""

    def __init__(self, url: str, client: httpx.Client, headers: dict[str, str]) -> None:
        """Bind the endpoint, HTTP client, and extra request headers."""
        self.url = url
        self.client = client
        self.headers = headers
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        self._next_id = 0

    def _request_headers(self) -> dict[str, str]:
        """Build headers carrying the negotiated session and version."""
        headers = {**self.headers, "Accept": ACCEPT}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        return headers

    def _post(self, message: dict[str, Any]) -> httpx.Response:
        """POST one JSON-RPC message and return the open streamed response."""
        request = self.client.build_request(
            "POST", self.url, json=message, headers=self._request_headers()
        )
        response = self.client.send(request, stream=True)
        if not 200 <= response.status_code < 300:
            response.close()
            raise ScanError(f"HTTP {response.status_code} for {message['method']}")
        session_id = response.headers.get("mcp-session-id")
        if session_id:
            self.session_id = session_id
        return response

    @staticmethod
    def _read_response(response: httpx.Response, req_id: int) -> dict[str, Any]:
        """Extract the response to ``req_id`` from a JSON or SSE body."""
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/event-stream"):
            for event in iter_sse_events(response.iter_lines()):
                matched = _match_response(json.loads(event.data), req_id)
                if matched is not None:
                    return matched
            raise ScanError("SSE stream ended without a response.")
        matched = _match_response(json.loads(response.read()), req_id)
        if matched is None:
            raise ScanError("Malformed JSON-RPC response.")
        return matched

    def request(self, method: str, params: dict[str, Any]) -> Any:
        """Send a request and return its ``result`` (errors raise ScanError)."""
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        response = self._post({**message, "params": params})
        try:
            payload = self._read_response(response, self._next_id)
        except ValueError as exc:
            raise ScanError(f"Invalid response to {method}.") from exc
        finally:
            response.close()
        if "error" in payload:
            raise ScanError(f"{method} failed: {payload['error']}")
        return payload["result"]

    def notify(self, method: str) -> None:
        """Send a notification (the response body is ignored)."""
        self._post({"jsonrpc": "2.0", "method": method}).close()

    def initialize(self) -> dict[str, Any]:
        """Run the MCP initialization handshake."""
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
        )
        if not isinstance(result, dict):
            raise ScanError("initialize returned a non-object result.")
        version = result.get("protocolVersion")
        self.protocol_version = version if isinstance(version, str) else None
        self.notify("notifications/initialized")
        return result

    def list_all(self, method: str, field: str) -> list[Any]:
        """Collect every page of a ``*/list`` method."""
        items: list[Any] = []
        params: dict[str, Any] = {}
        for _ in range(MAX_PAGES):
            result = self.request(method, params)
            page = result.get(field) if isinstance(result, dict) else None
            items.extend(page if isinstance(page, list) else [])
            cursor = result.get("nextCursor") if isinstance(result, dict) else None
            if not isinstance(cursor, str) or not cursor:
                break
            params = {"cursor": cursor}
        return items


def fetch_manifest(mcp: McpHttpClient) -> dict[str, Any]:
    """Discover a live server's instructions and advertised definitions."""
    init = mcp.initialize()
    capabilities = init.get("capabilities")
    advertised = capabilities if isinstance(capabilities, dict) else {}
    manifest: dict[str, Any] = {"instructions": init.get("instructions")}
    for method, field, capability in LIST_METHODS:
        if capability in advertised:
            manifest[field] = mcp.list_all(method, field)
    return manifest


def load_manifests(path: Path, name: str) -> dict[str, dict[str, Any]]:
    """Load one manifest or a ``{"servers": {...}}`` bundle from JSON."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ScanError("Manifest file must contain a JSON object.")
    servers = data.get("servers")
    if isinstance(servers, dict):
        return {
            str(server): manifest
            for server, manifest in servers.items()
            if isinstance(manifest, dict)
        }
    return {name: data}


def parse_headers(values: Sequence[str]) -> dict[str, str]:
    """Parse repeated ``--header 'Name: value'`` options."""
    headers: dict[str, str] = {}
    for value in values:
        name, separator, content = value.partition(":")
        if not separator or not name.strip():
            raise ScanError(f"Invalid header (expected 'Name: value'): {name!r}")
        headers[name.strip()] = content.strip()
    return headers


def render_text(report: ScanReport) -> str:
    """Human-readable findings, most severe first."""
    if not report.findings:
        return "No poisoning indicators found."
    ordered = sorted(
        report.findings, key=lambda f: (-f.score, f.server, f.kind, f.name)
    )
    lines = [
        f"[{f.severity.upper()}] {f.server}/{f.kind}:{f.name} {f.rule} "
        f"({f.location}) {f.evidence}".rstrip()
        for f in ordered
    ]
    lines.append(f"{len(ordered)} finding(s); risk score {report.risk_score}.")
    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    """Machine-readable report."""
    return json.dumps(
        {
            "risk_score": report.risk_score,
            "findings": [finding.as_dict() for finding in report.findings],
        },
        indent=2,
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line interface."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="MCP Streamable HTTP endpoint (http/https).")
    source.add_argument("--manifest", type=Path, help="Offline manifest JSON file.")
    parser.add_argument("--name", default="mcp-server", help="Server label.")
    parser.add_argument("--header", action="append", default=[], help="Name: value")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    parser.add_argument(
        "--fail-on", choices=list(SEVERITY_ORDER), default="high", dest="fail_on"
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser


def collect(
    args: argparse.Namespace, client: httpx.Client | None
) -> dict[str, dict[str, Any]]:
    """Gather manifests from the selected source."""
    if args.manifest is not None:
        return load_manifests(args.manifest, args.name)
    parts = urlsplit(args.url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ScanError("--url must be an absolute http(s) URL.")
    http = client or httpx.Client(timeout=args.timeout, follow_redirects=False)
    try:
        mcp = McpHttpClient(args.url, http, parse_headers(args.header))
        return {args.name: fetch_manifest(mcp)}
    finally:
        if client is None:
            http.close()


def main(argv: Sequence[str] | None = None, client: httpx.Client | None = None) -> int:
    """Run the scanner; returns the process exit code."""
    args = build_parser().parse_args(argv)
    try:
        manifests = collect(args, client)
    except (ScanError, httpx.HTTPError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    report = scan_servers(manifests)
    print(render_json(report) if args.json else render_text(report))
    failing = report.at_least(cast(Severity, args.fail_on))
    return EXIT_FINDINGS if failing else EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
