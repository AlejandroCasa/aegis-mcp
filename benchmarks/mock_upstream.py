"""Minimal JSON-RPC echo upstream for ``benchmarks/load_k6.js`` (stdlib only).

Answers every ``POST`` with a successful MCP ``tools/call`` result so the
load test measures the gateway, not a real tool server::

    uv run python benchmarks/mock_upstream.py --port 9100
    AEGIS_MCP_UPSTREAMS='{"bench-mcp":"http://127.0.0.1:9100/mcp"}' \
        uv run uvicorn app.main:app --port 8000
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class EchoHandler(BaseHTTPRequestHandler):
    """Reply ``{"result": {...}}`` with the caller's JSON-RPC id."""

    def do_POST(self) -> None:
        """Handle one JSON-RPC request."""
        length = int(self.headers.get("Content-Length", "0"))
        try:
            request_id = json.loads(self.rfile.read(length) or b"{}").get("id")
        except (ValueError, AttributeError):
            request_id = None
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"content": [{"type": "text", "text": "ok"}]},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Silence per-request access logs."""


def main() -> None:
    """Serve until interrupted."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9100)
    args = parser.parse_args()
    with ThreadingHTTPServer((args.host, args.port), EchoHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
