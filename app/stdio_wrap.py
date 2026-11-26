"""Zero-trust ``stdio`` MCP wrapper for local MCP servers.

Usage (e.g. as the ``command`` of a Claude Desktop / Cursor ``mcpServers``
entry)::

    uv run python -m app.stdio_wrap [--server-name NAME] [--agent-id AGENT]
        [--environment dev|staging|prod] [--policy PATH] [--db-path PATH]
        -- <command> [args...]

The wrapper spawns ``<command>`` (``shell=False``) with Aegis-internal
``AEGIS_*`` secrets stripped from its environment, then relays MCP ``stdio``
traffic (UTF-8, newline-delimited JSON-RPC 2.0; ``stderr`` is passed through)
between the host on our ``stdin``/``stdout`` and the child, running the same
pipeline as the HTTP gateway (``app/jsonrpc.py``) under one wrapper-lifetime
session id (taint tracking + ledger v2 ``session_id``):

* Client -> child: ``tools/call``, ``resources/read`` and ``prompts/get`` run
  ``MCPFirewall.inspect``; blocked calls never reach the child and are answered
  with ``-32003``. Discovery requests, ``notifications/*`` and client responses
  are DLP-redacted. Other methods get ``-32601``; batches ``-32600``.
* Child -> client: replies are matched to the pending request, toolguard
  screened (pinning, drift, poisoning, least-privilege ``tools/list``),
  DLP-redacted (promoting ``private_data`` taint) and have reserved gateway
  error codes neutralized. Server-initiated messages are DLP-redacted.
"""

import argparse
import json
import os
import re
import secrets

# subprocess spawns only the operator-configured MCP server (see ``spawn``).
import subprocess  # nosec B404
import sys
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import IO, Any

from app.config import settings
from app.firewall import MCPFirewall
from app.jsonrpc import (
    GENERIC_SERVER_ERROR,
    INVALID_REQUEST,
    MAX_IDENTIFIER_LENGTH,
    MAX_REQUEST_BYTES,
    MAX_UPSTREAM_BYTES,
    PARSE_ERROR,
    CallContext,
    Envelope,
    JsonRpcError,
    JsonRpcGateway,
    error_response,
    parse_envelope,
    redact_value,
    reject_constant,
    resolve_call,
    upstream_failure,
)
from app.policy import build_policy_engine
from app.schemas import Environment

MAX_PENDING_REQUESTS = 1024
STRIPPED_ENV_PREFIXES = ("AEGIS_",)
_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")
_ENVIRONMENTS: tuple[Environment, ...] = ("dev", "staging", "prod")

Writer = Callable[[bytes], None]


@dataclass(frozen=True)
class WrapConfig:
    """Validated wrapper command line."""

    command: list[str]
    server_name: str
    agent_id: str
    environment: Environment
    policy_path: str | None
    db_path: str


def sanitize_server_name(command: str) -> str:
    """Derive a ``[A-Za-z0-9_.-]+`` server name from the command basename."""
    base = os.path.basename(command.rstrip("/\\")) or command
    name = _UNSAFE_NAME_CHARS.sub("-", base).strip("-")
    return name[:MAX_IDENTIFIER_LENGTH] or "stdio-server"


def build_parser() -> argparse.ArgumentParser:
    """Build the wrapper CLI parser."""
    parser = argparse.ArgumentParser(
        prog="python -m app.stdio_wrap",
        description="Firewall a local stdio MCP server with Aegis-MCP.",
    )
    parser.add_argument("--server-name", default=None)
    parser.add_argument("--agent-id", default="stdio-agent")
    parser.add_argument(
        "--environment", choices=_ENVIRONMENTS, default=settings.environment
    )
    parser.add_argument("--policy", default=settings.policy_path)
    parser.add_argument("--db-path", default=settings.db_path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def parse_args(argv: Sequence[str] | None = None) -> WrapConfig:
    """Parse and validate argv; exits with code ``2`` on invalid input."""
    parser = build_parser()
    args = parser.parse_args(argv)
    command = [str(part) for part in args.command]
    if command and command[0] == "--":
        command = command[1:]
    if not command or not command[0]:
        parser.error("a server command is required after '--'")
    server_name = args.server_name or sanitize_server_name(command[0])
    if not 0 < len(server_name) <= MAX_IDENTIFIER_LENGTH:
        parser.error("--server-name must be 1-256 characters")
    if not 0 < len(args.agent_id) <= MAX_IDENTIFIER_LENGTH:
        parser.error("--agent-id must be 1-256 characters")
    return WrapConfig(
        command=command,
        server_name=server_name,
        agent_id=args.agent_id,
        environment=args.environment,
        policy_path=args.policy,
        db_path=args.db_path,
    )


def child_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """Copy ``environ`` without Aegis-internal secrets (confused deputy)."""
    return {
        key: value
        for key, value in environ.items()
        if not key.upper().startswith(STRIPPED_ENV_PREFIXES)
    }


def read_lines(stream: IO[bytes], cap: int) -> Iterator[bytes | None]:
    """Yield newline-delimited lines; ``None`` marks a line over ``cap`` bytes.

    Oversized lines are drained (never buffered beyond ``cap``) so the stream
    stays framed on the next newline.
    """
    while True:
        line = stream.readline(cap + 1)
        if not line:
            return
        if len(line) <= cap:
            yield line
            continue
        while line and not line.endswith(b"\n"):
            line = stream.readline(cap + 1)
        yield None


def encode(message: Any) -> bytes:
    """Serialize one JSON-RPC message as a single UTF-8 line."""
    text = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    return text.encode("utf-8") + b"\n"


def decode(line: bytes) -> Any:
    """Parse one line (raises ValueError on invalid UTF-8/JSON)."""
    return json.loads(line.decode("utf-8"), parse_constant=reject_constant)


def log(message: str) -> None:
    """Diagnostics go to ``stderr`` only (``stdout`` is the wire)."""
    print(f"aegis-stdio-wrap: {message}", file=sys.stderr, flush=True)


def _safe_id(value: Any) -> str | int | None:
    """Echo only a valid JSON-RPC id back to the host."""
    if isinstance(value, bool) or not isinstance(value, str | int):
        return None
    if isinstance(value, str) and len(value) > MAX_IDENTIFIER_LENGTH:
        return None
    return value


class StdioProxy:
    """Transport-agnostic firewalled relay between an MCP host and a server.

    ``write_child`` sends a line to the server's ``stdin``; ``write_client``
    sends a line to the host. Both directions may run on separate threads.
    """

    def __init__(
        self,
        gateway: JsonRpcGateway,
        context: CallContext,
        write_child: Writer,
        write_client: Writer,
        max_pending: int = MAX_PENDING_REQUESTS,
    ) -> None:
        """Bind the gateway pipeline, session context, and line writers."""
        self.gateway = gateway
        self.context = context
        self._write_child = write_child
        self._write_client = write_client
        self.max_pending = max_pending
        self.pending: dict[str | int, Envelope] = {}
        self._lock = threading.Lock()
        self._client_lock = threading.Lock()

    # -- output helpers --------------------------------------------------

    def send_client(self, message: Any) -> None:
        """Write one message to the host (serialized across threads)."""
        with self._client_lock:
            self._write_client(encode(message))

    def _reply_error(self, req_id: str | int | None, exc: JsonRpcError) -> None:
        """Answer the host with a JSON-RPC error object."""
        self.send_client(error_response(req_id, exc.to_object()))

    # -- client -> child -------------------------------------------------

    def handle_client_line(self, line: bytes | None) -> None:
        """Inspect one host line and forward or answer it."""
        if line is None:
            self._reply_error(None, JsonRpcError(INVALID_REQUEST, "Message too large."))
            return
        if not line.strip():
            return
        try:
            message = decode(line)
        except (ValueError, RecursionError):
            self._reply_error(None, JsonRpcError(PARSE_ERROR, "Parse error."))
            return
        self._dispatch_client(message)

    def _dispatch_client(self, message: Any) -> None:
        """Route a decoded host message by JSON-RPC kind."""
        if isinstance(message, dict) and "method" not in message:
            self._forward(redact_value(message))
        elif isinstance(message, dict) and "id" not in message:
            self._client_notification(message)
        else:
            self._client_request(message)

    def _client_notification(self, message: dict[str, Any]) -> None:
        """Forward redacted ``notifications/*``; drop anything else."""
        method = message.get("method")
        if isinstance(method, str) and method.startswith("notifications/"):
            self._forward(redact_value(message))

    def _client_request(self, message: Any) -> None:
        """Firewall a host request; blocked calls never reach the child."""
        req_id = _safe_id(message.get("id")) if isinstance(message, dict) else None
        try:
            envelope = parse_envelope(message)
            tool_name, params = resolve_call(envelope)
            self._track(envelope)
        except JsonRpcError as exc:
            self._reply_error(req_id, exc)
            return
        outbound = self._inspect(envelope, tool_name, params)
        if outbound is not None:
            self._send_request(envelope, outbound)

    def _inspect(
        self, envelope: Envelope, tool_name: str | None, params: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Run the gateway pipeline; on a block answer ``-32003`` and untrack."""
        try:
            return self.gateway.prepare(envelope, self.context, tool_name, params)
        except JsonRpcError as exc:
            error = exc
        except RecursionError:
            error = JsonRpcError(INVALID_REQUEST, "Request nesting too deep.")
        self._untrack(envelope.req_id)
        self._reply_error(envelope.req_id, error)
        return None

    def _track(self, envelope: Envelope) -> None:
        """Record an in-flight request so its reply can be screened."""
        with self._lock:
            if envelope.req_id in self.pending:
                raise JsonRpcError(INVALID_REQUEST, "Duplicate in-flight request id.")
            if len(self.pending) >= self.max_pending:
                raise JsonRpcError(GENERIC_SERVER_ERROR, "Too many in-flight requests.")
            self.pending[envelope.req_id] = envelope

    def _untrack(self, req_id: str | int) -> Envelope | None:
        """Forget an in-flight request."""
        with self._lock:
            return self.pending.pop(req_id, None)

    def _send_request(self, envelope: Envelope, params: dict[str, Any]) -> None:
        """Forward a sanitized request; a dead child yields ``-32004``."""
        outbound = {
            "jsonrpc": "2.0",
            "id": envelope.req_id,
            "method": envelope.method,
            "params": params,
        }
        if not self._forward(outbound):
            self._untrack(envelope.req_id)
            self._reply_error(envelope.req_id, upstream_failure())

    def _forward(self, message: Any) -> bool:
        """Write one message to the child; False if its stdin is gone."""
        try:
            self._write_child(encode(message))
        except (OSError, ValueError):
            return False
        return True

    # -- child -> client -------------------------------------------------

    def handle_child_line(self, line: bytes | None) -> None:
        """Screen one server line and relay it to the host."""
        if line is None:
            log("dropped oversized message from MCP server")
            return
        if not line.strip():
            return
        try:
            message = decode(line)
        except (ValueError, RecursionError):
            log("dropped malformed message from MCP server")
            return
        relayed = self._relay_child(message)
        if relayed is not None:
            self.send_client(relayed)

    def _relay_child(self, message: Any) -> Any:
        """Screen a decoded server message (or batch); None means drop."""
        if not isinstance(message, list):
            return self._relay_member(message)
        members = [self._relay_member(item) for item in message]
        kept = [member for member in members if member is not None]
        return kept or None

    def _relay_member(self, message: Any) -> Any:
        """Screen one server message."""
        if not isinstance(message, dict):
            return None
        if "method" in message:
            return redact_value(message)
        envelope = self._match(message.get("id"))
        if envelope is None:
            log("dropped server response with no matching request")
            return None
        return self._relay_response(envelope, message)

    def _match(self, req_id: Any) -> Envelope | None:
        """Pop the pending request a server response answers."""
        valid = _safe_id(req_id)
        return None if valid is None else self._untrack(valid)

    def _relay_response(
        self, envelope: Envelope, message: dict[str, Any]
    ) -> dict[str, Any]:
        """Toolguard-screen, DLP-redact and neutralize one server reply."""
        try:
            return self.gateway.relay(envelope, self.context, message)
        except JsonRpcError as exc:
            return error_response(envelope.req_id, exc.to_object())
        except RecursionError:
            return error_response(envelope.req_id, upstream_failure().to_object())

    def fail_pending(self) -> None:
        """Answer every unanswered request with ``-32004`` (child exited)."""
        with self._lock:
            orphaned = list(self.pending)
            self.pending.clear()
        for req_id in orphaned:
            self._reply_error(req_id, upstream_failure())

    # -- stream pumps ----------------------------------------------------

    def pump_client(self, stream: IO[bytes]) -> None:
        """Relay host lines until EOF."""
        for line in read_lines(stream, MAX_REQUEST_BYTES):
            self.handle_client_line(line)

    def pump_child(self, stream: IO[bytes]) -> None:
        """Relay server lines until EOF."""
        for line in read_lines(stream, MAX_UPSTREAM_BYTES):
            self.handle_child_line(line)


def new_session_id() -> str:
    """Mint the wrapper-lifetime session id (taint + ledger binding)."""
    return f"stdio-{secrets.token_hex(16)}"


def build_gateway(config: WrapConfig) -> JsonRpcGateway:
    """Build the firewall/toolguard pipeline (no HTTP upstreams)."""
    firewall = MCPFirewall(
        db_path=config.db_path,
        policy_engine=build_policy_engine(config.policy_path, config.environment),
    )
    return JsonRpcGateway(firewall, upstreams={})


def session_context(config: WrapConfig) -> CallContext:
    """Bind the wrapper identity to a fresh session."""
    return CallContext(
        agent_id=config.agent_id,
        server_name=config.server_name,
        environment=config.environment,
        session_id=new_session_id(),
    )


def spawn(command: list[str]) -> "subprocess.Popen[bytes]":
    """Spawn the MCP server without a shell and without Aegis secrets."""
    if not command or not all(isinstance(part, str) and part for part in command):
        raise ValueError("MCP server command must be a non-empty argv list.")
    # Explicit argv from the operator's own CLI, shell=False: no shell parsing.
    return subprocess.Popen(  # nosec B603
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,
        env=child_environment(os.environ),
        shell=False,
    )


def _writer(stream: IO[bytes]) -> Writer:
    """Return a line writer that flushes after every message."""

    def write(data: bytes) -> None:
        stream.write(data)
        stream.flush()

    return write


def _close_quietly(stream: IO[bytes]) -> None:
    """Close a pipe, ignoring an already-broken peer."""
    try:
        stream.close()
    except OSError:
        log("MCP server stdin was already closed")


def _relay(
    child: "subprocess.Popen[bytes]",
    proxy: StdioProxy,
    stdin: IO[bytes],
    child_stdout: IO[bytes],
) -> int:
    """Pump both directions until host EOF, then reap the child."""
    reader = threading.Thread(target=proxy.pump_child, args=(child_stdout,))
    reader.daemon = True
    reader.start()
    try:
        proxy.pump_client(stdin)
    finally:
        if child.stdin is not None:
            _close_quietly(child.stdin)
        returncode = child.wait()
        reader.join()
        child_stdout.close()
        proxy.fail_pending()
    return returncode


def run(config: WrapConfig, stdin: IO[bytes], stdout: IO[bytes]) -> int:
    """Relay ``stdin``/``stdout`` through the firewall to the spawned server."""
    try:
        child = spawn(config.command)
    except OSError as exc:
        log(f"cannot start MCP server: {exc.strerror or exc}")
        return 127
    if child.stdin is None or child.stdout is None:  # pragma: no cover
        child.kill()
        return 1
    gateway = build_gateway(config)
    proxy = StdioProxy(
        gateway, session_context(config), _writer(child.stdin), _writer(stdout)
    )
    try:
        return _relay(child, proxy, stdin, child.stdout)
    finally:
        gateway.client.close()


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    config = parse_args(argv)
    return run(config, sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
