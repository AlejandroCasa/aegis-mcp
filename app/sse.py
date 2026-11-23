"""Minimal, bounded Server-Sent Events (SSE) codec for MCP Streamable HTTP.

Parses ``text/event-stream`` bodies line by line (WHATWG HTML "event stream
interpretation") and serializes JSON-RPC messages as SSE ``message`` events.
Incomplete events at end-of-stream are discarded, comments are ignored, and
each event's ``data`` is capped so a hostile upstream cannot exhaust memory.
"""

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

MAX_EVENT_BYTES = 5_242_880
EVENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:/+=-]{1,128}$")


class SseError(ValueError):
    """Raised for an oversized SSE event."""


@dataclass(frozen=True)
class SseEvent:
    """One dispatched SSE event."""

    data: str
    event: str = "message"
    event_id: str | None = None


@dataclass
class _Pending:
    """Fields accumulated for the event being parsed."""

    data: list[str] = field(default_factory=list)
    event: str = "message"
    event_id: str | None = None
    size: int = 0


def _apply_field(pending: _Pending, line: str, limit: int) -> None:
    """Apply one ``field: value`` line to the pending event."""
    name, _, value = line.partition(":")
    value = value.removeprefix(" ")
    if name == "data":
        pending.data.append(value)
        pending.size += len(value) + 1
        if pending.size > limit:
            raise SseError("SSE event exceeds the size limit.")
    elif name == "event":
        pending.event = value or "message"
    elif name == "id" and "\x00" not in value:
        pending.event_id = value


def iter_sse_events(
    lines: Iterable[str], max_event_bytes: int = MAX_EVENT_BYTES
) -> Iterator[SseEvent]:
    """Yield SSE events from decoded lines (line terminators already removed)."""
    pending = _Pending()
    for raw in lines:
        line = raw.rstrip("\r")
        if not line:
            if pending.data:
                yield SseEvent("\n".join(pending.data), pending.event, pending.event_id)
            pending = _Pending()
        elif not line.startswith(":"):
            _apply_field(pending, line, max_event_bytes)


def safe_event_id(event_id: str | None) -> str | None:
    """Return ``event_id`` only if it is a short, header-safe token."""
    if event_id is not None and EVENT_ID_PATTERN.fullmatch(event_id):
        return event_id
    return None


def format_sse(message: Any, event_id: str | None = None) -> bytes:
    """Serialize one JSON-RPC message as an SSE ``message`` event."""
    lines = ["event: message"]
    safe_id = safe_event_id(event_id)
    if safe_id is not None:
        lines.append(f"id: {safe_id}")
    lines.append("data: " + json.dumps(message, separators=(",", ":")))
    return ("\n".join(lines) + "\n\n").encode("utf-8")
