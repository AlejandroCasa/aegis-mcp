"""TDD suite for the bounded Server-Sent Events codec."""

import json

import pytest

from app.sse import SseError, SseEvent, format_sse, iter_sse_events, safe_event_id


def test_events_are_parsed_per_the_event_stream_rules() -> None:
    """Multi-line data, names, ids, comments, and CRs are handled."""
    lines = [
        ": comment",
        "event: update",
        "id: 7",
        "data: first",
        "data:second\r",
        "",
        "data",
        "event:",
        "",
        "id: bad\x00id",
        "data: x",
        "",
        "retry: 10",
        "",
        "data: incomplete",
    ]
    assert list(iter_sse_events(lines)) == [
        SseEvent("first\nsecond", "update", "7"),
        SseEvent("", "message", None),
        SseEvent("x", "message", None),
    ]


def test_oversized_event_raises() -> None:
    """A hostile upstream cannot grow one event without bound."""
    with pytest.raises(SseError):
        list(iter_sse_events(["data: " + "a" * 20], max_event_bytes=10))


@pytest.mark.parametrize(
    ("event_id", "expected"),
    [("ev-1", "ev-1"), ("a b", None), ("x" * 129, None), (None, None)],
)
def test_safe_event_id(event_id: str | None, expected: str | None) -> None:
    """Only short header-safe ids are kept."""
    assert safe_event_id(event_id) == expected


def test_format_sse_round_trips() -> None:
    """Serialized messages parse back to the same JSON."""
    message = {"jsonrpc": "2.0", "method": "notifications/progress"}
    encoded = format_sse(message, "ev-1").decode()
    assert encoded.endswith("\n\n")
    events = list(iter_sse_events(encoded.split("\n")))
    assert events == [
        SseEvent(json.dumps(message, separators=(",", ":")), "message", "ev-1")
    ]
    assert "id:" not in format_sse(message, "bad id").decode()
    assert "id:" not in format_sse(message).decode()
