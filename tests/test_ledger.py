"""TDD suite for the v2 full-payload audit ledger and the v1 -> v2 migration."""

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from app import ledger as ledger_module
from app.firewall import MCPFirewall
from app.ledger import (
    GENESIS_HASH,
    LEDGER_HASH_VERSION,
    AuditLedger,
    LedgerRecord,
    compute_entry_hash,
    compute_entry_hash_v2,
    digest_arguments,
)
from app.schemas import MCPToolCallRequest

LEGACY_SCHEMA = """
    CREATE TABLE audit_ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        server_name TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        environment TEXT NOT NULL,
        decision TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        violations_json TEXT NOT NULL,
        redacted_json TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )
"""


LEGACY_ROW = ("legacy", "git-mcp", "git_log", "prod", "ALLOWED", 0, "[]", "[]")


def _record(**overrides: Any) -> LedgerRecord:
    fields: dict[str, Any] = {
        "agent_id": "agent-1",
        "server_name": "git-mcp",
        "tool_name": "git_status",
        "environment": "prod",
        "decision": "SANITIZED",
        "risk_score": 0,
        "violations": ["prompt_injection"],
        "redacted_categories": ["email"],
        "timestamp": "2026-11-23T12:00:00+00:00",
        "would_block": False,
        "policy_mode": "enforce",
        "policy_version": "a" * 64,
        "session_id": "session-1",
        "args_digest": digest_arguments({"path": "README.md"}),
    }
    fields.update(overrides)
    return LedgerRecord(**fields)


def _legacy_db(path: Path, rows: int) -> list[str]:
    """Create a pre-migration (v1) ledger and return its entry hashes."""
    hashes: list[str] = []
    prev = GENESIS_HASH
    with sqlite3.connect(path) as conn:
        conn.execute(LEGACY_SCHEMA)
        for index in range(rows):
            timestamp = f"2026-11-17T10:00:0{index}+00:00"
            entry = compute_entry_hash(
                prev, timestamp, "legacy", "git-mcp", "git_log", "ALLOWED", 0
            )
            conn.execute(
                "INSERT INTO audit_ledger (agent_id, server_name, tool_name, "
                "environment, decision, risk_score, violations_json, "
                "redacted_json, prev_hash, entry_hash, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (*LEGACY_ROW, prev, entry, timestamp),
            )
            hashes.append(entry)
            prev = entry
    return hashes


def _update(path: Path, assignment: str, value: Any, row_id: int = 1) -> None:
    with sqlite3.connect(path) as conn:
        # Test-only: assignment strings are literals from this module.
        conn.execute(
            f"UPDATE audit_ledger SET {assignment} = ? WHERE id = ?",  # nosec B608
            (value, row_id),
        )


@pytest.fixture
def ledger(tmp_path: Path) -> AuditLedger:
    instance = AuditLedger(str(tmp_path / "ledger.db"))
    instance.init()
    return instance


def test_append_writes_v2_links(ledger: AuditLedger) -> None:
    """New entries are v2 and chained from the genesis hash."""
    prev, entry = ledger.append(_record())
    assert prev == GENESIS_HASH
    stored = ledger.list_entries()[0]
    assert stored.hash_version == LEDGER_HASH_VERSION
    assert stored.entry_hash == entry == compute_entry_hash_v2(prev, _record())
    assert stored.session_id == "session-1"
    assert ledger.append(_record())[0] == entry
    report = ledger.verify()
    assert report.valid
    assert report.total_entries == 2
    assert report.legacy_entries == 0


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("violations_json", "[]"),
        ("redacted_json", "[]"),
        ("policy_version", "b" * 64),
        ("policy_mode", "monitor"),
        ("would_block", 1),
        ("session_id", "session-2"),
        ("args_digest", "0" * 64),
        ("environment", "dev"),
        ("risk_score", 99),
        ("prev_hash", "f" * 64),
    ],
)
def test_v2_detects_tampering_of_every_bound_field(
    ledger: AuditLedger, tmp_path: Path, column: str, value: Any
) -> None:
    """Editing any bound column (not just the v1 subset) breaks the chain."""
    ledger.append(_record())
    ledger.append(_record())
    _update(tmp_path / "ledger.db", column, value)
    report = ledger.verify()
    assert not report.valid
    assert report.corrupted_entry_id == 1


def test_entry_hash_v2_is_sensitive_to_session_binding() -> None:
    """The session id and argument digest are part of the link."""
    base = compute_entry_hash_v2(GENESIS_HASH, _record())
    assert base != compute_entry_hash_v2(GENESIS_HASH, _record(session_id="x"))
    assert base != compute_entry_hash_v2(GENESIS_HASH, _record(args_digest="0"))
    assert base == compute_entry_hash_v2(GENESIS_HASH, _record())


def test_v1_ledger_migrates_and_continues_with_v2(tmp_path: Path) -> None:
    """Legacy rows keep their v1 links; the chain continues with v2."""
    path = tmp_path / "legacy.db"
    legacy_hashes = _legacy_db(path, rows=3)
    ledger = AuditLedger(str(path))
    ledger.init()
    ledger.init()  # idempotent
    report = ledger.verify()
    assert report.valid
    assert report.legacy_entries == 3
    assert report.head_hash == legacy_hashes[-1]
    prev, _ = ledger.append(_record())
    assert prev == legacy_hashes[-1]
    entries = ledger.list_entries()
    assert [entry.hash_version for entry in entries] == [1, 1, 1, 2]
    assert entries[0].session_id == ""
    assert entries[0].args_digest == ""
    report = ledger.verify()
    assert report.valid
    assert report.total_entries == 4
    assert report.legacy_entries == 3


def test_v1_entries_remain_verifiable_against_tampering(tmp_path: Path) -> None:
    """Migration never re-hashes history: v1 tampering is still detected."""
    path = tmp_path / "legacy.db"
    _legacy_db(path, rows=2)
    ledger = AuditLedger(str(path))
    ledger.init()
    ledger.append(_record())
    _update(path, "decision", "BLOCKED", row_id=2)
    report = ledger.verify()
    assert not report.valid
    assert report.corrupted_entry_id == 2


def test_downgrade_to_v1_after_v2_is_rejected(
    ledger: AuditLedger, tmp_path: Path
) -> None:
    """A correctly computed v1 link after a v2 link is a downgrade attack."""
    _, head = ledger.append(_record())
    forged = compute_entry_hash(
        head, "2026-11-23T13:00:00+00:00", "a", "s", "t", "ALLOWED", 0
    )
    with sqlite3.connect(tmp_path / "ledger.db") as conn:
        conn.execute(
            "INSERT INTO audit_ledger (agent_id, server_name, tool_name, "
            "environment, decision, risk_score, violations_json, redacted_json, "
            "prev_hash, entry_hash, timestamp, hash_version) "
            "VALUES ('a', 's', 't', 'prod', 'ALLOWED', 0, '[]', '[]', ?, ?, "
            "'2026-11-23T13:00:00+00:00', 1)",
            (head, forged),
        )
    report = ledger.verify()
    assert not report.valid
    assert report.corrupted_entry_id == 2


def test_unknown_hash_version_is_rejected(ledger: AuditLedger, tmp_path: Path) -> None:
    """Only versions 1 and 2 are accepted."""
    ledger.append(_record())
    _update(tmp_path / "ledger.db", "hash_version", 3)
    assert not ledger.verify().valid


def test_wal_journal_mode(tmp_path: Path) -> None:
    """WAL is enabled by default and can be disabled."""
    wal = AuditLedger(str(tmp_path / "wal.db"))
    wal.init()
    assert wal.journal_mode() == "wal"
    plain = AuditLedger(str(tmp_path / "plain.db"), wal=False)
    plain.init()
    assert plain.journal_mode() == "delete"


def test_failed_append_rolls_back(
    ledger: AuditLedger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure inside the write transaction leaves the chain untouched."""

    def explode(*args: Any) -> tuple[Any, ...]:
        raise RuntimeError("disk full")

    monkeypatch.setattr(ledger_module, "_insert_values", explode)
    with pytest.raises(RuntimeError):
        ledger.append(_record())
    monkeypatch.undo()
    assert ledger.list_entries() == []
    assert ledger.append(_record())[0] == GENESIS_HASH


def test_reset_and_agent_filter(ledger: AuditLedger) -> None:
    """Entries can be filtered by agent and wiped for test isolation."""
    ledger.append(_record())
    ledger.append(_record(agent_id="agent-2"))
    assert [e.agent_id for e in ledger.list_entries("agent-2")] == ["agent-2"]
    ledger.reset()
    assert ledger.list_entries() == []


def test_digest_arguments_falls_back_for_non_jcs_values() -> None:
    """Values JCS cannot encode (NaN) still get a stable digest."""
    value = {"ratio": float("nan")}
    expected = hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    assert digest_arguments(value) == expected
    assert digest_arguments({"a": 1}) != digest_arguments({"a": 2})


def test_firewall_binds_sanitized_argument_digest(tmp_path: Path) -> None:
    """The firewall stores the digest of the sanitized (not raw) arguments."""
    firewall = MCPFirewall(db_path=str(tmp_path / "fw.db"))
    secret = "sk-" + "c" * 24
    report = firewall.inspect(
        MCPToolCallRequest(
            agent_id="agent-1",
            server_name="git-mcp",
            tool_name="git_status",
            arguments={"token": secret},
        ),
        session_id="sess-9",
    )
    entry = firewall.list_audit_entries()[-1]
    assert entry.args_digest == digest_arguments(report.sanitized_arguments)
    assert entry.args_digest != digest_arguments({"token": secret})
    assert entry.session_id == "sess-9"
    assert firewall.verify_chain().valid
