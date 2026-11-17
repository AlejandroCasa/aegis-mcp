"""Zero-Trust MCP Firewall and SHA-256 hash-chained SQLite audit ledger."""

import hashlib
import json
import re
import sqlite3
from typing import Any, Literal

from app.config import settings
from app.redactor import redact_payload
from app.schemas import (
    AuditEntry,
    ChainVerificationResponse,
    MCPInspectionResponse,
    MCPToolCallRequest,
)

GENESIS_HASH = "0" * 64

THREAT_RULES: tuple[tuple[str, int, re.Pattern[str]], ...] = (
    (
        "prompt_injection",
        90,
        re.compile(
            r"(?:ignore\s+(?:all\s+)?previous\s+instructions|"
            r"system\s+prompt\s*:|<\|im_start\|>|override\s+security\s+policy)",
            re.IGNORECASE,
        ),
    ),
    (
        "path_traversal",
        85,
        re.compile(
            r"(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|\.ssh/id_rsa|\.env\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "destructive_sql",
        80,
        re.compile(
            r"(?:\bDROP\s+TABLE\b|\bTRUNCATE\s+TABLE\b|"
            r"\bDELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1)",
            re.IGNORECASE,
        ),
    ),
    (
        "command_injection",
        95,
        re.compile(
            r"(?:\brm\s+-rf\b|;\s*(?:curl|wget|bash|sh)\b|"
            r"\|\s*(?:bash|sh)\b|\$\([^)]+\))",
            re.IGNORECASE,
        ),
    ),
)


def compute_entry_hash(
    prev_hash: str,
    timestamp_iso: str,
    agent_id: str,
    server_name: str,
    tool_name: str,
    decision: str,
    risk_score: int,
) -> str:
    """Compute deterministic SHA-256 hash linking the audit record to prev_hash."""
    canonical = (
        f"{prev_hash}|{timestamp_iso}|{agent_id}|"
        f"{server_name}|{tool_name}|{decision}|{risk_score}"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def evaluate_threats(payload_text: str) -> tuple[int, list[str]]:
    """Scan serialized tool arguments against deterministic Zero-Trust threat rules."""
    violations: list[str] = []
    max_score = 0

    for rule_name, score, pattern in THREAT_RULES:
        if pattern.search(payload_text):
            violations.append(rule_name)
            if score > max_score:
                max_score = score

    return max_score, violations


class MCPFirewall:
    """Inspects MCP tool calls, applies DLP redaction, and maintains a hash chain."""

    def __init__(self, db_path: str | None = None) -> None:
        """Initialize SQLite tamper-evident audit ledger."""
        self.db_path = db_path or settings.db_path
        self._init_db()

    def _init_db(self) -> None:
        """Create the audit_ledger table if it does not exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_ledger (
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
                """)
            conn.commit()

    def _get_last_hash(self, cursor: sqlite3.Cursor) -> str:
        """Fetch the most recent entry_hash or return the genesis hash."""
        cursor.execute("SELECT entry_hash FROM audit_ledger ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        return str(row[0]) if row else GENESIS_HASH

    def inspect(self, request: MCPToolCallRequest) -> MCPInspectionResponse:
        """Inspect an MCP tool call, redact PII/secrets, and append to hash ledger."""
        raw_serialized = json.dumps(request.arguments, sort_keys=True)
        risk_score, violations = evaluate_threats(raw_serialized)

        sanitized_args: dict[str, Any] = dict(request.arguments)
        redacted_categories: list[str] = []
        if settings.enable_dlp_redaction:
            sanitized_args, redacted_categories = redact_payload(request.arguments)
            if redacted_categories and risk_score < 25:
                risk_score = 25

        allowed = risk_score < settings.block_threshold_score
        decision: Literal["ALLOWED", "SANITIZED", "BLOCKED"] = "ALLOWED"
        if not allowed:
            decision = "BLOCKED"
        elif redacted_categories:
            decision = "SANITIZED"

        ts_iso = request.timestamp.isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            prev_hash = self._get_last_hash(cursor)
            entry_hash = compute_entry_hash(
                prev_hash=prev_hash,
                timestamp_iso=ts_iso,
                agent_id=request.agent_id,
                server_name=request.server_name,
                tool_name=request.tool_name,
                decision=decision,
                risk_score=risk_score,
            )
            cursor.execute(
                """
                INSERT INTO audit_ledger (
                    agent_id, server_name, tool_name, environment,
                    decision, risk_score, violations_json, redacted_json,
                    prev_hash, entry_hash, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.agent_id,
                    request.server_name,
                    request.tool_name,
                    request.environment,
                    decision,
                    risk_score,
                    json.dumps(violations),
                    json.dumps(redacted_categories),
                    prev_hash,
                    entry_hash,
                    ts_iso,
                ),
            )
            conn.commit()

        return MCPInspectionResponse(
            allowed=allowed,
            decision=decision,
            risk_score=risk_score,
            violations=violations,
            redacted_categories=redacted_categories,
            sanitized_arguments=sanitized_args if allowed else {},
            audit_hash=entry_hash,
            prev_hash=prev_hash,
            timestamp=request.timestamp,
        )

    def list_audit_entries(self, agent_id: str | None = None) -> list[AuditEntry]:
        """Return persisted audit entries, optionally filtered by agent_id."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if agent_id:
                cursor.execute(
                    "SELECT id, agent_id, server_name, tool_name, environment, "
                    "decision, risk_score, violations_json, redacted_json, "
                    "prev_hash, entry_hash, timestamp "
                    "FROM audit_ledger WHERE agent_id = ? ORDER BY id ASC",
                    (agent_id,),
                )
            else:
                cursor.execute(
                    "SELECT id, agent_id, server_name, tool_name, environment, "
                    "decision, risk_score, violations_json, redacted_json, "
                    "prev_hash, entry_hash, timestamp "
                    "FROM audit_ledger ORDER BY id ASC"
                )
            rows = cursor.fetchall()

        entries: list[AuditEntry] = []
        for row in rows:
            entries.append(
                AuditEntry(
                    id=int(row[0]),
                    agent_id=str(row[1]),
                    server_name=str(row[2]),
                    tool_name=str(row[3]),
                    environment=str(row[4]),
                    decision=row[5],
                    risk_score=int(row[6]),
                    violations=list(json.loads(str(row[7]))),
                    redacted_categories=list(json.loads(str(row[8]))),
                    prev_hash=str(row[9]),
                    entry_hash=str(row[10]),
                    timestamp=str(row[11]),
                )
            )
        return entries

    def verify_chain(self) -> ChainVerificationResponse:
        """Verify cryptographic integrity of every SHA-256 link in the audit ledger."""
        entries = self.list_audit_entries()
        expected_prev = GENESIS_HASH

        for entry in entries:
            recomputed = compute_entry_hash(
                prev_hash=expected_prev,
                timestamp_iso=entry.timestamp,
                agent_id=entry.agent_id,
                server_name=entry.server_name,
                tool_name=entry.tool_name,
                decision=entry.decision,
                risk_score=entry.risk_score,
            )
            if entry.prev_hash != expected_prev or entry.entry_hash != recomputed:
                return ChainVerificationResponse(
                    valid=False,
                    total_entries=len(entries),
                    head_hash=entries[-1].entry_hash,
                    corrupted_entry_id=entry.id,
                )
            expected_prev = entry.entry_hash

        return ChainVerificationResponse(
            valid=True,
            total_entries=len(entries),
            head_hash=expected_prev,
            corrupted_entry_id=None,
        )

    def close(self) -> None:
        """Flush SQLite connection on graceful shutdown."""
        with sqlite3.connect(self.db_path) as conn:
            conn.commit()

    def reset(self) -> None:
        """Clear audit ledger table for deterministic test isolation."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM audit_ledger")
            conn.commit()
