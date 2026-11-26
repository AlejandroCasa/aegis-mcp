"""Human-in-the-loop (HITL) approval queue for ``require_approval`` tool calls.

A call whose policy action is ``require_approval`` is bound to an
:class:`ApprovalKey` (agent, server, tool, environment and the RFC 8785
SHA-256 of its arguments) and parked as a ``pending`` request in SQLite:

* ``pending`` requests expire after the configured TTL (``expired``).
* An operator resolves a request ``approved`` or ``denied``; an approval is a
  **single-use, TTL-bound token**: it is redeemed (``consumed_at``) by the
  first re-invocation with identical arguments (or its explicit
  ``approval_id``) and expires unredeemed after the TTL.
* Denied, expired, or still-pending requests fail closed.

The store is async-safe: every operation opens its own connection inside a
``BEGIN IMMEDIATE`` transaction (serializing claim/consume races across
threads and processes) and the blocking poll loop only runs in worker
threads (FastAPI threadpool), never on the event loop.
"""

import json
import sqlite3
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from app.redactor import redact_payload
from app.schemas import ApprovalStatus, HitlApproval

HITL_REQUIRED_VIOLATION = "hitl_approval_required"
HITL_TIMEOUT_VIOLATION = "hitl_approval_timeout"
HITL_DENIED_VIOLATION = "hitl_approval_denied"
HITL_GRANTED_EVENT = "hitl_approval_granted"
HITL_RISK_SCORE = 50
HITL_DENIED_RISK_SCORE = 100
POLL_INTERVAL_SECONDS = 0.05
MAX_LIST_LIMIT = 500

_COLUMNS = (
    "id, agent_id, server_name, tool_name, environment, arguments_hash, "
    "sanitized_arguments, session_id, status, created_at, expires_at, "
    "resolved_by, resolved_at, reason, consumed_at"
)
_KEY_FILTER = (
    "agent_id = ? AND server_name = ? AND tool_name = ? AND environment = ? "
    "AND arguments_hash = ?"
)

Clock = Callable[[], datetime]


class ApprovalNotFoundError(LookupError):
    """Raised when resolving an approval request that does not exist."""


class ApprovalConflictError(ValueError):
    """Raised when resolving a request that is no longer pending."""


@dataclass(frozen=True)
class ApprovalKey:
    """Identity an approval is bound to (scope plus arguments digest)."""

    agent_id: str
    server_name: str
    tool_name: str
    environment: str
    arguments_hash: str

    def params(self) -> tuple[str, str, str, str, str]:
        """Return the SQL parameters matching ``_KEY_FILTER``."""
        return (
            self.agent_id,
            self.server_name,
            self.tool_name,
            self.environment,
            self.arguments_hash,
        )


@dataclass(frozen=True)
class HitlOutcome:
    """Verdict of the HITL gate for one inspected call."""

    violations: tuple[str, ...] = ()
    risk_score: int = 0
    blocking: bool = False
    approval: HitlApproval | None = None
    created: bool = False

    def response_fields(self) -> dict[str, Any]:
        """``approval_id`` / ``approval_status`` for the inspection response."""
        if self.approval is None:
            return {"approval_id": None, "approval_status": None}
        return {
            "approval_id": self.approval.id,
            "approval_status": self.approval.status,
        }


def gate_outcome(approval: HitlApproval, created: bool, waited: bool) -> HitlOutcome:
    """Map an approval's status to the fail-closed gate verdict.

    ``approved`` (already redeemed by the caller) allows; ``denied`` blocks
    with ``hitl_approval_denied``; ``expired`` or a pending request that
    outlived the wait window blocks with ``hitl_approval_timeout``; any other
    pending request blocks with ``hitl_approval_required``.
    """
    if approval.status == "approved":
        return HitlOutcome(approval=approval, created=created)
    if approval.status == "denied":
        return HitlOutcome(
            (HITL_DENIED_VIOLATION,), HITL_DENIED_RISK_SCORE, True, approval, created
        )
    timed_out = approval.status == "expired" or waited
    code = HITL_TIMEOUT_VIOLATION if timed_out else HITL_REQUIRED_VIOLATION
    return HitlOutcome((code,), HITL_RISK_SCORE, True, approval, created)


def monitor_outcome() -> HitlOutcome:
    """Shadow verdict: audit ``hitl_approval_required`` without queueing."""
    return HitlOutcome((HITL_REQUIRED_VIOLATION,), HITL_RISK_SCORE, True)


def _iso(moment: datetime) -> str:
    """Fixed-width ISO-8601 UTC (lexicographically ordered in SQLite)."""
    return moment.astimezone(UTC).isoformat(timespec="microseconds")


def _system_clock() -> datetime:
    """Return the current UTC time."""
    return datetime.now(UTC)


def _optional(value: Any) -> str | None:
    """Return ``value`` as str, preserving SQL NULL."""
    return None if value is None else str(value)


def _row_to_approval(row: tuple[Any, ...]) -> HitlApproval:
    """Convert a ``hitl_approvals`` row into the public model."""
    arguments = json.loads(str(row[6]))
    return HitlApproval(
        id=str(row[0]),
        agent_id=str(row[1]),
        server_name=str(row[2]),
        tool_name=str(row[3]),
        environment=str(row[4]),
        arguments_hash=str(row[5]),
        sanitized_arguments=arguments if isinstance(arguments, dict) else {},
        session_id=str(row[7]),
        status=row[8],
        created_at=str(row[9]),
        expires_at=str(row[10]),
        resolved_by=_optional(row[11]),
        resolved_at=_optional(row[12]),
        reason=_optional(row[13]),
        consumed_at=_optional(row[14]),
    )


class ApprovalQueue:
    """SQLite-backed queue of pending / resolved HITL approval requests."""

    def __init__(
        self, db_path: str, ttl_seconds: int = 900, clock: Clock | None = None
    ) -> None:
        """Bind the queue to ``db_path`` and create its table."""
        self.db_path = db_path
        self.ttl = timedelta(seconds=ttl_seconds)
        self._clock = clock or _system_clock
        self._init_db()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        """Yield a cursor inside a ``BEGIN IMMEDIATE`` write transaction."""
        conn = sqlite3.connect(self.db_path, isolation_level=None, timeout=30.0)
        try:
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            try:
                yield cursor
            except BaseException:
                cursor.execute("ROLLBACK")
                raise
            cursor.execute("COMMIT")
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create the ``hitl_approvals`` table and its lookup index."""
        with self._transaction() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hitl_approvals (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    server_name TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    arguments_hash TEXT NOT NULL,
                    sanitized_arguments TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    resolved_by TEXT,
                    resolved_at TEXT,
                    reason TEXT,
                    consumed_at TEXT
                )
                """)
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_hitl_approvals_key ON hitl_approvals "
                "(agent_id, server_name, tool_name, environment, arguments_hash, "
                "status)"
            )

    def _now(self) -> datetime:
        """Return the queue clock's current UTC time."""
        return self._clock()

    @staticmethod
    def _expire(cursor: sqlite3.Cursor, now: str) -> None:
        """Expire overdue pending requests and unredeemed approvals."""
        cursor.execute(
            "UPDATE hitl_approvals SET status = 'expired' WHERE expires_at <= ? "
            "AND (status = 'pending' OR (status = 'approved' "
            "AND consumed_at IS NULL))",
            (now,),
        )

    @staticmethod
    def _fetch(cursor: sqlite3.Cursor, where: str, params: tuple[Any, ...]) -> Any:
        """Return the newest row matching a constant ``where`` clause."""
        cursor.execute(
            f"SELECT {_COLUMNS} FROM hitl_approvals WHERE {where} "  # nosec B608
            "ORDER BY created_at DESC LIMIT 1",
            params,
        )
        return cursor.fetchone()

    def submit(
        self, key: ApprovalKey, sanitized_arguments: dict[str, Any], session_id: str
    ) -> tuple[HitlApproval, bool]:
        """Register a pending request; reuse a live identical one.

        Returns ``(approval, created)``. Stored arguments are always passed
        through DLP redaction, even when inbound redaction is disabled.
        """
        now = self._now()
        stamp = _iso(now)
        redacted, _ = redact_payload(sanitized_arguments)
        with self._transaction() as cursor:
            self._expire(cursor, stamp)
            row = self._fetch(
                cursor, f"{_KEY_FILTER} AND status = 'pending'", key.params()
            )
            if row is not None:
                return _row_to_approval(row), False
            approval_id = uuid.uuid4().hex
            cursor.execute(
                f"INSERT INTO hitl_approvals ({_COLUMNS}) "  # nosec B608
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, NULL, NULL, "
                "NULL, NULL)",
                (
                    approval_id,
                    *key.params(),
                    json.dumps(redacted, sort_keys=True, ensure_ascii=False),
                    session_id,
                    stamp,
                    _iso(now + self.ttl),
                ),
            )
            row = self._fetch(cursor, "id = ?", (approval_id,))
        return _row_to_approval(row), True

    def claim(
        self, key: ApprovalKey, approval_id: str | None = None
    ) -> HitlApproval | None:
        """Redeem a granted approval or return the live request for ``key``.

        An explicit ``approval_id`` bound to ``key`` is returned whatever its
        status (redeemed if approved). Otherwise the oldest unredeemed
        approval for ``key`` is redeemed, else the newest pending request is
        returned. Redemption is atomic and single-use; ``None`` means nothing
        usable exists.
        """
        stamp = _iso(self._now())
        with self._transaction() as cursor:
            self._expire(cursor, stamp)
            row = self._claim_row(cursor, key, approval_id)
            if row is None:
                return None
            approval = _row_to_approval(row)
            if approval.status != "approved":
                return approval
            if approval.consumed_at is not None:
                return None
            cursor.execute(
                "UPDATE hitl_approvals SET consumed_at = ? WHERE id = ?",
                (stamp, approval.id),
            )
        return approval.model_copy(update={"consumed_at": stamp})

    def _claim_row(
        self, cursor: sqlite3.Cursor, key: ApprovalKey, approval_id: str | None
    ) -> Any:
        """Select the row :meth:`claim` acts on (see its docstring)."""
        if approval_id is not None:
            row = self._fetch(
                cursor, f"id = ? AND {_KEY_FILTER}", (approval_id, *key.params())
            )
            if row is not None:
                return row
        cursor.execute(
            f"SELECT {_COLUMNS} FROM hitl_approvals WHERE {_KEY_FILTER} "  # nosec B608
            "AND status = 'approved' AND consumed_at IS NULL "
            "ORDER BY resolved_at ASC LIMIT 1",
            key.params(),
        )
        row = cursor.fetchone()
        if row is not None:
            return row
        return self._fetch(
            cursor, f"{_KEY_FILTER} AND status = 'pending'", key.params()
        )

    def wait(
        self, key: ApprovalKey, approval_id: str, timeout: float
    ) -> HitlApproval | None:
        """Poll (blocking, worker threads only) until resolved or ``timeout``."""
        deadline = time.monotonic() + timeout
        approval = self.claim(key, approval_id)
        while approval is not None and approval.status == "pending":
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(POLL_INTERVAL_SECONDS, remaining))
            approval = self.claim(key, approval_id)
        return approval

    def resolve(
        self,
        approval_id: str,
        status: Literal["approved", "denied"],
        resolved_by: str,
        reason: str | None = None,
    ) -> HitlApproval:
        """Approve or deny a pending request (approvals get a fresh TTL)."""
        now = self._now()
        stamp = _iso(now)
        clean_reason = None
        if reason is not None:
            clean_reason = str(redact_payload({"reason": reason})[0]["reason"])
        with self._transaction() as cursor:
            self._expire(cursor, stamp)
            row = self._fetch(cursor, "id = ?", (approval_id,))
            if row is None:
                raise ApprovalNotFoundError(approval_id)
            if row[8] != "pending":
                raise ApprovalConflictError(str(row[8]))
            cursor.execute(
                "UPDATE hitl_approvals SET status = ?, resolved_by = ?, "
                "resolved_at = ?, reason = ?, expires_at = ? WHERE id = ?",
                (
                    status,
                    resolved_by,
                    stamp,
                    clean_reason,
                    _iso(now + self.ttl),
                    approval_id,
                ),
            )
            row = self._fetch(cursor, "id = ?", (approval_id,))
        return _row_to_approval(row)

    def get(self, approval_id: str) -> HitlApproval | None:
        """Return one approval request (expiry applied) or None."""
        with self._transaction() as cursor:
            self._expire(cursor, _iso(self._now()))
            row = self._fetch(cursor, "id = ?", (approval_id,))
        return None if row is None else _row_to_approval(row)

    def list_requests(
        self, status: ApprovalStatus | None = None, limit: int = 100
    ) -> list[HitlApproval]:
        """Return the newest requests, optionally filtered by status."""
        query = f"SELECT {_COLUMNS} FROM hitl_approvals"  # nosec B608
        params: tuple[Any, ...] = ()
        if status is not None:
            query += " WHERE status = ?"
            params = (status,)
        bounded = max(1, min(limit, MAX_LIST_LIMIT))
        with self._transaction() as cursor:
            self._expire(cursor, _iso(self._now()))
            cursor.execute(
                query + " ORDER BY created_at DESC LIMIT ?", (*params, bounded)
            )
            rows = cursor.fetchall()
        return [_row_to_approval(row) for row in rows]

    def reset(self) -> None:
        """Delete every approval request (test isolation)."""
        with self._transaction() as cursor:
            cursor.execute("DELETE FROM hitl_approvals")
