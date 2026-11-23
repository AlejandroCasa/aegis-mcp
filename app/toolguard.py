"""MCP tool supply-chain defense: manifest pinning against rug-pull attacks.

Discovery responses (``initialize``, ``tools/list``, ``resources/list``,
``prompts/list``) are fingerprinted per definition with SHA-256 over the
RFC 8785 canonical JSON of its security-relevant fields and pinned in SQLite:

* **TOFU**: a definition seen for the first time is pinned as ``pending``.
* **Explicit approval**: ``POST /api/v1/toolguard/approve`` marks a pin
  ``approved`` (with ``AEGIS_TOOLGUARD_REQUIRE_APPROVAL=true`` pending tools
  and prompts cannot be called).
* **Drift (rug-pull)**: a later definition whose fingerprint differs from the
  pin is *sticky*: the pin records ``drift_fingerprint``, the definition is
  filtered out of discovery, and calls are blocked with
  ``tool_definition_drift`` until an operator approves either fingerprint.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from app.canonical import sha256_hex
from app.schemas import ToolPin

DRIFT_VIOLATION = "tool_definition_drift"
UNAPPROVED_VIOLATION = "tool_not_approved"
TOOLGUARD_RISK_SCORE = 100
MAX_DEFINITION_KEY_LENGTH = 1024

PinKind = Literal["server", "tool", "resource", "prompt"]
Verdict = Literal["pending", "approved", "drifted"]

FINGERPRINT_FIELDS: dict[str, tuple[str, ...]] = {
    "server": ("name", "serverName", "instructions"),
    "tool": ("name", "description", "inputSchema", "outputSchema", "annotations"),
    "resource": ("uri", "name", "description", "mimeType"),
    "prompt": ("name", "description", "arguments"),
}

LIST_METHODS: dict[str, tuple[PinKind, str]] = {
    "tools/list": ("tool", "tools"),
    "resources/list": ("resource", "resources"),
    "prompts/list": ("prompt", "prompts"),
}

_PIN_COLUMNS = (
    "server_name, kind, name, fingerprint, status, drift_fingerprint, "
    "first_seen, updated_at"
)


class PinNotFoundError(LookupError):
    """Raised when approving a definition that was never observed."""


class FingerprintMismatchError(ValueError):
    """Raised when an approval names neither the pinned nor drifted hash."""


def definition_key(kind: PinKind, definition: Any) -> str | None:
    """Return the identity of a definition (``uri`` for resources, else name)."""
    if not isinstance(definition, dict):
        return None
    key = definition.get("uri" if kind == "resource" else "name")
    if isinstance(key, str) and 0 < len(key) <= MAX_DEFINITION_KEY_LENGTH:
        return key
    return None


def fingerprint(kind: PinKind, definition: dict[str, Any]) -> str:
    """SHA-256 over the JCS form of the kind's security-relevant fields."""
    fields = FINGERPRINT_FIELDS[kind]
    return sha256_hex({field: definition.get(field) for field in fields})


def _now() -> str:
    """Return the current UTC time as ISO-8601."""
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class Observation:
    """Outcome of comparing one observed definition against its pin."""

    kind: PinKind
    name: str
    fingerprint: str
    verdict: Verdict
    first_seen: bool


def _row_to_pin(row: tuple[Any, ...]) -> ToolPin:
    """Convert a ``toolguard_pins`` row into the public ToolPin model."""
    return ToolPin(
        server_name=str(row[0]),
        kind=row[1],
        name=str(row[2]),
        fingerprint=str(row[3]),
        status=row[4],
        drift_fingerprint=None if row[5] is None else str(row[5]),
        first_seen=str(row[6]),
        updated_at=str(row[7]),
    )


class ToolGuard:
    """SQLite-backed TOFU pin store for MCP server, tool, resource, prompt defs."""

    def __init__(self, db_path: str, require_approval: bool = False) -> None:
        """Bind the pin store to ``db_path`` and create its table."""
        self.db_path = db_path
        self.require_approval = require_approval
        self._init_db()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        """Yield a cursor inside a ``BEGIN IMMEDIATE`` write transaction."""
        conn = sqlite3.connect(self.db_path, isolation_level=None)
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
        """Create the ``toolguard_pins`` table if missing."""
        with self._transaction() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS toolguard_pins (
                    server_name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    name TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    drift_fingerprint TEXT,
                    definition_json TEXT NOT NULL,
                    drift_json TEXT,
                    first_seen TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (server_name, kind, name)
                )
                """)

    def observe(
        self, server_name: str, kind: PinKind, definition: Any
    ) -> Observation | None:
        """Pin (TOFU) or compare one definition; None if it has no identity."""
        name = definition_key(kind, definition)
        if name is None:
            return None
        key = (server_name, kind, name)
        digest = fingerprint(kind, definition)
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT fingerprint, status, drift_fingerprint FROM toolguard_pins "
                "WHERE server_name = ? AND kind = ? AND name = ?",
                key,
            )
            row = cursor.fetchone()
            if row is None:
                self._insert(cursor, key, digest, definition)
                return Observation(kind, name, digest, "pending", True)
            pinned, status, drift = row
            if drift is None and digest == pinned:
                return Observation(kind, name, digest, status, False)
            if digest != pinned:
                self._record_drift(cursor, key, digest, definition)
            return Observation(kind, name, digest, "drifted", False)

    @staticmethod
    def _insert(
        cursor: sqlite3.Cursor,
        key: tuple[str, str, str],
        digest: str,
        definition: dict[str, Any],
    ) -> None:
        """Insert a new pending pin."""
        now = _now()
        cursor.execute(
            "INSERT INTO toolguard_pins (server_name, kind, name, fingerprint, "
            "status, drift_fingerprint, definition_json, drift_json, first_seen, "
            "updated_at) VALUES (?, ?, ?, ?, 'pending', NULL, ?, NULL, ?, ?)",
            (*key, digest, json.dumps(definition, sort_keys=True), now, now),
        )

    @staticmethod
    def _record_drift(
        cursor: sqlite3.Cursor,
        key: tuple[str, str, str],
        digest: str,
        definition: dict[str, Any],
    ) -> None:
        """Remember the latest drifted definition (drift is sticky)."""
        cursor.execute(
            "UPDATE toolguard_pins SET drift_fingerprint = ?, drift_json = ?, "
            "updated_at = ? WHERE server_name = ? AND kind = ? AND name = ?",
            (digest, json.dumps(definition, sort_keys=True), _now(), *key),
        )

    def call_violations(self, server_name: str, kind: PinKind, name: str) -> list[str]:
        """Return violations blocking a call to a pinned definition.

        Drifted pins always block. With ``require_approval`` pending or never
        listed tools/prompts block too (resources may be template-generated, so
        only their drift is enforced).
        """
        pin = self.get_pin(server_name, kind, name)
        if pin is not None and pin.drift_fingerprint is not None:
            return [DRIFT_VIOLATION]
        needs_approval = self.require_approval and kind in ("tool", "prompt")
        if needs_approval and (pin is None or pin.status != "approved"):
            return [UNAPPROVED_VIOLATION]
        return []

    def needs_approval(self, kind: PinKind, verdict: Verdict) -> bool:
        """Return True if an unapproved tool/prompt must stay hidden/blocked."""
        return (
            self.require_approval
            and kind in ("tool", "prompt")
            and verdict != "approved"
        )

    def get_pin(self, server_name: str, kind: PinKind, name: str) -> ToolPin | None:
        """Return one pin or None."""
        with self._transaction() as cursor:
            cursor.execute(
                f"SELECT {_PIN_COLUMNS} FROM toolguard_pins "  # nosec B608
                "WHERE server_name = ? AND kind = ? AND name = ?",
                (server_name, kind, name),
            )
            row = cursor.fetchone()
        return None if row is None else _row_to_pin(row)

    def list_pins(self, server_name: str | None = None) -> list[ToolPin]:
        """Return every pin, optionally for one server, in stable order."""
        query = f"SELECT {_PIN_COLUMNS} FROM toolguard_pins"  # nosec B608
        params: tuple[str, ...] = ()
        if server_name is not None:
            query += " WHERE server_name = ?"
            params = (server_name,)
        with self._transaction() as cursor:
            cursor.execute(query + " ORDER BY server_name, kind, name", params)
            rows = cursor.fetchall()
        return [_row_to_pin(row) for row in rows]

    def approve(
        self, server_name: str, kind: PinKind, name: str, digest: str
    ) -> ToolPin:
        """Approve the pinned or the drifted fingerprint, clearing drift.

        Approving the drifted fingerprint re-pins the new definition (accepted
        upgrade); approving the pinned one re-affirms the original definition.
        """
        key = (server_name, kind, name)
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT fingerprint, drift_fingerprint, definition_json, drift_json "
                "FROM toolguard_pins WHERE server_name = ? AND kind = ? AND name = ?",
                key,
            )
            row = cursor.fetchone()
            if row is None:
                raise PinNotFoundError(name)
            if digest not in (row[0], row[1]):
                raise FingerprintMismatchError(name)
            definition_json = row[3] if digest == row[1] else row[2]
            cursor.execute(
                "UPDATE toolguard_pins SET fingerprint = ?, status = 'approved', "
                "drift_fingerprint = NULL, drift_json = NULL, definition_json = ?, "
                "updated_at = ? WHERE server_name = ? AND kind = ? AND name = ?",
                (digest, definition_json, _now(), *key),
            )
        pin = self.get_pin(*key)
        assert pin is not None  # nosec B101 - row exists inside the same db
        return pin

    def reset(self) -> None:
        """Delete every pin (test isolation)."""
        with self._transaction() as cursor:
            cursor.execute("DELETE FROM toolguard_pins")
