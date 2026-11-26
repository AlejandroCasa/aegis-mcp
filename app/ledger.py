"""Tamper-evident SQLite audit ledger with full-payload hash binding (v2).

Every decision is appended to a SHA-256 hash chain. Two link formats exist:

* **v1** (legacy, ``hash_version = 1``): ``SHA-256(prev_hash | timestamp |
  agent_id | server_name | tool_name | decision | risk_score)``. It does not
  bind violations, DLP categories, or the policy version, so those columns
  could be edited without breaking the chain.
* **v2** (``hash_version = 2``, written by this release): SHA-256 over the
  RFC 8785 (JCS) canonical JSON of the *full* entry: ``prev_hash``,
  ``timestamp``, identity/scope, ``decision``, ``risk_score``,
  ``violations``, ``redacted_categories``, ``args_digest`` (JCS SHA-256 of
  the sanitized arguments; raw secrets never reach the ledger),
  ``policy_version``, ``policy_mode``, ``would_block`` and ``session_id``.

**Migration (v1 -> v2)** is additive and preserves evidence: new columns are
added with defaults (``hash_version = 1`` for existing rows), historical
links are *not* re-hashed (re-hashing would launder tampering), and the
chain simply continues with v2 links whose ``prev_hash`` is the last v1
hash. Verification checks each link with its own format and rejects any v1
link after the first v2 link (no downgrade attacks) or unknown versions.

The database runs in WAL mode (``AEGIS_LEDGER_WAL``) so readers never block
the single writer; appends take ``BEGIN IMMEDIATE`` before reading the head
so concurrent writers can never fork the chain.

**Merkle checkpoints** (``merkle_checkpoints`` table): with a
``CheckpointSigner`` the ledger signs an RFC 6962 Signed Tree Head over all
entry hashes every ``checkpoint_interval`` appends (inside the append
transaction, so a checkpoint always covers a consistent prefix) or on
demand, and serves O(log n) inclusion proofs (see ``app/merkle.py``).
"""

import bisect
import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from app.canonical import sha256_hex
from app.merkle import (
    GENESIS_CHECKPOINT_HASH,
    CheckpointSigner,
    SignedTreeHead,
    TreeHead,
    inclusion_proof,
    merkle_root,
)
from app.metrics import metrics_registry
from app.schemas import AuditEntry, ChainVerificationResponse, Decision, PolicyMode

GENESIS_HASH = "0" * 64
LEDGER_HASH_VERSION = 2
LEGACY_HASH_VERSION = 1

# Additive, idempotent schema migrations (column name, DDL type/default).
LEDGER_MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("policy_version", "TEXT NOT NULL DEFAULT ''"),
    ("policy_mode", "TEXT NOT NULL DEFAULT 'enforce'"),
    ("would_block", "INTEGER NOT NULL DEFAULT 0"),
    ("hash_version", "INTEGER NOT NULL DEFAULT 1"),
    ("session_id", "TEXT NOT NULL DEFAULT ''"),
    ("args_digest", "TEXT NOT NULL DEFAULT ''"),
)

LEDGER_COLUMNS = (
    "agent_id",
    "server_name",
    "tool_name",
    "environment",
    "decision",
    "risk_score",
    "violations_json",
    "redacted_json",
    "prev_hash",
    "entry_hash",
    "timestamp",
    "would_block",
    "policy_mode",
    "policy_version",
    "hash_version",
    "session_id",
    "args_digest",
)
# Column lists are module constants, never user input.
LEDGER_SELECT = (
    f"SELECT id, {', '.join(LEDGER_COLUMNS)} FROM audit_ledger"  # nosec B608
)
_INSERT = (
    f"INSERT INTO audit_ledger ({', '.join(LEDGER_COLUMNS)}) "  # nosec B608
    f"VALUES ({', '.join('?' for _ in LEDGER_COLUMNS)})"
)

# Fields bound by a v2 link, in addition to ``hash_version``/``prev_hash``.
V2_FIELDS = (
    "timestamp",
    "agent_id",
    "server_name",
    "tool_name",
    "environment",
    "decision",
    "risk_score",
    "violations",
    "redacted_categories",
    "args_digest",
    "policy_version",
    "policy_mode",
    "would_block",
    "session_id",
)

CHECKPOINTS_DDL = """
    CREATE TABLE IF NOT EXISTS merkle_checkpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tree_size INTEGER NOT NULL,
        last_entry_id INTEGER NOT NULL,
        root_hash TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        prev_checkpoint_hash TEXT NOT NULL,
        checkpoint_hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        public_key TEXT NOT NULL,
        key_fingerprint TEXT NOT NULL
    )
"""
_CHECKPOINT_SELECT = (
    "SELECT tree_size, root_hash, timestamp, prev_checkpoint_hash, signature, "
    "public_key FROM merkle_checkpoints"
)
_CHECKPOINT_INSERT = (
    "INSERT INTO merkle_checkpoints (tree_size, last_entry_id, root_hash, "
    "timestamp, prev_checkpoint_hash, checkpoint_hash, signature, public_key, "
    "key_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


@dataclass(frozen=True)
class ProofBundle:
    """RFC 6962 inclusion proof of one ledger entry against a tree head."""

    entry_id: int
    leaf_index: int
    tree_size: int
    entry_hash: str
    root_hash: str
    audit_path: list[str]
    checkpoint: SignedTreeHead | None


def leaf_bytes(entry_hash: str) -> bytes:
    """Merkle leaf for an entry: its raw 32-byte hash (UTF-8 if not hex)."""
    try:
        return bytes.fromhex(entry_hash)
    except ValueError:
        return entry_hash.encode("utf-8")


def _row_to_checkpoint(row: tuple[Any, ...]) -> SignedTreeHead:
    """Convert a ``_CHECKPOINT_SELECT`` row into a SignedTreeHead."""
    head = TreeHead(int(row[0]), str(row[1]), str(row[2]), str(row[3]))
    return SignedTreeHead(head=head, signature=str(row[4]), public_key=str(row[5]))


def _covers(checkpoint: SignedTreeHead | None, leaf_index: int) -> bool:
    """True when ``checkpoint`` commits to the leaf at ``leaf_index``."""
    return checkpoint is not None and checkpoint.head.tree_size > leaf_index


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    """True when ``name`` exists (older ledgers have no checkpoint table)."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone()
    return row is not None


@dataclass(frozen=True)
class LedgerRecord:
    """One decision or security event appended to the audit hash chain."""

    agent_id: str
    server_name: str
    tool_name: str
    environment: str
    decision: Decision
    risk_score: int
    violations: list[str]
    redacted_categories: list[str]
    timestamp: str
    would_block: bool
    policy_mode: PolicyMode
    policy_version: str
    session_id: str = ""
    args_digest: str = ""


class _HashFields(Protocol):
    """Read-only attributes shared by LedgerRecord and AuditEntry (v2 binds)."""

    @property
    def timestamp(self) -> str: ...

    @property
    def agent_id(self) -> str: ...

    @property
    def server_name(self) -> str: ...

    @property
    def tool_name(self) -> str: ...

    @property
    def environment(self) -> str: ...

    @property
    def decision(self) -> str: ...

    @property
    def risk_score(self) -> int: ...

    @property
    def violations(self) -> list[str]: ...

    @property
    def redacted_categories(self) -> list[str]: ...

    @property
    def args_digest(self) -> str: ...

    @property
    def policy_version(self) -> str: ...

    @property
    def policy_mode(self) -> str: ...

    @property
    def would_block(self) -> bool: ...

    @property
    def session_id(self) -> str: ...


def compute_entry_hash(
    prev_hash: str,
    timestamp_iso: str,
    agent_id: str,
    server_name: str,
    tool_name: str,
    decision: str,
    risk_score: int,
) -> str:
    """Compute the legacy v1 link hash (kept to verify historical entries)."""
    canonical = (
        f"{prev_hash}|{timestamp_iso}|{agent_id}|"
        f"{server_name}|{tool_name}|{decision}|{risk_score}"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_entry_hash_v2(prev_hash: str, entry: _HashFields) -> str:
    """Compute the v2 link hash: JCS SHA-256 over the full ledger entry."""
    document: dict[str, Any] = {
        "hash_version": LEDGER_HASH_VERSION,
        "prev_hash": prev_hash,
    }
    for name in V2_FIELDS:
        document[name] = getattr(entry, name)
    document["would_block"] = bool(document["would_block"])
    return sha256_hex(document)


def digest_arguments(arguments: Any) -> str:
    """JCS SHA-256 of sanitized arguments (falls back for non-JCS values)."""
    try:
        return sha256_hex(arguments)
    except ValueError:
        fallback = json.dumps(arguments, sort_keys=True, default=str)
        return hashlib.sha256(fallback.encode("utf-8")).hexdigest()


def _recompute(entry: AuditEntry, prev_hash: str) -> str:
    """Recompute an entry's hash with the format its version declares."""
    if entry.hash_version == LEDGER_HASH_VERSION:
        return compute_entry_hash_v2(prev_hash, entry)
    return compute_entry_hash(
        prev_hash,
        entry.timestamp,
        entry.agent_id,
        entry.server_name,
        entry.tool_name,
        entry.decision,
        entry.risk_score,
    )


def _link_is_valid(entry: AuditEntry, prev_hash: str, seen_v2: bool) -> bool:
    """Check linkage, version monotonicity (no downgrade), and the hash."""
    if entry.prev_hash != prev_hash:
        return False
    if entry.hash_version not in (LEGACY_HASH_VERSION, LEDGER_HASH_VERSION):
        return False
    if seen_v2 and entry.hash_version == LEGACY_HASH_VERSION:
        return False
    return entry.entry_hash == _recompute(entry, prev_hash)


def _row_to_entry(row: tuple[Any, ...]) -> AuditEntry:
    """Convert a ``LEDGER_SELECT`` row into an AuditEntry."""
    return AuditEntry(
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
        would_block=bool(row[12]),
        policy_mode=str(row[13]),
        policy_version=str(row[14]),
        hash_version=int(row[15]),
        session_id=str(row[16]),
        args_digest=str(row[17]),
    )


class AuditLedger:
    """SQLite-backed, hash-chained audit ledger."""

    def __init__(
        self,
        db_path: str,
        wal: bool = True,
        signer: CheckpointSigner | None = None,
        checkpoint_interval: int = 0,
        read_only: bool = False,
    ) -> None:
        """Bind the ledger to ``db_path`` (call ``init`` to create/migrate).

        ``signer`` enables Signed Tree Heads; ``checkpoint_interval`` > 0
        signs one automatically every that many appends. ``read_only``
        opens SQLite in ``mode=ro`` (offline verification of evidence).
        """
        self.db_path = db_path
        self.wal = wal
        self.signer = signer
        self.checkpoint_interval = checkpoint_interval
        self.read_only = read_only

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Yield an autocommit connection that is always closed."""
        if self.read_only:
            uri = Path(self.db_path).resolve().as_uri() + "?mode=ro"
            conn = sqlite3.connect(uri, isolation_level=None, uri=True)
        else:
            conn = sqlite3.connect(self.db_path, isolation_level=None)
        try:
            yield conn
        finally:
            conn.close()

    def init(self) -> None:
        """Create the table, enable WAL, and run additive migrations."""
        with self._connect() as conn:
            if self.wal:
                conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
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
            conn.execute(CHECKPOINTS_DDL)
            self._migrate(conn)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Add columns missing from ledgers created by older releases."""
        rows = conn.execute("PRAGMA table_info(audit_ledger)").fetchall()
        existing = {str(row[1]) for row in rows}
        for column, ddl in LEDGER_MIGRATIONS:
            if column not in existing:
                # Column names and DDL are module constants, never user input.
                conn.execute(f"ALTER TABLE audit_ledger ADD COLUMN {column} {ddl}")

    def journal_mode(self) -> str:
        """Return the active SQLite journal mode (``wal`` when enabled)."""
        with self._connect() as conn:
            return str(conn.execute("PRAGMA journal_mode").fetchone()[0])

    def append(self, record: LedgerRecord) -> tuple[str, str]:
        """Link ``record`` (v2) to the chain head; return ``(prev, entry)``."""
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT entry_hash FROM audit_ledger ORDER BY id DESC LIMIT 1"
                ).fetchone()
                prev_hash = str(row[0]) if row else GENESIS_HASH
                entry_hash = compute_entry_hash_v2(prev_hash, record)
                conn.execute(_INSERT, _insert_values(record, prev_hash, entry_hash))
                self._auto_checkpoint(conn)
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
        return prev_hash, entry_hash

    def _auto_checkpoint(self, conn: sqlite3.Connection) -> None:
        """Sign a checkpoint once ``checkpoint_interval`` entries are pending.

        Pending entries are counted by rowid range after the last
        checkpoint, so the check stays O(interval) however long the chain.
        """
        if self.signer is None or self.checkpoint_interval <= 0:
            return
        row = conn.execute(
            "SELECT last_entry_id FROM merkle_checkpoints ORDER BY id DESC LIMIT 1"
        ).fetchone()
        last_entry_id = int(row[0]) if row else 0
        pending = conn.execute(
            "SELECT COUNT(*) FROM audit_ledger WHERE id > ?", (last_entry_id,)
        ).fetchone()[0]
        if int(pending) >= self.checkpoint_interval:
            self._sign_checkpoint(conn, self.signer)

    @staticmethod
    def _latest_checkpoint(conn: sqlite3.Connection) -> SignedTreeHead | None:
        """Most recent checkpoint, if any (``None`` on pre-checkpoint ledgers)."""
        if not _has_table(conn, "merkle_checkpoints"):
            return None
        row = conn.execute(_CHECKPOINT_SELECT + " ORDER BY id DESC LIMIT 1").fetchone()
        return _row_to_checkpoint(row) if row else None

    def _sign_checkpoint(
        self, conn: sqlite3.Connection, signer: CheckpointSigner
    ) -> SignedTreeHead:
        """Sign a checkpoint; failures count as ``checkpoint_error`` and re-raise."""
        try:
            return self._sign_tree_head(conn, signer)
        except Exception:
            metrics_registry.record_ledger_error("checkpoint_error")
            raise

    def _sign_tree_head(
        self, conn: sqlite3.Connection, signer: CheckpointSigner
    ) -> SignedTreeHead:
        """Sign a Signed Tree Head over every entry (caller holds the lock)."""
        rows = conn.execute(
            "SELECT id, entry_hash FROM audit_ledger ORDER BY id ASC"
        ).fetchall()
        latest = self._latest_checkpoint(conn)
        if latest is not None and latest.head.tree_size == len(rows):
            return latest
        head = TreeHead(
            tree_size=len(rows),
            root_hash=merkle_root([leaf_bytes(str(row[1])) for row in rows]).hex(),
            timestamp=datetime.now(UTC).isoformat(),
            prev_checkpoint_hash=(
                latest.head.digest() if latest else GENESIS_CHECKPOINT_HASH
            ),
        )
        signed = signer.sign(head)
        conn.execute(
            _CHECKPOINT_INSERT,
            (
                head.tree_size,
                int(rows[-1][0]) if rows else 0,
                head.root_hash,
                head.timestamp,
                head.prev_checkpoint_hash,
                head.digest(),
                signed.signature,
                signed.public_key,
                signed.key_fingerprint,
            ),
        )
        return signed

    def create_checkpoint(self) -> SignedTreeHead | None:
        """Sign a checkpoint over the current tree now (``None`` w/o signer).

        Returns the latest checkpoint unchanged when it already covers every
        entry, so on-demand triggers never produce duplicate tree heads.
        """
        if self.signer is None:
            return None
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                signed = self._sign_checkpoint(conn, self.signer)
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
        return signed

    def list_checkpoints(self) -> list[SignedTreeHead]:
        """Every persisted checkpoint, oldest first."""
        with self._connect() as conn:
            if not _has_table(conn, "merkle_checkpoints"):
                return []
            rows = conn.execute(_CHECKPOINT_SELECT + " ORDER BY id ASC").fetchall()
        return [_row_to_checkpoint(row) for row in rows]

    def _proof_snapshot(
        self,
    ) -> tuple[list[tuple[int, str]], SignedTreeHead | None]:
        """Entries and latest checkpoint read in one consistent snapshot."""
        with self._connect() as conn:
            conn.execute("BEGIN")
            rows = conn.execute(
                "SELECT id, entry_hash FROM audit_ledger ORDER BY id ASC"
            ).fetchall()
            latest = self._latest_checkpoint(conn)
            conn.execute("COMMIT")
        return [(int(row[0]), str(row[1])) for row in rows], latest

    def _covering_snapshot(
        self,
        index: int,
        rows: list[tuple[int, str]],
        latest: SignedTreeHead | None,
    ) -> tuple[list[tuple[int, str]], SignedTreeHead | None]:
        """Sign on demand when needed; drop a checkpoint not covering ``index``."""
        if self.signer is not None and not _covers(latest, index):
            self.create_checkpoint()
            rows, latest = self._proof_snapshot()
        return rows, latest if _covers(latest, index) else None

    def inclusion_proof(self, entry_id: int) -> ProofBundle | None:
        """RFC 6962 inclusion proof for ``entry_id`` (``None`` if unknown).

        The proof targets the latest Signed Tree Head; when it does not cover
        the entry yet and a signer is configured, a checkpoint is signed on
        demand. Without any covering checkpoint the proof is computed against
        the current (unsigned) tree.
        """
        rows, latest = self._proof_snapshot()
        ids = [row[0] for row in rows]
        index = bisect.bisect_left(ids, entry_id)
        if index == len(ids) or ids[index] != entry_id:
            return None
        rows, latest = self._covering_snapshot(index, rows, latest)
        tree_size = latest.head.tree_size if latest else len(rows)
        leaves = [leaf_bytes(row[1]) for row in rows[:tree_size]]
        return ProofBundle(
            entry_id=entry_id,
            leaf_index=index,
            tree_size=tree_size,
            entry_hash=rows[index][1],
            root_hash=merkle_root(leaves).hex(),
            audit_path=[node.hex() for node in inclusion_proof(leaves, index)],
            checkpoint=latest,
        )

    def list_entries(self, agent_id: str | None = None) -> list[AuditEntry]:
        """Return persisted entries in chain order, optionally per agent."""
        with self._connect() as conn:
            if agent_id:
                rows = conn.execute(
                    LEDGER_SELECT + " WHERE agent_id = ? ORDER BY id ASC",
                    (agent_id,),
                ).fetchall()
            else:
                rows = conn.execute(LEDGER_SELECT + " ORDER BY id ASC").fetchall()
        return [_row_to_entry(row) for row in rows]

    def count(self) -> int:
        """Return the number of persisted ledger rows."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM audit_ledger").fetchone()
        return int(row[0])

    def list_recent(self, limit: int) -> list[AuditEntry]:
        """Return the newest ``limit`` entries, newest first (bounded read)."""
        with self._connect() as conn:
            rows = conn.execute(
                LEDGER_SELECT + " ORDER BY id DESC LIMIT ?", (max(1, limit),)
            ).fetchall()
        return [_row_to_entry(row) for row in rows]

    def verify(self) -> ChainVerificationResponse:
        """Verify every link (v1 legacy and v2 full-payload) of the chain."""
        entries = self.list_entries()
        expected_prev = GENESIS_HASH
        seen_v2 = False
        for entry in entries:
            if not _link_is_valid(entry, expected_prev, seen_v2):
                return ChainVerificationResponse(
                    valid=False,
                    total_entries=len(entries),
                    head_hash=entries[-1].entry_hash,
                    corrupted_entry_id=entry.id,
                    legacy_entries=_legacy_count(entries),
                )
            seen_v2 = seen_v2 or entry.hash_version == LEDGER_HASH_VERSION
            expected_prev = entry.entry_hash
        return ChainVerificationResponse(
            valid=True,
            total_entries=len(entries),
            head_hash=expected_prev,
            corrupted_entry_id=None,
            legacy_entries=_legacy_count(entries),
        )

    def reset(self) -> None:
        """Delete every entry and checkpoint (deterministic test isolation)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM audit_ledger")
            conn.execute("DELETE FROM merkle_checkpoints")


def _legacy_count(entries: list[AuditEntry]) -> int:
    """Number of v1 (pre full-payload binding) entries."""
    return sum(1 for entry in entries if entry.hash_version == LEGACY_HASH_VERSION)


def _insert_values(
    record: LedgerRecord, prev_hash: str, entry_hash: str
) -> tuple[Any, ...]:
    """Positional values matching ``LEDGER_COLUMNS``."""
    return (
        record.agent_id,
        record.server_name,
        record.tool_name,
        record.environment,
        record.decision,
        record.risk_score,
        json.dumps(record.violations),
        json.dumps(record.redacted_categories),
        prev_hash,
        entry_hash,
        record.timestamp,
        int(record.would_block),
        record.policy_mode,
        record.policy_version,
        LEDGER_HASH_VERSION,
        record.session_id,
        record.args_digest,
    )
