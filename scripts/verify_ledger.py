"""Offline verifier for Aegis-MCP audit ledgers (hash chain + signed Merkle).

Opens the SQLite ledger read-only and checks, without any running service:

1. the full SHA-256 hash chain (legacy ``v1`` and full-payload ``v2`` links,
   no downgrades);
2. every Ed25519 Signed Tree Head: signature (pinned to ``--pubkey`` when
   given), checkpoint chaining (``prev_checkpoint_hash``), monotonic tree
   sizes, and the RFC 6962 Merkle root recomputed from the entry hashes;
3. with ``--entry-id``, the RFC 6962 inclusion proof of that entry against
   the latest signed checkpoint covering it.

Usage::

    uv run python -m scripts.verify_ledger --db aegis_mcp.db \\
        [--pubkey aegis-signing.pub.pem] [--entry-id 42] [--json]

Exit codes: ``0`` valid, ``1`` tampering / verification failure, ``2`` usage
or I/O error (missing database, unreadable key).
"""

import argparse
import json
import sqlite3
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from app.ledger import AuditLedger, leaf_bytes
from app.merkle import (
    GENESIS_CHECKPOINT_HASH,
    SignedTreeHead,
    SigningKeyError,
    load_public_key,
    merkle_root,
    verify_inclusion,
)

EXIT_VALID = 0
EXIT_TAMPERED = 1
EXIT_ERROR = 2


@dataclass
class Report:
    """Verification outcome: failures make the ledger invalid, notes do not."""

    failures: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """True when no check failed."""
        return not self.failures


def verify_chain(ledger: AuditLedger, report: Report) -> list[bytes]:
    """Verify the hash chain; return the Merkle leaves (entry hashes)."""
    result = ledger.verify()
    if result.valid:
        report.notes.append(
            f"hash chain intact: {result.total_entries} entries "
            f"({result.legacy_entries} legacy v1)"
        )
    else:
        report.failures.append(
            f"hash chain broken at entry id {result.corrupted_entry_id}"
        )
    return [leaf_bytes(entry.entry_hash) for entry in ledger.list_entries()]


def _check_checkpoint(
    checkpoint: SignedTreeHead,
    expected_prev: str,
    previous_size: int,
    leaves: Sequence[bytes],
    trusted_key: bytes | None,
) -> list[str]:
    """Failures for one checkpoint (signature, chaining, size, Merkle root)."""
    head = checkpoint.head
    label = f"checkpoint tree_size={head.tree_size}"
    failures: list[str] = []
    if not checkpoint.verify(trusted_key):
        failures.append(f"{label}: invalid Ed25519 signature or untrusted key")
    if head.prev_checkpoint_hash != expected_prev:
        failures.append(f"{label}: broken checkpoint chain (prev_checkpoint_hash)")
    if not previous_size <= head.tree_size <= len(leaves):
        failures.append(f"{label}: tree size outside the ledger (truncation?)")
    elif merkle_root(leaves[: head.tree_size]).hex() != head.root_hash:
        failures.append(f"{label}: Merkle root does not match ledger entries")
    return failures


def verify_checkpoints(
    checkpoints: Sequence[SignedTreeHead],
    leaves: Sequence[bytes],
    trusted_key: bytes | None,
    report: Report,
) -> None:
    """Verify every Signed Tree Head and the checkpoint chain."""
    if not checkpoints:
        if trusted_key is not None:
            report.failures.append("no signed checkpoints, but --pubkey was given")
        else:
            report.notes.append("no signed checkpoints found")
        return
    expected_prev = GENESIS_CHECKPOINT_HASH
    previous_size = 0
    for checkpoint in checkpoints:
        report.failures.extend(
            _check_checkpoint(
                checkpoint, expected_prev, previous_size, leaves, trusted_key
            )
        )
        expected_prev = checkpoint.head.digest()
        previous_size = checkpoint.head.tree_size
    latest = checkpoints[-1]
    report.notes.append(
        f"{len(checkpoints)} signed checkpoints verified "
        f"(key {latest.key_fingerprint}); "
        f"{len(leaves) - latest.head.tree_size} entries after the latest one"
    )
    if trusted_key is None:
        report.notes.append("signing key not pinned: pass --pubkey to pin it")


def verify_entry(
    ledger: AuditLedger, entry_id: int, trusted_key: bytes | None, report: Report
) -> None:
    """Verify the RFC 6962 inclusion proof of one entry."""
    bundle = ledger.inclusion_proof(entry_id)
    if bundle is None:
        report.failures.append(f"entry {entry_id} not found")
        return
    proven = verify_inclusion(
        leaf_bytes(bundle.entry_hash),
        bundle.leaf_index,
        bundle.tree_size,
        [bytes.fromhex(node) for node in bundle.audit_path],
        bytes.fromhex(bundle.root_hash),
    )
    checkpoint = bundle.checkpoint
    if not proven:
        report.failures.append(f"entry {entry_id}: inclusion proof invalid")
    elif checkpoint is None:
        report.notes.append(
            f"entry {entry_id}: included in the current tree but not yet "
            "covered by a signed checkpoint"
        )
    elif checkpoint.head.root_hash != bundle.root_hash or not checkpoint.verify(
        trusted_key
    ):
        report.failures.append(
            f"entry {entry_id}: not committed by a valid signed checkpoint"
        )
    else:
        report.notes.append(
            f"entry {entry_id}: inclusion proven (leaf {bundle.leaf_index} of "
            f"signed tree size {bundle.tree_size})"
        )


def run(db: Path, trusted_key: bytes | None, entry_id: int | None) -> Report:
    """Run every offline check against the ledger at ``db`` (read-only)."""
    ledger = AuditLedger(str(db), wal=False, read_only=True)
    report = Report()
    leaves = verify_chain(ledger, report)
    verify_checkpoints(ledger.list_checkpoints(), leaves, trusted_key, report)
    if entry_id is not None:
        verify_entry(ledger, entry_id, trusted_key, report)
    return report


def build_parser() -> argparse.ArgumentParser:
    """CLI arguments."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", required=True, type=Path, help="SQLite ledger")
    parser.add_argument(
        "--pubkey",
        type=Path,
        help="Trusted Ed25519 public key (PEM or 64 hex chars) to pin",
    )
    parser.add_argument("--entry-id", type=int, help="Verify one inclusion proof")
    parser.add_argument("--json", action="store_true", help="JSON report")
    return parser


def _emit(report: Report, as_json: bool) -> None:
    """Print the report (human-readable or JSON)."""
    if as_json:
        document = {
            "valid": report.valid,
            "failures": report.failures,
            "notes": report.notes,
        }
        print(json.dumps(document, indent=2))
        return
    for note in report.notes:
        print(f"OK    {note}")
    for failure in report.failures:
        print(f"FAIL  {failure}")
    print("VALID" if report.valid else "TAMPERED")


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint; returns the process exit code."""
    args = build_parser().parse_args(argv)
    if not args.db.is_file():
        print(f"error: ledger database not found: {args.db}", file=sys.stderr)
        return EXIT_ERROR
    try:
        trusted = load_public_key(args.pubkey.read_bytes()) if args.pubkey else None
        report = run(args.db, trusted, args.entry_id)
    except (OSError, SigningKeyError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    _emit(report, args.json)
    return EXIT_VALID if report.valid else EXIT_TAMPERED


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
