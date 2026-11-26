"""OCSF (Open Cybersecurity Schema Framework) SIEM export of the audit ledger.

Each ledger entry becomes one OCSF 1.3.0 **API Activity** event
(``class_uid 6003``, category *Application Activity*) with the
``security_control`` profile (``action``/``disposition``). Aegis-specific
data that has no OCSF attribute lives under ``unmapped``:

* ``unmapped.aegis``: decision, risk score, violations, DLP categories and
  policy provenance;
* ``unmapped.integrity``: hash-chain link (``entry_hash``/``prev_hash``,
  ``hash_version``) plus the RFC 6962 Merkle leaf index and the first
  Ed25519 Signed Tree Head that commits to the entry, so a SIEM can prove
  the event was not altered after export;
* ``unmapped.compliance``: EU AI Act Art. 12 (record-keeping) and ISO/IEC
  42001:2023 Annex A.6.2.8 (AI system recording of event logs) evidence.

Events are serialized as JSON Lines (one compact, key-sorted object per line).
"""

import bisect
import json
from collections.abc import Iterator, Sequence
from datetime import datetime
from typing import Any

from app.merkle import SignedTreeHead, leaf_hash
from app.schemas import AuditEntry

OCSF_VERSION = "1.3.0"
PRODUCT_VERSION = "0.1.0"
API_ACTIVITY_CLASS_UID = 6003
APPLICATION_ACTIVITY_CATEGORY_UID = 6
ACTIVITY_OTHER = 99
NDJSON_MEDIA_TYPE = "application/x-ndjson"

# (minimum risk score, severity_id, severity) — first match wins.
_SEVERITIES: tuple[tuple[int, int, str], ...] = (
    (90, 5, "Critical"),
    (70, 4, "High"),
    (40, 3, "Medium"),
    (1, 2, "Low"),
    (0, 1, "Informational"),
)

# decision -> (action_id, action, disposition_id, disposition, status_id, status)
_OUTCOMES: dict[str, tuple[int, str, int, str, int, str]] = {
    "ALLOWED": (1, "Allowed", 1, "Allowed", 1, "Success"),
    "SANITIZED": (4, "Modified", 11, "Corrected", 1, "Success"),
    "BLOCKED": (2, "Denied", 2, "Blocked", 2, "Failure"),
}

EU_AI_ACT_ART_12 = {
    "framework": "EU AI Act (Regulation (EU) 2024/1689)",
    "requirement": "Art. 12",
    "title": "Record-keeping",
    "provisions": [
        "Art. 12(1) automatic recording of events over the system lifetime",
        "Art. 12(2)(a) identification of situations that may present a risk",
        "Art. 12(2)(b) facilitation of post-market monitoring",
        "Art. 12(2)(c) monitoring of the operation of the system",
    ],
}
ISO_42001_A_6_2_8 = {
    "framework": "ISO/IEC 42001:2023",
    "requirement": "Annex A.6.2.8",
    "title": "AI system recording of event logs",
}
TAMPER_EVIDENCE = "sha256-hash-chain+rfc6962-merkle+ed25519-signed-tree-head"


def severity(risk_score: int) -> tuple[int, str]:
    """OCSF ``(severity_id, severity)`` for a 0-100 risk score."""
    for minimum, severity_id, label in _SEVERITIES:
        if risk_score >= minimum:
            return severity_id, label
    return 0, "Unknown"


def _epoch_ms(timestamp: str) -> int:
    """OCSF ``time`` (epoch milliseconds); 0 when the timestamp is invalid."""
    try:
        return int(datetime.fromisoformat(timestamp).timestamp() * 1000)
    except ValueError:
        return 0


def _covering(
    checkpoints: Sequence[SignedTreeHead], sizes: Sequence[int], leaf_index: int
) -> SignedTreeHead | None:
    """First checkpoint whose tree includes ``leaf_index`` (sizes ascending)."""
    position = bisect.bisect_right(sizes, leaf_index)
    return checkpoints[position] if position < len(checkpoints) else None


def _integrity(
    entry: AuditEntry, leaf_index: int, checkpoint: SignedTreeHead | None
) -> dict[str, Any]:
    """Hash-chain and Merkle commitment evidence for one event."""
    try:
        merkle_leaf = leaf_hash(bytes.fromhex(entry.entry_hash)).hex()
    except ValueError:
        merkle_leaf = ""
    merkle: dict[str, Any] = {"leaf_index": leaf_index, "leaf_hash": merkle_leaf}
    if checkpoint is not None:
        merkle["checkpoint"] = {
            "tree_size": checkpoint.head.tree_size,
            "root_hash": checkpoint.head.root_hash,
            "checkpoint_hash": checkpoint.head.digest(),
            "key_fingerprint": checkpoint.key_fingerprint,
        }
    return {
        "hash_algorithm": "SHA-256",
        "hash_version": entry.hash_version,
        "entry_hash": entry.entry_hash,
        "prev_hash": entry.prev_hash,
        "merkle": merkle,
    }


def _compliance(entry: AuditEntry) -> dict[str, Any]:
    """EU AI Act Art. 12 / ISO/IEC 42001 evidence metadata."""
    return {
        "evidence_type": "automatic_event_log",
        "tamper_evidence": TAMPER_EVIDENCE,
        "risk_relevant": entry.would_block or entry.decision != "ALLOWED",
        "eu_ai_act": EU_AI_ACT_ART_12,
        "iso_iec_42001": ISO_42001_A_6_2_8,
    }


def to_ocsf(
    entry: AuditEntry, leaf_index: int, checkpoint: SignedTreeHead | None = None
) -> dict[str, Any]:
    """Map one ledger entry to an OCSF API Activity event."""
    severity_id, severity_label = severity(entry.risk_score)
    action_id, action, disposition_id, disposition, status_id, status = _OUTCOMES[
        entry.decision
    ]
    actor: dict[str, Any] = {"user": {"uid": entry.agent_id, "type": "AI Agent"}}
    if entry.session_id:
        actor["session"] = {"uid": entry.session_id}
    return {
        "category_uid": APPLICATION_ACTIVITY_CATEGORY_UID,
        "category_name": "Application Activity",
        "class_uid": API_ACTIVITY_CLASS_UID,
        "class_name": "API Activity",
        "activity_id": ACTIVITY_OTHER,
        "activity_name": "MCP Tool Call",
        "type_uid": API_ACTIVITY_CLASS_UID * 100 + ACTIVITY_OTHER,
        "type_name": "API Activity: Other",
        "time": _epoch_ms(entry.timestamp),
        "time_dt": entry.timestamp,
        "severity_id": severity_id,
        "severity": severity_label,
        "status_id": status_id,
        "status": status,
        "action_id": action_id,
        "action": action,
        "disposition_id": disposition_id,
        "disposition": disposition,
        "message": (
            f"{entry.decision} {entry.server_name}/{entry.tool_name} "
            f"for {entry.agent_id}"
        ),
        "metadata": {
            "version": OCSF_VERSION,
            "uid": entry.entry_hash,
            "sequence": entry.id,
            "log_name": "aegis_audit_ledger",
            "profiles": ["security_control"],
            "product": {
                "name": "Aegis-MCP",
                "vendor_name": "Aegis-MCP",
                "version": PRODUCT_VERSION,
                "feature": {"name": "MCP Firewall"},
            },
        },
        "actor": actor,
        "api": {
            "operation": entry.tool_name,
            "service": {"name": entry.server_name},
        },
        "src_endpoint": {"name": entry.agent_id},
        "dst_endpoint": {"svc_name": entry.server_name},
        "resources": [{"name": entry.tool_name, "type": "mcp_tool"}],
        "unmapped": {
            "aegis": {
                "decision": entry.decision,
                "risk_score": entry.risk_score,
                "violations": entry.violations,
                "redacted_categories": entry.redacted_categories,
                "environment": entry.environment,
                "policy_mode": entry.policy_mode,
                "policy_version": entry.policy_version,
                "would_block": entry.would_block,
                "args_digest": entry.args_digest,
            },
            "integrity": _integrity(entry, leaf_index, checkpoint),
            "compliance": _compliance(entry),
        },
    }


def ocsf_lines(
    entries: Sequence[AuditEntry],
    checkpoints: Sequence[SignedTreeHead],
    agent_id: str | None = None,
) -> Iterator[str]:
    """JSON Lines of OCSF events; ``entries`` must be the full chain in order.

    The Merkle leaf index is the entry's position in the full chain, so the
    optional ``agent_id`` filter is applied after indexing.
    """
    sizes = [checkpoint.head.tree_size for checkpoint in checkpoints]
    for index, entry in enumerate(entries):
        if agent_id and entry.agent_id != agent_id:
            continue
        event = to_ocsf(entry, index, _covering(checkpoints, sizes, index))
        yield json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
