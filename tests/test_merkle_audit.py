"""TDD suite: RFC 6962 Merkle checkpoints, Ed25519 STHs, OCSF export, verifier."""

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from app import main
from app.config import settings
from app.firewall import MCPFirewall
from app.ledger import AuditLedger, LedgerRecord, digest_arguments, leaf_bytes
from app.merkle import (
    GENESIS_CHECKPOINT_HASH,
    CheckpointSigner,
    SignedTreeHead,
    SigningKeyError,
    TreeHead,
    inclusion_proof,
    key_fingerprint,
    leaf_hash,
    load_public_key,
    load_signer,
    merkle_root,
    node_hash,
    verify_inclusion,
)
from app.ocsf import ocsf_lines, severity, to_ocsf
from app.schemas import AuditEntry, MCPToolCallRequest
from scripts import verify_ledger

ADMIN_KEY = "merkle-admin-key"
client = TestClient(main.app)


def _record(index: int = 0, **overrides: Any) -> LedgerRecord:
    fields: dict[str, Any] = {
        "agent_id": f"agent-{index % 3}",
        "server_name": "git-mcp",
        "tool_name": "git_status",
        "environment": "prod",
        "decision": "ALLOWED",
        "risk_score": 0,
        "violations": [],
        "redacted_categories": [],
        "timestamp": f"2026-11-26T12:00:{index % 60:02d}+00:00",
        "would_block": False,
        "policy_mode": "enforce",
        "policy_version": "a" * 64,
        "session_id": f"session-{index}",
        "args_digest": digest_arguments({"i": index}),
    }
    fields.update(overrides)
    return LedgerRecord(**fields)


def _ledger(
    path: Path, signer: CheckpointSigner | None = None, interval: int = 0
) -> AuditLedger:
    ledger = AuditLedger(str(path), signer=signer, checkpoint_interval=interval)
    ledger.init()
    return ledger


def _fill(ledger: AuditLedger, count: int) -> None:
    for index in range(count):
        ledger.append(_record(index))


def _sql(path: Path, statement: str, *params: Any) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute(statement, params)


@pytest.fixture
def signer() -> CheckpointSigner:
    return CheckpointSigner.generate()


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "ledger.db"


# --------------------------------------------------------------------------
# RFC 6962 Merkle tree
# --------------------------------------------------------------------------


def test_domain_separation_prefixes() -> None:
    """Leaves hash with 0x00 and interior nodes with 0x01 (RFC 6962 2.1)."""
    left, right = b"L" * 32, b"R" * 32
    assert leaf_hash(b"x") == hashlib.sha256(b"\x00x").digest()
    assert node_hash(left, right) == hashlib.sha256(b"\x01" + left + right).digest()
    assert leaf_hash(left + right) != node_hash(left, right)


def test_root_of_empty_and_single_leaf() -> None:
    assert merkle_root([]) == hashlib.sha256(b"").digest()
    assert merkle_root([b"a"]) == leaf_hash(b"a")


def test_root_matches_rfc6962_recursive_definition() -> None:
    """MTH(D[n]) splits at the largest power of two < n."""
    leaves = [bytes([i]) for i in range(5)]
    hashed = [leaf_hash(leaf) for leaf in leaves]
    left = node_hash(node_hash(hashed[0], hashed[1]), node_hash(hashed[2], hashed[3]))
    assert merkle_root(leaves) == node_hash(left, hashed[4])


def test_second_preimage_interior_node_as_leaf_is_rejected() -> None:
    """A 2-leaf tree's root cannot be forged as a 1-leaf tree of h0||h1."""
    leaves = [b"a", b"b"]
    forged_leaf = leaf_hash(b"a") + leaf_hash(b"b")
    assert merkle_root([forged_leaf]) != merkle_root(leaves)
    assert not verify_inclusion(forged_leaf, 0, 1, [], merkle_root(leaves))


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33])
def test_inclusion_proofs_verify_for_every_leaf(size: int) -> None:
    leaves = [hashlib.sha256(str(i).encode()).digest() for i in range(size)]
    root = merkle_root(leaves)
    for index, leaf in enumerate(leaves):
        path = inclusion_proof(leaves, index)
        assert len(path) <= max(1, (size - 1).bit_length())
        assert verify_inclusion(leaf, index, size, path, root)


def test_inclusion_proof_rejects_tampering() -> None:
    leaves = [bytes([i]) * 32 for i in range(6)]
    root = merkle_root(leaves)
    path = inclusion_proof(leaves, 3)
    assert not verify_inclusion(b"\xff" * 32, 3, 6, path, root)
    assert not verify_inclusion(leaves[3], 2, 6, path, root)
    assert not verify_inclusion(leaves[3], 3, 6, path[:-1], root)
    assert not verify_inclusion(leaves[3], 3, 6, [*path, b"\x00" * 32], root)
    assert not verify_inclusion(leaves[3], 3, 6, list(reversed(path)), root)
    assert not verify_inclusion(leaves[3], 6, 6, path, root)
    assert not verify_inclusion(leaves[3], -1, 6, path, root)
    with pytest.raises(IndexError):
        inclusion_proof(leaves, 6)


# --------------------------------------------------------------------------
# Ed25519 Signed Tree Heads and key handling
# --------------------------------------------------------------------------


def _head(**overrides: Any) -> TreeHead:
    fields: dict[str, Any] = {
        "tree_size": 3,
        "root_hash": "ab" * 32,
        "timestamp": "2026-11-26T12:00:00+00:00",
        "prev_checkpoint_hash": GENESIS_CHECKPOINT_HASH,
    }
    fields.update(overrides)
    return TreeHead(**fields)


def test_signed_tree_head_verifies_and_detects_tampering(
    signer: CheckpointSigner,
) -> None:
    sth = signer.sign(_head())
    assert sth.verify()
    assert sth.verify(signer.public_key)
    assert sth.key_fingerprint == signer.fingerprint
    assert sth.key_fingerprint == hashlib.sha256(signer.public_key).hexdigest()
    for field_name, value in [
        ("tree_size", 4),
        ("root_hash", "cd" * 32),
        ("timestamp", "2026-11-26T12:00:01+00:00"),
        ("prev_checkpoint_hash", "1" * 64),
    ]:
        forged = SignedTreeHead(
            _head(**{field_name: value}), sth.signature, sth.public_key
        )
        assert not forged.verify(), field_name


def test_signed_tree_head_rejects_untrusted_or_malformed_keys(
    signer: CheckpointSigner,
) -> None:
    sth = signer.sign(_head())
    other = CheckpointSigner.generate()
    assert not sth.verify(other.public_key)
    resigned = other.sign(_head())
    assert resigned.verify() and not resigned.verify(signer.public_key)
    assert not SignedTreeHead(sth.head, "zz", sth.public_key).verify()
    assert not SignedTreeHead(sth.head, sth.signature, "00" * 31).verify()
    assert SignedTreeHead(sth.head, sth.signature, "zz").key_fingerprint == ""


def test_canonical_message_is_domain_separated(signer: CheckpointSigner) -> None:
    message = json.loads(_head().message())
    assert message["format"] == "aegis-sth/v1"
    assert set(message) == {
        "format",
        "tree_size",
        "root_hash",
        "timestamp",
        "prev_checkpoint_hash",
    }
    assert _head().digest() == hashlib.sha256(_head().message()).hexdigest()
    assert signer.sign(_head()).as_dict()["checkpoint_hash"] == _head().digest()


def _pem(private_key: Any) -> bytes:
    return bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def test_load_signer_from_pem_file(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "signing.pem"
    path.write_bytes(_pem(key))
    signer = load_signer(True, str(path), False, "prod")
    assert signer is not None
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert signer.public_key == raw
    assert load_public_key(signer.public_key_pem()) == raw
    assert load_public_key(raw.hex().encode()) == raw


def test_load_signer_fail_closed_and_dev_modes(tmp_path: Path) -> None:
    assert load_signer(False, None, False, "prod") is None
    with pytest.raises(SigningKeyError, match="required in prod"):
        load_signer(True, None, True, "prod")
    assert load_signer(True, None, False, "dev") is None
    assert isinstance(load_signer(True, None, True, "dev"), CheckpointSigner)
    with pytest.raises(SigningKeyError, match="cannot read"):
        load_signer(True, str(tmp_path / "missing.pem"), False, "dev")
    bad = tmp_path / "bad.pem"
    bad.write_bytes(b"not a key")
    with pytest.raises(SigningKeyError, match="valid PEM"):
        load_signer(True, str(bad), False, "dev")
    wrong = tmp_path / "x25519.pem"
    wrong.write_bytes(_pem(X25519PrivateKey.generate()))
    with pytest.raises(SigningKeyError, match="Ed25519 private key"):
        load_signer(True, str(wrong), False, "dev")


def test_load_public_key_rejects_invalid_material() -> None:
    with pytest.raises(SigningKeyError, match="hex"):
        load_public_key(b"z" * 64)
    with pytest.raises(SigningKeyError, match="PEM"):
        load_public_key(b"garbage")
    x25519_pub = (
        X25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    with pytest.raises(SigningKeyError, match="Ed25519 key"):
        load_public_key(x25519_pub)


def test_firewall_fails_closed_in_prod_without_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(settings, "environment", "prod")
    monkeypatch.setattr(settings, "checkpoint_signing", True)
    monkeypatch.setattr(settings, "signing_key_path", None)
    with pytest.raises(SigningKeyError):
        MCPFirewall(db_path=str(tmp_path / "fw.db"))
    monkeypatch.setattr(settings, "checkpoint_signing", False)
    assert MCPFirewall(db_path=str(tmp_path / "fw.db")).ledger.signer is None


# --------------------------------------------------------------------------
# Ledger checkpoints and proofs
# --------------------------------------------------------------------------


def test_automatic_checkpoints_every_interval(
    db: Path, signer: CheckpointSigner
) -> None:
    ledger = _ledger(db, signer, interval=4)
    _fill(ledger, 9)
    checkpoints = ledger.list_checkpoints()
    assert [cp.head.tree_size for cp in checkpoints] == [4, 8]
    assert checkpoints[0].head.prev_checkpoint_hash == GENESIS_CHECKPOINT_HASH
    assert checkpoints[1].head.prev_checkpoint_hash == checkpoints[0].head.digest()
    hashes = [leaf_bytes(entry.entry_hash) for entry in ledger.list_entries()]
    assert checkpoints[1].head.root_hash == merkle_root(hashes[:8]).hex()
    assert all(cp.verify(signer.public_key) for cp in checkpoints)


def test_no_checkpoints_without_signer_or_interval(
    db: Path, signer: CheckpointSigner
) -> None:
    unsigned = _ledger(db, None, interval=1)
    _fill(unsigned, 3)
    assert unsigned.list_checkpoints() == []
    assert unsigned.create_checkpoint() is None
    manual_only = _ledger(db, signer, interval=0)
    _fill(manual_only, 2)
    assert manual_only.list_checkpoints() == []


def test_manual_checkpoint_is_idempotent(db: Path, signer: CheckpointSigner) -> None:
    ledger = _ledger(db, signer)
    _fill(ledger, 3)
    first = ledger.create_checkpoint()
    assert first is not None and first.head.tree_size == 3
    assert ledger.create_checkpoint() == first
    ledger.append(_record(3))
    second = ledger.create_checkpoint()
    assert second is not None and second.head.tree_size == 4
    assert len(ledger.list_checkpoints()) == 2


def test_inclusion_proof_against_signed_checkpoint(
    db: Path, signer: CheckpointSigner
) -> None:
    ledger = _ledger(db, signer, interval=5)
    _fill(ledger, 7)
    entries = ledger.list_entries()
    bundle = ledger.inclusion_proof(entries[2].id)
    assert bundle is not None and bundle.checkpoint is not None
    assert (bundle.leaf_index, bundle.tree_size) == (2, 5)
    assert bundle.root_hash == bundle.checkpoint.head.root_hash
    assert verify_inclusion(
        leaf_bytes(bundle.entry_hash),
        bundle.leaf_index,
        bundle.tree_size,
        [bytes.fromhex(node) for node in bundle.audit_path],
        bytes.fromhex(bundle.root_hash),
    )
    # Entry 7 is not covered yet: a checkpoint is signed on demand.
    tail = ledger.inclusion_proof(entries[6].id)
    assert tail is not None and tail.checkpoint is not None
    assert tail.tree_size == 7
    assert len(ledger.list_checkpoints()) == 2
    assert ledger.inclusion_proof(10_000) is None


def test_inclusion_proof_without_signer_uses_current_tree(db: Path) -> None:
    ledger = _ledger(db)
    _fill(ledger, 3)
    bundle = ledger.inclusion_proof(ledger.list_entries()[1].id)
    assert bundle is not None
    assert bundle.checkpoint is None and bundle.tree_size == 3


def test_stale_checkpoint_not_covering_entry_is_omitted(
    db: Path, signer: CheckpointSigner
) -> None:
    signed = _ledger(db, signer)
    _fill(signed, 2)
    signed.create_checkpoint()
    signed.append(_record(2))
    unsigned = AuditLedger(str(db))
    bundle = unsigned.inclusion_proof(unsigned.list_entries()[2].id)
    assert bundle is not None
    assert bundle.checkpoint is None and bundle.tree_size == 3


def test_reset_clears_checkpoints(db: Path, signer: CheckpointSigner) -> None:
    ledger = _ledger(db, signer, interval=1)
    _fill(ledger, 2)
    ledger.reset()
    assert ledger.list_checkpoints() == [] and ledger.list_entries() == []


def test_pre_checkpoint_ledger_has_no_checkpoints(db: Path) -> None:
    _sql(db, "CREATE TABLE audit_ledger (id INTEGER PRIMARY KEY)")
    assert AuditLedger(str(db)).list_checkpoints() == []


def test_leaf_bytes_falls_back_for_non_hex() -> None:
    assert leaf_bytes("ab" * 32) == bytes.fromhex("ab" * 32)
    assert leaf_bytes("not-hex") == b"not-hex"
    assert key_fingerprint(b"k") == hashlib.sha256(b"k").hexdigest()


# --------------------------------------------------------------------------
# OCSF export
# --------------------------------------------------------------------------


def _entry(**overrides: Any) -> AuditEntry:
    fields: dict[str, Any] = {
        "id": 1,
        "agent_id": "agent-0",
        "server_name": "git-mcp",
        "tool_name": "git_status",
        "environment": "prod",
        "decision": "ALLOWED",
        "risk_score": 0,
        "prev_hash": "0" * 64,
        "entry_hash": "ab" * 32,
        "timestamp": "2026-11-26T12:00:00+00:00",
        "hash_version": 2,
        "session_id": "s-1",
    }
    fields.update(overrides)
    return AuditEntry(**fields)


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0, 1), (1, 2), (39, 2), (40, 3), (70, 4), (89, 4), (90, 5), (100, 5), (-1, 0)],
)
def test_severity_mapping(score: int, expected: int) -> None:
    assert severity(score)[0] == expected


@pytest.mark.parametrize(
    ("decision", "action_id", "disposition_id", "status_id"),
    [("ALLOWED", 1, 1, 1), ("SANITIZED", 4, 11, 1), ("BLOCKED", 2, 2, 2)],
)
def test_ocsf_api_activity_core_fields(
    decision: str, action_id: int, disposition_id: int, status_id: int
) -> None:
    event = to_ocsf(_entry(decision=decision, risk_score=95), 0)
    assert event["class_uid"] == 6003 and event["category_uid"] == 6
    assert event["type_uid"] == 600399 and event["activity_id"] == 99
    assert event["time"] == 1795694400000
    assert event["severity_id"] == 5
    assert (event["action_id"], event["disposition_id"], event["status_id"]) == (
        action_id,
        disposition_id,
        status_id,
    )
    assert event["metadata"]["version"] == "1.3.0"
    assert event["metadata"]["uid"] == "ab" * 32
    assert event["metadata"]["product"]["name"] == "Aegis-MCP"
    assert event["actor"]["user"]["uid"] == "agent-0"
    assert event["actor"]["session"]["uid"] == "s-1"
    assert event["api"] == {"operation": "git_status", "service": {"name": "git-mcp"}}


def test_ocsf_eu_ai_act_and_iso_42001_evidence() -> None:
    event = to_ocsf(_entry(session_id="", timestamp="not-a-date"), 4)
    assert "session" not in event["actor"] and event["time"] == 0
    compliance = event["unmapped"]["compliance"]
    assert compliance["eu_ai_act"]["requirement"] == "Art. 12"
    assert any("12(2)(a)" in p for p in compliance["eu_ai_act"]["provisions"])
    assert compliance["iso_iec_42001"]["requirement"] == "Annex A.6.2.8"
    assert compliance["evidence_type"] == "automatic_event_log"
    assert compliance["risk_relevant"] is False
    integrity = event["unmapped"]["integrity"]
    assert integrity["hash_algorithm"] == "SHA-256"
    assert integrity["merkle"]["leaf_index"] == 4
    assert integrity["merkle"]["leaf_hash"] == leaf_hash(bytes.fromhex("ab" * 32)).hex()
    assert "checkpoint" not in integrity["merkle"]
    blocked = to_ocsf(_entry(decision="BLOCKED", entry_hash="xyz"), 0)
    assert blocked["unmapped"]["compliance"]["risk_relevant"] is True
    assert blocked["unmapped"]["integrity"]["merkle"]["leaf_hash"] == ""


def test_ocsf_lines_reference_covering_checkpoint(
    db: Path, signer: CheckpointSigner
) -> None:
    ledger = _ledger(db, signer, interval=2)
    _fill(ledger, 5)
    checkpoints = ledger.list_checkpoints()
    lines = list(ocsf_lines(ledger.list_entries(), checkpoints))
    events = [json.loads(line) for line in lines]
    assert all(line.endswith("\n") and "\n" not in line[:-1] for line in lines)
    sizes = [
        event["unmapped"]["integrity"]["merkle"].get("checkpoint", {}).get("tree_size")
        for event in events
    ]
    assert sizes == [2, 2, 4, 4, None]
    filtered = [json.loads(x) for x in ocsf_lines(ledger.list_entries(), [], "agent-1")]
    assert [e["unmapped"]["integrity"]["merkle"]["leaf_index"] for e in filtered] == [
        1,
        4,
    ]


# --------------------------------------------------------------------------
# HTTP API
# --------------------------------------------------------------------------


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch, signer: CheckpointSigner) -> Iterator[None]:
    monkeypatch.setattr(settings, "api_key", ADMIN_KEY)
    monkeypatch.setattr(settings, "policy_mode", "enforce")
    monkeypatch.setattr(main.firewall.ledger, "signer", signer)
    monkeypatch.setattr(main.firewall.ledger, "checkpoint_interval", 0)
    main.firewall.reset()
    yield
    main.firewall.reset()


def _inspect(index: int) -> None:
    request = MCPToolCallRequest(
        agent_id=f"agent-{index}",
        server_name="git-mcp",
        tool_name="git_status",
        arguments={"path": f"file-{index}.md"},
    )
    main.firewall.inspect(request)


HEADERS = {"X-API-Key": ADMIN_KEY}


@pytest.mark.usefixtures("api")
def test_proof_endpoint_returns_signed_inclusion_proof(
    signer: CheckpointSigner,
) -> None:
    for index in range(5):
        _inspect(index)
    entries = main.firewall.list_audit_entries()
    response = client.get(f"/api/v1/audit/proof/{entries[3].id}", headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["leaf_index"] == 3 and body["tree_size"] == 5
    assert body["entry_hash"] == entries[3].entry_hash
    checkpoint = body["checkpoint"]
    assert checkpoint["algorithm"] == "Ed25519"
    assert checkpoint["key_fingerprint"] == signer.fingerprint
    assert checkpoint["root_hash"] == body["root_hash"]
    assert verify_inclusion(
        bytes.fromhex(body["entry_hash"]),
        body["leaf_index"],
        body["tree_size"],
        [bytes.fromhex(node) for node in body["audit_path"]],
        bytes.fromhex(body["root_hash"]),
    )
    head = TreeHead(
        checkpoint["tree_size"],
        checkpoint["root_hash"],
        checkpoint["timestamp"],
        checkpoint["prev_checkpoint_hash"],
    )
    sth = SignedTreeHead(head, checkpoint["signature"], checkpoint["public_key"])
    assert sth.verify(signer.public_key)


@pytest.mark.usefixtures("api")
def test_proof_endpoint_not_found_and_validation() -> None:
    assert client.get("/api/v1/audit/proof/999999", headers=HEADERS).status_code == 404
    assert client.get("/api/v1/audit/proof/0", headers=HEADERS).status_code == 422


@pytest.mark.usefixtures("api")
def test_proof_endpoint_requires_authentication() -> None:
    assert client.get("/api/v1/audit/proof/1").status_code == 401
    assert client.get("/api/v1/audit/export/ocsf").status_code == 401


@pytest.mark.usefixtures("api")
def test_checkpoint_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    _inspect(0)
    assert client.post("/api/v1/audit/checkpoints").status_code == 401
    created = client.post("/api/v1/audit/checkpoints", headers=HEADERS)
    assert created.status_code == 200 and created.json()["tree_size"] == 1
    listed = client.get("/api/v1/audit/checkpoints", headers=HEADERS)
    assert [cp["tree_size"] for cp in listed.json()] == [1]
    monkeypatch.setattr(main.firewall.ledger, "signer", None)
    conflict = client.post("/api/v1/audit/checkpoints", headers=HEADERS)
    assert conflict.status_code == 409


@pytest.mark.usefixtures("api")
def test_ocsf_export_endpoint_streams_json_lines() -> None:
    for index in range(3):
        _inspect(index)
    response = client.get("/api/v1/audit/export/ocsf", headers=HEADERS)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    events = [json.loads(line) for line in response.text.splitlines()]
    assert len(events) == 3
    assert all(event["class_uid"] == 6003 for event in events)
    assert [event["metadata"]["sequence"] for event in events] == [
        entry.id for entry in main.firewall.list_audit_entries()
    ]
    one = client.get(
        "/api/v1/audit/export/ocsf", params={"agent_id": "agent-2"}, headers=HEADERS
    )
    assert [json.loads(x)["actor"]["user"]["uid"] for x in one.text.splitlines()] == [
        "agent-2"
    ]


# --------------------------------------------------------------------------
# Offline verifier CLI
# --------------------------------------------------------------------------


@pytest.fixture
def signed_db(db: Path, signer: CheckpointSigner) -> Path:
    ledger = _ledger(db, signer, interval=3)
    _fill(ledger, 7)
    return db


@pytest.fixture
def pubkey(tmp_path: Path, signer: CheckpointSigner) -> Path:
    path = tmp_path / "signing.pub.pem"
    path.write_bytes(signer.public_key_pem())
    return path


def _verify(*args: str) -> int:
    return verify_ledger.main(list(args))


def test_verifier_accepts_valid_ledger(
    signed_db: Path, pubkey: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _verify("--db", str(signed_db), "--pubkey", str(pubkey)) == 0
    out = capsys.readouterr().out
    assert "VALID" in out and "2 signed checkpoints verified" in out
    assert _verify("--db", str(signed_db), "--entry-id", "2", "--json") == 0
    report = json.loads(capsys.readouterr().out)
    assert report["valid"] is True
    assert any("inclusion proven" in note for note in report["notes"])
    assert any("not pinned" in note for note in report["notes"])


def test_verifier_notes_uncovered_entry(signed_db: Path, pubkey: Path) -> None:
    """Entry 7 is after the last checkpoint: valid, but only noted."""
    assert _verify("--db", str(signed_db), "--entry-id", "7") == 0


def test_verifier_is_read_only(signed_db: Path) -> None:
    before = signed_db.read_bytes()
    assert _verify("--db", str(signed_db), "--entry-id", "7") == 0
    assert signed_db.read_bytes() == before


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_ledger SET risk_score = 1 WHERE id = 2",
        "UPDATE merkle_checkpoints SET root_hash = '" + "00" * 32 + "' WHERE id = 1",
        "UPDATE merkle_checkpoints SET timestamp = 'forged' WHERE id = 1",
        "UPDATE merkle_checkpoints SET prev_checkpoint_hash = 'x' WHERE id = 2",
        "UPDATE merkle_checkpoints SET tree_size = 99 WHERE id = 2",
        "DELETE FROM merkle_checkpoints WHERE id = 1",
        # Truncating signed history keeps the chain valid but not the STH.
        "DELETE FROM audit_ledger WHERE id >= 6",
    ],
)
def test_verifier_detects_tampering(
    signed_db: Path, pubkey: Path, statement: str
) -> None:
    _sql(signed_db, statement)
    assert _verify("--db", str(signed_db), "--pubkey", str(pubkey)) == 1


def test_verifier_detects_consistent_rewrite_with_signed_root(
    signed_db: Path, pubkey: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Rewriting entry 2 *and* re-linking the chain still breaks the STH."""
    ledger = AuditLedger(str(signed_db))
    entries = ledger.list_entries()
    _sql(signed_db, "DELETE FROM audit_ledger")
    rebuilt = AuditLedger(str(signed_db))
    for index in range(len(entries)):
        rebuilt.append(_record(index, risk_score=1 if index == 1 else 0))
    assert rebuilt.verify().valid
    assert (
        _verify("--db", str(signed_db), "--pubkey", str(pubkey), "--entry-id", "9") == 1
    )
    assert "Merkle root does not match" in capsys.readouterr().out


def test_verifier_rejects_foreign_signing_key(signed_db: Path, tmp_path: Path) -> None:
    other = tmp_path / "other.pub"
    other.write_text(CheckpointSigner.generate().public_key.hex())
    assert _verify("--db", str(signed_db), "--pubkey", str(other)) == 1


def test_verifier_entry_failures(
    signed_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _verify("--db", str(signed_db), "--entry-id", "999") == 1
    assert "not found" in capsys.readouterr().out
    _sql(signed_db, "UPDATE merkle_checkpoints SET signature = '00' WHERE id = 2")
    assert _verify("--db", str(signed_db), "--entry-id", "5") == 1
    assert "not committed by a valid signed checkpoint" in capsys.readouterr().out


def test_verifier_flags_invalid_inclusion_proof(
    signed_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(verify_ledger, "verify_inclusion", lambda *_: False)
    assert _verify("--db", str(signed_db), "--entry-id", "1") == 1
    assert "inclusion proof invalid" in capsys.readouterr().out


def test_verifier_unsigned_ledger(db: Path, pubkey: Path) -> None:
    _fill(_ledger(db), 2)
    assert _verify("--db", str(db)) == 0
    assert _verify("--db", str(db), "--pubkey", str(pubkey)) == 1


def test_verifier_usage_errors(
    tmp_path: Path, signed_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _verify("--db", str(tmp_path / "missing.db")) == 2
    bad_key = tmp_path / "bad.pem"
    bad_key.write_text("garbage")
    assert _verify("--db", str(signed_db), "--pubkey", str(bad_key)) == 2
    not_a_db = tmp_path / "not.db"
    not_a_db.write_text("plain text")
    assert _verify("--db", str(not_a_db)) == 2
    assert "error:" in capsys.readouterr().err
