"""RFC 6962 Merkle tree and Ed25519 Signed Tree Heads over the audit ledger.

The hash chain (``app/ledger.py``) proves *linear* integrity: verifying one
entry requires replaying every link before it. This module adds the
Certificate Transparency construction on top of the chain's entry hashes:

* **Merkle Tree Hash** (RFC 6962 section 2.1 / RFC 9162 section 2.1.1) with
  domain separation: leaves are ``SHA-256(0x00 || leaf)`` and interior nodes
  ``SHA-256(0x01 || left || right)``, so a leaf can never be passed off as
  an interior node (second-preimage attack). Each leaf is the 32-byte
  ``entry_hash`` of a ledger entry, in chain order.
* **Inclusion proofs** (audit paths): ``O(log n)`` sibling hashes that prove
  one entry is committed by a tree head without disclosing other entries.
* **Signed Tree Heads** (checkpoints): Ed25519 signatures over the RFC 8785
  canonical JSON of ``tree_size``, ``root_hash``, ``timestamp`` and
  ``prev_checkpoint_hash``. Checkpoints chain to one another, so dropping,
  reordering or rewriting history after a checkpoint was signed (or
  exported to a SIEM) is detectable offline with only the public key.

Signing keys are PKCS#8 PEM Ed25519 private keys, e.g.
``openssl genpkey -algorithm ed25519 -out aegis-signing.pem``.
"""

import hashlib
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.canonical import canonical_bytes

logger = logging.getLogger("aegis_mcp.merkle")

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
CHECKPOINT_FORMAT = "aegis-sth/v1"
SIGNATURE_ALGORITHM = "Ed25519"
GENESIS_CHECKPOINT_HASH = "0" * 64


class SigningKeyError(RuntimeError):
    """The checkpoint signing key is missing, unreadable or not Ed25519."""


def leaf_hash(leaf: bytes) -> bytes:
    """RFC 6962 leaf hash: ``SHA-256(0x00 || leaf)``."""
    return hashlib.sha256(LEAF_PREFIX + leaf).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash: ``SHA-256(0x01 || left || right)``."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _split(size: int) -> int:
    """Largest power of two strictly smaller than ``size`` (``size >= 2``)."""
    return 1 << ((size - 1).bit_length() - 1)


def _root(leaf_hashes: Sequence[bytes]) -> bytes:
    """Merkle Tree Hash of a non-empty list of already-hashed leaves."""
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    k = _split(len(leaf_hashes))
    return node_hash(_root(leaf_hashes[:k]), _root(leaf_hashes[k:]))


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash of ``leaves`` (``SHA-256("")`` when empty)."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    return _root([leaf_hash(leaf) for leaf in leaves])


def _path(index: int, leaf_hashes: Sequence[bytes]) -> list[bytes]:
    """RFC 6962 ``PATH(m, D[n])`` over already-hashed leaves."""
    if len(leaf_hashes) == 1:
        return []
    k = _split(len(leaf_hashes))
    if index < k:
        return [*_path(index, leaf_hashes[:k]), _root(leaf_hashes[k:])]
    return [*_path(index - k, leaf_hashes[k:]), _root(leaf_hashes[:k])]


def inclusion_proof(leaves: Sequence[bytes], index: int) -> list[bytes]:
    """Audit path proving ``leaves[index]`` is in the tree of all ``leaves``."""
    if not 0 <= index < len(leaves):
        raise IndexError(f"leaf index {index} outside tree of size {len(leaves)}")
    return _path(index, [leaf_hash(leaf) for leaf in leaves])


def _fold(index: int, last: int, digest: bytes, path: Sequence[bytes]) -> bytes:
    """RFC 9162 section 2.1.3.2 fold; returns ``b""`` when the path is invalid."""
    for sibling in path:
        if last == 0:
            return b""
        if index & 1 or index == last:
            digest = node_hash(sibling, digest)
            while not index & 1 and index:
                index >>= 1
                last >>= 1
        else:
            digest = node_hash(digest, sibling)
        index >>= 1
        last >>= 1
    return digest if last == 0 else b""


def verify_inclusion(
    leaf: bytes, index: int, tree_size: int, path: Sequence[bytes], root: bytes
) -> bool:
    """Verify an RFC 6962 audit path for raw ``leaf`` at ``index``."""
    if not 0 <= index < tree_size:
        return False
    return _fold(index, tree_size - 1, leaf_hash(leaf), path) == root


def key_fingerprint(public_key: bytes) -> str:
    """SHA-256 hex fingerprint of a raw 32-byte Ed25519 public key."""
    return hashlib.sha256(public_key).hexdigest()


@dataclass(frozen=True)
class TreeHead:
    """Unsigned checkpoint metadata committed to by an Ed25519 signature."""

    tree_size: int
    root_hash: str
    timestamp: str
    prev_checkpoint_hash: str

    def message(self) -> bytes:
        """RFC 8785 canonical bytes that are signed (domain-separated)."""
        return canonical_bytes(
            {
                "format": CHECKPOINT_FORMAT,
                "tree_size": self.tree_size,
                "root_hash": self.root_hash,
                "timestamp": self.timestamp,
                "prev_checkpoint_hash": self.prev_checkpoint_hash,
            }
        )

    def digest(self) -> str:
        """Checkpoint hash: chains the next checkpoint to this one."""
        return hashlib.sha256(self.message()).hexdigest()


@dataclass(frozen=True)
class SignedTreeHead:
    """A tree head plus its Ed25519 signature and raw public key (hex)."""

    head: TreeHead
    signature: str
    public_key: str

    @property
    def key_fingerprint(self) -> str:
        """SHA-256 fingerprint of the signing public key ("" when malformed)."""
        try:
            return key_fingerprint(bytes.fromhex(self.public_key))
        except ValueError:
            return ""

    def verify(self, trusted_public_key: bytes | None = None) -> bool:
        """Check the signature (and the pinned key, when one is given)."""
        try:
            public_key = bytes.fromhex(self.public_key)
            signature = bytes.fromhex(self.signature)
            if trusted_public_key is not None and public_key != trusted_public_key:
                return False
            key = Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(signature, self.head.message())
        except (ValueError, InvalidSignature):
            return False
        return True

    def as_dict(self) -> dict[str, Any]:
        """Flat JSON-ready representation (API responses and exports)."""
        return {
            "tree_size": self.head.tree_size,
            "root_hash": self.head.root_hash,
            "timestamp": self.head.timestamp,
            "prev_checkpoint_hash": self.head.prev_checkpoint_hash,
            "checkpoint_hash": self.head.digest(),
            "algorithm": SIGNATURE_ALGORITHM,
            "signature": self.signature,
            "public_key": self.public_key,
            "key_fingerprint": self.key_fingerprint,
        }


class CheckpointSigner:
    """Signs tree heads with an Ed25519 private key."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        """Wrap ``private_key``; the raw public key is derived once."""
        self._key = private_key
        self.public_key = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @classmethod
    def generate(cls) -> "CheckpointSigner":
        """Ephemeral in-memory key (development and tests only)."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, data: bytes) -> "CheckpointSigner":
        """Load an unencrypted PKCS#8 PEM Ed25519 private key."""
        try:
            key = serialization.load_pem_private_key(data, password=None)
        except (ValueError, TypeError) as exc:
            raise SigningKeyError("signing key is not a valid PEM key") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise SigningKeyError("signing key must be an Ed25519 private key")
        return cls(key)

    @property
    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the public key."""
        return key_fingerprint(self.public_key)

    def public_key_pem(self) -> bytes:
        """SubjectPublicKeyInfo PEM of the public key (for offline verifiers)."""
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, head: TreeHead) -> SignedTreeHead:
        """Sign ``head`` and return the Signed Tree Head."""
        return SignedTreeHead(
            head=head,
            signature=self._key.sign(head.message()).hex(),
            public_key=self.public_key.hex(),
        )


def load_public_key(data: bytes) -> bytes:
    """Raw Ed25519 public key from SubjectPublicKeyInfo PEM or 64 hex chars."""
    text = data.strip()
    if len(text) == 64:
        try:
            return bytes.fromhex(text.decode("ascii"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise SigningKeyError("public key is not valid hex") from exc
    try:
        key = serialization.load_pem_public_key(text)
    except (ValueError, TypeError) as exc:
        raise SigningKeyError("public key is not a valid PEM key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SigningKeyError("public key must be an Ed25519 key")
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load_signer(
    enabled: bool, key_path: str | None, ephemeral: bool, environment: str
) -> CheckpointSigner | None:
    """Resolve the checkpoint signer from configuration (fail-closed in prod).

    * signing disabled -> ``None`` (no checkpoints are produced);
    * ``key_path`` set -> load it; any error raises ``SigningKeyError``;
    * no key in ``prod`` -> ``SigningKeyError`` (never silently unsigned);
    * no key elsewhere -> an ephemeral key when explicitly requested,
      otherwise ``None`` with a warning.
    """
    if not enabled:
        return None
    if key_path:
        try:
            data = Path(key_path).read_bytes()
        except OSError as exc:
            raise SigningKeyError(f"cannot read signing key {key_path!r}") from exc
        return CheckpointSigner.from_pem(data)
    if environment == "prod":
        raise SigningKeyError(
            "AEGIS_SIGNING_KEY_PATH is required in prod when checkpoint signing "
            "is enabled (set AEGIS_CHECKPOINT_SIGNING=false to opt out)"
        )
    if ephemeral:
        logger.warning("Using an ephemeral Ed25519 checkpoint key (dev/test only)")
        return CheckpointSigner.generate()
    logger.info("No checkpoint signing key configured: checkpoints disabled")
    return None
