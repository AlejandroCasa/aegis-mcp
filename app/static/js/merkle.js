// Independent client-side RFC 6962 / RFC 9162 inclusion-proof verification.
// Leaves are SHA-256(0x00 || entry_hash bytes); nodes SHA-256(0x01 || l || r).
// Pure module (no DOM) so it runs unchanged in browsers and in Node tests.

const HEX = /^(?:[0-9a-f]{2})+$/;

export function hexToBytes(hex) {
  const text = String(hex || "").toLowerCase();
  if (!HEX.test(text)) {
    throw new TypeError("expected an even-length lowercase hex string");
  }
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function leafBytes(entryHash) {
  const text = String(entryHash || "");
  return HEX.test(text) ? hexToBytes(text) : new TextEncoder().encode(text);
}

function subtle() {
  const api = globalThis.crypto && globalThis.crypto.subtle;
  if (!api) {
    throw new Error("Web Crypto is unavailable (requires a secure context)");
  }
  return api;
}

async function sha256(prefix, ...parts) {
  const size = parts.reduce((total, part) => total + part.length, 1);
  const buffer = new Uint8Array(size);
  buffer[0] = prefix;
  let offset = 1;
  for (const part of parts) {
    buffer.set(part, offset);
    offset += part.length;
  }
  return new Uint8Array(await subtle().digest("SHA-256", buffer));
}

export const leafHash = (leaf) => sha256(0x00, leaf);
export const nodeHash = (left, right) => sha256(0x01, left, right);

// RFC 9162 section 2.1.3.2 fold. Returns null for a malformed path.
async function fold(index, last, digest, path) {
  let fn = index;
  let sn = last;
  let result = digest;
  for (const sibling of path) {
    if (sn === 0) {
      return null;
    }
    if (fn & 1 || fn === sn) {
      result = await nodeHash(sibling, result);
      while (!(fn & 1) && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      result = await nodeHash(result, sibling);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 ? result : null;
}

// Verify an InclusionProofResponse payload; resolves to { valid, computedRoot }.
export async function verifyInclusionProof(proof) {
  const index = Number(proof.leaf_index);
  const size = Number(proof.tree_size);
  if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) {
    return { valid: false, computedRoot: "" };
  }
  const path = (proof.audit_path || []).map(hexToBytes);
  const leaf = await leafHash(leafBytes(proof.entry_hash));
  const root = await fold(index, size - 1, leaf, path);
  const computedRoot = root ? bytesToHex(root) : "";
  return { valid: computedRoot !== "" && computedRoot === proof.root_hash, computedRoot };
}
