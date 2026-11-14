'use strict';
// SHA-256 Merkle tree in the Certificate Transparency form (RFC 6962, section 2.1;
// RFC 9162, section 2.1): leaf = SHA-256(0x00 || data), node = SHA-256(0x01 || left || right),
// and a tree of n leaves splits at the largest power of two below n (no duplicated leaves).
//
// The leaves Oberig anchors are receipt hashes (32 bytes each), oldest first.

const crypto = require('node:crypto');

const H = (...parts) => { const h = crypto.createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
const LEAF = Buffer.from([0]);
const NODE = Buffer.from([1]);

const toBuf = (x) => (Buffer.isBuffer(x) ? x : typeof x === 'string' ? Buffer.from(x, 'hex') : Buffer.from(x));
const leafHash = (data) => H(LEAF, toBuf(data));
const nodeHash = (left, right) => H(NODE, left, right);

/** Largest power of two strictly smaller than n (n >= 2). */
function split(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function rootOfHashes(hs) {
  if (hs.length === 1) return hs[0];
  const k = split(hs.length);
  return nodeHash(rootOfHashes(hs.slice(0, k)), rootOfHashes(hs.slice(k)));
}

/** Merkle tree hash of the leaves (Buffers or hex strings). The empty tree hashes to SHA-256(""). */
function root(leaves) {
  if (!leaves.length) return H();
  return rootOfHashes(leaves.map(leafHash));
}

function pathOf(m, hs) {
  if (hs.length === 1) return [];
  const k = split(hs.length);
  if (m < k) return [...pathOf(m, hs.slice(0, k)), rootOfHashes(hs.slice(k))];
  return [...pathOf(m - k, hs.slice(k)), rootOfHashes(hs.slice(0, k))];
}

/** Inclusion proof (audit path) for leaf `index`: {index, size, path: [Buffer]}, leaf side first. */
function proof(leaves, index) {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) throw new RangeError('leaf index out of range');
  return { index, size: leaves.length, path: pathOf(index, leaves.map(leafHash)) };
}

/** Root a proof leads to from `leaf` (RFC 9162, 2.1.3.2), or null when the proof is malformed. */
function rootFromProof(leaf, { index, size, path }) {
  if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) return null;
  let fn = index;
  let sn = size - 1;
  let r = leafHash(leaf);
  for (const raw of path) {
    const p = toBuf(raw);
    if (p.length !== 32 || sn === 0) return null;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 ? r : null;
}

/** True when `proof` shows `leaf` is in the tree with root `expectedRoot`. */
function verify(leaf, prf, expectedRoot) {
  const r = rootFromProof(leaf, prf);
  return !!r && r.equals(toBuf(expectedRoot));
}

module.exports = { root, proof, verify, rootFromProof, leafHash, nodeHash };
