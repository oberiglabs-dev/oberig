'use strict';
// Small, dependency-free pieces for NEAR AI's ECDSA signatures:
//   keccak256 (Ethereum's Keccak, which is NOT node's sha3-256: the padding differs)
//   secp256k1 public key recovery
//   EIP-191 personal_sign signer recovery
// Oberig asks for Ed25519 by default (node:crypto verifies it natively).
// This module is the fallback when a service only offers ECDSA.

const ROT = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const M64 = (1n << 64n) - 1n;
const rotl = (v, n) => (n === 0 ? v : ((v << BigInt(n)) | (v >> BigInt(64 - n))) & M64);

function keccakF(s) {
  const c = new Array(5);
  const b = new Array(25);
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) s[x + 5 * y] ^= d;
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[x + 5 * y], ROT[x][y]);
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        s[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & M64 & b[((x + 2) % 5) + 5 * y]);
      }
    }
    s[0] ^= RC[round];
  }
}

/** Sponge with rate 136 bytes and 32-byte output. pad = 0x01 for Keccak-256, 0x06 for SHA3-256. */
function sponge256(data, pad) {
  const msg = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const rate = 136;
  const blocks = Math.floor(msg.length / rate) + 1;
  const padded = Buffer.alloc(blocks * rate);
  msg.copy(padded);
  padded[msg.length] ^= pad;
  padded[padded.length - 1] ^= 0x80;
  const s = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) s[i] ^= padded.readBigUInt64LE(off + i * 8);
    keccakF(s);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(s[i], i * 8);
  return out;
}

const keccak256 = (data) => sponge256(data, 0x01);

// ---- secp256k1 ----
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
];

const mod = (a, m = P) => { const r = a % m; return r >= 0n ? r : r + m; };
function inv(a, m = P) {
  let [lo, hi, x0, x1] = [mod(a, m), m, 1n, 0n];
  while (lo > 1n) { const q = hi / lo; [lo, hi] = [hi - q * lo, lo]; [x0, x1] = [x1 - q * x0, x0]; }
  return mod(x0, m);
}
function powmod(b, e, m = P) {
  let r = 1n; b = mod(b, m);
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}
// Jacobian point arithmetic (null = point at infinity).
function jDouble(p) {
  if (!p) return null;
  const [X, Y, Z] = p;
  if (Y === 0n) return null;
  const S = mod(4n * X * Y * Y);
  const M = mod(3n * X * X);
  const X3 = mod(M * M - 2n * S);
  return [X3, mod(M * (S - X3) - 8n * Y * Y * Y * Y), mod(2n * Y * Z)];
}
function jAdd(p, q) {
  if (!p) return q;
  if (!q) return p;
  const [X1, Y1, Z1] = p;
  const [X2, Y2, Z2] = q;
  const Z1s = mod(Z1 * Z1), Z2s = mod(Z2 * Z2);
  const U1 = mod(X1 * Z2s), U2 = mod(X2 * Z1s);
  const S1 = mod(Y1 * Z2s * Z2), S2 = mod(Y2 * Z1s * Z1);
  if (U1 === U2) return S1 === S2 ? jDouble(p) : null;
  const H = mod(U2 - U1), R = mod(S2 - S1);
  const H2 = mod(H * H), H3 = mod(H2 * H);
  const X3 = mod(R * R - H3 - 2n * U1 * H2);
  return [X3, mod(R * (U1 * H2 - X3) - S1 * H3), mod(H * Z1 * Z2)];
}
function jMul(pt, k) {
  let r = null;
  let a = [pt[0], pt[1], 1n];
  while (k > 0n) { if (k & 1n) r = jAdd(r, a); a = jDouble(a); k >>= 1n; }
  return r;
}
function toAffine(p) {
  if (!p) return null;
  const zi = inv(p[2]);
  return [mod(p[0] * zi * zi), mod(p[1] * zi * zi * zi)];
}
const big = (buf) => BigInt('0x' + (Buffer.from(buf).toString('hex') || '0'));
const buf32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex');

/** Recovers the 64-byte uncompressed public key (x||y) from a 32-byte hash and r, s, recid. */
function recoverPublicKey(hash, r, s, recid) {
  r = typeof r === 'bigint' ? r : big(r);
  s = typeof s === 'bigint' ? s : big(s);
  if (r <= 0n || r >= N || s <= 0n || s >= N) throw new Error('signature values out of range');
  if (recid < 0 || recid > 3) throw new Error('bad recovery id');
  const x = recid & 2 ? r + N : r;
  if (x >= P) throw new Error('bad r for recovery id');
  const alpha = mod(x * x * x + 7n);
  let y = powmod(alpha, (P + 1n) / 4n);
  if (mod(y * y) !== alpha) throw new Error('r is not on the curve');
  if ((y & 1n) !== BigInt(recid & 1)) y = P - y;
  const z = mod(big(hash), N);
  const rInv = inv(r, N);
  const u1 = mod(-z * rInv, N);
  const u2 = mod(s * rInv, N);
  const Q = toAffine(jAdd(jMul(G, u1), jMul([x, y], u2)));
  if (!Q) throw new Error('recovered point at infinity');
  return Buffer.concat([buf32(Q[0]), buf32(Q[1])]);
}

function addressOf(pub64) {
  return '0x' + keccak256(pub64).subarray(12).toString('hex');
}

function eip191Hash(text) {
  const body = Buffer.from(text, 'utf8');
  return keccak256(Buffer.concat([Buffer.from('\x19Ethereum Signed Message:\n' + body.length, 'utf8'), body]));
}

/** Recovers the Ethereum address that personal_signed `text`. sig: 65 bytes r||s||v (hex or Buffer). */
function recoverEip191(text, sig) {
  const b = Buffer.isBuffer(sig) ? sig : Buffer.from(String(sig).replace(/^0x/i, ''), 'hex');
  if (b.length !== 65) throw new Error('ECDSA signature must be 65 bytes');
  let v = b[64];
  if (v >= 27) v -= 27;
  return addressOf(recoverPublicKey(eip191Hash(text), b.subarray(0, 32), b.subarray(32, 64), v));
}

module.exports = { keccak256, sponge256, recoverPublicKey, addressOf, eip191Hash, recoverEip191 };
