'use strict';
// Borsh encoding for NEAR transactions, written out by hand for the few types
// Oberig needs: PublicKey, Signature, Action, Transaction and SignedTransaction.
// Field order and enum indexes follow nearcore (core/primitives).
//
// Numbers: u8/u32 are JS numbers, u64/u128 are BigInt (or anything BigInt() accepts).

const KEY_TYPES = { ed25519: 0, secp256k1: 1 };
const KEY_NAMES = ['ed25519', 'secp256k1'];
const KEY_LEN = [32, 64];
const SIG_LEN = [64, 65];
const ACTIONS = ['CreateAccount', 'DeployContract', 'FunctionCall', 'Transfer', 'Stake', 'AddKey', 'DeleteKey', 'DeleteAccount', 'Delegate'];

const U64_MAX = (1n << 64n) - 1n;
const U128_MAX = (1n << 128n) - 1n;

function big(v, max, name) {
  const n = BigInt(v);
  if (n < 0n || n > max) throw new RangeError(`borsh: ${name} out of range`);
  return n;
}

class Writer {
  constructor() { this.parts = []; }
  raw(b) { this.parts.push(Buffer.from(b)); return this; }
  u8(n) {
    if (!Number.isInteger(n) || n < 0 || n > 255) throw new RangeError('borsh: u8 out of range');
    return this.raw([n]);
  }
  u32(n) {
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new RangeError('borsh: u32 out of range');
    const b = Buffer.alloc(4); b.writeUInt32LE(n); return this.raw(b);
  }
  u64(v) { const b = Buffer.alloc(8); b.writeBigUInt64LE(big(v, U64_MAX, 'u64')); return this.raw(b); }
  u128(v) {
    const n = big(v, U128_MAX, 'u128');
    const b = Buffer.alloc(16);
    b.writeBigUInt64LE(n & U64_MAX, 0);
    b.writeBigUInt64LE(n >> 64n, 8);
    return this.raw(b);
  }
  fixed(bytes, len) {
    const b = Buffer.from(bytes);
    if (b.length !== len) throw new RangeError(`borsh: expected ${len} bytes, got ${b.length}`);
    return this.raw(b);
  }
  bytes(bytes) { const b = Buffer.from(bytes); this.u32(b.length); return this.raw(b); }
  string(s) { return this.bytes(Buffer.from(String(s), 'utf8')); }
  vec(items, fn) { this.u32(items.length); for (const it of items) fn(this, it); return this; }
  option(v, fn) { if (v === null || v === undefined) return this.u8(0); this.u8(1); fn(this, v); return this; }
  toBuffer() { return Buffer.concat(this.parts); }
}

class Reader {
  constructor(buf) { this.buf = Buffer.from(buf); this.pos = 0; }
  take(n) {
    if (this.pos + n > this.buf.length) throw new RangeError('borsh: unexpected end of data');
    const b = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return b;
  }
  u8() { return this.take(1)[0]; }
  u32() { return this.take(4).readUInt32LE(0); }
  u64() { return this.take(8).readBigUInt64LE(0); }
  u128() { const b = this.take(16); return b.readBigUInt64LE(0) | (b.readBigUInt64LE(8) << 64n); }
  fixed(n) { return Buffer.from(this.take(n)); }
  bytes() { return this.fixed(this.u32()); }
  string() { return this.bytes().toString('utf8'); }
  vec(fn) { const n = this.u32(); const out = []; for (let i = 0; i < n; i++) out.push(fn(this)); return out; }
  option(fn) { const t = this.u8(); if (t === 0) return null; if (t !== 1) throw new Error('borsh: bad option tag'); return fn(this); }
  end() { if (this.pos !== this.buf.length) throw new Error('borsh: trailing bytes'); }
}

// ---- NEAR types ----

function writePublicKey(w, pk) {
  if (!pk || !(pk.keyType in KEY_LEN)) throw new Error('borsh: unknown public key type');
  w.u8(pk.keyType).fixed(pk.data, KEY_LEN[pk.keyType]);
}
function readPublicKey(r) {
  const keyType = r.u8();
  if (!(keyType in KEY_LEN)) throw new Error('borsh: unknown public key type');
  return { keyType, data: r.fixed(KEY_LEN[keyType]) };
}
function writeSignature(w, sig) {
  if (!sig || !(sig.keyType in SIG_LEN)) throw new Error('borsh: unknown signature type');
  w.u8(sig.keyType).fixed(sig.data, SIG_LEN[sig.keyType]);
}
function readSignature(r) {
  const keyType = r.u8();
  if (!(keyType in SIG_LEN)) throw new Error('borsh: unknown signature type');
  return { keyType, data: r.fixed(SIG_LEN[keyType]) };
}

function writePermission(w, p) {
  if (p.type === 'FullAccess') return w.u8(1);
  if (p.type !== 'FunctionCall') throw new Error('borsh: unknown access key permission');
  w.u8(0);
  w.option(p.allowance, (x, v) => x.u128(v));
  w.string(p.receiverId);
  w.vec(p.methodNames || [], (x, m) => x.string(m));
  return w;
}
function readPermission(r) {
  const t = r.u8();
  if (t === 1) return { type: 'FullAccess' };
  if (t !== 0) throw new Error('borsh: unknown access key permission');
  return { type: 'FunctionCall', allowance: r.option((x) => x.u128()), receiverId: r.string(), methodNames: r.vec((x) => x.string()) };
}

function writeAction(w, a) {
  const i = ACTIONS.indexOf(a && a.type);
  if (i === -1) throw new Error(`borsh: unsupported action ${a && a.type}`);
  w.u8(i);
  switch (a.type) {
    case 'CreateAccount': return w;
    case 'DeployContract': return w.bytes(a.code);
    case 'FunctionCall': return w.string(a.methodName).bytes(a.args).u64(a.gas).u128(a.deposit);
    case 'Transfer': return w.u128(a.deposit);
    case 'Stake': w.u128(a.stake); writePublicKey(w, a.publicKey); return w;
    case 'AddKey': writePublicKey(w, a.publicKey); w.u64(a.accessKey.nonce); return writePermission(w, a.accessKey.permission);
    case 'DeleteKey': writePublicKey(w, a.publicKey); return w;
    case 'DeleteAccount': return w.string(a.beneficiaryId);
    case 'Delegate': writeDelegateAction(w, a.delegateAction); writeSignature(w, a.signature); return w;
  }
  return w;
}
function readAction(r) {
  const i = r.u8();
  const type = ACTIONS[i];
  switch (type) {
    case 'CreateAccount': return { type };
    case 'DeployContract': return { type, code: r.bytes() };
    case 'FunctionCall': return { type, methodName: r.string(), args: r.bytes(), gas: r.u64(), deposit: r.u128() };
    case 'Transfer': return { type, deposit: r.u128() };
    case 'Stake': return { type, stake: r.u128(), publicKey: readPublicKey(r) };
    case 'AddKey': { const publicKey = readPublicKey(r); return { type, publicKey, accessKey: { nonce: r.u64(), permission: readPermission(r) } }; }
    case 'DeleteKey': return { type, publicKey: readPublicKey(r) };
    case 'DeleteAccount': return { type, beneficiaryId: r.string() };
    case 'Delegate': return { type, delegateAction: readDelegateAction(r), signature: readSignature(r) };
  }
  throw new Error(`borsh: unsupported action index ${i}`);
}

function writeDelegateAction(w, d) {
  w.string(d.senderId).string(d.receiverId);
  w.vec(d.actions, (x, a) => {
    if (a.type === 'Delegate') throw new Error('borsh: a delegate action cannot contain another one');
    writeAction(x, a);
  });
  w.u64(d.nonce).u64(d.maxBlockHeight);
  writePublicKey(w, d.publicKey);
  return w;
}
function readDelegateAction(r) {
  const senderId = r.string();
  const receiverId = r.string();
  const actions = r.vec(readAction);
  return { senderId, receiverId, actions, nonce: r.u64(), maxBlockHeight: r.u64(), publicKey: readPublicKey(r) };
}

/**
 * Transaction: version 0 (what wallets sign today) has no prefix byte; version 1
 * starts with a 1 byte and ends with priority_fee (u64).
 */
function writeTransaction(w, tx) {
  const v1 = tx.version === 1;
  if (v1) w.u8(1);
  w.string(tx.signerId);
  writePublicKey(w, tx.publicKey);
  w.u64(tx.nonce).string(tx.receiverId).fixed(tx.blockHash, 32);
  w.vec(tx.actions, writeAction);
  if (v1) w.u64(tx.priorityFee || 0);
  return w;
}
function readTransaction(r) {
  // Version 0 starts with the u32 length of an account id (at most 64), so its
  // second byte is always 0. Version 1 starts with 1, then a non-zero length byte.
  const v1 = r.buf[r.pos] === 1 && r.buf[r.pos + 1] !== 0;
  if (v1) r.u8();
  const tx = { version: v1 ? 1 : 0, signerId: r.string(), publicKey: readPublicKey(r), nonce: r.u64(), receiverId: r.string(), blockHash: r.fixed(32), actions: r.vec(readAction) };
  if (v1) tx.priorityFee = r.u64();
  return tx;
}

const serializeTransaction = (tx) => writeTransaction(new Writer(), tx).toBuffer();
function serializeSignedTransaction(stx) {
  const w = new Writer();
  writeTransaction(w, stx.transaction);
  writeSignature(w, stx.signature);
  return w.toBuffer();
}
function deserializeSignedTransaction(buf) {
  const r = new Reader(buf);
  const transaction = readTransaction(r);
  const signature = readSignature(r);
  r.end();
  return { transaction, signature };
}

module.exports = {
  Writer, Reader, KEY_TYPES, KEY_NAMES, KEY_LEN, SIG_LEN, ACTIONS,
  writePublicKey, readPublicKey, writeSignature, readSignature, writeAction, readAction,
  serializeTransaction, serializeSignedTransaction, deserializeSignedTransaction,
};
