'use strict';
// NEAR keys and transactions: parse "ed25519:<base58>" keys, build a
// FunctionCall transaction, hash and sign it with node:crypto (Ed25519).
//
// NEAR signs the SHA-256 hash of the borsh-encoded transaction, and that hash,
// in base58, is the transaction hash shown by explorers.
//
// A secret key only ever lives inside the closure returned by keyPairFromSecret.
// Nothing here prints, logs or returns it, and errors never include it.

const crypto = require('node:crypto');
const util = require('node:util');
const bs58 = require('./base58.js');
const B = require('./borsh.js');

const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');
const ACCOUNT_ID = /^(?=.{2,64}$)(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const isAccountId = (s) => typeof s === 'string' && ACCOUNT_ID.test(s);

/** "ed25519:<base58>" (or "secp256k1:...") to {keyType, data}. */
function parsePublicKey(text) {
  const m = /^(ed25519|secp256k1):([1-9A-HJ-NP-Za-km-z]+)$/.exec(String(text || '').trim());
  if (!m) throw new Error('public key must look like ed25519:<base58>');
  const keyType = B.KEY_TYPES[m[1]];
  const data = bs58.decode(m[2]);
  if (data.length !== B.KEY_LEN[keyType]) throw new Error(`a ${m[1]} public key has ${B.KEY_LEN[keyType]} bytes`);
  return { keyType, data };
}
const publicKeyToString = (pk) => `${B.KEY_NAMES[pk.keyType]}:${bs58.encode(pk.data)}`;

function parseSignature(text) {
  const m = /^(ed25519|secp256k1):([1-9A-HJ-NP-Za-km-z]+)$/.exec(String(text || '').trim());
  if (!m) throw new Error('signature must look like ed25519:<base58>');
  const keyType = B.KEY_TYPES[m[1]];
  const data = bs58.decode(m[2]);
  if (data.length !== B.SIG_LEN[keyType]) throw new Error('signature has the wrong length');
  return { keyType, data };
}
const signatureToString = (sig) => `${B.KEY_NAMES[sig.keyType]}:${bs58.encode(sig.data)}`;

/**
 * Loads a NEAR secret key: "ed25519:<base58>" of 64 bytes (seed + public key,
 * the form NEAR wallets export) or of a 32-byte seed. Returns a signer that can
 * sign but never reveals the secret.
 */
function keyPairFromSecret(text, label = 'NEAR_PRIVATE_KEY') {
  const m = /^ed25519:([1-9A-HJ-NP-Za-km-z]+)$/.exec(String(text || '').trim());
  if (!m) throw new Error(`${label} must be an Ed25519 key that looks like ed25519:<base58>`);
  let raw;
  try { raw = bs58.decode(m[1]); } catch { throw new Error(`${label} is not valid base58`); }
  if (raw.length !== 64 && raw.length !== 32) throw new Error(`${label} must decode to 64 bytes (or a 32-byte seed)`);
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, raw.subarray(0, 32)]), format: 'der', type: 'pkcs8' });
  } catch { throw new Error(`${label} could not be loaded as an Ed25519 key`); }
  const pub = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).subarray(-32);
  const damaged = raw.length === 64 && !raw.subarray(32).equals(pub);
  raw.fill(0);
  if (damaged) throw new Error(`${label} is damaged: its public half does not match its secret half`);
  const publicKey = { keyType: 0, data: Buffer.from(pub) };
  const publicKeyText = publicKeyToString(publicKey);
  const signer = {
    publicKey,
    publicKeyText,
    sign: (message) => crypto.sign(null, Buffer.from(message), privateKey),
    toJSON: () => ({ publicKey: publicKeyText }),
    toString: () => `[NEAR key ${publicKeyText}]`,
  };
  signer[util.inspect.custom] = () => `[NEAR key ${publicKeyText}]`;
  return Object.freeze(signer);
}

/** Ed25519 check of a NEAR signature over `message` (for a transaction: its 32-byte hash). */
function verifySignature(publicKey, message, signature) {
  if (publicKey.keyType !== 0 || signature.keyType !== 0) throw new Error('only ed25519 signatures are checked here');
  const key = crypto.createPublicKey({ key: Buffer.concat([SPKI_ED25519, publicKey.data]), format: 'der', type: 'spki' });
  return crypto.verify(null, Buffer.from(message), key, signature.data);
}

/** A FunctionCall action. `args` is an object (sent as JSON) or raw bytes. */
function functionCall(methodName, args, gas, deposit) {
  const bytes = Buffer.isBuffer(args) || args instanceof Uint8Array ? Buffer.from(args) : Buffer.from(JSON.stringify(args), 'utf8');
  return { type: 'FunctionCall', methodName, args: bytes, gas: BigInt(gas), deposit: BigInt(deposit) };
}

function createTransaction({ signerId, publicKey, nonce, receiverId, blockHash, actions }) {
  if (!isAccountId(signerId)) throw new Error('signer is not a valid NEAR account id');
  if (!isAccountId(receiverId)) throw new Error('receiver is not a valid NEAR account id');
  const hash = typeof blockHash === 'string' ? bs58.decode(blockHash) : Buffer.from(blockHash);
  if (hash.length !== 32) throw new Error('block hash must be 32 bytes');
  return { version: 0, signerId, publicKey: typeof publicKey === 'string' ? parsePublicKey(publicKey) : publicKey, nonce: BigInt(nonce), receiverId, blockHash: hash, actions };
}

/** Hash of a transaction: SHA-256 of its borsh bytes. Returns {bytes, hash (Buffer), id (base58)}. */
function hashTransaction(tx) {
  const bytes = B.serializeTransaction(tx);
  const hash = sha256(bytes);
  return { bytes, hash, id: bs58.encode(hash) };
}

/** Signs `tx` with `signer` (from keyPairFromSecret). The signer's key must be the transaction's key. */
function signTransaction(tx, signer) {
  if (tx.publicKey.keyType !== signer.publicKey.keyType || !tx.publicKey.data.equals(signer.publicKey.data)) {
    throw new Error('the transaction names a different public key than the signing key');
  }
  const { hash, id } = hashTransaction(tx);
  const signature = { keyType: 0, data: signer.sign(hash) };
  const signed = B.serializeSignedTransaction({ transaction: tx, signature });
  return { id, hash, signature, signed, base64: signed.toString('base64') };
}

// ---- RPC JSON (SignedTransactionView) to the borsh model ----

const permissionFromView = (p) => (p === 'FullAccess' ? { type: 'FullAccess' } : {
  type: 'FunctionCall',
  allowance: p.FunctionCall.allowance == null ? null : BigInt(p.FunctionCall.allowance),
  receiverId: p.FunctionCall.receiver_id,
  methodNames: p.FunctionCall.method_names || [],
});

function actionFromView(a) {
  if (a === 'CreateAccount') return { type: 'CreateAccount' };
  const [type] = Object.keys(a || {});
  const v = a[type];
  switch (type) {
    case 'CreateAccount': return { type };
    case 'DeployContract': return { type, code: Buffer.from(v.code, 'base64') };
    case 'FunctionCall': return { type, methodName: v.method_name, args: Buffer.from(v.args, 'base64'), gas: BigInt(v.gas), deposit: BigInt(v.deposit) };
    case 'Transfer': return { type, deposit: BigInt(v.deposit) };
    case 'Stake': return { type, stake: BigInt(v.stake), publicKey: parsePublicKey(v.public_key) };
    case 'AddKey': return { type, publicKey: parsePublicKey(v.public_key), accessKey: { nonce: BigInt(v.access_key.nonce), permission: permissionFromView(v.access_key.permission) } };
    case 'DeleteKey': return { type, publicKey: parsePublicKey(v.public_key) };
    case 'DeleteAccount': return { type, beneficiaryId: v.beneficiary_id };
    case 'Delegate': {
      const d = v.delegate_action;
      return {
        type,
        delegateAction: { senderId: d.sender_id, receiverId: d.receiver_id, actions: d.actions.map(actionFromView), nonce: BigInt(d.nonce), maxBlockHeight: BigInt(d.max_block_height), publicKey: parsePublicKey(d.public_key) },
        signature: parseSignature(v.signature),
      };
    }
  }
  throw new Error(`unsupported action in view: ${type}`);
}

/**
 * Rebuilds a transaction from an RPC SignedTransactionView. The view has no
 * block hash, so the caller supplies the one the signer used.
 */
function transactionFromView(view, blockHash) {
  const tx = {
    version: 0, signerId: view.signer_id, publicKey: parsePublicKey(view.public_key), nonce: BigInt(view.nonce),
    receiverId: view.receiver_id, blockHash: typeof blockHash === 'string' ? bs58.decode(blockHash) : Buffer.from(blockHash), actions: view.actions.map(actionFromView),
  };
  if (view.priority_fee) { tx.version = 1; tx.priorityFee = BigInt(view.priority_fee); }
  return tx;
}

module.exports = {
  sha256, isAccountId, parsePublicKey, publicKeyToString, parseSignature, signatureToString,
  keyPairFromSecret, verifySignature, functionCall, createTransaction, hashTransaction, signTransaction,
  actionFromView, transactionFromView,
};
