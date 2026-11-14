'use strict';
// Anchor: publish the Merkle root of a session's receipt hashes to NEAR, under
// the user's own account, in SocialDB (social.near on mainnet, v1.social08.testnet
// on testnet). Later anyone can check a root, or a receipt with its inclusion
// proof, with a free view call.
//
//   key    <account>/oberig/anchors/<root>
//   value  {"v":1,"tree":"rfc6962-sha256","n":<receipts>,"t":"<UTC time>","app":"oberig/<version>"}
//
// Only receipt hashes go into the tree. Receipts are metadata (no prompt or
// answer text), and the chain only ever sees one 32-byte root per anchor.

const fs = require('node:fs');
const { VERSION } = require('../config.js');
const R = require('../receipt.js');
const M = require('./merkle.js');
const T = require('./tx.js');
const { explorerTx, failureText } = require('./rpc.js');

const TREE = 'rfc6962-sha256';
const HEX64 = /^[0-9a-f]{64}$/;
const GAS = 30000000000000n; // 30 TGas attached; a write of this size uses about 4 TGas
const TYPICAL_GAS = 5000000000000n; // what one anchor usually burns (3.7 TGas measured on a real SocialDB write)
const RECEIPT_GAS = 1000000000000n; // creating the call receipt, bought together with the attached gas
const YOCTO = 10n ** 24n;
// SocialDB storage estimate, the same per-entry sizes near.social uses before every write.
const KV_BYTES = 40 * 3 + 8 + 12;
const NODE_BYTES = 40 * 2 + 8 + 10;
const EXTRA_BYTES = 500; // headroom, refunded when not used
const NEW_ACCOUNT_BYTES = 150; // SocialDB's own record for a newly registered account (about 120 bytes)
const MIN_ACCOUNT_BYTES = 2000; // SocialDB registers an account only with at least this much deposit

const isHex64 = (s) => typeof s === 'string' && HEX64.test(s);

/** yoctoNEAR (BigInt) to a short NEAR string: 0.0124 */
function near(yocto, digits = 4) {
  const v = BigInt(yocto);
  const neg = v < 0n;
  const a = neg ? -v : v;
  const scale = 10n ** BigInt(24 - digits);
  const units = (a + scale / 2n) / scale; // rounded
  const whole = units / 10n ** BigInt(digits);
  const frac = (units % 10n ** BigInt(digits)).toString().padStart(digits, '0').replace(/0+$/, '');
  return (neg ? '-' : '') + whole.toString() + (frac ? '.' + frac : '');
}

// ---- receipts in, hashes out ----

/**
 * Turns receipts (full receipt objects, {hash} objects or hex strings) into a list of
 * unique receipt hashes, keeping their order. Full receipts are hashed again from their
 * fields, so a receipt edited after it was sealed is refused.
 */
function receiptHashes(items) {
  const hashes = [];
  const seen = new Set();
  const bad = [];
  let list = items || [];
  // Receipts that carry their time are put oldest first, so a saved gateway state
  // (newest first) gives the same root as the gateway itself.
  if (list.length && list.every((it) => it && typeof it === 'object' && Number.isFinite(it.time))) {
    list = list.map((it, i) => [it, i]).sort((a, b) => a[0].time - b[0].time || a[1] - b[1]).map((x) => x[0]);
  }
  for (const it of list) {
    let h = null;
    if (typeof it === 'string') h = it.trim().toLowerCase();
    else if (it && typeof it === 'object' && typeof it.hash === 'string') {
      h = it.hash.trim().toLowerCase();
      const fields = Object.keys(it).filter((k) => !['hash', 'id', 'time', 'verdict'].includes(k));
      if (fields.length && R.seal({ ...it }).hash !== h) { bad.push(String(it.id || h.slice(0, 4))); continue; }
    }
    if (!isHex64(h)) { bad.push(String(h).slice(0, 12) || '(empty)'); continue; }
    if (!seen.has(h)) { seen.add(h); hashes.push(h); }
  }
  return { hashes, bad };
}

/**
 * Reads a file given to --receipts or --proof. Accepts a JSON array of receipts or
 * hashes, the gateway state ({receipts: [...]}), one receipt, an anchor file written by
 * "oberig anchor --out", a proof file, JSON Lines, or one hash per line.
 */
function loadFile(file) {
  const text = fs.readFileSync(file, 'utf8').replace(/^﻿/, '');
  let j;
  try { j = JSON.parse(text); } catch { j = undefined; }
  if (j !== undefined) {
    if (Array.isArray(j)) return { kind: 'receipts', items: j };
    if (j && j.oberig === 'anchor' && Array.isArray(j.leaves)) return { kind: 'anchor', anchor: j, items: j.leaves };
    if (j && j.oberig === 'proof') return { kind: 'proof', proof: j, items: [] };
    if (j && Array.isArray(j.receipts)) return { kind: 'receipts', items: j.receipts };
    if (j && typeof j.hash === 'string') return { kind: 'receipts', items: [j] };
    throw new Error(`${file}: no receipts found (expected receipts, receipt hashes, an anchor file or a proof file)`);
  }
  const items = text.split(/\r?\n/).map((s) => s.trim()).filter(Boolean).map((line) => {
    if (line.startsWith('{')) {
      try { return JSON.parse(line); } catch { throw new Error(`${file}: a line is not valid JSON`); }
    }
    return line;
  });
  return { kind: 'receipts', items };
}

/** Receipts and anchors from the running gateway, or null when none answers. */
async function fromGateway(port, fetchImpl = globalThis.fetch) {
  let res;
  try {
    res = await fetchImpl(`http://127.0.0.1:${port}/_oberig/receipts`, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(2500) });
  } catch { return null; }
  if (!res.ok) return null;
  const j = await res.json().catch(() => null);
  return j && Array.isArray(j.receipts) ? j : null;
}

/** Tells the running gateway about a successful anchor, so its dashboard marks the receipts. */
async function tellGateway(port, anchor, fetchImpl = globalThis.fetch) {
  try {
    const res = await fetchImpl(`http://127.0.0.1:${port}/_oberig/anchored`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(anchor), signal: AbortSignal.timeout(2500),
    });
    return res.ok;
  } catch { return false; }
}

// ---- the record ----

/** The SocialDB record and the set() arguments for a list of receipt hashes. */
function buildRecord(accountId, hashes, now = Date.now()) {
  if (!T.isAccountId(accountId)) throw new Error(`"${accountId}" is not a valid NEAR account id`);
  if (!hashes.length) throw new Error('no receipts to anchor');
  const root = M.root(hashes).toString('hex');
  const value = JSON.stringify({ v: 1, tree: TREE, n: hashes.length, t: new Date(now).toISOString().slice(0, 19) + 'Z', app: `oberig/${VERSION}` });
  const key = `${accountId}/oberig/anchors/${root}`;
  const args = { data: { [accountId]: { oberig: { anchors: { [root]: value } } } }, options: { refund_unused_deposit: true } };
  return { root, key, value, args, count: hashes.length };
}

/** Bytes SocialDB will charge for this record, given which parent nodes exist already. */
function estimateBytes({ accountId, root, value, registered, hasOberig, hasAnchors }) {
  let b = root.length * 2 + KV_BYTES + Buffer.byteLength(value);
  if (!hasAnchors) b += 'anchors'.length * 2 + KV_BYTES + NODE_BYTES;
  if (!hasOberig) b += 'oberig'.length * 2 + KV_BYTES + NODE_BYTES;
  if (!registered) b += accountId.length * 2 + KV_BYTES + NODE_BYTES + NEW_ACCOUNT_BYTES;
  return Math.ceil(b * 1.15); // the per-entry sizes run about 15% low on real accounts
}

/**
 * Cost of one anchor. Storage stays locked in SocialDB while the record exists; the
 * attached deposit above that comes back in the same transaction (refund_unused_deposit).
 * Gas is bought up front at the protocol's purchase price and the unused part is refunded.
 */
function estimateCost({ bytes, storage, registered, gasPrice, storagePerByte, minGasPurchasePrice }) {
  const perByte = BigInt(storagePerByte);
  const keep = BigInt(bytes) * perByte;
  const want = BigInt(bytes + EXTRA_BYTES) * perByte;
  const available = storage ? BigInt(storage.available_bytes || 0) * perByte : 0n;
  let deposit = want > available ? want - available : 0n;
  const minimum = BigInt(MIN_ACCOUNT_BYTES) * perByte;
  if (!registered && deposit < minimum) deposit = minimum;
  const buyPrice = minGasPurchasePrice && BigInt(minGasPurchasePrice) > BigInt(gasPrice) ? BigInt(minGasPurchasePrice) : BigInt(gasPrice);
  const gasHeld = (GAS + RECEIPT_GAS) * buyPrice;
  const gasUsed = TYPICAL_GAS * BigInt(gasPrice);
  return {
    bytes, keep, deposit, gas: GAS, gasHeld, gasUsed,
    total: (keep > available ? keep - available : 0n) + gasUsed,
    needed: deposit + gasHeld + 10n ** 21n, // plus 0.001 NEAR for the transaction itself
  };
}

const dig = (o, path) => path.reduce((x, k) => (x && typeof x === 'object' ? x[k] : undefined), o);

/** Reads everything a dry run shows. Only view calls: nothing is signed or sent. */
async function plan({ rpc, net, accountId, signer = null, hashes, now = Date.now() }) {
  const rec = buildRecord(accountId, hashes, now);
  const account = await rpc.account(accountId);
  const storage = account ? (await rpc.view(net.social, 'get_account_storage', { account_id: accountId })).value : null;
  const registered = !!storage;
  let hasOberig = false;
  let hasAnchors = false;
  let existing = null;
  if (registered) {
    const k = (await rpc.view(net.social, 'keys', { keys: [`${accountId}/oberig/*`] })).value;
    const o = dig(k, [accountId, 'oberig']);
    hasOberig = o !== undefined;
    hasAnchors = !!(o && typeof o === 'object' && 'anchors' in o);
    if (hasAnchors) existing = dig((await rpc.view(net.social, 'get', { keys: [rec.key] })).value, [accountId, 'oberig', 'anchors', rec.root]) || null;
  }
  const gasPrice = await rpc.gasPrice();
  // Without the protocol config, assume today's values: 1e19 yoctoNEAR per byte, gas bought at 1e9 or more.
  const prices = await rpc.prices().catch(() => ({ storagePerByte: 10n ** 19n, minGasPurchasePrice: 1000000000n }));
  const bytes = estimateBytes({ accountId, root: rec.root, value: rec.value, registered, hasOberig, hasAnchors });
  const cost = estimateCost({ bytes, storage, registered, gasPrice, storagePerByte: prices.storagePerByte, minGasPurchasePrice: prices.minGasPurchasePrice });
  let accessKey = null;
  if (signer && account) accessKey = await rpc.accessKey(accountId, signer.publicKeyText);
  const balance = account ? BigInt(account.amount) : 0n;
  const problems = [];
  if (!account) problems.push(`${accountId} does not exist on ${net.name}`);
  else if (balance < cost.needed) problems.push(`${accountId} has ${near(balance)} NEAR; this anchor needs about ${near(cost.needed, 3)} NEAR available (fund it with about 0.2 NEAR)`);
  if (signer && account) {
    if (!accessKey) problems.push(`the key in NEAR_PRIVATE_KEY (${signer.publicKeyText}) is not an access key of ${accountId}`);
    else if (accessKey.permission !== 'FullAccess') {
      const fc = accessKey.permission && accessKey.permission.FunctionCall;
      if (!fc || fc.receiver_id !== net.social || (fc.method_names.length && !fc.method_names.includes('set'))) problems.push(`the key in NEAR_PRIVATE_KEY cannot call ${net.social} set`);
      else if (cost.deposit > 0n) problems.push('the key in NEAR_PRIVATE_KEY is a function-call key, which cannot attach the storage deposit (use a full-access key)');
    }
  }
  if (existing) problems.push('this root is already anchored under this account; nothing new to write');
  return { ...rec, network: net.id, contract: net.social, accountId, account, balance, storage, registered, hasOberig, hasAnchors, existing, gasPrice, prices, cost, accessKey, signer: signer ? signer.publicKeyText : null, problems, hashes };
}

/** Signs and broadcasts the set() call, then confirms the record with a view call. */
async function send(p, { rpc, net, signer, sleep, confirmTries = 6 }) {
  if (p.problems.length) throw new Error(p.problems[0]);
  const wait = sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
  const ak = await rpc.accessKey(p.accountId, signer.publicKeyText);
  if (!ak) throw new Error(`the key in NEAR_PRIVATE_KEY is not an access key of ${p.accountId}`);
  const block = await rpc.finalBlock();
  const tx = T.createTransaction({
    signerId: p.accountId, publicKey: signer.publicKey, nonce: BigInt(ak.nonce) + 1n, receiverId: net.social, blockHash: block.hash,
    actions: [T.functionCall('set', p.args, GAS, p.cost.deposit)],
  });
  const signed = T.signTransaction(tx, signer);
  let outcome;
  try {
    outcome = await rpc.broadcast(signed.base64, { hash: signed.id, signerId: p.accountId });
  } catch (err) {
    const reason = err.rpc ? failureText(err.rpc) : err.message;
    return { ok: false, hash: signed.id, explorer: explorerTx(net, signed.id), reason, sent: err.kind === 'NO_OUTCOME' };
  }
  const status = outcome && outcome.status;
  if (!status || !('SuccessValue' in status)) {
    return { ok: false, hash: signed.id, explorer: explorerTx(net, signed.id), reason: failureText(status && status.Failure ? status.Failure : status), sent: true };
  }
  let blockHeight = null;
  try { blockHeight = Number(JSON.parse(Buffer.from(status.SuccessValue, 'base64').toString('utf8')).block_height) || null; } catch { /* older SocialDB returns nothing */ }
  let seen = null;
  for (let i = 0; i < confirmTries && !(seen && seen.found); i++) {
    if (i) await wait(1500);
    seen = await check({ rpc, net, accountId: p.accountId, root: p.root }).catch(() => null);
  }
  return { ok: true, hash: signed.id, explorer: explorerTx(net, signed.id), blockHeight: blockHeight || (seen && seen.blockHeight) || null, confirmed: !!(seen && seen.found), sent: true };
}

/** Looks the root up in SocialDB with a view call (free; needs no key or account of your own). */
async function check({ rpc, net, accountId, root }) {
  if (!T.isAccountId(accountId)) throw new Error(`"${accountId}" is not a valid NEAR account id`);
  if (!isHex64(root)) throw new Error('a root is 64 hex characters');
  const key = `${accountId}/oberig/anchors/${root}`;
  const r = await rpc.view(net.social, 'get', { keys: [key], options: { with_block_height: true } });
  const node = dig(r.value, [accountId, 'oberig', 'anchors', root]);
  if (node === undefined || node === null) return { found: false, key, viewedAt: r.blockHeight };
  const value = typeof node === 'string' ? node : node[''];
  if (typeof value !== 'string') return { found: false, key, viewedAt: r.blockHeight };
  let record = null;
  try { record = JSON.parse(value); } catch { /* not ours */ }
  return { found: true, key, value, record, blockHeight: typeof node === 'object' ? node[':block'] || null : null, viewedAt: r.blockHeight };
}

/** A standalone proof that `receipt` is in the anchored tree of `leaves`. */
function proofFor(leaves, receipt, meta = {}) {
  const index = leaves.indexOf(receipt);
  if (index === -1) return null;
  const pr = M.proof(leaves, index);
  return {
    oberig: 'proof', v: 1, tree: TREE, network: meta.network, contract: meta.contract, account: meta.account,
    root: M.root(leaves).toString('hex'), receipt, index: pr.index, size: pr.size, path: pr.path.map((b) => b.toString('hex')),
    tx: meta.tx || null,
  };
}

/** Root a proof file leads to, or null if it is malformed. */
function proofRoot(pr) {
  if (!pr || !isHex64(pr.receipt) || !Array.isArray(pr.path) || !pr.path.every(isHex64)) return null;
  const r = M.rootFromProof(Buffer.from(pr.receipt, 'hex'), { index: pr.index, size: pr.size, path: pr.path });
  return r ? r.toString('hex') : null;
}

/** The file "oberig anchor --out" writes: every leaf, so any receipt's proof can be rebuilt later. */
function anchorFile(p, result) {
  return {
    oberig: 'anchor', v: 1, tree: TREE, network: p.network, contract: p.contract, account: p.accountId,
    key: p.key, root: p.root, value: p.value, leaves: p.hashes,
    tx: result && result.ok ? result.hash : null, explorer: result && result.ok ? result.explorer : null,
    block: result && result.ok ? result.blockHeight : null, time: new Date().toISOString(),
  };
}

module.exports = {
  TREE, GAS, YOCTO, isHex64, near, receiptHashes, loadFile, fromGateway, tellGateway, buildRecord,
  estimateBytes, estimateCost, plan, send, check, proofFor, proofRoot, anchorFile,
};
