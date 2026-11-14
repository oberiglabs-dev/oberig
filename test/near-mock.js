'use strict';
// A mock NEAR RPC for the anchor tests: accounts and access keys, final blocks,
// gas price, protocol prices, and a tiny SocialDB (get, keys, get_account_storage,
// set). Every signed transaction it receives is decoded and checked: borsh, the
// Ed25519 signature over the transaction hash, the access key, nonce and block hash.

const http = require('node:http');
const crypto = require('node:crypto');
const bs58 = require('../src/near/base58.js');
const B = require('../src/near/borsh.js');
const T = require('../src/near/tx.js');

const PER_BYTE = 10n ** 19n;
const MIN_BALANCE = 2000n * PER_BYTE;

async function mockNearRpc(opts = {}) {
  const contract = opts.contract || 'social.near';
  const accounts = new Map(); // id -> {amount, keys: Map(publicKeyText -> {nonce, permission})}
  const social = new Map(); // "acc/oberig/anchors/<root>" -> {value, block}
  const storage = new Map(); // acc -> {balance, used}
  const txs = new Map();
  const seen = { methods: [], broadcasts: [], rejected: [] };
  let height = 224450000;
  const blockHash = (h) => bs58.encode(crypto.createHash('sha256').update(`block-${h}`).digest());

  function addAccount(id, amount, keys = []) {
    const a = { amount: BigInt(amount), keys: new Map() };
    for (const k of keys) a.keys.set(k.publicKey, { nonce: BigInt(k.nonce || 224446692000000), permission: k.permission || 'FullAccess' });
    accounts.set(id, a);
    return a;
  }
  function registerSocial(id, balanceYocto, usedBytes = 0) { storage.set(id, { balance: BigInt(balanceYocto), used: BigInt(usedBytes) }); }

  const err = (cause, info, name = 'HANDLER_ERROR') => ({ error: { name, cause: { name: cause, info }, code: -32000, message: 'Server error', data: info } });

  function socialView(method, args) {
    if (method === 'get_account_storage') {
      const s = storage.get(args.account_id);
      return s ? { used_bytes: Number(s.used), available_bytes: Number(s.balance / PER_BYTE - s.used) } : null;
    }
    if (method === 'storage_balance_of') {
      const s = storage.get(args.account_id);
      return s ? { total: s.balance.toString(), available: (s.balance - s.used * PER_BYTE).toString() } : null;
    }
    if (method === 'keys') {
      const out = {};
      for (const pattern of args.keys) {
        const m = /^([^/]+)\/oberig\/\*$/.exec(pattern);
        if (m && [...social.keys()].some((k) => k.startsWith(`${m[1]}/oberig/anchors/`))) out[m[1]] = { oberig: { anchors: true } };
      }
      return out;
    }
    if (method === 'get') {
      const withBlock = args.options && args.options.with_block_height;
      const out = {};
      for (const key of args.keys) {
        const rec = social.get(key);
        if (!rec) continue;
        const [acc, , , root] = key.split('/');
        out[acc] = { oberig: { anchors: { [root]: withBlock ? { ':block': rec.block, '': rec.value } : rec.value } } };
        if (withBlock) out[':block'] = height;
      }
      return out;
    }
    return undefined;
  }

  /** Applies a SocialDB set from `signer` with `deposit`; returns null or a failure message. */
  function applySet(signer, args, deposit) {
    const data = args.data || {};
    const acc = Object.keys(data)[0];
    if (acc !== signer) return 'Permission denied';
    let s = storage.get(acc);
    if (!s) {
      if (deposit < MIN_BALANCE) return 'The attached deposit is less than the minimum storage balance';
      s = { balance: 0n, used: 500n };
      storage.set(acc, s);
    }
    s.balance += deposit;
    const anchors = (((data[acc] || {}).oberig || {}).anchors) || {};
    for (const [root, value] of Object.entries(anchors)) {
      if (typeof value !== 'string') return 'The JSON value is not a string, a null or an object';
      s.used += BigInt(root.length * 2 + 140 + value.length);
      social.set(`${acc}/oberig/anchors/${root}`, { value, block: height });
    }
    if (s.used * PER_BYTE > s.balance) return 'Not enough storage balance';
    if (args.options && args.options.refund_unused_deposit) {
      const refund = s.balance - s.used * PER_BYTE < deposit ? s.balance - s.used * PER_BYTE : deposit;
      s.balance -= refund;
      accounts.get(acc).amount += refund;
    }
    return null;
  }

  function broadcast(b64) {
    let stx;
    try { stx = B.deserializeSignedTransaction(Buffer.from(b64, 'base64')); } catch (e) { return { error: { name: 'REQUEST_VALIDATION_ERROR', cause: { name: 'PARSE_ERROR' }, code: -32700, message: 'Parse error', data: e.message } }; }
    const tx = stx.transaction;
    const h = T.hashTransaction(tx);
    const reject = (what) => { seen.rejected.push(what); return err('INVALID_TRANSACTION', { TxExecutionError: { InvalidTxError: what } }); };
    if (!T.verifySignature(tx.publicKey, h.hash, stx.signature)) return reject({ InvalidSignature: null });
    const acc = accounts.get(tx.signerId);
    const key = acc && acc.keys.get(T.publicKeyToString(tx.publicKey));
    if (!key) return reject({ InvalidAccessKeyError: { AccessKeyNotFound: {} } });
    if (tx.nonce <= key.nonce) return reject({ InvalidNonce: { tx_nonce: Number(tx.nonce), ak_nonce: Number(key.nonce) } });
    const recent = [];
    for (let i = 0; i < 20; i++) recent.push(blockHash(height - i));
    if (!recent.includes(bs58.encode(tx.blockHash))) return reject({ Expired: null });
    const fc = tx.actions[0];
    if (opts.failNext) { opts.failNext = false; return reject({ InvalidNonce: { tx_nonce: Number(tx.nonce), ak_nonce: Number(tx.nonce) } }); }
    if (acc.amount < fc.deposit + 3n * 10n ** 22n) return reject({ NotEnoughBalance: { signer_id: tx.signerId } });
    key.nonce = tx.nonce;
    height += 2;
    acc.amount -= fc.deposit;
    let status;
    let args = null;
    try { args = JSON.parse(fc.args.toString('utf8')); } catch { args = null; }
    const problem = tx.receiverId !== contract || fc.methodName !== 'set' || !args ? 'unexpected call' : applySet(tx.signerId, args, fc.deposit);
    if (problem) {
      acc.amount += fc.deposit;
      status = { Failure: { ActionError: { index: 0, kind: { FunctionCallError: { ExecutionError: `Smart contract panicked: ${problem}` } } } } };
    } else {
      status = { SuccessValue: Buffer.from(JSON.stringify({ block_height: String(height) })).toString('base64') };
    }
    const outcome = { status, final_execution_status: 'EXECUTED_OPTIMISTIC', transaction: { hash: h.id, signer_id: tx.signerId, receiver_id: tx.receiverId }, transaction_outcome: {}, receipts_outcome: [] };
    txs.set(h.id, outcome);
    seen.broadcasts.push({ id: h.id, tx, args, signature: stx.signature });
    if (opts.timeoutFirstBroadcast) { opts.timeoutFirstBroadcast = false; return err('TIMEOUT_ERROR', 'Timeout', 'HANDLER_ERROR'); }
    return { result: outcome };
  }

  function handle(method, params) {
    seen.methods.push(method);
    if (method === 'block') return { result: { header: { hash: blockHash(height), height, prev_hash: blockHash(height - 1) } } };
    if (method === 'gas_price') return { result: { gas_price: '100000000' } };
    if (method === 'EXPERIMENTAL_protocol_config') return { result: { protocol_version: 88, runtime_config: { storage_amount_per_byte: PER_BYTE.toString(), min_gas_purchase_price: '1000000000' } } };
    if (method === 'broadcast_tx_commit') return broadcast(params[0]);
    if (method === 'EXPERIMENTAL_tx_status') {
      const t = txs.get(params.tx_hash);
      return t ? { result: t } : err('UNKNOWN_TRANSACTION', {});
    }
    if (method === 'query') {
      const p = params;
      const meta = { block_height: height, block_hash: blockHash(height) };
      if (p.request_type === 'view_account') {
        const a = accounts.get(p.account_id);
        if (!a) return err('UNKNOWN_ACCOUNT', { requested_account_id: p.account_id });
        return { result: { amount: a.amount.toString(), locked: '0', code_hash: '11111111111111111111111111111111', storage_usage: 182, storage_paid_at: 0, ...meta } };
      }
      if (p.request_type === 'view_access_key') {
        const a = accounts.get(p.account_id);
        const k = a && a.keys.get(p.public_key);
        if (!k) return { result: { ...meta, error: `access key ${p.public_key} does not exist while viewing`, logs: [] } };
        return { result: { nonce: Number(k.nonce), permission: k.permission, ...meta } };
      }
      if (p.request_type === 'call_function') {
        if (p.account_id !== contract) return { result: { ...meta, error: 'wasm execution failed: no such contract', logs: [] } };
        const args = JSON.parse(Buffer.from(p.args_base64, 'base64').toString('utf8') || '{}');
        const v = socialView(p.method_name, args);
        if (v === undefined) return { result: { ...meta, error: `MethodNotFound ${p.method_name}`, logs: [] } };
        return { result: { ...meta, result: [...Buffer.from(JSON.stringify(v))], logs: [] } };
      }
    }
    return { error: { name: 'REQUEST_VALIDATION_ERROR', cause: { name: 'METHOD_NOT_FOUND' }, code: -32601, message: 'Method not found' } };
  }

  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { res.writeHead(400); return res.end(); }
    if (opts.rateLimitFirst && seen.methods.length === 0 && !seen.limited) {
      seen.limited = true;
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, error: { code: -429, message: 'Rate limits exceeded' } }));
    }
    const out = handle(body.method, body.params);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, ...out }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}`;
  return { url, seen, social, storage, accounts, addAccount, registerSocial, get height() { return height; }, close: () => new Promise((r) => server.close(r)) };
}

/** A throwaway NEAR key made at runtime: {text: "ed25519:<base58 of seed + public key>", publicKey}. */
function nearTestKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const seed = Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
  const pub = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
  return { text: ['ed25519', bs58.encode(Buffer.concat([seed, pub]))].join(':'), publicKey: `ed25519:${bs58.encode(pub)}` };
}

module.exports = { mockNearRpc, nearTestKey, PER_BYTE };
