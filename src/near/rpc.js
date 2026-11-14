'use strict';
// A small NEAR JSON-RPC client: view calls, accounts, access keys, the latest
// final block, gas price, broadcasting a signed transaction and its status.
// Read calls fall back to the next RPC address on network errors and rate limits.

const { VERSION } = require('../config.js');

const NETWORKS = {
  mainnet: {
    id: 'mainnet', name: 'NEAR mainnet', social: 'social.near', explorer: 'https://nearblocks.io',
    rpc: ['https://rpc.mainnet.near.org', 'https://rpc.mainnet.fastnear.com'],
  },
  testnet: {
    id: 'testnet', name: 'NEAR testnet', social: 'v1.social08.testnet', explorer: 'https://testnet.nearblocks.io',
    rpc: ['https://rpc.testnet.near.org', 'https://rpc.testnet.fastnear.com'],
  },
};

/** Network settings; NEAR_RPC_URL (one address) replaces the default RPC list. */
function network(id = 'mainnet', env = process.env) {
  const n = NETWORKS[String(id).toLowerCase()];
  if (!n) throw new Error(`--network must be mainnet or testnet (got "${id}")`);
  const custom = String(env.NEAR_RPC_URL || '').trim();
  if (custom && !/^https?:\/\/[^\s]+$/i.test(custom)) throw new Error('NEAR_RPC_URL must be an http(s) address');
  return { ...n, rpc: custom ? [custom] : n.rpc.slice() };
}

const explorerTx = (net, hash) => `${net.explorer}/txns/${hash}`;
const hostOf = (url) => { try { return new URL(url).host; } catch { return 'the RPC'; } };

class RpcError extends Error {
  constructor(message, extra = {}) {
    super(message);
    this.name = 'RpcError';
    Object.assign(this, extra);
  }
}

function rpcError(e) {
  const cause = (e && e.cause && e.cause.name) || '';
  const info = e && (e.data !== undefined ? e.data : e.cause && e.cause.info);
  const detail = typeof info === 'string' ? info : info ? JSON.stringify(info) : '';
  const rateLimited = String(e && e.code) === '-429' || /rate limit/i.test(String(e && e.message));
  return new RpcError(`${cause || (e && e.name) || 'RPC error'}${detail ? ': ' + detail.slice(0, 400) : ''}`, { kind: cause || (e && e.name) || 'RPC_ERROR', rpc: e, rateLimited });
}

function createRpc(opts = {}) {
  const urls = opts.urls && opts.urls.length ? opts.urls : NETWORKS.mainnet.rpc;
  const fetchImpl = opts.fetch || globalThis.fetch;
  const timeoutMs = opts.timeoutMs || 20000;
  const wait = opts.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
  let seq = 0;

  /** One JSON-RPC call. Retries other addresses on network errors, HTTP 429/5xx and rate limits. */
  async function call(method, params, o = {}) {
    let last = null;
    const tries = o.tries || Math.max(2, urls.length * 2);
    for (let i = 0; i < tries; i++) {
      const url = urls[i % urls.length];
      if (i > 0 && last && last.retryDelay) await wait(last.retryDelay);
      let res;
      try {
        res = await fetchImpl(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': `oberig/${VERSION}` },
          body: JSON.stringify({ jsonrpc: '2.0', id: `oberig-${++seq}`, method, params }),
          signal: AbortSignal.timeout(o.timeoutMs || timeoutMs),
        });
      } catch (err) {
        last = new RpcError(`could not reach ${hostOf(url)} (${err.message})`, { kind: 'NETWORK', retryDelay: 300 });
        if (o.once) throw last;
        continue;
      }
      if (res.status === 429 || res.status >= 500) {
        last = new RpcError(`${hostOf(url)} answered HTTP ${res.status}`, { kind: res.status === 429 ? 'RATE_LIMIT' : 'HTTP', retryDelay: 600 * (i + 1) });
        if (o.once) throw last;
        continue;
      }
      let j;
      try { j = await res.json(); } catch { last = new RpcError(`${hostOf(url)} sent a response that is not JSON`, { kind: 'HTTP' }); continue; }
      if (j && j.error) {
        const e = rpcError(j.error);
        if (e.rateLimited && !o.once) { e.retryDelay = 800 * (i + 1); last = e; continue; }
        throw e;
      }
      if (!j || !('result' in j)) { last = new RpcError(`${hostOf(url)} sent no result`, { kind: 'HTTP' }); continue; }
      return j.result;
    }
    throw last || new RpcError('no RPC address answered');
  }

  /** Calls a view method; returns {value, blockHeight, blockHash}. */
  async function view(contract, method, args = {}) {
    const r = await call('query', {
      request_type: 'call_function', finality: 'final', account_id: contract, method_name: method,
      args_base64: Buffer.from(JSON.stringify(args), 'utf8').toString('base64'),
    });
    if (r && typeof r.error === 'string') throw new RpcError(`${contract} ${method}: ${r.error.slice(0, 300)}`, { kind: 'CONTRACT_EXECUTION_ERROR' });
    const text = Buffer.from(r.result || []).toString('utf8');
    return { value: text ? JSON.parse(text) : null, blockHeight: r.block_height, blockHash: r.block_hash };
  }

  /** view_account, or null when the account does not exist. */
  async function account(accountId) {
    try {
      return await call('query', { request_type: 'view_account', finality: 'final', account_id: accountId });
    } catch (err) {
      if (err.kind === 'UNKNOWN_ACCOUNT') return null;
      throw err;
    }
  }

  /** view_access_key: {nonce, permission, block_hash, block_height}, or null when the key is not on the account. */
  async function accessKey(accountId, publicKeyText) {
    let r;
    try {
      r = await call('query', { request_type: 'view_access_key', finality: 'final', account_id: accountId, public_key: publicKeyText });
    } catch (err) {
      if (err.kind === 'UNKNOWN_ACCESS_KEY' || err.kind === 'UNKNOWN_ACCOUNT') return null;
      throw err;
    }
    if (r && typeof r.error === 'string') {
      if (/does not exist/i.test(r.error)) return null;
      throw new RpcError(r.error.slice(0, 300), { kind: 'ACCESS_KEY' });
    }
    return r;
  }

  /** Header of the latest final block: {hash, height}. */
  async function finalBlock() {
    const b = await call('block', { finality: 'final' });
    return { hash: b.header.hash, height: b.header.height };
  }

  async function gasPrice() {
    const r = await call('gas_price', [null]);
    return BigInt(r.gas_price);
  }

  /** Storage price per byte and the minimum price prepaid gas is bought at (if the protocol has one). */
  async function prices() {
    const c = await call('EXPERIMENTAL_protocol_config', { finality: 'final' });
    const rc = c.runtime_config || {};
    return {
      storagePerByte: BigInt(rc.storage_amount_per_byte || '10000000000000000000'),
      minGasPurchasePrice: rc.min_gas_purchase_price ? BigInt(rc.min_gas_purchase_price) : null,
      protocolVersion: c.protocol_version,
    };
  }

  /** Transaction status (waits until executed). Returns null while the RPC does not know the hash. */
  async function txStatus(hash, signerId, waitUntil = 'EXECUTED_OPTIMISTIC') {
    try {
      return await call('EXPERIMENTAL_tx_status', { tx_hash: hash, sender_account_id: signerId, wait_until: waitUntil });
    } catch (err) {
      if (err.kind === 'UNKNOWN_TRANSACTION' || err.kind === 'TIMEOUT_ERROR') return null;
      throw err;
    }
  }

  /**
   * Broadcasts a signed transaction with broadcast_tx_commit and waits for the outcome.
   * On a timeout or a lost connection it does not send again blindly: it asks for the
   * status by hash first, and only re-sends when no RPC has seen the transaction.
   */
  async function broadcast(base64, { hash, signerId, polls = 10, pollMs = 2500 } = {}) {
    let sendErr = null;
    for (let round = 0; round < 2; round++) {
      try {
        return await call('broadcast_tx_commit', [base64], { tries: 1, timeoutMs: 60000, once: true });
      } catch (err) {
        const limited = err.rateLimited || err.kind === 'RATE_LIMIT';
        if (!limited && err.kind !== 'TIMEOUT_ERROR' && err.kind !== 'NETWORK' && err.kind !== 'HTTP') throw err;
        sendErr = err;
      }
      if (sendErr.rateLimited || sendErr.kind === 'RATE_LIMIT') {
        await wait(1500); // refused before it was accepted: nothing to look up
      } else {
        for (let i = 0; i < polls; i++) {
          const st = await txStatus(hash, signerId).catch(() => null);
          if (st && st.status) return st;
          await wait(pollMs);
        }
      }
      if (round === 0 && urls.length > 1) urls.push(urls.shift());
    }
    throw new RpcError(`the transaction was sent but no outcome came back (${sendErr && sendErr.message}). Look it up by its hash.`, { kind: 'NO_OUTCOME' });
  }

  return { call, view, account, accessKey, finalBlock, gasPrice, prices, txStatus, broadcast, urls };
}

/** A readable reason for a failed transaction outcome or an invalid-transaction error. */
function failureText(x) {
  const s = JSON.stringify(x || {});
  if (/InvalidNonce/.test(s)) return 'the access key nonce was already used (another transaction went first); run the command again';
  if (/NotEnoughBalance|LackBalanceForState/.test(s)) return 'the account does not have enough NEAR for the deposit and gas';
  if (/Expired/.test(s)) return 'the transaction expired before it was included; run the command again';
  if (/NotEnoughAllowance/.test(s)) return 'the access key allowance is too low for this transaction';
  if (/DepositWithFunctionCall|ReceiverMismatch|MethodNameMismatch/.test(s)) return 'this access key is limited and cannot make this call (use a full-access key)';
  if (/Not enough storage balance/.test(s)) return 'SocialDB says the storage deposit was too small';
  const m = /"(?:panic_msg|ExecutionError)":"([^"]{1,300})/.exec(s);
  return m ? m[1] : s.slice(0, 300);
}

module.exports = { NETWORKS, network, explorerTx, createRpc, RpcError, failureText };
