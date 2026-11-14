'use strict';
// Anchor logic against a mock NEAR RPC: the SocialDB record, cost estimates,
// receipt loading, the dry-run plan, signing and sending, and view-call checks.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const A = require('../src/near/anchor.js');
const N = require('../src/near/rpc.js');
const T = require('../src/near/tx.js');
const M = require('../src/near/merkle.js');
const R = require('../src/receipt.js');
const { mockNearRpc, nearTestKey, PER_BYTE } = require('./near-mock.js');

const ACCOUNT = 'anchor-test.near';
const NET = { ...N.NETWORKS.mainnet };
const hashes = (n) => Array.from({ length: n }, (_, i) => crypto.createHash('sha256').update(`receipt-${i}`).digest('hex'));

function receipt(i) {
  return R.seal({ v: 1, time: 1763100000000 + i * 1000, client: 'claude-code', route: 'messages', model: 'deepseek-ai/DeepSeek-V4.1-Flash-1017', verdict: 'verified', status: 200, masked: { total: i % 3, kinds: {} }, requestHash: 'aa'.repeat(32), responseHash: 'bb'.repeat(32) });
}

async function setup(fn) {
  const near = await mockNearRpc();
  const rpc = N.createRpc({ urls: [near.url], sleep: async () => {} });
  try { return await fn({ near, rpc, net: { ...NET, rpc: [near.url] } }); } finally { await near.close(); }
}

test('the record is one root under <account>/oberig/anchors with SocialDB-safe keys', () => {
  const hs = hashes(3);
  const rec = A.buildRecord(ACCOUNT, hs, Date.UTC(2026, 10, 14, 3, 21, 7));
  assert.equal(rec.root, M.root(hs).toString('hex'));
  assert.equal(rec.key, `${ACCOUNT}/oberig/anchors/${rec.root}`);
  for (const k of rec.key.split('/').slice(1)) assert.match(k, /^[a-zA-Z0-9_.-]{1,256}$/);
  assert.deepEqual(JSON.parse(rec.value), { v: 1, tree: 'rfc6962-sha256', n: 3, t: '2026-11-14T03:21:07Z', app: 'oberig/0.1.0' });
  assert.equal(rec.args.data[ACCOUNT].oberig.anchors[rec.root], rec.value);
  assert.deepEqual(rec.args.options, { refund_unused_deposit: true });
  assert.throws(() => A.buildRecord('Bad Account', hs), /not a valid NEAR account/);
  assert.throws(() => A.buildRecord(ACCOUNT, []), /no receipts/);
});

test('cost: a new SocialDB account pays the 0.02 NEAR minimum; prepaid storage can cover a write', () => {
  const base = { root: 'ab'.repeat(32), value: '{"v":1,"tree":"rfc6962-sha256","n":3,"t":"2026-11-14T03:21:07Z","app":"oberig/0.1.0"}', accountId: ACCOUNT };
  const fresh = A.estimateBytes({ ...base, registered: false, hasOberig: false, hasAnchors: false });
  const later = A.estimateBytes({ ...base, registered: true, hasOberig: true, hasAnchors: true });
  assert.ok(fresh > later * 2, 'the first anchor creates the parent nodes');
  assert.ok(later > 300 && later < 600, `one more record is a few hundred bytes (${later})`);
  const prices = { gasPrice: 100000000n, storagePerByte: PER_BYTE, minGasPurchasePrice: 1000000000n };
  const c1 = A.estimateCost({ bytes: fresh, storage: null, registered: false, ...prices });
  assert.equal(c1.deposit, 2000n * PER_BYTE);
  assert.equal(A.near(c1.deposit), '0.02');
  assert.equal(c1.gasHeld, 31000000000000n * 1000000000n, 'gas is bought at the minimum purchase price');
  assert.equal(c1.gasUsed, 5000000000000n * 100000000n);
  const c2 = A.estimateCost({ bytes: later, storage: { used_bytes: 100, available_bytes: 5000 }, registered: true, ...prices });
  assert.equal(c2.deposit, 0n);
  const c3 = A.estimateCost({ bytes: later, storage: { used_bytes: 100, available_bytes: 10 }, registered: true, ...prices });
  assert.equal(c3.deposit, BigInt(later + 500 - 10) * PER_BYTE);
  assert.equal(A.near(12345678901234567890123n), '0.0123');
  assert.equal(A.near(0n), '0');
});

test('receipt hashes: order kept, duplicates dropped, edited receipts refused', () => {
  const r = [receipt(1), receipt(2), receipt(3)];
  const out = A.receiptHashes([r[0], r[1], r[0].hash, { hash: r[2].hash, id: r[2].id }]);
  assert.deepEqual(out.hashes, [r[0].hash, r[1].hash, r[2].hash]);
  assert.deepEqual(out.bad, []);
  const edited = { ...receipt(4), verdict: 'refused' };
  const bad = A.receiptHashes([edited, 'not-a-hash']);
  assert.equal(bad.hashes.length, 0);
  assert.equal(bad.bad.length, 2);
  // A saved gateway state lists receipts newest first; the tree is always oldest first.
  assert.deepEqual(A.receiptHashes([r[2], r[1], r[0]]).hashes, [r[0].hash, r[1].hash, r[2].hash]);
});

test('loadFile reads receipts, gateway state, JSON Lines, anchor files and proof files', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oberig-anchor-'));
  try {
    const r = [receipt(1), receipt(2)];
    const w = (name, text) => { const f = path.join(dir, name); fs.writeFileSync(f, text); return f; };
    assert.equal(A.loadFile(w('a.json', JSON.stringify(r))).items.length, 2);
    assert.equal(A.loadFile(w('s.json', JSON.stringify({ version: '0.1.0', receipts: r }))).items.length, 2);
    assert.equal(A.loadFile(w('l.jsonl', r.map((x) => JSON.stringify(x)).join('\n') + '\n')).items.length, 2);
    assert.deepEqual(A.loadFile(w('h.txt', `${r[0].hash}\r\n${r[1].hash}\n`)).items, [r[0].hash, r[1].hash]);
    assert.equal(A.loadFile(w('anchor.json', JSON.stringify({ oberig: 'anchor', leaves: [r[0].hash] }))).kind, 'anchor');
    assert.equal(A.loadFile(w('proof.json', JSON.stringify({ oberig: 'proof' }))).kind, 'proof');
    assert.throws(() => A.loadFile(w('x.json', '{"nothing":1}')), /no receipts found/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('proofs: a proof file leads from the receipt to the root, and edits break it', () => {
  const hs = hashes(7);
  const pr = A.proofFor(hs, hs[4], { network: 'mainnet', contract: 'social.near', account: ACCOUNT });
  assert.equal(pr.oberig, 'proof');
  assert.equal(pr.root, M.root(hs).toString('hex'));
  assert.equal(A.proofRoot(pr), pr.root);
  assert.notEqual(A.proofRoot({ ...pr, receipt: hs[3] }), pr.root);
  assert.equal(A.proofRoot({ ...pr, path: ['zz'] }), null);
  assert.equal(A.proofFor(hs, 'cd'.repeat(32)), null);
});

test('plan (dry run): reads the chain, sends nothing, and names what blocks a send', () => setup(async ({ near, rpc, net }) => {
  const key = nearTestKey();
  near.addAccount(ACCOUNT, 0n, [{ publicKey: key.publicKey }]);
  const signer = T.keyPairFromSecret(key.text);
  const p = await A.plan({ rpc, net, accountId: ACCOUNT, signer, hashes: hashes(4) });
  assert.equal(p.registered, false);
  assert.equal(p.cost.deposit, 2000n * PER_BYTE);
  assert.equal(p.accessKey.permission, 'FullAccess');
  assert.match(p.problems.join(' '), /has 0 NEAR/);
  assert.equal(near.seen.broadcasts.length, 0);
  assert.ok(!near.seen.methods.includes('broadcast_tx_commit'));

  const other = T.keyPairFromSecret(nearTestKey().text);
  const p2 = await A.plan({ rpc, net, accountId: ACCOUNT, signer: other, hashes: hashes(4) });
  assert.match(p2.problems.join(' '), /is not an access key of anchor-test\.near/);

  const missing = await A.plan({ rpc, net, accountId: 'nobody-here.near', hashes: hashes(1) });
  assert.match(missing.problems.join(' '), /does not exist/);

  const fcKey = nearTestKey();
  near.addAccount('limited.near', 10n ** 24n, [{ publicKey: fcKey.publicKey, permission: { FunctionCall: { allowance: null, receiver_id: 'social.near', method_names: ['set'] } } }]);
  const p3 = await A.plan({ rpc, net, accountId: 'limited.near', signer: T.keyPairFromSecret(fcKey.text), hashes: hashes(2) });
  assert.match(p3.problems.join(' '), /function-call key, which cannot attach the storage deposit/);
}));

test('send: signs one SocialDB set with the planned deposit, refunds the rest, reads it back', () => setup(async ({ near, rpc, net }) => {
  const key = nearTestKey();
  near.addAccount(ACCOUNT, 2n * 10n ** 23n, [{ publicKey: key.publicKey, nonce: 224446692000000 }]);
  const signer = T.keyPairFromSecret(key.text);
  const hs = hashes(5);
  const p = await A.plan({ rpc, net, accountId: ACCOUNT, signer, hashes: hs });
  assert.deepEqual(p.problems, []);
  const r = await A.send(p, { rpc, net, signer, sleep: async () => {} });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.confirmed, true);
  assert.equal(near.seen.broadcasts.length, 1);
  const b = near.seen.broadcasts[0];
  assert.equal(r.hash, b.id);
  assert.equal(r.explorer, `https://nearblocks.io/txns/${b.id}`);
  assert.equal(b.tx.signerId, ACCOUNT);
  assert.equal(b.tx.receiverId, 'social.near');
  assert.equal(b.tx.nonce, 224446692000001n);
  const fc = b.tx.actions[0];
  assert.equal(fc.methodName, 'set');
  assert.equal(fc.gas, A.GAS);
  assert.equal(fc.deposit, p.cost.deposit);
  assert.deepEqual(b.args, p.args);
  assert.equal(r.blockHeight, near.height);
  // SocialDB kept only what the record uses; the rest came back.
  const s = near.storage.get(ACCOUNT);
  assert.equal(s.balance, s.used * PER_BYTE);

  const c = await A.check({ rpc, net, accountId: ACCOUNT, root: p.root });
  assert.equal(c.found, true);
  assert.equal(c.record.n, 5);
  assert.equal(c.blockHeight > 0, true);
  const again = await A.plan({ rpc, net, accountId: ACCOUNT, signer, hashes: hs });
  assert.match(again.problems.join(' '), /already anchored/);
  const next = await A.plan({ rpc, net, accountId: ACCOUNT, signer, hashes: hashes(6) });
  assert.equal(next.registered, true);
  assert.equal(next.hasAnchors, true);
}));

test('send: a rejected transaction comes back as a readable reason, not a crash', () => setup(async ({ near, rpc, net }) => {
  const key = nearTestKey();
  near.addAccount(ACCOUNT, 2n * 10n ** 23n, [{ publicKey: key.publicKey }]);
  const signer = T.keyPairFromSecret(key.text);
  const p = await A.plan({ rpc, net, accountId: ACCOUNT, signer, hashes: hashes(2) });
  near.accounts.get(ACCOUNT).amount = 10n ** 21n; // spent elsewhere after the plan
  const r = await A.send(p, { rpc, net, signer, sleep: async () => {} });
  assert.equal(r.ok, false);
  assert.match(r.reason, /does not have enough NEAR/);
  assert.equal(near.social.size, 0);
}));

test('send: a timed-out broadcast is looked up by its hash, not sent twice', async () => {
  const near = await mockNearRpc({ timeoutFirstBroadcast: true });
  try {
    const rpc = N.createRpc({ urls: [near.url], sleep: async () => {} });
    const net = { ...NET, rpc: [near.url] };
    const key = nearTestKey();
    near.addAccount(ACCOUNT, 2n * 10n ** 23n, [{ publicKey: key.publicKey }]);
    const signer = T.keyPairFromSecret(key.text);
    const p = await A.plan({ rpc, net, accountId: ACCOUNT, signer, hashes: hashes(3) });
    const r = await A.send(p, { rpc, net, signer, sleep: async () => {} });
    assert.equal(r.ok, true, r.reason);
    assert.equal(near.seen.broadcasts.length, 1);
    assert.ok(near.seen.methods.includes('EXPERIMENTAL_tx_status'));
  } finally { await near.close(); }
});

test('check: a missing root is reported as not found', () => setup(async ({ rpc, net }) => {
  const c = await A.check({ rpc, net, accountId: ACCOUNT, root: 'ef'.repeat(32) });
  assert.equal(c.found, false);
  assert.equal(c.key, `${ACCOUNT}/oberig/anchors/${'ef'.repeat(32)}`);
  await assert.rejects(A.check({ rpc, net, accountId: ACCOUNT, root: 'xyz' }), /64 hex/);
}));

test('rpc: rate limits are retried, unknown accounts are null, missing keys are null', async () => {
  const near = await mockNearRpc({ rateLimitFirst: true });
  try {
    const rpc = N.createRpc({ urls: [near.url], sleep: async () => {} });
    const b = await rpc.finalBlock();
    assert.ok(near.seen.limited, 'the first call was rate limited');
    assert.equal(b.height, near.height);
    assert.equal(await rpc.account('nobody-here.near'), null);
    near.addAccount(ACCOUNT, 1n);
    assert.equal(await rpc.accessKey(ACCOUNT, nearTestKey().publicKey), null);
    assert.equal(await rpc.gasPrice(), 100000000n);
    await assert.rejects(rpc.view('social.near', 'nope', {}), /MethodNotFound/);
  } finally { await near.close(); }
});

test('networks: mainnet and testnet contracts and explorers; NEAR_RPC_URL replaces the RPC list', () => {
  assert.equal(N.network('mainnet', {}).social, 'social.near');
  assert.equal(N.network('testnet', {}).social, 'v1.social08.testnet');
  assert.equal(N.explorerTx(N.network('testnet', {}), 'abc'), 'https://testnet.nearblocks.io/txns/abc');
  assert.deepEqual(N.network('mainnet', { NEAR_RPC_URL: 'http://127.0.0.1:9' }).rpc, ['http://127.0.0.1:9']);
  assert.throws(() => N.network('devnet', {}), /mainnet or testnet/);
  assert.throws(() => N.network('mainnet', { NEAR_RPC_URL: 'file:///etc/passwd' }), /http/);
});
