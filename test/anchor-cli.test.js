'use strict';
// "oberig anchor" as a real process: the dry run, --send against a mock NEAR RPC,
// the gateway's "anchored" marks, and --check with a proof file. The NEAR key is
// made at runtime and must never appear in the output.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { loadConfig } = require('../src/config.js');
const { createGateway } = require('../src/server.js');
const M = require('../src/near/merkle.js');
const R = require('../src/receipt.js');
const H = require('./helpers.js');
const { mockNearRpc, nearTestKey } = require('./near-mock.js');

const BIN = path.join(__dirname, '..', 'bin', 'oberig.js');
const ACCOUNT = 'anchor-cli.near';
const DEAD_RPC = 'http://127.0.0.1:9';

function run(args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, ...args], {
      env: { ...process.env, NO_COLOR: '1', OBERIG_PORT: '1', NEAR_ACCOUNT_ID: '', NEAR_PRIVATE_KEY: '', NEAR_RPC_URL: DEAD_RPC, ...env },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const timer = setTimeout(() => child.kill(), 30000);
    child.on('close', (status) => { clearTimeout(timer); resolve({ status, stdout, stderr }); });
  });
}

function receipts(n) {
  return Array.from({ length: n }, (_, i) => R.seal({ v: 1, time: 1763100000000 + i, client: 'codex', route: 'chat', model: 'm', verdict: 'verified', status: 200, requestHash: crypto.randomBytes(32).toString('hex'), responseHash: crypto.randomBytes(32).toString('hex') }));
}

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'oberig-anchor-cli-')); }

test('anchor dry run reads the chain, prints the plan and sends nothing', async () => {
  const near = await mockNearRpc();
  const dir = tmp();
  try {
    near.addAccount(ACCOUNT, 0n);
    const rs = receipts(3);
    const file = path.join(dir, 'receipts.json');
    fs.writeFileSync(file, JSON.stringify(rs));
    const r = await run(['anchor', '--receipts', file], { NEAR_ACCOUNT_ID: ACCOUNT, NEAR_RPC_URL: near.url });
    assert.equal(r.status, 0, r.stderr);
    const root = M.root(rs.map((x) => x.hash)).toString('hex');
    assert.match(r.stdout, /OBERIG · anchor\s+dry run: only reads from the chain, nothing is signed or sent/);
    assert.match(r.stdout, new RegExp(`receipts  3 from ${file.replace(/[\\.]/g, '\\$&')}`));
    assert.ok(r.stdout.includes(`root      ${root}`));
    assert.ok(r.stdout.includes(`record    ${ACCOUNT}/oberig/anchors/${root}`));
    assert.match(r.stdout, /contract  social\.near · set \(SocialDB\)/);
    assert.match(r.stdout, /network   NEAR mainnet · RPC 127\.0\.0\.1:\d+/);
    assert.match(r.stdout, /signer    NEAR_PRIVATE_KEY not set/);
    assert.match(r.stdout, /not registered yet: the first write registers the account \(0\.02 NEAR minimum deposit\)/);
    assert.match(r.stdout, /deposit  0\.02 NEAR attached/);
    assert.match(r.stdout, /✗ anchor-cli\.near has 0 NEAR/);
    assert.match(r.stdout, /Nothing was sent\. Add --send/);
    assert.equal(near.seen.broadcasts.length, 0);
    assert.ok(!near.seen.methods.includes('broadcast_tx_commit'));

    const j = await run(['anchor', '--receipts', file, '--json'], { NEAR_ACCOUNT_ID: ACCOUNT, NEAR_RPC_URL: near.url });
    const out = JSON.parse(j.stdout);
    assert.equal(out.dryRun, true);
    assert.equal(out.root, root);
    assert.equal(out.contract, 'social.near');
    assert.equal(out.cost.depositNear, '0.02');
  } finally { await near.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('anchor refuses to send without NEAR_PRIVATE_KEY, and never echoes a bad key', async () => {
  const dir = tmp();
  try {
    const file = path.join(dir, 'r.json');
    fs.writeFileSync(file, JSON.stringify(receipts(1)));
    const r = await run(['anchor', '--receipts', file, '--send'], { NEAR_ACCOUNT_ID: ACCOUNT });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /--send needs NEAR_PRIVATE_KEY/);
    assert.match(r.stderr, /never reads keys from files/);
    const bad = nearTestKey().text.slice(0, -3) + '0OI';
    const b = await run(['anchor', '--receipts', file], { NEAR_ACCOUNT_ID: ACCOUNT, NEAR_PRIVATE_KEY: bad });
    assert.equal(b.status, 1);
    assert.ok(!(b.stdout + b.stderr).includes(bad.split(':')[1]), 'the key text is not printed');
    assert.match(b.stderr, /NEAR_PRIVATE_KEY must be an Ed25519 key/);
    const n = await run(['anchor', '--receipts', file]);
    assert.equal(n.status, 1);
    assert.match(n.stderr, /set NEAR_ACCOUNT_ID/);
    const none = await run(['anchor'], { NEAR_ACCOUNT_ID: ACCOUNT });
    assert.equal(none.status, 1);
    assert.match(none.stderr, /no Oberig gateway answered on 127\.0\.0\.1:1/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('anchor --send: gateway receipts go on chain, the dashboard marks them, proofs check out', async () => {
  const nearAi = await H.mockNear({ reply: () => ({ content: 'ok' }) });
  const cfg = loadConfig({ port: 0, nearUrl: nearAi.base, apiKey: H.fake.nearKey(), quiet: true }, {});
  const gw = createGateway(cfg, { rootFingerprint: nearAi.rootFingerprint, retryMs: 5 });
  const addr = await gw.listen();
  const port = String(addr.port);
  const rpc = await mockNearRpc();
  const key = nearTestKey();
  const dir = tmp();
  try {
    for (let i = 0; i < 3; i++) {
      const res = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'x', messages: [{ role: 'user', content: `hello ${i}` }] }) });
      assert.equal(res.status, 200);
      await res.text();
    }
    for (let i = 0; i < 100 && gw.book.items.length < 3; i++) await new Promise((r) => setTimeout(r, 10));
    const hashes = gw.book.items.slice().reverse().map((r) => r.hash);
    const root = M.root(hashes).toString('hex');
    rpc.addAccount(ACCOUNT, 2n * 10n ** 23n, [{ publicKey: key.publicKey }]);
    const env = { OBERIG_PORT: port, NEAR_RPC_URL: rpc.url, NEAR_ACCOUNT_ID: ACCOUNT, NEAR_PRIVATE_KEY: key.text };
    const out = path.join(dir, 'anchor.json');

    const s = await run(['anchor', '--send', '--out', out], env);
    const secret = key.text.split(':')[1];
    assert.ok(!(s.stdout + s.stderr).includes(secret), 'the secret key never appears');
    assert.equal(s.status, 0, s.stdout + s.stderr);
    assert.equal(rpc.seen.broadcasts.length, 1);
    const txId = rpc.seen.broadcasts[0].id;
    assert.match(s.stdout, /receipts  3 from the running gateway/);
    assert.match(s.stdout, new RegExp(`signing with ${key.publicKey}`));
    assert.match(s.stdout, /✓ anchored at block \d+ · 3 receipts/);
    assert.ok(s.stdout.includes(`tx        ${txId}`));
    assert.ok(s.stdout.includes(`explorer  https://nearblocks.io/txns/${txId}`));
    assert.match(s.stdout, /view      ✓ the record reads back with a view call/);
    assert.match(s.stdout, /The dashboard now marks these receipts as anchored/);

    // The gateway checked the leaves against the root and marks the receipts.
    const anchors = gw.anchors;
    assert.equal(anchors.length, 1);
    assert.equal(anchors[0].root, root);
    assert.deepEqual(anchors[0].hashes.slice().sort(), hashes.slice().sort());
    assert.equal(anchors[0].explorer, `https://nearblocks.io/txns/${txId}`);
    const state = await (await fetch(`http://127.0.0.1:${port}/_oberig/state`)).json();
    assert.equal(state.anchors[0].tx, txId);
    const list = await (await fetch(`http://127.0.0.1:${port}/_oberig/receipts`)).json();
    assert.deepEqual(list.receipts.map((r) => r.hash), hashes);
    assert.deepEqual(list.anchors[0].leaves, hashes);

    const file = JSON.parse(fs.readFileSync(out, 'utf8'));
    assert.equal(file.oberig, 'anchor');
    assert.equal(file.root, root);
    assert.equal(file.tx, txId);
    assert.deepEqual(file.leaves, hashes);

    // --check a receipt through the running gateway.
    const c1 = await run(['anchor', '--check', hashes[1]], env);
    assert.equal(c1.status, 0, c1.stdout + c1.stderr);
    assert.match(c1.stdout, /✓ leaf 2 of 3; its proof \(2 hashes\) leads to the root/);
    assert.match(c1.stdout, /✓ anchored on chain at block \d+ · 3 receipts/);
    assert.match(c1.stdout, /Nothing was signed or paid/);

    // A standalone proof file, checked after the gateway is gone.
    const proofFile = path.join(dir, 'proof.json');
    const c2 = await run(['anchor', '--check', hashes[2], '--receipts', out, '--out', proofFile], { ...env, OBERIG_PORT: '1' });
    assert.equal(c2.status, 0, c2.stdout + c2.stderr);
    await gw.close();
    const c3 = await run(['anchor', '--check', hashes[2], '--proof', proofFile], { OBERIG_PORT: '1', NEAR_RPC_URL: rpc.url });
    assert.equal(c3.status, 0, c3.stdout + c3.stderr);
    assert.match(c3.stdout, /leaf 3 of 3/);
    assert.match(c3.stdout, /✓ anchored on chain/);

    // A changed proof proves nothing.
    const pr = JSON.parse(fs.readFileSync(proofFile, 'utf8'));
    pr.path[0] = 'ab'.repeat(32);
    fs.writeFileSync(proofFile, JSON.stringify(pr));
    const c4 = await run(['anchor', '--check', hashes[2], '--proof', proofFile], { OBERIG_PORT: '1', NEAR_RPC_URL: rpc.url });
    assert.equal(c4.status, 1);
    assert.match(c4.stdout, /does not lead to its root/);

    // An unknown root is not found.
    const c5 = await run(['anchor', '--check', 'cd'.repeat(32), '--account', ACCOUNT], { OBERIG_PORT: '1', NEAR_RPC_URL: rpc.url });
    assert.equal(c5.status, 1);
    assert.match(c5.stdout, /✗ no anchor record for this root under anchor-cli\.near on NEAR mainnet/);
  } finally {
    await gw.close().catch(() => {});
    await nearAi.close();
    await rpc.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('gateway: /_oberig/anchored only accepts leaves that give the root, from local tools', async () => {
  const nearAi = await H.mockNear({});
  const cfg = loadConfig({ port: 0, nearUrl: nearAi.base, apiKey: H.fake.nearKey(), quiet: true }, {});
  const gw = createGateway(cfg, { rootFingerprint: nearAi.rootFingerprint, retryMs: 5 });
  const { port } = await gw.listen();
  const url = `http://127.0.0.1:${port}/_oberig/anchored`;
  const post = (body, headers = {}) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  try {
    const leaves = [crypto.randomBytes(32).toString('hex'), crypto.randomBytes(32).toString('hex')];
    const good = { root: M.root(leaves).toString('hex'), network: 'mainnet', account: ACCOUNT, contract: 'social.near', tx: '2DxF45NY3gCQUWFN2QiNct1WhUBXdzyy7cei21ZRWjLz', block: 5, leaves };
    let r = await post({ ...good, root: 'ab'.repeat(32) });
    assert.equal(r.status, 400);
    assert.match((await r.json()).error, /leaves do not give this root/);
    r = await post({ ...good, contract: 'evil.near' });
    assert.equal(r.status, 400);
    r = await post({ ...good, tx: 'not a hash' });
    assert.equal(r.status, 400);
    r = await post(good, { origin: 'https://example.com' });
    assert.equal(r.status, 403);
    r = await post(good);
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { ok: true, marked: 0 });
    assert.equal(gw.anchors[0].explorer, 'https://nearblocks.io/txns/2DxF45NY3gCQUWFN2QiNct1WhUBXdzyy7cei21ZRWjLz');
    const html = await (await fetch(`http://127.0.0.1:${port}/`)).text();
    assert.ok(html.includes("addEventListener('anchored'"), 'dashboard listens for anchors');
    assert.ok(html.includes('◈'), 'dashboard has the anchored mark');
  } finally { await gw.close(); await nearAi.close(); }
});
