'use strict';
// Exact terminal strings: the startup banner, the per-request line and the enclave receipt.

const test = require('node:test');
const assert = require('node:assert/strict');
const ui = require('../src/ui.js');
const { loadConfig } = require('../src/config.js');

const cfg = loadConfig({ apiKey: 'set-in-test' }, {});

test('startup banner matches the published format', () => {
  const lines = ui.banner({ cfg, attestation: { ok: true, signer: '3f2a' + '0'.repeat(56) + '9c1b' } }, false).split('\n');
  assert.deepEqual(lines, [
    '  ×   ×',
    '×   ×   ×   OBERIG v0.2.0',
    "  ×   ×     your agent's amulet",
    'Enclave    NEAR AI · deepseek-ai/DeepSeek-V4.1-Flash-1017',
    'Verified   ✓ enclave attested · signer 0x3f2a…9c1b',
    'Guards     mask on · shield on · seals on',
    'Privacy    runs only on this computer · stores nothing · no telemetry',
  ]);
});

test('banner says so when the enclave is not attested or the key is missing', () => {
  const out = ui.banner({ cfg: { ...cfg, apiKey: null }, attestation: { ok: false, error: 'nonce bound in quote report data: failed' } }, false);
  assert.match(out, /Verified   ✗ not attested · nonce bound/);
  assert.match(out, /Key        missing · set NEARAI_API_KEY/);
  assert.match(out, /nothing is sent until a check passes/);
});

test('per-request line matches the published format', () => {
  const r = { time: new Date(2026, 10, 13, 14, 5, 2).getTime(), client: 'claude-code', verdict: 'verified', masked: { total: 2 }, shield: { mode: 'block', stopped: 1 }, status: 200, ms: 1800, id: '7f3a' };
  assert.equal(ui.logLine(r, false), '14:05:02  claude-code → near ✓ verified  ◆ masked 2  ⚑ stopped 1  200  1.8s  seal 7f3a');
  assert.match(ui.logLine({ ...r, verdict: 'refused', status: 503 }, false), /near ✗ refused/);
  assert.match(ui.logLine({ ...r, shield: { mode: 'warn', stopped: 3 } }, false), /⚑ flagged 3/);
});

test('enclave receipt lists every check and the seal', () => {
  const rec = {
    time: Date.UTC(2026, 10, 13, 14, 5, 2), hash: 'ab'.repeat(32), id: 'abab',
    attestation: { ok: true, model: 'm/one', nonce: 'cd'.repeat(32), signer: 'ef'.repeat(32), algo: 'ed25519', checks: [
      { label: 'TDX quote signed by an Intel-rooted key', status: 'ok' },
      { label: 'nonce bound in quote report data', status: 'ok' },
      { label: 'Intel TCB status', status: 'skip', detail: 'not checked locally' },
    ] },
  };
  const out = ui.enclaveReceipt(rec, { color: false });
  assert.match(out, /OBERIG · enclave receipt/);
  assert.match(out, /✓  TDX quote signed by an Intel-rooted key/);
  assert.match(out, /·  Intel TCB status: not checked locally/);
  assert.match(out, /result    ✓ enclave attested/);
  assert.match(out, /seal abab/);
  assert.ok(out.includes('×'), 'stitched seal art');
});
