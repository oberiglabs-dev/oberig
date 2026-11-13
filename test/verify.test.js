'use strict';
// Verify: attestation checks on real captured NEAR AI reports and on synthetic
// reports, plus response signature checks.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const V = require('../src/verify.js');
const Q = require('../src/quote.js');
const H = require('./helpers.js');

const MODEL = 'deepseek-ai/DeepSeek-V4.1-Flash-1017';
const ED = require('./fixtures/near-report-ed25519.json');
const EC = require('./fixtures/near-report-ecdsa.json');
const clone = (o) => JSON.parse(JSON.stringify(o));
const status = (r, id) => (r.checks.find((c) => c.id === id) || {}).status;

test('real NEAR AI report (ed25519): every local check passes, incl. Intel quote chain', () => {
  const r = V.checkAttestation(ED.report, ED.nonce, { model: MODEL, algo: 'ed25519' });
  assert.equal(r.ok, true, r.error);
  for (const id of ['report', 'algo', 'nonce-echo', 'tdx', 'quote-chain', 'debug', 'nonce-bound', 'signer-bound', 'config', 'rtmr3', 'gpu-nonce', 'gateway']) {
    assert.equal(status(r, id), 'ok', id);
  }
  assert.equal(status(r, 'tcb'), 'skip');
  assert.equal(status(r, 'gpu-verdict'), 'skip');
  assert.equal(r.signer, ED.report.model_attestations[0].signing_address.toLowerCase());
});

test('real NEAR AI report (ecdsa): 20-byte signer binding passes', () => {
  const r = V.checkAttestation(EC.report, EC.nonce, { model: MODEL, algo: 'ecdsa' });
  assert.equal(r.ok, true, r.error);
  assert.equal(status(r, 'signer-bound'), 'ok');
});

test('nonce mismatch: a report for another nonce fails', () => {
  const r = V.checkAttestation(ED.report, crypto.randomBytes(32).toString('hex'), { model: MODEL, algo: 'ed25519' });
  assert.equal(r.ok, false);
  assert.equal(status(r, 'nonce-echo'), 'fail');
  assert.equal(status(r, 'nonce-bound'), 'fail');
});

test('a changed byte in the quote breaks the Intel signature chain', () => {
  const rep = clone(ED.report);
  const q = Buffer.from(rep.model_attestations[0].intel_quote, 'hex');
  q[300] ^= 1; // inside the signed TD report (mr_owner)
  rep.model_attestations[0].intel_quote = q.toString('hex');
  const r = V.checkAttestation(rep, ED.nonce, { model: MODEL, algo: 'ed25519' });
  assert.equal(status(r, 'quote-chain'), 'fail');
  assert.equal(r.ok, false);
});

test('a swapped signer is not bound by the quote', () => {
  const rep = clone(ED.report);
  rep.model_attestations[0].signing_address = 'ab'.repeat(32);
  const r = V.checkAttestation(rep, ED.nonce, { model: MODEL, algo: 'ed25519' });
  assert.equal(status(r, 'signer-bound'), 'fail');
});

test('a changed event log no longer replays to RTMR3', () => {
  const rep = clone(ED.report);
  const log = rep.model_attestations[0].event_log;
  const ev = log.find((e) => e.imr === 3);
  ev.event_payload = '00' + ev.event_payload.slice(2);
  ev.digest = '';
  const r = V.checkAttestation(rep, ED.nonce, { model: MODEL, algo: 'ed25519' });
  assert.equal(status(r, 'rtmr3'), 'fail');
});

test('empty model_attestations is refused', () => {
  const r = V.checkAttestation({ gateway_attestation: ED.report.gateway_attestation, model_attestations: [] }, ED.nonce, { model: MODEL });
  assert.equal(r.ok, false);
  assert.equal(status(r, 'report'), 'fail');
});

test('the Intel root is pinned by fingerprint', () => {
  const q = Q.parseQuote(ED.report.model_attestations[0].intel_quote);
  assert.equal(Q.verifyQuoteChain(q).ok, true);
  const other = Q.verifyQuoteChain(q, { rootFingerprint: 'AA:'.repeat(31) + 'AA' });
  assert.equal(other.ok, false);
});

test('synthetic report: passes with its own pinned test root, fails against the Intel pin', () => {
  const mk = H.ed25519Key(), gk = H.ed25519Key();
  const nonce = crypto.randomBytes(32).toString('hex');
  const body = H.makeReport({ model: 'm/one', nonce, modelKey: mk, gatewayKey: gk });
  assert.equal(V.checkAttestation(body, nonce, { model: 'm/one', algo: 'ed25519', rootFingerprint: H.testChain().fingerprint }).ok, true);
  assert.equal(V.checkAttestation(body, nonce, { model: 'm/one', algo: 'ed25519' }).ok, false);
  const dbg = H.makeReport({ model: 'm/one', nonce, modelKey: mk, gatewayKey: gk, debug: true });
  const r = V.checkAttestation(dbg, nonce, { model: 'm/one', algo: 'ed25519', rootFingerprint: H.testChain().fingerprint });
  assert.equal(status(r, 'debug'), 'fail');
  const gpu = H.makeReport({ model: 'm/one', nonce, modelKey: mk, gatewayKey: gk, gpuNonce: 'ef'.repeat(32) });
  assert.equal(status(V.checkAttestation(gpu, nonce, { model: 'm/one', algo: 'ed25519', rootFingerprint: H.testChain().fingerprint }), 'gpu-nonce'), 'fail');
});

function sigCase() {
  const key = H.ed25519Key();
  const req = H.sha('sha256', 'request bytes').toString('hex');
  const resp = H.sha('sha256', 'response bytes').toString('hex');
  const text = `m/one:${req}:${resp}`;
  const sig = { text, signature: key.sign(text), signing_address: key.hex, signing_algo: 'ed25519', signature_kind: 'provider_tee' };
  const ctx = { model: 'm/one', requestHash: req, responseHash: resp, attestation: { modelSigners: [key.hex], gatewaySigner: null, algo: 'ed25519' } };
  return { key, sig, ctx };
}

test('response signature ok: model TEE key over model:request:response', () => {
  const { sig, ctx } = sigCase();
  const r = V.checkSignature(sig, ctx);
  assert.equal(r.status, 'verified', r.reason);
  assert.equal(r.kind, 'provider_tee');
});

test('bad signature is caught', () => {
  const { sig, ctx } = sigCase();
  const bad = { ...sig, signature: (sig.signature[0] === 'a' ? 'b' : 'a') + sig.signature.slice(1) };
  const r = V.checkSignature(bad, ctx);
  assert.equal(r.status, 'failed');
  assert.match(r.reason, /does not verify/);
});

test('signature over other bytes is caught (hash mismatch)', () => {
  const { sig, ctx } = sigCase();
  const r = V.checkSignature(sig, { ...ctx, responseHash: H.sha('sha256', 'something else').toString('hex') });
  assert.equal(r.status, 'failed');
  assert.match(r.reason, /response hash/);
});

test('a valid signature from a key that was not attested is refused', () => {
  const { sig, ctx } = sigCase();
  const r = V.checkSignature(sig, { ...ctx, attestation: { modelSigners: ['cd'.repeat(32)], algo: 'ed25519' } });
  assert.equal(r.status, 'failed');
  assert.match(r.reason, /signer/);
});

test('gateway signatures use request:response and the gateway key', () => {
  const key = H.ed25519Key();
  const text = `${'1'.repeat(64)}:${'2'.repeat(64)}`;
  const r = V.checkSignature({ text, signature: key.sign(text), signing_address: key.hex, signing_algo: 'ed25519', signature_kind: 'gateway' },
    { model: 'm', requestHash: '1'.repeat(64), responseHash: '2'.repeat(64), attestation: { modelSigners: [], gatewaySigner: key.hex, algo: 'ed25519' } });
  assert.equal(r.status, 'verified');
});

test('unavailable results are not treated as signatures', () => {
  assert.equal(V.checkSignature({ error_code: 'stream_disconnected', message: 'gone' }, {}).status, 'unavailable');
  assert.equal(V.checkSignature(null, {}).status, 'unavailable');
});

test('ECDSA path: EIP-191 signature recovers the signing address', () => {
  // Public test vector (private key 0x4c08...2318, message "Some data").
  const sig = '0x' + ['b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd', '6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a029', '1c'].join('');
  assert.equal(V.verifyEcdsa('Some data', sig, '0x2c7536E3605D9C16a7a3D7b1898e529396a65c23'), true);
  assert.equal(V.verifyEcdsa('Other data', sig, '0x2c7536E3605D9C16a7a3D7b1898e529396a65c23'), false);
});

test('attest() refuses when the service binds a different nonce', async () => {
  const near = await H.mockNear({ tamper: { nonce: true } });
  try {
    const r = await V.attest({ nearUrl: near.base, model: 'm/one', signingAlgo: 'ed25519', verifyMode: 'local' }, { rootFingerprint: near.rootFingerprint });
    assert.equal(r.ok, false);
    assert.match(r.error, /nonce/);
  } finally { await near.close(); }
});

test('attest() passes against a well-behaved mock and pins both signers', async () => {
  const near = await H.mockNear();
  try {
    const r = await V.attest({ nearUrl: near.base, model: 'm/one', signingAlgo: 'ed25519', verifyMode: 'local' }, { rootFingerprint: near.rootFingerprint });
    assert.equal(r.ok, true, r.error);
    assert.deepEqual(r.modelSigners, [near.modelKey.hex]);
    assert.equal(r.gatewaySigner, near.gatewayKey.hex);
  } finally { await near.close(); }
});

test('shortSigner matches the banner format', () => {
  assert.equal(V.shortSigner('3f2a00000000000000000000000000000000009c1b'), '0x3f2a…9c1b');
});
