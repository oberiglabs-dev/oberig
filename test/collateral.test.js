'use strict';
// OBERIG_VERIFY=full: Intel PCS collateral and NVIDIA NRAS tokens.
// Real data: fixtures/near-full-capture.json holds a DeepSeek V4.1 Flash report
// with the Intel TCB info, QE identity, CRLs and NRAS tokens fetched for it in
// the same run (checked at the capture time). Synthetic data (helpers.pcsWorld)
// covers what live data cannot show: OutOfDate and Revoked levels, a revoked
// PCK certificate, refusals.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const V = require('../src/verify.js');
const Q = require('../src/quote.js');
const P = require('../src/pcs.js');
const N = require('../src/nras.js');
const D = require('../src/der.js');
const ui = require('../src/ui.js');
const { loadConfig } = require('../src/config.js');
const H = require('./helpers.js');

const F = require('./fixtures/near-full-capture.json');
const NOW = new Date(F.captured);
const NEAR = 'https://cloud-api.near.ai/v1';
const status = (rows, id) => (rows.find((c) => c.id === id) || {}).status;
const detail = (rows, id) => (rows.find((c) => c.id === id) || {}).detail || '';
const quotes = () => [...F.report.model_attestations, F.report.gateway_attestation].map((rep) => {
  const q = Q.parseQuote(rep.intel_quote);
  return { q, pems: Q.verifyQuoteChain(q, { now: NOW }).pems };
});

/** fetch serving the capture. edit(url, {body, headers}) may change an Intel response. */
function captureFetch({ edit, gpu, log } = {}) {
  return async (url, init = {}) => {
    if (log) log.push(url);
    const u = new URL(url);
    if (u.host === 'cloud-api.near.ai') return new Response(JSON.stringify(F.report), { status: 200, headers: { 'content-type': 'application/json' } });
    if (u.pathname === '/v3/attest/gpu') {
      const posted = JSON.parse(init.body).evidence_list[0].evidence;
      const i = F.report.model_attestations.findIndex((m) => JSON.parse(m.nvidia_payload).evidence_list[0].evidence === posted);
      const answer = JSON.parse(JSON.stringify(F.nras.answers[i]));
      return new Response(JSON.stringify(gpu ? gpu(answer) : answer), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (u.pathname === '/.well-known/jwks.json') return new Response(JSON.stringify(F.nras.jwks), { status: 200 });
    const hit = F.intel[url];
    if (!hit) return new Response('not found', { status: 404 });
    let r = { body: hit.bodyText != null ? Buffer.from(hit.bodyText, 'utf8') : Buffer.from(hit.bodyBase64, 'base64'), headers: { ...hit.headers } };
    if (edit) r = edit(url, r) || r;
    return new Response(r.body, { status: 200, headers: r.headers });
  };
}

const cfgFull = (extra = {}) => ({ nearUrl: NEAR, model: F.model, signingAlgo: 'ed25519', verifyMode: 'full', requireTcb: 'warn', ...extra });

// ---- real data ----

test('live capture: the PCK certificate carries FMSPC, PCE ID and TCB components', () => {
  const [model, , gateway] = quotes();
  const ext = D.sgxExtension(new crypto.X509Certificate(model.pems[0]).raw);
  assert.equal(ext.fmspc, '90c06f000000');
  assert.equal(ext.pceId, '0000');
  assert.equal(ext.pcesvn, 13);
  assert.equal(ext.comps.length, 16);
  assert.equal(D.sgxExtension(new crypto.X509Certificate(gateway.pems[0]).raw).fmspc, '70a06d070000');
});

test('live capture: Intel collateral verifies for both model candidates and the gateway, TCB UpToDate', async () => {
  for (const { q, pems } of quotes()) {
    const r = await P.checkCollateral(q, pems, { now: NOW }, { fetch: captureFetch(), cache: new Map() });
    for (const id of ['pcs-tcbinfo', 'pcs-qeidentity', 'pck-revocation', 'qe-identity', 'tdx-module', 'tcb']) assert.equal(status(r.checks, id), 'ok', `${id}: ${detail(r.checks, id)}`);
    assert.equal(r.tcbStatus, 'UpToDate');
  }
});

test('live capture: NRAS tokens verify (ES384 with the NRAS key, our nonce, not expired, 8/8 GPUs)', () => {
  F.report.model_attestations.forEach((m, i) => {
    const r = N.checkNrasResult(F.nras.answers[i], JSON.parse(m.nvidia_payload), F.nonce, F.nras.jwks.keys, NOW.getTime());
    for (const c of r.checks) assert.equal(c.status, 'ok', `${c.id}: ${c.detail}`);
    assert.equal(r.passed, 8);
  });
});

test('full mode end to end on the live capture: every new check passes and the receipt shows them', async () => {
  const r = await V.attest(cfgFull(), { fetch: captureFetch(), nonce: F.nonce, now: NOW, cache: new Map() });
  assert.equal(r.ok, true, r.error);
  for (const id of ['quote-chain', 'gateway', 'pcs-tcbinfo', 'pcs-qeidentity', 'pck-revocation', 'qe-identity', 'tdx-module', 'tcb', 'gateway-tcb', 'gpu-tokens', 'gpu-fresh', 'gpu-verdict']) {
    assert.equal(status(r.checks, id), 'ok', `${id}: ${detail(r.checks, id)}`);
  }
  assert.deepEqual(r.tcb, { model: 'UpToDate', gateway: 'UpToDate' });
  assert.match(detail(r.checks, 'gpu-verdict'), /16\/16 GPUs pass \(2 candidates\)/);
  const text = ui.enclaveReceipt({ time: NOW.getTime(), hash: 'ab'.repeat(32), id: 'ab12', attestation: { ...r, mode: 'full' } });
  assert.match(text, /✓ {2}Intel TCB status: UpToDate/);
  assert.match(text, /✓ {2}gateway Intel TCB status: UpToDate/);
  assert.match(text, /✓ {2}GPU verdict \(NVIDIA NRAS\)/);
});

test('default mode stays local: only NEAR AI is contacted', async () => {
  const log = [];
  const r = await V.attest(cfgFull({ verifyMode: 'local' }), { fetch: captureFetch({ log }), nonce: F.nonce, now: NOW, cache: new Map() });
  assert.equal(r.ok, true, r.error);
  assert.deepEqual([...new Set(log.map((u) => new URL(u).host))], ['cloud-api.near.ai']);
  assert.equal(status(r.checks, 'tcb'), 'skip');
  assert.equal(status(r.checks, 'gpu-verdict'), 'skip');
});

test('collateral is fetched once per URL and reused from the in-memory cache', async () => {
  const log = [];
  const cache = new Map();
  const f = captureFetch({ log });
  for (const { q, pems } of quotes()) await P.checkCollateral(q, pems, { now: NOW }, { fetch: f, cache });
  assert.equal(log.length, new Set(log).size);
  assert.equal(log.length, 5); // TCB info for the model and the gateway FMSPC, QE identity, PCK CRL, Root CA CRL
});

// ---- negative cases on real data ----

test('tampered TCB info: one changed byte breaks Intel\'s signature', async () => {
  const [{ q, pems }] = quotes();
  const edit = (url, r) => (url.includes('/tcb?') ? { ...r, body: Buffer.from(r.body.toString('latin1').replace('"tcbEvaluationDataNumber":20', '"tcbEvaluationDataNumber":21'), 'latin1') } : r);
  const r = await P.checkCollateral(q, pems, { now: NOW }, { fetch: captureFetch({ edit }), cache: new Map() });
  assert.equal(status(r.checks, 'pcs-tcbinfo'), 'fail');
  assert.match(detail(r.checks, 'pcs-tcbinfo'), /signature does not verify/);
  assert.equal(status(r.checks, 'tcb'), 'fail');
  assert.equal(r.tcbStatus, null);
});

test('tampered signature value on the QE identity is caught', async () => {
  const [{ q, pems }] = quotes();
  const edit = (url, r) => {
    if (!url.includes('/qe/identity')) return r;
    const t = r.body.toString('latin1');
    const i = t.indexOf('"signature":"') + 13;
    return { ...r, body: Buffer.from(t.slice(0, i) + (t[i] === '0' ? '1' : '0') + t.slice(i + 1), 'latin1') };
  };
  const r = await P.checkCollateral(q, pems, { now: NOW }, { fetch: captureFetch({ edit }), cache: new Map() });
  assert.equal(status(r.checks, 'pcs-qeidentity'), 'fail');
  assert.match(detail(r.checks, 'pcs-qeidentity'), /signature does not verify/);
});

test('wrong FMSPC: a genuine Intel TCB info for another platform is refused', async () => {
  const [{ q, pems }] = quotes();
  const other = 'https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=70a06d070000';
  const edit = (url, r) => (url.includes('fmspc=90c06f000000') ? { body: Buffer.from(F.intel[other].bodyText), headers: F.intel[other].headers } : r);
  const r = await P.checkCollateral(q, pems, { now: NOW }, { fetch: captureFetch({ edit }), cache: new Map() });
  assert.equal(status(r.checks, 'pcs-tcbinfo'), 'fail');
  assert.match(detail(r.checks, 'pcs-tcbinfo'), /FMSPC 70a06d070000.*90c06f000000/);
});

test('issuer chain that does not end at the pinned Intel root is refused', async () => {
  const [{ q, pems }] = quotes();
  const tc = H.testChain();
  const edit = (url, r) => (url.includes('/tcb?') ? { ...r, headers: { ...r.headers, 'tcb-info-issuer-chain': encodeURIComponent(tc.pem.split('-----END CERTIFICATE-----\n').slice(1).join('-----END CERTIFICATE-----\n')) } } : r);
  const r = await P.checkCollateral(q, pems, { now: NOW }, { fetch: captureFetch({ edit }), cache: new Map() });
  assert.equal(status(r.checks, 'pcs-tcbinfo'), 'fail');
  assert.match(detail(r.checks, 'pcs-tcbinfo'), /pinned Intel SGX Root CA/);
});

test('expired collateral: after nextUpdate the TCB info, QE identity and CRLs are refused', async () => {
  const [{ q, pems }] = quotes();
  const later = new Date(Date.parse(JSON.parse(F.intel[P.URLS.qe()].bodyText).enclaveIdentity.nextUpdate) + 86400000);
  const r = await P.checkCollateral(q, pems, { now: later }, { fetch: captureFetch(), cache: new Map() });
  assert.match(detail(r.checks, 'pcs-tcbinfo'), /expired/);
  assert.match(detail(r.checks, 'pcs-qeidentity'), /expired/);
  assert.match(detail(r.checks, 'pck-revocation'), /expired/);
  assert.equal(status(r.checks, 'tcb'), 'fail');
  const early = new Date(Date.parse(JSON.parse(F.intel[P.URLS.qe()].bodyText).enclaveIdentity.issueDate) - 86400000);
  const e = await P.checkCollateral(q, pems, { now: early }, { fetch: captureFetch(), cache: new Map() });
  assert.match(detail(e.checks, 'pcs-qeidentity'), /not valid yet/);
});

test('tampered CRL is refused (signature by the PCK CA)', async () => {
  const [{ q, pems }] = quotes();
  const edit = (url, r) => {
    if (!url.includes('pckcrl')) return r;
    const b = Buffer.from(r.body);
    b[b.length - 5] ^= 1; // inside the signature
    return { ...r, body: b };
  };
  const r = await P.checkCollateral(q, pems, { now: NOW }, { fetch: captureFetch({ edit }), cache: new Map() });
  assert.equal(status(r.checks, 'pck-revocation'), 'fail');
  assert.match(detail(r.checks, 'pck-revocation'), /PCK CRL/);
});

test('the real Intel PCK CRL parses: issuer, dates and revoked serials', () => {
  const crl = D.parseCrl(Buffer.from(F.intel[P.URLS.pckCrl('platform')].bodyBase64, 'base64'));
  const ca = new crypto.X509Certificate(quotes()[0].pems[1]);
  assert.ok(crl.revoked.size > 0);
  assert.ok(crl.thisUpdate <= NOW.getTime() && NOW.getTime() <= crl.nextUpdate);
  assert.equal(P.verifyCrl(Buffer.from(F.intel[P.URLS.pckCrl('platform')].bodyBase64, 'base64'), ca, NOW.getTime(), 'PCK CRL').revoked.size, crl.revoked.size);
  assert.equal(crl.revoked.has(D.certFields(new crypto.X509Certificate(quotes()[0].pems[0]).raw).serial), false);
});

test('bad JWT signature: a changed NRAS token signature is refused and attestation fails', async () => {
  const gpu = (answer) => {
    const t = answer[1]['GPU-2'].split('.');
    const s = Buffer.from(t[2], 'base64url');
    s[20] ^= 1;
    answer[1]['GPU-2'] = [t[0], t[1], s.toString('base64url')].join('.');
    return answer;
  };
  const r = await V.attest(cfgFull(), { fetch: captureFetch({ gpu }), nonce: F.nonce, now: NOW, cache: new Map() });
  assert.equal(r.ok, false);
  assert.equal(status(r.checks, 'gpu-tokens'), 'fail');
  assert.match(detail(r.checks, 'gpu-tokens'), /GPU-2: token signature does not verify/);
  assert.equal(status(r.checks, 'gpu-verdict'), 'fail');
});

test('NRAS tokens: unknown key, wrong nonce, expired, failed GPU claim, overall false', () => {
  const m = F.report.model_attestations[0];
  const payload = JSON.parse(m.nvidia_payload);
  const ans = F.nras.answers[0];
  const keys = F.nras.jwks.keys;
  const run = (o = {}) => N.checkNrasResult(o.answer || ans, payload, o.nonce || F.nonce, o.keys || keys, o.now || NOW.getTime()).checks;
  assert.match(detail(run({ keys: [] }), 'gpu-tokens'), /not in the NRAS JWKS/);
  assert.equal(status(run({ nonce: 'cd'.repeat(32) }), 'gpu-fresh'), 'fail');
  assert.match(detail(run({ now: NOW.getTime() + 3 * 3600e3 }), 'gpu-fresh'), /validity window/);
  // A token NVIDIA did not sign cannot change a claim: re-signing with our own key fails the signature check.
  const w = H.pcsWorld();
  const own = w.nrasAnswer(payload, { result: false });
  assert.equal(status(N.checkNrasResult(own, payload, F.nonce, keys, Date.now()).checks, 'gpu-tokens'), 'fail');
  const signedFalse = N.checkNrasResult(own, payload, F.nonce, [w.jwk], Date.now()).checks;
  assert.match(detail(signedFalse, 'gpu-verdict'), /overall result is not true/);
  const badGpu = w.nrasAnswer(payload, { gpuClaims: { measres: 'fail' } });
  assert.match(detail(N.checkNrasResult(badGpu, payload, F.nonce, [w.jwk], Date.now()).checks, 'gpu-verdict'), /measres/);
});

// ---- synthetic PCS: policy, revocation, refusals ----

async function synthetic(o = {}, cfg = {}) {
  const w = H.pcsWorld();
  return V.attest({ nearUrl: NEAR, model: 'm/one', signingAlgo: 'ed25519', verifyMode: 'full', requireTcb: 'warn', ...cfg }, { fetch: w.serve(o), rootFingerprint: w.rootFingerprint, cache: new Map() });
}

test('synthetic PCS: an UpToDate platform passes every full-mode check', async () => {
  const r = await synthetic();
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(r.tcb, { model: 'UpToDate', gateway: 'UpToDate' });
  assert.equal(status(r.checks, 'gpu-verdict'), 'ok');
});

test('OutOfDate is shown as a warning and still sent; OBERIG_REQUIRE_TCB=uptodate refuses it', async () => {
  const warn = await synthetic({ tcbStatus: 'OutOfDate' });
  assert.equal(warn.ok, true, warn.error);
  assert.equal(status(warn.checks, 'tcb'), 'warn');
  assert.equal(warn.checks.find((c) => c.id === 'tcb').label, 'Intel TCB status: OutOfDate');
  assert.match(detail(warn.checks, 'tcb'), /warning only.*INTEL-SA-00000/);
  const text = ui.enclaveReceipt({ time: Date.now(), hash: 'cd'.repeat(32), id: 'cd34', attestation: { ...warn, mode: 'full' } });
  assert.match(text, /✗ {2}Intel TCB status: OutOfDate {2}warning only/);
  assert.match(text, /result {4}✓ enclave attested/);
  const strict = await synthetic({ tcbStatus: 'OutOfDate' }, { requireTcb: 'uptodate' });
  assert.equal(strict.ok, false);
  assert.equal(status(strict.checks, 'tcb'), 'fail');
  assert.match(strict.error, /Intel TCB status: OutOfDate/);
});

test('SWHardeningNeeded and ConfigurationNeeded warn; Revoked is always refused', async () => {
  for (const s of ['SWHardeningNeeded', 'ConfigurationNeeded']) {
    const r = await synthetic({ tcbStatus: s });
    assert.equal(status(r.checks, 'tcb'), 'warn', s);
    assert.equal(r.ok, true);
  }
  const rev = await synthetic({ tcbStatus: 'Revoked' });
  assert.equal(rev.ok, false);
  assert.match(detail(rev.checks, 'tcb'), /revoked by Intel/);
});

test('an OutOfDate quoting enclave or TDX module makes the platform OutOfDate', async () => {
  const qe = await synthetic({ qeStatus: 'OutOfDate' });
  assert.equal(qe.tcb.model, 'OutOfDate');
  const mod = await synthetic({ moduleStatus: 'OutOfDate', tcbStatus: 'ConfigurationNeeded' });
  assert.equal(mod.tcb.model, 'OutOfDateConfigurationNeeded');
  const rev = await synthetic({ qeStatus: 'Revoked' });
  assert.equal(rev.tcb.model, 'Revoked');
  assert.equal(rev.ok, false);
});

test('revoked serial: a PCK certificate listed in the PCK CRL is refused', async () => {
  const r = await synthetic({ revokeLeaf: true });
  assert.equal(r.ok, false);
  assert.equal(status(r.checks, 'pck-revocation'), 'fail');
  assert.match(detail(r.checks, 'pck-revocation'), new RegExp(`PCK certificate is revoked \\(serial ${H.pcsWorld().leafSerial}\\)`));
  assert.equal(status(r.checks, 'gateway'), 'fail');
});

test('synthetic PCS: expired and tampered collateral is refused', async () => {
  const exp = await synthetic({ expired: true });
  assert.equal(exp.ok, false);
  assert.match(detail(exp.checks, 'pcs-tcbinfo'), /expired/);
  const t = await synthetic({ tamper: 'tcb' });
  assert.match(detail(t.checks, 'pcs-tcbinfo'), /signature does not verify/);
  const qe = await synthetic({ tamper: 'qe' });
  assert.match(detail(qe.checks, 'pcs-qeidentity'), /signature does not verify/);
  const gpu = await synthetic({ gpu: { badSig: true } });
  assert.equal(status(gpu.checks, 'gpu-tokens'), 'fail');
  assert.equal(gpu.ok, false);
});

test('a token signed with a key newer than the cached JWKS triggers one fresh JWKS fetch', async () => {
  const w = H.pcsWorld();
  const cache = new Map();
  cache.set(N.JWKS_URL, { at: Date.now(), promise: Promise.resolve([]) }); // stale set without the signing key
  const r = await V.attest({ nearUrl: NEAR, model: 'm/one', signingAlgo: 'ed25519', verifyMode: 'full' }, { fetch: w.serve(), rootFingerprint: w.rootFingerprint, cache });
  assert.equal(status(r.checks, 'gpu-tokens'), 'ok', detail(r.checks, 'gpu-tokens'));
  assert.equal(r.ok, true, r.error);
});

test('full mode fails closed when Intel PCS cannot be reached', async () => {
  const w = H.pcsWorld();
  const inner = w.serve();
  const fetch = async (url, init) => (new URL(url).host.endsWith('trustedservices.intel.com') ? new Response('busy', { status: 503 }) : inner(url, init));
  const r = await V.attest({ nearUrl: NEAR, model: 'm/one', signingAlgo: 'ed25519', verifyMode: 'full' }, { fetch, rootFingerprint: w.rootFingerprint, cache: new Map() });
  assert.equal(r.ok, false);
  assert.match(detail(r.checks, 'pcs-tcbinfo'), /could not fetch the TCB info \(api\.trustedservices\.intel\.com returned 503\)/);
});

// ---- pure rules ----

const level = (sgx, pcesvn, tdx, tcbStatus) => ({ tcb: { sgxtcbcomponents: sgx.map((svn) => ({ svn })), pcesvn, tdxtcbcomponents: tdx.map((svn) => ({ svn })) }, tcbStatus });
const z16 = (a) => [...a, ...new Array(16 - a.length).fill(0)];

test('TCB level matching follows Intel: SGX components, PCESVN, then TEE TCB SVN from index 2 when [1] > 0', () => {
  const info = { tcbLevels: [level(z16([4, 4]), 13, z16([9, 0, 4]), 'UpToDate'), level(z16([2, 2]), 13, z16([5, 0, 2]), 'OutOfDate')] };
  const pck = { comps: z16([4, 4]), pcesvn: 13 };
  // TEE TCB SVN[1] = 1: indexes 0 and 1 are the TDX module's, judged by its identity instead.
  assert.equal(P.matchTcbLevel(info, pck, Buffer.from(z16([3, 1, 4]))).tcbStatus, 'UpToDate');
  // TEE TCB SVN[1] = 0: all 16 are compared, so [0] = 3 < 9 drops to the next level.
  assert.equal(P.matchTcbLevel(info, pck, Buffer.from(z16([5, 0, 4]))).tcbStatus, 'OutOfDate');
  assert.equal(P.matchTcbLevel(info, { comps: z16([3, 4]), pcesvn: 13 }, Buffer.from(z16([3, 1, 4]))).tcbStatus, 'OutOfDate');
  assert.equal(P.matchTcbLevel(info, { comps: z16([4, 4]), pcesvn: 12 }, Buffer.from(z16([3, 1, 4]))), null);
});

test('status merge and policy', () => {
  assert.equal(P.converge('UpToDate', 'OutOfDate'), 'OutOfDate');
  assert.equal(P.converge('SWHardeningNeeded', 'OutOfDate'), 'OutOfDate');
  assert.equal(P.converge('ConfigurationAndSWHardeningNeeded', 'OutOfDate'), 'OutOfDateConfigurationNeeded');
  assert.equal(P.converge('ConfigurationNeeded', 'Revoked'), 'Revoked');
  assert.equal(P.converge('SWHardeningNeeded', 'UpToDate'), 'SWHardeningNeeded');
  assert.equal(P.tcbPolicy('UpToDate', 'warn'), 'ok');
  assert.equal(P.tcbPolicy('OutOfDate', 'warn'), 'warn');
  assert.equal(P.tcbPolicy('OutOfDate', 'uptodate'), 'fail');
  assert.equal(P.tcbPolicy('Revoked', 'warn'), 'fail');
  assert.equal(P.tcbPolicy('SomethingNew', 'warn'), 'fail');
});

test('QE identity: MRSIGNER, ISVPRODID, attributes and ISVSVN are all checked', () => {
  const [{ q }] = quotes();
  const id = JSON.parse(F.intel[P.URLS.qe()].bodyText).enclaveIdentity;
  assert.equal(P.matchQeIdentity(q.qeReport, id).ok, true);
  assert.match(P.matchQeIdentity(q.qeReport, { ...id, mrsigner: '00'.repeat(32) }).error, /MRSIGNER/);
  assert.match(P.matchQeIdentity(q.qeReport, { ...id, isvprodid: 1 }).error, /ISVPRODID/);
  assert.match(P.matchQeIdentity(q.qeReport, { ...id, attributes: '01000000000000000000000000000000' }).error, /ATTRIBUTES/);
  assert.match(P.matchQeIdentity(q.qeReport, { ...id, tcbLevels: [{ tcb: { isvsvn: 99 }, tcbStatus: 'UpToDate' }] }).error, /below every Intel TCB level/);
});

test('TDX module identity: TDX_<TEE TCB SVN[1]> must exist and match', () => {
  const [{ q }] = quotes();
  const info = JSON.parse(F.intel[P.URLS.tcb('90c06f000000')].bodyText).tcbInfo;
  const ok = P.matchTdxModule(info, q);
  assert.equal(ok.id, 'TDX_01');
  assert.equal(ok.status, 'UpToDate');
  assert.match(P.matchTdxModule({ ...info, tdxModuleIdentities: [] }, q).error, /no TDX module identity TDX_01/);
  const other = info.tdxModuleIdentities.map((m) => ({ ...m, mrsigner: 'ff'.repeat(48) }));
  assert.match(P.matchTdxModule({ ...info, tdxModuleIdentities: other }, q).error, /MRSIGNERSEAM/);
});

test('rawJsonValue returns the exact signed bytes, braces inside strings included', () => {
  const text = '{"a":1, "tcbInfo" : {"x":"}{\\"","y":[1,{"z":2}]},"signature":"00"}';
  assert.equal(P.rawJsonValue(text, 'tcbInfo'), '{"x":"}{\\"","y":[1,{"z":2}]}');
  assert.equal(P.rawJsonValue(text, 'signature'), '"00"');
  assert.throws(() => P.rawJsonValue(text, 'missing'), /missing/);
});

test('a synthetic CRL signed by the CA lists the revoked serial; a CRL from another key is refused', () => {
  const w = H.pcsWorld();
  const ca = new crypto.X509Certificate(w.caPem);
  const now = Date.now();
  const dates = { thisUpdate: new Date(now - 1000), nextUpdate: new Date(now + 86400000) };
  const good = H.makeCrl({ issuer: 'Intel SGX PCK Platform CA', signKey: w.ca.privateKey, revoked: [w.leafSerial], ...dates });
  assert.equal(P.verifyCrl(good, ca, now, 'PCK CRL').revoked.has(w.leafSerial), true);
  const forged = H.makeCrl({ issuer: 'Intel SGX PCK Platform CA', signKey: crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey, ...dates });
  assert.throws(() => P.verifyCrl(forged, ca, now, 'PCK CRL'), /signature does not verify/);
});

test('OBERIG_REQUIRE_TCB: warn by default, uptodate accepted, anything else rejected', () => {
  assert.equal(loadConfig({}, {}).requireTcb, 'warn');
  assert.equal(loadConfig({}, { OBERIG_REQUIRE_TCB: 'UpToDate' }).requireTcb, 'uptodate');
  assert.throws(() => loadConfig({}, { OBERIG_REQUIRE_TCB: 'yes' }), /OBERIG_REQUIRE_TCB/);
});
