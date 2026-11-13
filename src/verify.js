'use strict';
// Verify: attestation preflight and per-answer signature checks for NEAR AI Cloud.
//
// Before a prompt is sent, Oberig asks NEAR AI for a fresh attestation report
// (its own random nonce, the canonical model ID, provider=near, no aliasing) and
// checks it locally. After each answer it fetches the answer's signature and
// checks it against the exact bytes it sent and received.
//
// Every check reports 'ok', 'fail' or 'skip' (not checked). Nothing is claimed
// that is not checked here.

const crypto = require('node:crypto');
const { parseQuote, verifyQuoteChain, hexBuf, b64url } = require('./quote.js');
const { recoverEip191 } = require('./ecdsa.js');
const { VERSION } = require('./config.js');

const NRAS_URL = 'https://nras.attestation.nvidia.com/v3/attest/gpu';

const sha = (alg, ...parts) => { const h = crypto.createHash(alg); for (const p of parts) h.update(p); return h.digest(); };
const parseMaybe = (v) => (typeof v === 'string' ? JSON.parse(v) : v);
const randomNonce = () => crypto.randomBytes(32).toString('hex');
const normAddr = (a) => String(a || '').trim().toLowerCase().replace(/^0x/, '');

/** Short display form: 0x3f2a…9c1b */
function shortSigner(addr) {
  const a = normAddr(addr);
  return a ? `0x${a.slice(0, 4)}…${a.slice(-4)}` : 'none';
}

function replayRtmr3(eventLog) {
  let acc = Buffer.alloc(48);
  let n = 0;
  for (const e of parseMaybe(eventLog) || []) {
    if (e.imr !== 3) continue;
    const t = Buffer.alloc(4);
    t.writeUInt32LE(e.event_type >>> 0);
    const d = sha('sha384', t, ':', Buffer.from(String(e.event || ''), 'utf8'), ':', hexBuf(e.event_payload || ''));
    if (e.digest && !hexBuf(e.digest).equals(d)) throw new Error(`event digest mismatch (${e.event})`);
    acc = sha('sha384', acc, d);
    n++;
  }
  return { value: acc, events: n };
}

/**
 * Checks one attestation (model or gateway) against our nonce.
 * Returns {ok, signer, algo, checks: [{id, label, status, detail}]}.
 */
function checkOne(rep, nonce, opts = {}) {
  const checks = [];
  const add = (id, label, status, detail = '') => { checks.push({ id, label, status, detail }); return status === 'ok'; };
  const isModel = opts.kind !== 'gateway';
  const algo = String(rep && rep.signing_algo || '').toLowerCase();
  const signer = rep && rep.signing_address;
  if (!rep || !rep.intel_quote || !signer) {
    add('report', 'attestation evidence present', 'fail', 'missing quote or signer');
    return { ok: false, signer, algo, checks };
  }
  if (opts.algo) add('algo', `signing algorithm is ${opts.algo}`, algo === opts.algo ? 'ok' : 'fail', algo);
  add('nonce-echo', 'fresh nonce echoed by the service', normAddr(rep.request_nonce) === normAddr(nonce) ? 'ok' : 'fail');

  let q = null;
  try { q = parseQuote(rep.intel_quote); } catch (err) { add('quote', 'TDX quote parsed', 'fail', err.message); }
  if (q) {
    add('tdx', 'quote is an Intel TDX quote', q.teeType === 0x81 ? 'ok' : 'fail', '0x' + q.teeType.toString(16));
    const chain = verifyQuoteChain(q, opts);
    add('quote-chain', 'TDX quote signed by an Intel-rooted key', chain.ok ? 'ok' : 'fail', chain.ok ? 'chain to pinned Intel SGX Root CA' : chain.error);
    add('debug', 'TD debug mode off', q.debug ? 'fail' : 'ok');

    const id = hexBuf(signer);
    let bound;
    if (rep.tls_cert_fingerprint) bound = sha('sha256', id, hexBuf(rep.tls_cert_fingerprint));
    else if (id.length <= 32) bound = Buffer.concat([id, Buffer.alloc(32 - id.length)]);
    else bound = Buffer.alloc(32, 0xff);
    add('nonce-bound', 'nonce bound in quote report data', q.reportData.subarray(32, 64).equals(hexBuf(nonce)) ? 'ok' : 'fail');
    add('signer-bound', 'signer bound in quote report data', q.reportData.subarray(0, 32).equals(bound) ? 'ok' : 'fail');

    try {
      const tcb = parseMaybe(rep.info && rep.info.tcb_info);
      const compose = tcb && tcb.app_compose;
      if (typeof compose !== 'string') throw new Error('app_compose missing');
      const want = Buffer.concat([Buffer.from([1]), sha('sha256', Buffer.from(compose, 'utf8')), Buffer.alloc(15)]);
      add('config', 'app config measured (MRCONFIGID)', q.mrConfigId.equals(want) ? 'ok' : 'fail');
    } catch (err) {
      add('config', 'app config measured (MRCONFIGID)', 'fail', err.message);
    }
    try {
      const log = rep.event_log || (parseMaybe(rep.info && rep.info.tcb_info) || {}).event_log;
      const r = replayRtmr3(log);
      add('rtmr3', 'RTMR3 event log replayed', r.events > 0 && r.value.equals(q.rtmr[3]) ? 'ok' : 'fail', `${r.events} events`);
    } catch (err) {
      add('rtmr3', 'RTMR3 event log replayed', 'fail', err.message);
    }
  }
  if (isModel) {
    try {
      const p = rep.nvidia_payload ? parseMaybe(rep.nvidia_payload) : null;
      if (!p) add('gpu-nonce', 'GPU evidence nonce matched', 'fail', 'no GPU evidence');
      else add('gpu-nonce', 'GPU evidence nonce matched', normAddr(p.nonce) === normAddr(nonce) ? 'ok' : 'fail', `${(p.evidence_list || []).length} GPUs`);
    } catch (err) {
      add('gpu-nonce', 'GPU evidence nonce matched', 'fail', err.message);
    }
  }
  const ok = checks.every((c) => c.status !== 'fail');
  return { ok, signer, algo, checks };
}

/** Checks a full /v1/attestation/report body for one model. Pure (no network). */
function checkAttestation(body, nonce, opts = {}) {
  const model = opts.model;
  const out = { ok: false, model, nonce, modelSigners: [], gateway: null, models: [], checks: [], error: null };
  const list = body && Array.isArray(body.model_attestations) ? body.model_attestations : [];
  const named = list.filter((m) => !model || !m.model_name || m.model_name === model);
  if (!named.length) {
    out.error = 'no model attestation returned for ' + model;
    out.checks.push({ id: 'report', label: 'attestation report for this model', status: 'fail', detail: out.error });
    return out;
  }
  out.checks.push({ id: 'report', label: 'attestation report for this model', status: 'ok', detail: `${named.length} candidate(s), provider near` });
  // Verify every returned candidate; all must pass.
  out.models = named.map((m) => checkOne(m, nonce, { ...opts, kind: 'model' }));
  for (const c of out.models[0].checks) {
    const all = out.models.map((r) => r.checks.find((x) => x.id === c.id));
    const status = all.some((x) => !x || x.status === 'fail') ? 'fail' : c.status;
    out.checks.push({ ...c, status, detail: status === 'fail' ? (all.find((x) => x && x.status === 'fail') || c).detail : c.detail });
  }
  out.modelSigners = [...new Set(out.models.map((m) => normAddr(m.signer)))];
  out.algo = out.models[0].algo;
  if (body.gateway_attestation) out.gateway = checkOne(body.gateway_attestation, nonce, { ...opts, kind: 'gateway' });
  out.checks.push({
    id: 'gateway', label: 'gateway enclave quote checked', status: out.gateway ? (out.gateway.ok ? 'ok' : 'fail') : 'fail',
    detail: out.gateway ? (out.gateway.ok ? `${out.gateway.checks.length} checks` : (out.gateway.checks.find((c) => c.status === 'fail') || {}).label) : 'no gateway evidence',
  });
  if (out.modelSigners.length !== 1) out.checks.push({ id: 'one-signer', label: 'one model signing key', status: 'fail', detail: `${out.modelSigners.length} keys` });
  out.checks.push({ id: 'tcb', label: 'Intel TCB status', status: 'skip', detail: 'not checked locally' });
  out.checks.push({ id: 'gpu-verdict', label: 'GPU verdict (NVIDIA)', status: 'skip', detail: 'not checked locally' });
  out.ok = out.checks.every((c) => c.status !== 'fail');
  out.signer = out.modelSigners[0] || null;
  out.gatewaySigner = out.gateway ? normAddr(out.gateway.signer) : null;
  if (!out.ok) {
    const f = out.checks.find((c) => c.status === 'fail');
    out.error = f ? `${f.label}: ${f.detail || 'failed'}` : 'attestation failed';
  }
  return out;
}

function decodeJwtPayload(token) {
  const part = String(token || '').split('.')[1];
  if (!part) throw new Error('not a JWT');
  return JSON.parse(Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
}

/** OBERIG_VERIFY=full: asks NVIDIA NRAS for the GPU verdict. Returns a check object. */
async function nrasCheck(rep, nonce, fetchImpl) {
  const label = 'GPU verdict (NVIDIA NRAS)';
  try {
    const payload = parseMaybe(rep.nvidia_payload);
    const res = await fetchImpl(NRAS_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': `oberig/${VERSION}` },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(20000),
    });
    if (!res.ok) return { id: 'gpu-verdict', label, status: 'fail', detail: `NRAS returned ${res.status}` };
    const j = await res.json();
    const first = Array.isArray(j) ? j[0] : null;
    const token = Array.isArray(first) && first[0] === 'JWT' ? first[1] : null;
    const claims = decodeJwtPayload(token);
    const pass = claims['x-nvidia-overall-att-result'] === true;
    const nonceOk = !claims.eat_nonce || normAddr(claims.eat_nonce) === normAddr(nonce);
    return {
      id: 'gpu-verdict', label, status: pass && nonceOk ? 'ok' : 'fail',
      detail: pass ? (nonceOk ? 'overall result true (token signature not checked)' : 'nonce mismatch in token') : 'overall result false',
    };
  } catch (err) {
    return { id: 'gpu-verdict', label, status: 'fail', detail: err.message };
  }
}

function reportUrl(cfg, nonce) {
  const qs = new URLSearchParams({ model: cfg.model, provider: 'near', nonce, signing_algo: cfg.signingAlgo, include_tls_fingerprint: 'false' });
  return `${cfg.nearUrl}/attestation/report?${qs}`;
}

/**
 * Fetches a fresh report and checks it. deps.fetch and deps.nonce exist for tests.
 * Never throws: failures come back as {ok: false, error}.
 */
async function attest(cfg, deps = {}) {
  const fetchImpl = deps.fetch || globalThis.fetch;
  const nonce = deps.nonce || randomNonce();
  const started = Date.now();
  const headers = { accept: 'application/json', 'x-no-aliasing': 'true', 'accept-encoding': 'identity', 'user-agent': `oberig/${VERSION}` };
  try {
    let res = await fetchImpl(reportUrl(cfg, nonce), { headers, signal: AbortSignal.timeout(30000) });
    if (res.status === 429 && cfg.apiKey) {
      // Anonymous report requests share a small limit; retry once with the key.
      res = await fetchImpl(reportUrl(cfg, nonce), { headers: { ...headers, authorization: `Bearer ${cfg.apiKey}` }, signal: AbortSignal.timeout(30000) });
    }
    if (!res.ok) {
      const t = await res.text().catch(() => '');
      return { ok: false, model: cfg.model, nonce, fetchedAt: started, checks: [], error: `attestation report request returned ${res.status} ${t.slice(0, 160)}` };
    }
    const body = await res.json();
    const out = checkAttestation(body, nonce, { model: cfg.model, algo: cfg.signingAlgo, now: deps.now, rootFingerprint: deps.rootFingerprint });
    if (cfg.verifyMode === 'full' && out.models.length) {
      const gpu = await nrasCheck(body.model_attestations.find((m) => !cfg.model || m.model_name === cfg.model) || body.model_attestations[0], nonce, fetchImpl);
      const i = out.checks.findIndex((c) => c.id === 'gpu-verdict');
      out.checks[i] = gpu;
      out.ok = out.checks.every((c) => c.status !== 'fail');
      if (!out.ok && !out.error) out.error = `${gpu.label}: ${gpu.detail}`;
    }
    out.fetchedAt = started;
    out.ms = Date.now() - started;
    out.mode = cfg.verifyMode;
    return out;
  } catch (err) {
    return { ok: false, model: cfg.model, nonce, fetchedAt: started, checks: [], error: `could not fetch attestation report (${err.message})` };
  }
}

function sigBytes(s) {
  const v = String(s || '').trim();
  if (/^(0x)?[0-9a-fA-F]+$/.test(v) && v.replace(/^0x/i, '').length % 2 === 0) return Buffer.from(v.replace(/^0x/i, ''), 'hex');
  return Buffer.from(v, 'base64');
}

function verifyEd25519(text, signature, publicKeyHex) {
  try {
    const pub = hexBuf(publicKeyHex);
    if (pub.length !== 32) return false;
    const key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64url(pub) }, format: 'jwk' });
    const sig = sigBytes(signature);
    return sig.length === 64 && crypto.verify(null, Buffer.from(text, 'utf8'), key, sig);
  } catch {
    return false;
  }
}

function verifyEcdsa(text, signature, address) {
  try { return normAddr(recoverEip191(text, sigBytes(signature))) === normAddr(address); } catch { return false; }
}

/**
 * Checks one /v1/signature response against what Oberig sent and received.
 * ctx: {model, requestHash, responseHash, attestation: {modelSigners, gatewaySigner, algo}}
 * Returns {status: 'verified'|'failed'|'unavailable', kind, signer, checks, reason}.
 */
function checkSignature(sig, ctx) {
  if (!sig || typeof sig !== 'object' || sig.error_code || !sig.signature || !sig.text) {
    return { status: 'unavailable', kind: null, reason: (sig && (sig.message || sig.error_code)) || 'no signature' };
  }
  const parts = String(sig.text).split(':');
  const kind = sig.signature_kind || (parts.length >= 3 ? 'provider_tee' : 'gateway');
  const expected = kind === 'provider_tee' ? `${ctx.model}:${ctx.requestHash}:${ctx.responseHash}` : `${ctx.requestHash}:${ctx.responseHash}`;
  const a = ctx.attestation || {};
  const pinned = kind === 'provider_tee' ? (a.modelSigners || []) : (a.gatewaySigner ? [a.gatewaySigner] : []);
  const algo = String(sig.signing_algo || '').toLowerCase();
  const checks = {
    requestHash: parts.length >= 2 && parts[parts.length - 2] === ctx.requestHash,
    responseHash: parts.length >= 2 && parts[parts.length - 1] === ctx.responseHash,
    text: sig.text === expected,
    signer: pinned.includes(normAddr(sig.signing_address)) && (!a.algo || algo === a.algo),
    signature: algo === 'ed25519' ? verifyEd25519(sig.text, sig.signature, sig.signing_address)
      : algo === 'ecdsa' ? verifyEcdsa(sig.text, sig.signature, sig.signing_address) : false,
  };
  const ok = Object.values(checks).every(Boolean);
  let reason = '';
  if (!checks.requestHash) reason = 'request hash does not match what Oberig sent';
  else if (!checks.responseHash) reason = 'response hash does not match what Oberig received';
  else if (!checks.text) reason = 'signed text does not match';
  else if (!checks.signer) reason = 'signer is not the attested key';
  else if (!checks.signature) reason = 'signature does not verify';
  return { status: ok ? 'verified' : 'failed', kind, signer: normAddr(sig.signing_address), algo, checks, reason };
}

/** Fetches /v1/signature/{id}. Retries a 404 for a short, bounded time. */
async function fetchSignature(cfg, id, deps = {}) {
  const fetchImpl = deps.fetch || globalThis.fetch;
  const qs = new URLSearchParams({ model: cfg.model, signing_algo: cfg.signingAlgo });
  const url = `${cfg.nearUrl}/signature/${encodeURIComponent(id)}?${qs}`;
  const tries = deps.tries || 4;
  for (let i = 0; i < tries; i++) {
    let res;
    try {
      res = await fetchImpl(url, { headers: { authorization: `Bearer ${cfg.apiKey}`, accept: 'application/json', 'user-agent': `oberig/${VERSION}` }, signal: AbortSignal.timeout(15000) });
    } catch (err) {
      return { error_code: 'network', message: err.message };
    }
    if (res.status === 404 && i < tries - 1) {
      res.body && res.body.cancel().catch(() => {});
      await new Promise((r) => setTimeout(r, deps.retryMs != null ? deps.retryMs : 500));
      continue;
    }
    if (!res.ok) return { error_code: String(res.status), message: `signature request returned ${res.status}` };
    try { return await res.json(); } catch { return { error_code: 'parse', message: 'signature response is not JSON' }; }
  }
  return { error_code: '404', message: 'signature not found' };
}

module.exports = {
  checkOne, checkAttestation, checkSignature, attest, fetchSignature, nrasCheck,
  verifyEd25519, verifyEcdsa, replayRtmr3, shortSigner, normAddr, randomNonce, reportUrl,
};
