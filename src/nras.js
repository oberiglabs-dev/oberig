'use strict';
// NVIDIA NRAS for OBERIG_VERIFY=full. Oberig posts the GPU evidence from the
// NEAR AI report, unchanged, to NVIDIA's Remote Attestation Service and checks
// the answer here with node:crypto:
//
//   every token (the overall EAT and one per GPU) is an ES384 JWT signed by a
//   key from NRAS's JWKS (fetched over HTTPS) and issued by NRAS;
//   every token carries our nonce (eat_nonce) and is within nbf..exp;
//   the overall result (x-nvidia-overall-att-result) is true, the overall token
//   binds each GPU token by its SHA-256 digest (submods), there is one GPU
//   token per evidence entry sent, and each GPU token passes NVIDIA's per-GPU
//   claims (measurements, report signature and nonce, certificate chains,
//   driver and VBIOS reference values, secure boot on, debug off).
//
// The JWKS is kept in memory for 30 minutes.

const crypto = require('node:crypto');
const { VERSION } = require('./config.js');

const NRAS_URL = 'https://nras.attestation.nvidia.com/v3/attest/gpu';
const JWKS_URL = 'https://nras.attestation.nvidia.com/.well-known/jwks.json';
const ISSUER = 'https://nras.attestation.nvidia.com';
const CACHE_MS = 30 * 60 * 1000;
const SKEW_S = 60;

// NVIDIA's GPU claims (claims version 2.0) that must be true for each GPU.
const GPU_TRUE = [
  'x-nvidia-gpu-arch-check',
  'x-nvidia-gpu-attestation-report-cert-chain-validated',
  'x-nvidia-gpu-attestation-report-signature-verified',
  'x-nvidia-gpu-attestation-report-nonce-match',
  'x-nvidia-gpu-driver-rim-fetched',
  'x-nvidia-gpu-driver-rim-schema-validated',
  'x-nvidia-gpu-driver-rim-cert-validated',
  'x-nvidia-gpu-driver-rim-signature-verified',
  'x-nvidia-gpu-driver-rim-measurements-available',
  'x-nvidia-gpu-vbios-rim-fetched',
  'x-nvidia-gpu-vbios-rim-schema-validated',
  'x-nvidia-gpu-vbios-rim-cert-validated',
  'x-nvidia-gpu-vbios-rim-signature-verified',
  'x-nvidia-gpu-vbios-rim-measurements-available',
  'x-nvidia-gpu-vbios-index-no-conflict',
  'secboot',
];

const LABEL = {
  sig: 'NVIDIA attestation tokens signed (ES384, NRAS keys)',
  fresh: 'NVIDIA tokens carry our nonce and are not expired',
  verdict: 'GPU verdict (NVIDIA NRAS)',
};

const parseMaybe = (v) => (typeof v === 'string' ? JSON.parse(v) : v);
const norm = (h) => String(h || '').trim().toLowerCase().replace(/^0x/, '');
const part = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));

let jwksCache = null;

/** NRAS's signing keys. force skips the cache (NRAS adds keys often; a new kid means a fresh fetch). */
async function getJwks(deps = {}, force = false) {
  const cache = deps.cache || null;
  const hit = cache ? cache.get(JWKS_URL) : jwksCache;
  if (!force && hit && Date.now() - hit.at < CACHE_MS) return hit.promise;
  const fetchImpl = deps.fetch || globalThis.fetch;
  const promise = (async () => {
    const res = await fetchImpl(JWKS_URL, { headers: { accept: 'application/json', 'user-agent': `oberig/${VERSION}` }, signal: AbortSignal.timeout(20000) });
    if (!res.ok) throw new Error(`NRAS JWKS returned ${res.status}`);
    const j = await res.json();
    if (!j || !Array.isArray(j.keys)) throw new Error('NRAS JWKS has no keys');
    return j.keys;
  })();
  const entry = { at: Date.now(), promise };
  if (cache) cache.set(JWKS_URL, entry); else jwksCache = entry;
  promise.catch(() => { if (cache) cache.delete(JWKS_URL); else if (jwksCache === entry) jwksCache = null; });
  return promise;
}

function publicKey(jwk) {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-384') throw new Error(`key ${jwk.kid} is not an EC P-384 key`);
  if (jwk.x && jwk.y) return crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-384', x: jwk.x, y: jwk.y }, format: 'jwk' });
  if (Array.isArray(jwk.x5c) && jwk.x5c[0]) return new crypto.X509Certificate(Buffer.from(jwk.x5c[0], 'base64')).publicKey;
  throw new Error(`key ${jwk.kid} has no public key`);
}

/** Verifies one ES384 JWT against JWKS keys. Returns {ok, header, claims, error}. */
function verifyJwt(token, keys) {
  const p = String(token || '').split('.');
  if (p.length !== 3) return { ok: false, error: 'not a JWT' };
  let header, claims;
  try { header = part(p[0]); claims = part(p[1]); } catch { return { ok: false, error: 'token is not readable' }; }
  if (header.alg !== 'ES384') return { ok: false, header, claims, error: `token algorithm is ${header.alg}, not ES384` };
  const jwk = (keys || []).find((k) => k && k.kid === header.kid);
  if (!jwk) return { ok: false, header, claims, error: 'signing key is not in the NRAS JWKS' };
  try {
    const sig = Buffer.from(p[2], 'base64url');
    const ok = sig.length === 96 && crypto.verify('sha384', Buffer.from(`${p[0]}.${p[1]}`, 'ascii'), { key: publicKey(jwk), dsaEncoding: 'ieee-p1363' }, sig);
    return { ok, header, claims, error: ok ? '' : 'token signature does not verify' };
  } catch (err) {
    return { ok: false, header, claims, error: err.message };
  }
}

function failed(msg) {
  const checks = [['gpu-tokens', LABEL.sig], ['gpu-fresh', LABEL.fresh], ['gpu-verdict', LABEL.verdict]].map(([id, label]) => ({ id, label, status: 'fail', detail: msg }));
  return { checks, gpus: 0, passed: 0 };
}

/**
 * Checks an NRAS v3 answer ([["JWT", overall], {"GPU-0": token, ...}]) for the
 * evidence `payload` sent with `nonce`. Pure. Returns {checks, gpus, passed}.
 */
function checkNrasResult(result, payload, nonce, keys, nowMs = Date.now()) {
  const checks = [];
  const add = (id, label, status, detail = '') => checks.push({ id, label, status, detail });
  const overall = Array.isArray(result) && Array.isArray(result[0]) && result[0][0] === 'JWT' ? result[0][1] : null;
  const gpuMap = Array.isArray(result) && result[1] && typeof result[1] === 'object' && !Array.isArray(result[1]) ? result[1] : null;
  if (!overall || !gpuMap) return failed('NRAS answer is not in the expected form');
  const tokens = [['overall', overall], ...Object.entries(gpuMap)];
  const v = tokens.map(([name, t]) => ({ name, token: t, ...verifyJwt(t, keys) }));

  const badSig = v.find((x) => !x.ok);
  const badIss = v.find((x) => x.ok && x.claims.iss !== ISSUER);
  if (badSig) add('gpu-tokens', LABEL.sig, 'fail', `${badSig.name}: ${badSig.error}`);
  else if (badIss) add('gpu-tokens', LABEL.sig, 'fail', `${badIss.name}: issuer is ${badIss.claims.iss}`);
  else add('gpu-tokens', LABEL.sig, 'ok', `1 overall + ${v.length - 1} GPU tokens`);

  const now = Math.floor(nowMs / 1000);
  const stale = v.find((x) => !x.claims || norm(x.claims.eat_nonce) !== norm(nonce));
  const expired = v.find((x) => x.claims && !(typeof x.claims.exp === 'number' && now < x.claims.exp + SKEW_S && (typeof x.claims.nbf !== 'number' || now >= x.claims.nbf - SKEW_S)));
  if (badSig || badIss) add('gpu-fresh', LABEL.fresh, 'fail', 'tokens not verified');
  else if (stale) add('gpu-fresh', LABEL.fresh, 'fail', `${stale.name}: nonce does not match`);
  else if (expired) add('gpu-fresh', LABEL.fresh, 'fail', `${expired.name}: outside its validity window`);
  else add('gpu-fresh', LABEL.fresh, 'ok', `expires ${new Date(v[0].claims.exp * 1000).toISOString().slice(0, 16).replace('T', ' ')} UTC`);

  const claims = v[0].claims || {};
  const sent = Array.isArray(payload && payload.evidence_list) ? payload.evidence_list.length : 0;
  const gpus = v.slice(1);
  const submods = claims.submods && typeof claims.submods === 'object' ? claims.submods : {};
  const digest = (t) => crypto.createHash('sha256').update(String(t), 'utf8').digest('hex');
  const failures = [];
  let passed = 0;
  for (const g of gpus) {
    const c = g.claims || {};
    const d = submods[g.name];
    const why = [];
    if (!Array.isArray(d) || d[0] !== 'DIGEST' || !Array.isArray(d[1]) || norm(d[1][1]) !== digest(g.token)) why.push('not bound to the overall token');
    for (const k of GPU_TRUE) if (c[k] !== true) why.push(k);
    if (c.measres !== 'success') why.push('measres');
    if (c.dbgstat !== 'disabled') why.push('dbgstat');
    if (why.length) failures.push(`${g.name}: ${why.slice(0, 3).join(', ')}`);
    else passed++;
  }
  const missing = Object.keys(submods).filter((k) => !(k in gpuMap));
  let verdict = null;
  if (claims['x-nvidia-overall-att-result'] !== true) verdict = 'overall result is not true';
  else if (!gpus.length) verdict = 'no GPU tokens';
  else if (gpus.length !== sent) verdict = `${gpus.length} GPU tokens for ${sent} evidence entries`;
  else if (missing.length) verdict = `no token for ${missing.join(', ')}`;
  else if (failures.length) verdict = failures[0];
  const unverified = badSig || badIss;
  add('gpu-verdict', LABEL.verdict, (unverified || verdict) ? 'fail' : 'ok', unverified ? 'tokens not verified' : verdict || `overall result true · ${passed}/${gpus.length} GPUs pass`);
  return { checks, gpus: gpus.length, passed };
}

/** Posts the evidence of one model attestation to NRAS and checks the answer. Never throws. */
async function nrasAttest(rep, nonce, opts = {}, deps = {}) {
  const fetchImpl = deps.fetch || globalThis.fetch;
  try {
    const payload = parseMaybe(rep.nvidia_payload);
    if (!payload || !Array.isArray(payload.evidence_list)) throw new Error('no GPU evidence in the report');
    const [res, keys] = await Promise.all([
      fetchImpl(NRAS_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': `oberig/${VERSION}` },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(30000),
      }),
      getJwks(deps),
    ]);
    if (!res.ok) throw new Error(`NRAS returned ${res.status}`);
    const result = await res.json();
    let jwks = keys;
    const kids = [];
    try {
      for (const t of [result[0][1], ...Object.values(result[1] || {})]) kids.push(JSON.parse(Buffer.from(String(t).split('.')[0], 'base64url').toString('utf8')).kid);
    } catch { /* checkNrasResult reports the malformed answer */ }
    if (kids.some((kid) => !jwks.some((k) => k && k.kid === kid))) jwks = await getJwks(deps, true);
    return checkNrasResult(result, payload, nonce, jwks, (opts.now || new Date()).getTime());
  } catch (err) {
    return failed(err.message);
  }
}

function clearCache() { jwksCache = null; }

module.exports = { NRAS_URL, JWKS_URL, GPU_TRUE, LABEL, verifyJwt, checkNrasResult, nrasAttest, getJwks, clearCache };
