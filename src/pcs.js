'use strict';
// Intel PCS collateral for OBERIG_VERIFY=full. For a TDX quote whose PCK chain
// already verified (quote.js), Oberig fetches four documents from Intel and
// checks them here with node:crypto:
//
//   TDX TCB Info for the FMSPC in the PCK certificate, and the TDX QE Identity:
//     issuer chain from the response header to the pinned Intel SGX Root CA,
//     ECDSA P-256 signature over the exact tcbInfo / enclaveIdentity JSON bytes,
//     issueDate <= now <= nextUpdate.
//   PCK CRL (platform or processor CA) and Intel SGX Root CA CRL: signed by the
//     CA that issued the PCK certificate / by the pinned root, within
//     thisUpdate..nextUpdate, and neither the PCK certificate, its CA nor the
//     TCB signing certificate is listed.
//   QE report against the QE Identity: MRSIGNER, ISVPRODID, MISCSELECT and
//     ATTRIBUTES under their masks, then ISVSVN to a TCB level.
//   TCB status, following Intel's steps for TDX (PCS API v4, Get TDX TCB Info):
//     the PCK SGX TCB components and PCESVN, then the quote's TEE TCB SVN
//     (from index 2 when TEE TCB SVN[1] > 0), then the TDX module identity
//     TDX_<TEE TCB SVN[1]>; the module and QE statuses are merged with the
//     platform status the way Intel's quote verification library does.
//
// Responses are kept in memory for 30 minutes. Every check runs on every use.

const crypto = require('node:crypto');
const D = require('./der.js');
const { splitPem, INTEL_ROOT_SHA256 } = require('./quote.js');
const { VERSION } = require('./config.js');

const PCS = 'https://api.trustedservices.intel.com';
const URLS = {
  tcb: (fmspc) => `${PCS}/tdx/certification/v4/tcb?fmspc=${fmspc}`,
  qe: () => `${PCS}/tdx/certification/v4/qe/identity`,
  pckCrl: (ca) => `${PCS}/sgx/certification/v4/pckcrl?ca=${ca}&encoding=der`,
  rootCrl: () => 'https://certificates.trustedservices.intel.com/IntelSGXRootCA.der',
};
const CACHE_MS = 30 * 60 * 1000;
const ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const STATUSES = ['UpToDate', 'SWHardeningNeeded', 'ConfigurationNeeded', 'ConfigurationAndSWHardeningNeeded', 'OutOfDate', 'OutOfDateConfigurationNeeded', 'Revoked'];

const LABEL = {
  tcbInfo: 'Intel TCB info signed by Intel and current',
  qeIdentity: 'Intel QE identity signed by Intel and current',
  crl: 'certificates not revoked (Intel PCK and Root CA CRLs)',
  qe: 'quoting enclave matches Intel QE identity',
  module: 'TDX module matches Intel TCB info',
  tcb: 'Intel TCB status',
};

const hex = (s) => Buffer.from(String(s || ''), 'hex');
const day = (t) => new Date(t).toISOString().slice(0, 10);
const cn = (cert, name) => cert.subject.split('\n').includes(`CN=${name}`);

const shared = new Map();

/** GET with a short in-memory cache by URL. Resolves to {body: Buffer, header(name)}. */
function fetchCached(url, deps = {}) {
  const cache = deps.cache || shared;
  const hit = cache.get(url);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.promise;
  const fetchImpl = deps.fetch || globalThis.fetch;
  const promise = (async () => {
    const res = await fetchImpl(url, { headers: { 'user-agent': `oberig/${VERSION}` }, signal: AbortSignal.timeout(20000) });
    if (!res.ok) throw new Error(`${new URL(url).host} returned ${res.status}`);
    const body = Buffer.from(await res.arrayBuffer());
    const headers = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { body, header: (name) => headers[name.toLowerCase()] || null };
  })();
  cache.set(url, { at: Date.now(), promise });
  promise.catch(() => { if (cache.get(url) && cache.get(url).promise === promise) cache.delete(url); });
  return promise;
}

function clearCache() { shared.clear(); }

// ---- signed JSON ----

function readString(text, i) {
  for (let j = i + 1; j < text.length; j++) {
    if (text[j] === '\\') j++;
    else if (text[j] === '"') return [text.slice(i + 1, j), j + 1];
  }
  throw new Error('unterminated JSON string');
}

function skipValue(text, i) {
  if (text[i] === '"') return readString(text, i)[1];
  if (text[i] === '{' || text[i] === '[') {
    let depth = 0;
    for (let j = i; j < text.length; j++) {
      const c = text[j];
      if (c === '"') j = readString(text, j)[1] - 1;
      else if (c === '{' || c === '[') depth++;
      else if (c === '}' || c === ']') { if (--depth === 0) return j + 1; }
    }
    throw new Error('unterminated JSON value');
  }
  const m = /^[^,}\]\s]+/.exec(text.slice(i));
  if (!m) throw new Error('bad JSON value');
  return i + m[0].length;
}

/** The exact text of the top-level `key` value in a JSON object, as it appears. */
function rawJsonValue(text, key) {
  const ws = (i) => { while (/\s/.test(text[i] || '')) i++; return i; };
  let i = ws(0);
  if (text[i] !== '{') throw new Error('not a JSON object');
  i = ws(i + 1);
  while (text[i] === '"') {
    const [k, next] = readString(text, i);
    i = ws(next);
    if (text[i] !== ':') throw new Error('bad JSON object');
    const start = ws(i + 1);
    i = skipValue(text, start);
    if (k === key) return text.slice(start, i);
    i = ws(i);
    if (text[i] === ',') i = ws(i + 1);
  }
  throw new Error(`"${key}" missing`);
}

function inWindow(from, to, nowMs, what) {
  const a = Date.parse(from);
  const b = Date.parse(to);
  if (!Number.isFinite(a) || !Number.isFinite(b)) throw new Error(`${what}: issueDate or nextUpdate missing`);
  if (nowMs < a) throw new Error(`${what}: not valid yet (issued ${from})`);
  if (nowMs > b) throw new Error(`${what}: expired (next update was due ${to})`);
}

/** Checks an Intel issuer chain header (URL-encoded PEM: signing certificate, then root). */
function verifyChain(value, what, o) {
  if (!value) throw new Error(`${what}: issuer chain header missing`);
  let pems;
  try { pems = splitPem(decodeURIComponent(value)); } catch { throw new Error(`${what}: issuer chain header is not URL-encoded PEM`); }
  if (pems.length !== 2) throw new Error(`${what}: issuer chain should hold 2 certificates, got ${pems.length}`);
  const [signer, root] = pems.map((p) => new crypto.X509Certificate(p));
  const pin = (o.rootFingerprint || INTEL_ROOT_SHA256).toUpperCase();
  if (root.fingerprint256.toUpperCase() !== pin) throw new Error(`${what}: issuer chain does not end at the pinned Intel SGX Root CA`);
  if (!root.verify(root.publicKey) || !signer.verify(root.publicKey) || !signer.checkIssued(root)) throw new Error(`${what}: issuer chain signatures do not verify`);
  if (![signer, root].every((c) => o.nowMs >= Date.parse(c.validFrom) && o.nowMs <= Date.parse(c.validTo))) throw new Error(`${what}: an issuer certificate is expired or not yet valid`);
  return { signer, root };
}

/**
 * Verifies an Intel signed JSON response ({"tcbInfo": {...}, "signature": "<hex>"}):
 * issuer chain to the pinned root, signer is the Intel SGX TCB Signing certificate,
 * ECDSA P-256 / SHA-256 signature over the exact bytes of the `field` value.
 */
function verifySignedJson(resp, field, chainHeader, what, o) {
  const { signer } = verifyChain(resp.header(chainHeader), what, o);
  if (!cn(signer, 'Intel SGX TCB Signing')) throw new Error(`${what}: not signed by the Intel SGX TCB Signing certificate`);
  const text = resp.body.toString('latin1');
  let raw, sigHex;
  try {
    raw = Buffer.from(rawJsonValue(text, field), 'latin1');
    sigHex = JSON.parse(resp.body.toString('utf8')).signature;
  } catch (err) {
    throw new Error(`${what}: ${err.message}`);
  }
  if (!/^[0-9a-fA-F]{128}$/.test(sigHex || '')) throw new Error(`${what}: signature missing or malformed`);
  const ok = crypto.verify('sha256', raw, { key: signer.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(sigHex, 'hex'));
  if (!ok) throw new Error(`${what}: signature does not verify`);
  return { data: JSON.parse(raw.toString('utf8')), signer };
}

// ---- CRLs ----

function crlDer(body) {
  const pem = /-----BEGIN X509 CRL-----([\s\S]+?)-----END X509 CRL-----/.exec(body.toString('latin1'));
  return pem ? Buffer.from(pem[1].replace(/\s+/g, ''), 'base64') : body;
}

/** Parses a CRL and checks its issuer, signature and validity window. */
function verifyCrl(der, issuer, nowMs, what) {
  let crl;
  try { crl = D.parseCrl(crlDer(der)); } catch (err) { throw new Error(`${what}: ${err.message}`); }
  if (crl.algorithm !== ECDSA_SHA256) throw new Error(`${what}: unexpected signature algorithm`);
  if (!crl.issuer.equals(D.certFields(issuer.raw).subject)) throw new Error(`${what}: issued by another CA`);
  if (!crypto.verify('sha256', crl.tbs, issuer.publicKey, crl.signature)) throw new Error(`${what}: signature does not verify`);
  if (nowMs < crl.thisUpdate) throw new Error(`${what}: not valid yet`);
  if (crl.nextUpdate == null || nowMs > crl.nextUpdate) throw new Error(`${what}: expired (next update was due ${crl.nextUpdate ? new Date(crl.nextUpdate).toISOString() : 'not set'})`);
  return crl;
}

const sameKey = (a, b) => a.publicKey.export({ type: 'spki', format: 'der' }).equals(b.publicKey.export({ type: 'spki', format: 'der' }));

// ---- matching ----

const byIsvsvnDesc = (levels) => [...(levels || [])].sort((a, b) => (b.tcb && b.tcb.isvsvn) - (a.tcb && a.tcb.isvsvn));

function masked(value, mask, want) {
  return value.length === mask.length && want.length === mask.length && value.every((b, i) => (b & mask[i]) === want[i]);
}

/** QE report (384 bytes) against an enclaveIdentity. Returns {ok, isvsvn, status, advisories, error}. */
function matchQeIdentity(report, id) {
  const r = {
    miscselect: report.readUInt32LE(16), attributes: report.subarray(48, 64), mrsigner: report.subarray(128, 160),
    isvprodid: report.readUInt16LE(256), isvsvn: report.readUInt16LE(258),
  };
  if (id.id !== 'TD_QE') return { ok: false, error: `QE identity is ${id.id}, not TD_QE` };
  if (!r.mrsigner.equals(hex(id.mrsigner))) return { ok: false, error: 'QE MRSIGNER is not the one Intel lists' };
  if (r.isvprodid !== id.isvprodid) return { ok: false, error: `QE ISVPRODID ${r.isvprodid}, Intel lists ${id.isvprodid}` };
  const misc = Number.parseInt(id.miscselect, 16);
  const miscMask = Number.parseInt(id.miscselectMask, 16);
  if (!Number.isFinite(misc) || !Number.isFinite(miscMask) || ((r.miscselect & miscMask) >>> 0) !== misc >>> 0) return { ok: false, error: 'QE MISCSELECT does not match' };
  if (!masked(r.attributes, hex(id.attributesMask), hex(id.attributes))) return { ok: false, error: 'QE ATTRIBUTES do not match' };
  const level = byIsvsvnDesc(id.tcbLevels).find((l) => r.isvsvn >= l.tcb.isvsvn);
  if (!level) return { ok: false, isvsvn: r.isvsvn, error: `QE ISVSVN ${r.isvsvn} is below every Intel TCB level` };
  return { ok: true, isvsvn: r.isvsvn, status: level.tcbStatus, advisories: level.advisoryIDs || [] };
}

/** The TDX module (MRSIGNERSEAM, SEAMATTRIBUTES, module SVN) against the TCB info. */
function matchTdxModule(tcbInfo, q) {
  const svn = q.teeTcbSvn;
  const version = svn[1];
  let ident;
  let id;
  if (version === 0) {
    ident = tcbInfo.tdxModule;
    id = 'tdxModule';
    if (!ident) return { ok: false, error: 'TCB info has no tdxModule' };
  } else {
    id = `TDX_${version.toString(16).padStart(2, '0').toUpperCase()}`;
    ident = (tcbInfo.tdxModuleIdentities || []).find((x) => String(x.id).toUpperCase() === id);
    if (!ident) return { ok: false, error: `no TDX module identity ${id} in Intel's TCB info` };
  }
  if (!q.mrSignerSeam.equals(hex(ident.mrsigner))) return { ok: false, error: `MRSIGNERSEAM is not the ${id} signer` };
  if (!masked(q.seamAttributes, hex(ident.attributesMask), hex(ident.attributes))) return { ok: false, error: `SEAM attributes do not match ${id}` };
  if (version === 0) return { ok: true, id, status: null, advisories: [] };
  const level = byIsvsvnDesc(ident.tcbLevels).find((l) => svn[0] >= l.tcb.isvsvn);
  if (!level) return { ok: false, error: `TDX module SVN ${svn[0]} is below every ${id} TCB level` };
  return { ok: true, id, svn: svn[0], status: level.tcbStatus, advisories: level.advisoryIDs || [] };
}

/** First TCB level (Intel's order) the platform meets: PCK SGX components, PCESVN, TEE TCB SVN. */
function matchTcbLevel(tcbInfo, pck, teeTcbSvn) {
  const from = teeTcbSvn[1] > 0 ? 2 : 0;
  for (const level of tcbInfo.tcbLevels || []) {
    const t = level.tcb || {};
    const sgx = (t.sgxtcbcomponents || []).map((c) => c.svn);
    const tdx = (t.tdxtcbcomponents || []).map((c) => c.svn);
    if (sgx.length !== 16 || tdx.length !== 16) continue;
    if (!pck.comps.every((v, i) => v >= sgx[i])) continue;
    if (!(pck.pcesvn >= t.pcesvn)) continue;
    let ok = true;
    for (let i = from; i < 16; i++) if (teeTcbSvn[i] < tdx[i]) { ok = false; break; }
    if (ok) return level;
  }
  return null;
}

/** Merges a QE or TDX module status (UpToDate, OutOfDate, Revoked) into the platform status. */
function converge(platform, other) {
  if (!other || other === 'UpToDate') return platform;
  if (other === 'Revoked') return 'Revoked';
  if (other !== 'OutOfDate') return other;
  if (platform === 'UpToDate' || platform === 'SWHardeningNeeded') return 'OutOfDate';
  if (platform === 'ConfigurationNeeded' || platform === 'ConfigurationAndSWHardeningNeeded') return 'OutOfDateConfigurationNeeded';
  return platform;
}

/** ok for UpToDate; Revoked and unknown statuses fail; the rest warn, or fail with requireTcb 'uptodate'. */
function tcbPolicy(status, requireTcb) {
  if (status === 'UpToDate') return 'ok';
  if (status === 'Revoked' || !STATUSES.includes(status)) return 'fail';
  return requireTcb === 'uptodate' ? 'fail' : 'warn';
}

function tcbDetail(status, policy, advisories, date) {
  const adv = advisories.length ? ` · ${advisories.join(', ')}` : '';
  if (policy === 'ok') return `TCB level of ${day(date)}`;
  if (status === 'Revoked') return `revoked by Intel${adv}`;
  if (policy === 'warn') return `warning only, still sent (OBERIG_REQUIRE_TCB=uptodate refuses)${adv}`;
  return `refused by OBERIG_REQUIRE_TCB=uptodate${adv}`;
}

/** The collateral rows, all failed with one reason (for a quote that cannot be checked). */
function failedCollateral(msg) {
  const rows = [['pcs-tcbinfo', LABEL.tcbInfo], ['pcs-qeidentity', LABEL.qeIdentity], ['pck-revocation', LABEL.crl], ['qe-identity', LABEL.qe], ['tdx-module', LABEL.module], ['tcb', `${LABEL.tcb}: not determined`]];
  return { checks: rows.map(([id, label]) => ({ id, label, status: 'fail', detail: msg })), tcbStatus: null, advisories: [], fmspc: null };
}

/**
 * Full Intel collateral check for one parsed quote. `pems` is the quote's verified
 * PCK chain [leaf, CA, root]. opts: {now, rootFingerprint, requireTcb}.
 * deps: {fetch, cache}. Never throws. Returns {checks, tcbStatus, advisories, fmspc}.
 */
async function checkCollateral(q, pems, opts = {}, deps = {}) {
  const nowMs = (opts.now || new Date()).getTime();
  const o = { nowMs, rootFingerprint: opts.rootFingerprint };
  const checks = [];
  const add = (id, label, status, detail = '') => checks.push({ id, label, status, detail });
  const out = { checks, tcbStatus: null, advisories: [], fmspc: null };

  let leaf, inter, root, pck, ca;
  try {
    [leaf, inter, root] = pems.map((p) => new crypto.X509Certificate(p));
    pck = D.sgxExtension(leaf.raw);
    ca = cn(inter, 'Intel SGX PCK Platform CA') ? 'platform' : cn(inter, 'Intel SGX PCK Processor CA') ? 'processor' : null;
    if (!ca) throw new Error('PCK certificate is not issued by an Intel SGX PCK Platform or Processor CA');
  } catch (err) {
    return failedCollateral(err.message);
  }
  out.fmspc = pck.fmspc;

  const get = (url) => fetchCached(url, deps);
  const settled = await Promise.allSettled([get(URLS.tcb(pck.fmspc)), get(URLS.qe()), get(URLS.pckCrl(ca)), get(URLS.rootCrl())]);
  const val = (i, what) => {
    if (settled[i].status === 'rejected') throw new Error(`could not fetch the ${what} (${settled[i].reason.message})`);
    return settled[i].value;
  };

  let tcbInfo = null, tcbSigner = null;
  try {
    const v = verifySignedJson(val(0, 'TCB info'), 'tcbInfo', 'TCB-Info-Issuer-Chain', 'TCB info', o);
    const t = v.data;
    if (t.id !== 'TDX' || t.version !== 3) throw new Error(`TCB info is ${t.id} version ${t.version}, expected TDX version 3`);
    if (String(t.fmspc).toLowerCase() !== pck.fmspc) throw new Error(`TCB info is for FMSPC ${t.fmspc}, the PCK certificate says ${pck.fmspc}`);
    if (String(t.pceId).toLowerCase() !== pck.pceId) throw new Error(`TCB info PCE ID ${t.pceId} does not match ${pck.pceId}`);
    inWindow(t.issueDate, t.nextUpdate, nowMs, 'TCB info');
    tcbInfo = t;
    tcbSigner = v.signer;
    add('pcs-tcbinfo', LABEL.tcbInfo, 'ok', `FMSPC ${pck.fmspc} · next update ${day(t.nextUpdate)}`);
  } catch (err) {
    add('pcs-tcbinfo', LABEL.tcbInfo, 'fail', err.message);
  }

  let qeId = null, qeSigner = null;
  try {
    const v = verifySignedJson(val(1, 'QE identity'), 'enclaveIdentity', 'SGX-Enclave-Identity-Issuer-Chain', 'QE identity', o);
    const e = v.data;
    if (e.id !== 'TD_QE' || e.version !== 2) throw new Error(`QE identity is ${e.id} version ${e.version}, expected TD_QE version 2`);
    inWindow(e.issueDate, e.nextUpdate, nowMs, 'QE identity');
    qeId = e;
    qeSigner = v.signer;
    add('pcs-qeidentity', LABEL.qeIdentity, 'ok', `TD_QE · next update ${day(e.nextUpdate)}`);
  } catch (err) {
    add('pcs-qeidentity', LABEL.qeIdentity, 'fail', err.message);
  }

  try {
    const pckResp = val(2, 'PCK CRL');
    const { signer: crlCa } = verifyChain(pckResp.header('SGX-PCK-CRL-Issuer-Chain'), 'PCK CRL', o);
    if (!sameKey(crlCa, inter)) throw new Error('PCK CRL issuer chain is not for the CA that issued this PCK certificate');
    const pckCrl = verifyCrl(pckResp.body, inter, nowMs, 'PCK CRL');
    const rootCrl = verifyCrl(val(3, 'Root CA CRL').body, root, nowMs, 'Root CA CRL');
    const listed = [[pckCrl, leaf, 'PCK certificate'], [rootCrl, inter, 'PCK CA certificate']];
    for (const s of [tcbSigner, qeSigner]) if (s) listed.push([rootCrl, s, 'TCB signing certificate']);
    for (const [crl, cert, what] of listed) {
      const serial = D.certFields(cert.raw).serial;
      if (crl.revoked.has(serial)) throw new Error(`${what} is revoked (serial ${serial})`);
    }
    add('pck-revocation', LABEL.crl, 'ok', `${ca} CA CRL lists ${pckCrl.revoked.size}, not this PCK · root CRL lists ${rootCrl.revoked.size} · next update ${day(pckCrl.nextUpdate)}`);
  } catch (err) {
    add('pck-revocation', LABEL.crl, 'fail', err.message);
  }

  let qe = null;
  if (qeId) {
    qe = matchQeIdentity(q.qeReport, qeId);
    add('qe-identity', LABEL.qe, qe.ok ? 'ok' : 'fail', qe.ok ? `TD_QE ISVSVN ${qe.isvsvn}: ${qe.status}` : qe.error);
  } else add('qe-identity', LABEL.qe, 'fail', 'no verified QE identity');

  let mod = null, level = null;
  if (tcbInfo) {
    mod = matchTdxModule(tcbInfo, q);
    add('tdx-module', LABEL.module, mod.ok ? 'ok' : 'fail', mod.ok ? (mod.status ? `${mod.id} SVN ${mod.svn}: ${mod.status}` : mod.id) : mod.error);
    level = matchTcbLevel(tcbInfo, pck, q.teeTcbSvn);
  } else add('tdx-module', LABEL.module, 'fail', 'no verified TCB info');

  if (!tcbInfo || !qeId) add('tcb', `${LABEL.tcb}: not determined`, 'fail', 'needs verified TCB info and QE identity');
  else if (!level) add('tcb', `${LABEL.tcb}: not supported`, 'fail', 'no Intel TCB level matches this platform');
  else if (!mod.ok || !qe.ok) add('tcb', `${LABEL.tcb}: not determined`, 'fail', 'the TDX module or quoting enclave does not match Intel');
  else {
    const status = converge(converge(level.tcbStatus, mod.status), qe.status);
    const advisories = [...new Set([...(level.advisoryIDs || []), ...mod.advisories, ...qe.advisories])];
    const policy = tcbPolicy(status, opts.requireTcb);
    out.tcbStatus = status;
    out.advisories = advisories;
    add('tcb', `${LABEL.tcb}: ${status}`, policy, tcbDetail(status, policy, advisories, level.tcbDate));
  }
  return out;
}

module.exports = {
  URLS, STATUSES, LABEL, fetchCached, clearCache, rawJsonValue, verifyChain, verifySignedJson, verifyCrl,
  matchQeIdentity, matchTdxModule, matchTcbLevel, converge, tcbPolicy, checkCollateral, failedCollateral,
};
