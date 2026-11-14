'use strict';
// Intel TDX quote (v4) parsing and the local signature chain check:
//   attestation key signs the quote header and TD report,
//   the QE report binds that attestation key,
//   the PCK leaf certificate signs the QE report,
//   and the PCK chain ends at the pinned Intel SGX Root CA.
// Pure node:crypto. What this does NOT do: TCB status, QE identity and CRLs
// (those need Intel PCS collateral, see pcs.js and OBERIG_VERIFY=full).

const crypto = require('node:crypto');

// SHA-256 fingerprint of "Intel SGX Root CA" (Intel_SGX_Provisioning_Certification_RootCA.cer).
const INTEL_ROOT_SHA256 =
  '44:A0:19:6B:2B:99:F8:89:B8:E1:49:E9:5B:80:7A:35:0E:74:24:96:43:99:E8:85:A7:CB:B8:CC:FA:B6:74:D3';

const HEADER = 48;
const BODY = 584;
const SIGNED_LEN = HEADER + BODY; // 632

function hexBuf(v) {
  return Buffer.from(String(v || '').trim().replace(/^0x/i, ''), 'hex');
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function p256Key(xy) {
  return crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: b64url(xy.subarray(0, 32)), y: b64url(xy.subarray(32, 64)) },
    format: 'jwk',
  });
}

/** Parses the fields Oberig needs from a TDX quote (hex string or Buffer). Throws on bad input. */
function parseQuote(input) {
  const q = Buffer.isBuffer(input) ? input : hexBuf(input);
  if (q.length < SIGNED_LEN + 4) throw new Error('quote too short');
  const version = q.readUInt16LE(0);
  const attKeyType = q.readUInt16LE(2);
  const teeType = q.readUInt32LE(4);
  if (version !== 4) throw new Error('unsupported quote version ' + version);
  const b = q.subarray(HEADER, SIGNED_LEN);
  const out = {
    raw: q,
    version,
    attKeyType,
    teeType,
    teeTcbSvn: b.subarray(0, 16),
    mrSignerSeam: b.subarray(64, 112),
    seamAttributes: b.subarray(112, 120),
    tdAttributes: b.subarray(120, 128),
    mrTd: b.subarray(136, 184),
    mrConfigId: b.subarray(184, 232),
    rtmr: [b.subarray(328, 376), b.subarray(376, 424), b.subarray(424, 472), b.subarray(472, 520)],
    reportData: b.subarray(520, 584),
    debug: (b[120] & 1) === 1,
  };
  const sigLen = q.readUInt32LE(SIGNED_LEN);
  const s = SIGNED_LEN + 4;
  if (q.length < s + sigLen || sigLen < 64 + 64 + 6) {
    out.sigError = 'signature data truncated';
    return out;
  }
  out.quoteSignature = q.subarray(s, s + 64);
  out.attestationKey = q.subarray(s + 64, s + 128);
  let p = s + 128;
  const certType = q.readUInt16LE(p);
  const certSize = q.readUInt32LE(p + 2);
  p += 6;
  if (certType !== 6) {
    out.sigError = 'unexpected certification data type ' + certType;
    return out;
  }
  const cd = q.subarray(p, p + certSize);
  out.qeReport = cd.subarray(0, 384);
  out.qeReportSignature = cd.subarray(384, 448);
  const authLen = cd.readUInt16LE(448);
  out.qeAuthData = cd.subarray(450, 450 + authLen);
  let c = 450 + authLen;
  const innerType = cd.readUInt16LE(c);
  const innerSize = cd.readUInt32LE(c + 2);
  c += 6;
  if (innerType !== 5) {
    out.sigError = 'unexpected QE certification data type ' + innerType;
    return out;
  }
  out.pckChainPem = cd.subarray(c, c + innerSize).toString('utf8');
  return out;
}

function splitPem(pem) {
  return (pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []);
}

/**
 * Checks the quote's signature chain up to the pinned Intel root.
 * Returns {ok, steps: [{name, ok, detail}], error}.
 * opts.now (Date) and opts.rootFingerprint exist for tests only.
 */
function verifyQuoteChain(quote, opts = {}) {
  const steps = [];
  const step = (name, ok, detail) => { steps.push({ name, ok: !!ok, detail: detail || '' }); return !!ok; };
  try {
    const q = quote.raw ? quote : parseQuote(quote);
    if (q.sigError) return { ok: false, steps, error: q.sigError };
    if (q.attKeyType !== 2) return { ok: false, steps, error: 'attestation key type is not ECDSA P-256' };

    // 1. Attestation key signs header + TD report body.
    const attKey = p256Key(q.attestationKey);
    const sigOk = crypto.verify('sha256', q.raw.subarray(0, SIGNED_LEN), { key: attKey, dsaEncoding: 'ieee-p1363' }, q.quoteSignature);
    if (!step('quote signed by attestation key', sigOk)) return { ok: false, steps, error: 'quote signature does not verify' };

    // 2. QE report data binds the attestation key and QE auth data.
    const want = crypto.createHash('sha256').update(q.attestationKey).update(q.qeAuthData).digest();
    const qeRd = q.qeReport.subarray(320, 384);
    const bindOk = qeRd.subarray(0, 32).equals(want) && qeRd.subarray(32).equals(Buffer.alloc(32));
    if (!step('QE report binds attestation key', bindOk)) return { ok: false, steps, error: 'QE report does not bind the attestation key' };

    // 3. PCK chain: leaf -> platform/processor CA -> pinned root.
    const pems = splitPem(q.pckChainPem);
    if (pems.length < 3) return { ok: false, steps, error: 'PCK certificate chain incomplete' };
    const [leaf, inter, root] = pems.slice(0, 3).map((p) => new crypto.X509Certificate(p));
    const pin = (opts.rootFingerprint || INTEL_ROOT_SHA256).toUpperCase();
    if (!step('chain ends at pinned Intel SGX Root CA', root.fingerprint256.toUpperCase() === pin, root.subject.split('\n').join(', ')))
      return { ok: false, steps, error: 'root certificate is not the pinned Intel root' };
    const chainOk = root.verify(root.publicKey) && inter.verify(root.publicKey) && leaf.verify(inter.publicKey)
      && inter.checkIssued(root) && leaf.checkIssued(inter);
    if (!step('PCK chain signatures', chainOk)) return { ok: false, steps, error: 'PCK chain signatures do not verify' };
    const now = (opts.now || new Date()).getTime();
    const inDate = [leaf, inter, root].every((c) => now >= Date.parse(c.validFrom) && now <= Date.parse(c.validTo));
    if (!step('certificates within validity dates', inDate)) return { ok: false, steps, error: 'a certificate in the PCK chain is expired or not yet valid' };

    // 4. PCK leaf signs the QE report.
    const qeOk = crypto.verify('sha256', q.qeReport, { key: leaf.publicKey, dsaEncoding: 'ieee-p1363' }, q.qeReportSignature);
    if (!step('QE report signed by PCK leaf', qeOk)) return { ok: false, steps, error: 'QE report signature does not verify' };

    return { ok: true, steps, pems: pems.slice(0, 3) };
  } catch (err) {
    return { ok: false, steps, error: 'quote chain check failed: ' + err.message };
  }
}

module.exports = { parseQuote, verifyQuoteChain, splitPem, INTEL_ROOT_SHA256, hexBuf, b64url, SIGNED_LEN };
