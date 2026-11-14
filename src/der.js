'use strict';
// A small DER reader for the few structures Oberig reads itself: the Intel SGX
// extension inside PCK certificates, certificate names and serials, and X.509
// CRLs. Read only. Single-byte tags, definite lengths.

/** Reads one TLV at `pos` of `buf`. */
function node(buf, pos = 0) {
  if (pos + 2 > buf.length) throw new Error('DER: truncated');
  const tag = buf[pos];
  if ((tag & 0x1f) === 0x1f) throw new Error('DER: multi-byte tag');
  let len = buf[pos + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || pos + 2 + n > buf.length) throw new Error('DER: bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[pos + 2 + i];
    hdr += n;
  }
  const end = pos + hdr + len;
  if (end > buf.length) throw new Error('DER: truncated');
  const value = buf.subarray(pos + hdr, end);
  return { tag, value, raw: buf.subarray(pos, end), end, kids: () => list(value) };
}

/** Reads consecutive TLVs filling `buf`. */
function list(buf) {
  const out = [];
  for (let p = 0; p < buf.length;) { const n = node(buf, p); out.push(n); p = n.end; }
  return out;
}

/** Reads a whole DER document (one TLV, nothing after it). */
function parse(buf) {
  const n = node(buf, 0);
  if (n.end !== buf.length) throw new Error('DER: trailing bytes');
  return n;
}

function oid(value) {
  const arcs = [];
  let v = 0;
  for (const b of value) {
    v = v * 128 + (b & 0x7f);
    if (!(b & 0x80)) { arcs.push(v); v = 0; }
  }
  const first = arcs.shift();
  const a = first < 40 ? 0 : first < 80 ? 1 : 2;
  return [a, first - 40 * a, ...arcs].join('.');
}

/** Non-negative INTEGER as a number (small values only). */
function int(value) {
  if (!value.length || value.length > 6 || value[0] & 0x80) throw new Error('DER: integer out of range');
  let v = 0;
  for (const b of value) v = v * 256 + b;
  return v;
}

/** INTEGER as uppercase hex without leading zeros (for serial numbers). */
function serialHex(value) {
  return value.toString('hex').toUpperCase().replace(/^0+/, '') || '0';
}

/** UTCTime or GeneralizedTime as milliseconds since the epoch. */
function time(n) {
  const s = n.value.toString('latin1');
  let m;
  if (n.tag === 0x17) {
    m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s);
    if (m) m[1] = String((Number(m[1]) < 50 ? 2000 : 1900) + Number(m[1]));
  } else if (n.tag === 0x18) {
    m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s);
  }
  if (!m) throw new Error('DER: bad time');
  return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
}

/** The fields Oberig needs from a DER certificate: serial, issuer and subject names (raw DER), extensions. */
function certFields(der) {
  const tbs = parse(der).kids()[0];
  const f = tbs.kids();
  let i = f[0].tag === 0xa0 ? 1 : 0;
  const serial = serialHex(f[i].value);
  const issuer = f[i + 2].raw;
  const subject = f[i + 4].raw;
  const extensions = [];
  for (const x of f.slice(i + 6)) {
    if (x.tag !== 0xa3) continue;
    for (const e of x.kids()[0].kids()) {
      const k = e.kids();
      extensions.push({ oid: oid(k[0].value), value: k[k.length - 1].value });
    }
  }
  return { serial, issuer, subject, extensions };
}

const SGX_EXT = '1.2.840.113741.1.13.1';

/** Reads Intel's SGX extension from a PCK certificate: FMSPC, PCE ID, TCB components, PCESVN. */
function sgxExtension(der) {
  const ext = certFields(der).extensions.find((e) => e.oid === SGX_EXT);
  if (!ext) throw new Error('PCK certificate has no Intel SGX extension');
  const out = { fmspc: null, pceId: null, comps: [], pcesvn: null, cpusvn: null };
  for (const item of parse(ext.value).kids()) {
    const [o, v] = item.kids();
    const id = oid(o.value);
    if (id === `${SGX_EXT}.2`) {
      for (const c of v.kids()) {
        const [co, cv] = c.kids();
        const cid = oid(co.value);
        if (!cid.startsWith(`${SGX_EXT}.2.`)) continue;
        const n = Number(cid.slice(SGX_EXT.length + 3));
        if (n >= 1 && n <= 16) out.comps[n - 1] = int(cv.value);
        else if (n === 17) out.pcesvn = int(cv.value);
        else if (n === 18) out.cpusvn = cv.value.toString('hex');
      }
    } else if (id === `${SGX_EXT}.3`) out.pceId = v.value.toString('hex');
    else if (id === `${SGX_EXT}.4`) out.fmspc = v.value.toString('hex');
  }
  const compsOk = out.comps.length === 16 && out.comps.every((c) => Number.isInteger(c));
  if (!out.fmspc || out.fmspc.length !== 12 || !compsOk || !Number.isInteger(out.pcesvn)) throw new Error('PCK certificate SGX extension incomplete');
  return out;
}

/** Parses a DER X.509 CRL. Revoked serials are uppercase hex without leading zeros. */
function parseCrl(der) {
  const [tbs, alg, sig] = parse(der).kids();
  const f = tbs.kids();
  let i = f[0].tag === 0x02 ? 1 : 0;
  i++; // inner signature algorithm
  const issuer = f[i++].raw;
  const thisUpdate = time(f[i++]);
  let nextUpdate = null;
  if (f[i] && (f[i].tag === 0x17 || f[i].tag === 0x18)) nextUpdate = time(f[i++]);
  const revoked = new Set();
  if (f[i] && f[i].tag === 0x30) {
    for (const entry of f[i].kids()) revoked.add(serialHex(entry.kids()[0].value));
  }
  if (sig.tag !== 0x03 || sig.value[0] !== 0) throw new Error('CRL signature is not a plain BIT STRING');
  return { tbs: tbs.raw, algorithm: oid(alg.kids()[0].value), signature: sig.value.subarray(1), issuer, thisUpdate, nextUpdate, revoked };
}

module.exports = { node, list, parse, oid, int, serialHex, time, certFields, sgxExtension, parseCrl, SGX_EXT };
