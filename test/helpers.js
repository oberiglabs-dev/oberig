'use strict';
// Test helpers: fake keys built from pieces, a synthetic NEAR AI attestation
// report (own certificate chain, pinned in tests only), and a mock NEAR AI server.

const crypto = require('node:crypto');
const http = require('node:http');

// ---- fake secrets, assembled at runtime so no full-format key sits in the source ----
const fake = {
  nearKey: () => ['sk', 'oberigtest' + 'Z9'.repeat(12)].join('-'),
  openai: () => ['sk', 'proj', 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z'].join('-'),
  github: () => 'gh' + 'p_' + 'R7mQ2xK9pL4vN8sT1wY6zB3cF5hJ0dG2aE4u',
  aws: () => 'AK' + 'IA' + 'Q3EXAMPLE7RT2WZK'.toUpperCase(),
};

// ---- minimal DER writer for test certificates ----
function len(n) {
  if (n < 128) return Buffer.from([n]);
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const der = (tag, content) => Buffer.concat([Buffer.from([tag]), len(content.length), content]);
const SEQ = (...x) => der(0x30, Buffer.concat(x));
const SET = (...x) => der(0x31, Buffer.concat(x));
const INT = (n) => der(0x02, Buffer.from([n]));
const BOOL = (b) => der(0x01, Buffer.from([b ? 0xff : 0]));
const OCT = (b) => der(0x04, b);
const BIT = (b) => der(0x03, Buffer.concat([Buffer.from([0]), b]));
const UTF8 = (s) => der(0x0c, Buffer.from(s, 'utf8'));
const EXPLICIT = (n, c) => der(0xa0 + n, c);
function OID(s) {
  const arcs = s.split('.').map(Number);
  const out = [40 * arcs[0] + arcs[1]];
  for (const a of arcs.slice(2)) {
    const tmp = [a & 0x7f];
    let v = a >> 7;
    while (v > 0) { tmp.unshift(0x80 | (v & 0x7f)); v >>= 7; }
    out.push(...tmp);
  }
  return der(0x06, Buffer.from(out));
}
function UTC(d) {
  const p = (n) => String(n).padStart(2, '0');
  return der(0x17, Buffer.from(`${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`));
}
const ECDSA_SHA256 = SEQ(OID('1.2.840.10045.4.3.2'));
const name = (cn) => SEQ(SET(SEQ(OID('2.5.4.3'), UTF8(cn))));

function makeCert(subject, issuer, subjectPub, issuerPriv, isCA, serial) {
  const now = Date.now();
  const spki = subjectPub.export({ type: 'spki', format: 'der' });
  const bc = SEQ(OID('2.5.29.19'), BOOL(true), OCT(isCA ? SEQ(BOOL(true)) : SEQ()));
  const tbs = SEQ(EXPLICIT(0, INT(2)), INT(serial), ECDSA_SHA256, name(issuer), SEQ(UTC(new Date(now - 86400000)), UTC(new Date(now + 365 * 86400000))), name(subject), spki, EXPLICIT(3, SEQ(bc)));
  const sig = crypto.sign('sha256', tbs, issuerPriv);
  const body = SEQ(tbs, ECDSA_SHA256, BIT(sig)).toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

let chainCache = null;
function testChain() {
  if (chainCache) return chainCache;
  const gen = () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const root = gen(), inter = gen(), leaf = gen();
  const rootPem = makeCert('Oberig Test Root CA', 'Oberig Test Root CA', root.publicKey, root.privateKey, true, 1);
  const interPem = makeCert('Oberig Test Platform CA', 'Oberig Test Root CA', inter.publicKey, root.privateKey, true, 2);
  const leafPem = makeCert('Oberig Test PCK', 'Oberig Test Platform CA', leaf.publicKey, inter.privateKey, false, 3);
  chainCache = { leafKey: leaf.privateKey, pem: leafPem + interPem + rootPem, fingerprint: new crypto.X509Certificate(rootPem).fingerprint256 };
  return chainCache;
}

const sha = (alg, ...parts) => { const h = crypto.createHash(alg); for (const p of parts) h.update(p); return h.digest(); };

function eventLog() {
  const events = ['system-preparing', 'app-id', 'compose-hash', 'instance-id', 'boot-mr-done', 'system-ready'].map((e, i) => ({ imr: 3, event_type: 134217729, event: e, event_payload: Buffer.from('payload-' + i).toString('hex') }));
  let acc = Buffer.alloc(48);
  for (const e of events) {
    const t = Buffer.alloc(4); t.writeUInt32LE(e.event_type);
    const d = sha('sha384', t, ':', Buffer.from(e.event), ':', Buffer.from(e.event_payload, 'hex'));
    e.digest = d.toString('hex');
    acc = sha('sha384', acc, d);
  }
  return { events, rtmr3: acc };
}

/** Builds a TDX v4 quote binding `signer` (Buffer) and `nonce` (hex). */
function makeQuote({ signer, nonce, compose, debug = false }) {
  const chain = testChain();
  const att = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = att.publicKey.export({ format: 'jwk' });
  const attXY = Buffer.concat([Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  const header = Buffer.alloc(48);
  header.writeUInt16LE(4, 0); header.writeUInt16LE(2, 2); header.writeUInt32LE(0x81, 4);
  const body = Buffer.alloc(584);
  if (debug) body[120] = 1;
  Buffer.concat([Buffer.from([1]), sha('sha256', Buffer.from(compose, 'utf8')), Buffer.alloc(15)]).copy(body, 184);
  const log = eventLog();
  log.rtmr3.copy(body, 472);
  Buffer.concat([signer, Buffer.alloc(32 - signer.length)]).copy(body, 520);
  Buffer.from(nonce, 'hex').copy(body, 552);
  const signed = Buffer.concat([header, body]);
  const quoteSig = crypto.sign('sha256', signed, { key: att.privateKey, dsaEncoding: 'ieee-p1363' });
  const auth = Buffer.from('oberig-test-auth-data');
  const qe = Buffer.alloc(384);
  sha('sha256', attXY, auth).copy(qe, 320);
  const qeSig = crypto.sign('sha256', qe, { key: chain.leafKey, dsaEncoding: 'ieee-p1363' });
  const pem = Buffer.from(chain.pem, 'utf8');
  const authLen = Buffer.alloc(2); authLen.writeUInt16LE(auth.length);
  const inner = Buffer.alloc(6); inner.writeUInt16LE(5, 0); inner.writeUInt32LE(pem.length, 2);
  const certData = Buffer.concat([qe, qeSig, authLen, auth, inner, pem]);
  const certHead = Buffer.alloc(6); certHead.writeUInt16LE(6, 0); certHead.writeUInt32LE(certData.length, 2);
  const sigData = Buffer.concat([quoteSig, attXY, certHead, certData]);
  const sigLen = Buffer.alloc(4); sigLen.writeUInt32LE(sigData.length);
  return { quote: Buffer.concat([signed, sigLen, sigData]).toString('hex'), events: log.events };
}

function ed25519Key() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const raw = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
  return { raw, hex: raw.toString('hex'), sign: (text) => crypto.sign(null, Buffer.from(text, 'utf8'), privateKey).toString('hex') };
}

/** A synthetic /v1/attestation/report body for `model`, bound to `nonce`. */
function makeReport({ model, nonce, modelKey, gatewayKey, bindNonce, debug, gpuNonce }) {
  const one = (key, withGpu) => {
    const compose = JSON.stringify({ name: 'oberig-test', services: { model: { image: 'test' } } });
    const q = makeQuote({ signer: key.raw, nonce: bindNonce || nonce, compose, debug });
    const rep = {
      signing_address: key.hex, signing_algo: 'ed25519', request_nonce: nonce, intel_quote: q.quote, event_log: q.events,
      info: { tcb_info: JSON.stringify({ app_compose: compose, event_log: q.events }) },
    };
    if (withGpu) {
      rep.model_name = model;
      rep.signing_public_key = key.hex;
      rep.nvidia_payload = JSON.stringify({ nonce: gpuNonce || nonce, arch: 'HOPPER', evidence_list: [{ certificate: 'test', evidence: 'test' }] });
    }
    return rep;
  };
  return { gateway_attestation: one(gatewayKey, false), model_attestations: [one(modelKey, true)] };
}

/**
 * Mock NEAR AI Cloud. opts.reply(reqJson) returns the completion JSON.
 * opts.tamper: {nonce: true} binds a wrong nonce, {signature: true} corrupts signatures.
 */
async function mockNear(opts = {}) {
  const modelKey = ed25519Key();
  const gatewayKey = ed25519Key();
  const sigs = new Map();
  const seen = { reports: 0, chats: [], signatures: 0 };
  let n = 0;
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const raw = Buffer.concat(chunks);
    const url = new URL(req.url, 'http://x');
    const send = (status, obj, type = 'application/json') => { res.writeHead(status, { 'content-type': type }); res.end(typeof obj === 'string' || Buffer.isBuffer(obj) ? obj : JSON.stringify(obj)); };
    if (url.pathname === '/v1/attestation/report') {
      seen.reports++;
      const nonce = url.searchParams.get('nonce');
      const t = opts.tamper || {};
      return send(200, makeReport({ model: url.searchParams.get('model'), nonce, modelKey, gatewayKey, bindNonce: t.nonce ? 'ab'.repeat(32) : null, debug: t.debug }));
    }
    if (url.pathname === '/v1/chat/completions' && req.method === 'POST') {
      const j = JSON.parse(raw.toString('utf8'));
      seen.chats.push({ headers: req.headers, raw, json: j });
      const id = `chatcmpl-test${++n}`;
      const reply = opts.reply ? opts.reply(j) : { content: 'ok' };
      if (j.stream) {
        const lines = [
          { id, object: 'chat.completion.chunk', model: j.model, choices: [{ index: 0, delta: { role: 'assistant', content: '' } }] },
          ...String(reply.content || '').match(/.{1,7}/gs) ? String(reply.content).match(/.{1,7}/gs).map((piece) => ({ id, object: 'chat.completion.chunk', model: j.model, choices: [{ index: 0, delta: { content: piece } }] })) : [],
          { id, object: 'chat.completion.chunk', model: j.model, choices: [{ index: 0, delta: {}, finish_reason: 'stop' }], usage: { prompt_tokens: 11, completion_tokens: 5 } },
        ];
        const body = lines.map((l) => `data: ${JSON.stringify(l)}\n\n`).join('') + 'data: [DONE]\n\n';
        const text = `${sha('sha256', raw).toString('hex')}:${sha('sha256', Buffer.from(body)).toString('hex')}`;
        sigs.set(id, { text, signature: gatewayKey.sign(text), signing_address: gatewayKey.hex, signing_algo: 'ed25519', signature_kind: 'gateway' });
        return send(200, body, 'text/event-stream');
      }
      const message = { role: 'assistant', content: reply.content == null ? null : reply.content };
      if (reply.tool_calls) message.tool_calls = reply.tool_calls;
      const body = Buffer.from(JSON.stringify({ id, object: 'chat.completion', model: j.model, choices: [{ index: 0, message, finish_reason: reply.tool_calls ? 'tool_calls' : 'stop' }], usage: { prompt_tokens: 42, completion_tokens: 7 } }));
      const text = `${j.model}:${sha('sha256', raw).toString('hex')}:${sha('sha256', body).toString('hex')}`;
      let signature = modelKey.sign(text);
      if (opts.tamper && opts.tamper.signature) signature = (signature[0] === 'a' ? 'b' : 'a') + signature.slice(1);
      sigs.set(id, { text, signature, signing_address: modelKey.hex, signing_algo: 'ed25519', signature_kind: 'provider_tee' });
      return send(200, body);
    }
    const m = /^\/v1\/signature\/(.+)$/.exec(url.pathname);
    if (m && req.method === 'GET') {
      seen.signatures++;
      const s = sigs.get(decodeURIComponent(m[1]));
      return s ? send(200, s) : send(404, { error: 'not found' });
    }
    send(404, { error: 'unknown path' });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}/v1`;
  return { base, seen, modelKey, gatewayKey, rootFingerprint: testChain().fingerprint, close: () => new Promise((r) => server.close(r)) };
}

module.exports = { fake, makeReport, makeQuote, ed25519Key, testChain, mockNear, sha };
