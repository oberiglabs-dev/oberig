'use strict';
// The Oberig gateway. Listens on 127.0.0.1 only and sends every model request
// to NEAR AI Cloud, after checking the enclave, shielding and masking.

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { VERSION } = require('./config.js');
const M = require('./mask.js');
const Shield = require('./shield.js');
const T = require('./translate.js');
const S = require('./streams.js');
const V = require('./verify.js');
const R = require('./receipt.js');
const Merkle = require('./near/merkle.js');
const bs58 = require('./near/base58.js');
const { NETWORKS, explorerTx } = require('./near/rpc.js');
const { isAccountId } = require('./near/tx.js');

const HEX64 = /^[0-9a-f]{64}$/;
const MAX_ANCHORS = 50;
const MAX_LEAVES = 5000;

/**
 * Checks an anchor reported by "oberig anchor --send" before the dashboard shows it:
 * the leaves must hash to the root, and every field must have the expected shape.
 * The explorer link is built here, never taken from the request.
 */
function validAnchor(b) {
  if (!b || typeof b !== 'object') return 'JSON object expected';
  const net = NETWORKS[b.network];
  if (!net) return 'network must be mainnet or testnet';
  if (b.contract !== net.social) return `contract must be ${net.social}`;
  if (!isAccountId(b.account)) return 'account is not a NEAR account id';
  if (typeof b.root !== 'string' || !HEX64.test(b.root)) return 'root must be 64 hex characters';
  if (!Array.isArray(b.leaves) || !b.leaves.length || b.leaves.length > MAX_LEAVES || !b.leaves.every((h) => typeof h === 'string' && HEX64.test(h))) return 'leaves must be receipt hashes';
  if (new Set(b.leaves).size !== b.leaves.length) return 'leaves must be unique';
  let tx = null;
  try { tx = typeof b.tx === 'string' && b.tx.length <= 64 ? bs58.decode(b.tx) : null; } catch { tx = null; }
  if (!tx || tx.length !== 32) return 'tx must be a NEAR transaction hash';
  if (b.block != null && !(Number.isInteger(b.block) && b.block > 0)) return 'block must be a block height';
  if (Merkle.root(b.leaves).toString('hex') !== b.root) return 'the leaves do not give this root';
  return null;
}

const FILES = {
  '/': [path.join(__dirname, '..', 'dashboard', 'index.html'), 'text/html; charset=utf-8'],
  '/_oberig/seal.js': [path.join(__dirname, 'seal.js'), 'text/javascript; charset=utf-8'],
  '/_oberig/stitch.js': [path.join(__dirname, 'stitch.js'), 'text/javascript; charset=utf-8'],
};
const MAX_BODY = 32 * 1024 * 1024;
const ALLOWED_HOST = /^(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$/i;
const SECURITY_HEADERS = { 'x-content-type-options': 'nosniff', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' };
const CSP = "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');

function sendJSON(res, status, obj, extra = {}) {
  if (res.headersSent) { try { res.end(); } catch { /* closed */ } return; }
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...SECURITY_HEADERS, ...extra });
  res.end(JSON.stringify(obj));
}

function errorBody(route, status, message) {
  if (route === 'messages') {
    const type = status === 401 ? 'authentication_error' : status === 400 ? 'invalid_request_error' : status === 429 ? 'rate_limit_error' : status === 503 ? 'overloaded_error' : 'api_error';
    return { type: 'error', error: { type, message } };
  }
  return { error: { message, type: 'oberig_error', code: status } };
}

function sseHead(res) {
  res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-cache', connection: 'keep-alive', 'x-content-type-options': 'nosniff' });
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY) throw Object.assign(new Error('request body too large'), { status: 413 });
    chunks.push(c);
  }
  return Buffer.concat(chunks);
}

function detectClient(headers, route) {
  const ua = String(headers['user-agent'] || '').toLowerCase();
  if (ua.includes('claude-cli') || ua.includes('claude-code') || ua.includes('claude code')) return 'claude-code';
  if (ua.includes('codex')) return 'codex';
  if (ua.includes('opencode')) return 'opencode';
  return route === 'messages' ? 'anthropic-client' : 'openai-client';
}

/** Applies the shield to tool results (all rules) and user text (hidden-content rules). */
function shieldBody(body, route, mode) {
  const result = { body, stopped: 0, rules: new Set(), prints: [] };
  if (mode === 'off' || !body || !Array.isArray(body.messages)) return result;
  const block = mode === 'block';
  const scanText = (text, scope) => {
    if (typeof text !== 'string' || text.length < 4) return text;
    const r = Shield.scan(text, { scope, mode: block ? 'block' : 'warn' });
    if (!r.count) return text;
    result.stopped += r.count;
    for (const f of r.findings) {
      result.rules.add(f.rule);
      result.prints.push(sha256(f.rule + '\u0000' + text.slice(f.start, f.end)));
    }
    return block ? r.clean : text;
  };
  const scanContent = (content, scope) => {
    if (typeof content === 'string') return scanText(content, scope);
    if (!Array.isArray(content)) return content;
    return content.map((b) => {
      if (!b || typeof b !== 'object') return b;
      if (b.type === 'text') return { ...b, text: scanText(b.text, scope) };
      if (b.type === 'tool_result') return { ...b, content: scanContent(b.content, 'full') };
      if (b.type === 'document' && b.source && b.source.type === 'text') return { ...b, source: { ...b.source, data: scanText(b.source.data, 'full') } };
      return b;
    });
  };
  const messages = body.messages.map((m) => {
    if (!m || typeof m !== 'object') return m;
    if (m.role === 'tool' || m.role === 'function') return { ...m, content: scanContent(m.content, 'full') };
    if (m.role === 'user') return { ...m, content: scanContent(m.content, 'hidden') };
    return m;
  });
  result.body = { ...body, messages };
  return result;
}

function createGateway(cfg, deps = {}) {
  const fetchImpl = deps.fetch || globalThis.fetch;
  const log = deps.log || (() => {});
  const vault = new M.Vault();
  const book = new R.ReceiptBook();
  const events = new EventEmitter();
  events.setMaxListeners(50);
  const stoppedSeen = new Set();
  const startedAt = Date.now();
  const anchors = []; // roots published with "oberig anchor --send" during this session, oldest first
  let att = null;
  let attPromise = null;

  /** Anchor as the dashboard sees it: only the leaves that are receipts of this session. */
  function publicAnchor(a) {
    const known = new Set(book.items.map((r) => r.hash));
    return {
      root: a.root, network: a.network, account: a.account, contract: a.contract, tx: a.tx, explorer: a.explorer,
      block: a.block, time: a.time, count: a.leaves.length, hashes: a.leaves.filter((h) => known.has(h)),
    };
  }

  function addAnchor(b) {
    const a = {
      root: b.root, network: b.network, account: b.account, contract: b.contract, tx: b.tx,
      explorer: explorerTx(NETWORKS[b.network], b.tx), block: b.block == null ? null : b.block, time: Date.now(), leaves: b.leaves.slice(),
    };
    const i = anchors.findIndex((x) => x.root === a.root && x.network === a.network && x.account === a.account);
    if (i !== -1) anchors.splice(i, 1);
    anchors.push(a);
    if (anchors.length > MAX_ANCHORS) anchors.shift();
    const pub = publicAnchor(a);
    events.emit('anchored', pub);
    return pub;
  }

  function publicAtt(a) {
    if (!a) return null;
    return {
      ok: !!a.ok, model: a.model, signer: a.signer || null, gatewaySigner: a.gatewaySigner || null, algo: a.algo || null,
      nonce: a.nonce || null, fetchedAt: a.fetchedAt || null, error: a.error || null, mode: a.mode || cfg.verifyMode,
      checks: (a.checks || []).map((c) => ({ label: c.label, status: c.status, detail: c.detail })),
    };
  }

  function ensureAttestation(force = false) {
    if (!force && att && att.ok && Date.now() - att.fetchedAt < cfg.attestTtlMs) return Promise.resolve(att);
    if (attPromise) return attPromise;
    attPromise = V.attest(cfg, { fetch: fetchImpl, nonce: deps.nonce ? deps.nonce() : undefined, now: deps.now, rootFingerprint: deps.rootFingerprint })
      .then((r) => { att = r; events.emit('attestation', publicAtt(r)); return r; })
      .finally(() => { attPromise = null; });
    return attPromise;
  }

  function counters() {
    return {
      verifiedAnswers: book.totals.verified,
      secretsKeptHome: vault.size,
      hiddenStopped: stoppedSeen.size,
      tracesScrubbed: book.totals.scrubbedFiles,
      requests: book.totals.requests,
    };
  }

  function snapshot() {
    return {
      version: VERSION, model: cfg.model, startedAt,
      guards: { mask: cfg.mask, shield: cfg.shield, seals: true, requireAttestation: cfg.requireAttestation, verify: cfg.verifyMode },
      attestation: publicAtt(att), counters: counters(), receipts: book.items.slice(0, 80),
      anchors: anchors.map(publicAnchor),
    };
  }

  function finish(rec) {
    R.seal(rec);
    book.add(rec);
    events.emit('receipt', rec);
    log(rec);
    return rec;
  }

  function verdictOf(rec) {
    if (!rec.attestation || !rec.attestation.ok) return 'unverified';
    if (rec.signature && rec.signature.status === 'verified') return 'verified';
    if (rec.signature && rec.signature.status === 'failed') return 'bad-signature';
    return 'attested';
  }

  async function handleModel(route, req, res, body, signal) {
    const t0 = Date.now();
    const rec = {
      v: 1, time: t0, client: detectClient(req.headers, route), route, model: cfg.model,
      requested: typeof body.model === 'string' ? body.model.slice(0, 120) : null, stream: !!body.stream,
      attestation: null, signature: { status: 'none' }, masked: { total: 0, kinds: {} }, shield: { mode: cfg.shield, stopped: 0, rules: [] },
      requestHash: null, responseHash: null, status: 0, ms: 0, tokens: { in: 0, out: 0 }, verdict: 'error',
    };
    const fail = (status, message, verdict = 'refused') => {
      rec.status = status;
      rec.verdict = verdict;
      rec.ms = Date.now() - t0;
      rec.reason = message.replace(/^Oberig: /, '').slice(0, 200);
      sendJSON(res, status, errorBody(route, status, message));
      return finish(rec);
    };

    if (!cfg.apiKey) return fail(401, 'Oberig: no NEAR AI key. Set NEARAI_API_KEY (or NEAR_AI_API_KEY) in the environment and restart Oberig. Nothing was sent.');

    const a = await ensureAttestation();
    rec.attestation = { ok: !!a.ok, signer: a.signer || null, gatewaySigner: a.gatewaySigner || null, algo: a.algo || null, nonce: a.nonce || null, fetchedAt: a.fetchedAt || null, mode: cfg.verifyMode };
    if (!a.ok && cfg.requireAttestation) {
      return fail(503, `Oberig: the NEAR AI enclave check failed (${a.error || 'unknown reason'}). Nothing was sent. Run "oberig verify" for details.`);
    }

    // Shield, then mask. Both work on a copy; the client's body is never sent as is.
    const sh = shieldBody(body, route, cfg.shield);
    for (const p of sh.prints) stoppedSeen.add(p);
    rec.shield = { mode: cfg.shield, stopped: sh.stopped, rules: [...sh.rules] };
    const report = M.newReport();
    const masked = cfg.mask ? M.maskDeep(sh.body, cfg, vault, report) : sh.body;
    rec.masked = { total: report.total, kinds: report.kinds };

    const wantStream = !!body.stream;
    const upStream = !!cfg.upstreamStream && wantStream;
    let up;
    if (route === 'messages') up = T.anthropicToOpenAI(masked, cfg.model, { maxTokens: cfg.maxTokens, stream: upStream });
    else {
      up = { ...masked, model: cfg.model };
      if (upStream) { up.stream = true; up.stream_options = { include_usage: true }; } else { delete up.stream; delete up.stream_options; }
    }
    const bytes = Buffer.from(JSON.stringify(up), 'utf8');
    rec.requestHash = sha256(bytes);

    let ping = null;
    if (wantStream) {
      sseHead(res);
      ping = setInterval(() => res.write(route === 'messages' ? S.formatSSE({ event: 'ping', data: { type: 'ping' } }) : ': ping\n\n'), 10000);
    }
    const streamError = (status, message) => {
      rec.status = status;
      if (route === 'messages') res.write(S.formatSSE({ event: 'error', data: errorBody(route, status, message) }));
      else res.write(S.formatSSE({ data: errorBody(route, status, message) }));
      res.end();
    };

    let completionId = null;
    try {
      let r;
      try {
        r = await fetchImpl(`${cfg.nearUrl}/chat/completions`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${cfg.apiKey}`, 'content-type': 'application/json', accept: upStream ? 'text/event-stream' : 'application/json',
            'accept-encoding': 'identity', 'x-no-aliasing': 'true', 'user-agent': `oberig/${VERSION}`,
          },
          body: bytes,
          signal,
        });
      } catch (err) {
        if (signal.aborted) throw err;
        const msg = `Oberig: could not reach NEAR AI Cloud (${err.message}).`;
        if (wantStream) { clearInterval(ping); streamError(502, msg); rec.verdict = 'error'; rec.ms = Date.now() - t0; return finish(rec); }
        return fail(502, msg, 'error');
      }
      if (!r.ok) {
        const t = await r.text().catch(() => '');
        const msg = `Oberig: NEAR AI Cloud returned ${r.status}: ${t.slice(0, 500)}`;
        if (wantStream) { clearInterval(ping); streamError(r.status, msg); rec.verdict = 'error'; rec.ms = Date.now() - t0; return finish(rec); }
        return fail(r.status, msg, 'error');
      }

      if (upStream) {
        const raw = [];
        if (route === 'messages') {
          const tr = T.createStreamTranslator(cfg.model);
          const restore = S.anthropicRestorer(vault);
          const write = (evs) => { for (const e of evs) for (const o of restore(e)) res.write(S.formatSSE(o)); };
          for await (const e of S.readSSE(r.body, (c) => raw.push(Buffer.from(c)))) {
            if (e.data === '[DONE]') continue;
            let chunk;
            try { chunk = JSON.parse(e.data); } catch { continue; }
            if (chunk.id && !completionId) completionId = chunk.id;
            write(tr.push(chunk));
          }
          write(tr.end());
          rec.tokens = { in: tr.usage.input_tokens, out: tr.usage.output_tokens };
        } else {
          const restore = S.openaiRestorer(vault);
          for await (const e of S.readSSE(r.body, (c) => raw.push(Buffer.from(c)))) {
            if (e.data === '[DONE]') { res.write('data: [DONE]\n\n'); continue; }
            let chunk;
            try { chunk = JSON.parse(e.data); } catch { continue; }
            if (chunk.id && !completionId) completionId = chunk.id;
            if (chunk.usage) rec.tokens = { in: chunk.usage.prompt_tokens || 0, out: chunk.usage.completion_tokens || 0 };
            res.write(S.formatSSE({ data: restore(chunk) }));
          }
        }
        clearInterval(ping);
        res.end();
        rec.responseHash = sha256(Buffer.concat(raw));
      } else {
        const raw = Buffer.from(await r.arrayBuffer());
        rec.responseHash = sha256(raw);
        let j;
        try { j = JSON.parse(raw.toString('utf8')); } catch {
          if (wantStream) { clearInterval(ping); streamError(502, 'Oberig: NEAR AI Cloud sent a response that is not JSON.'); rec.verdict = 'error'; rec.ms = Date.now() - t0; return finish(rec); }
          return fail(502, 'Oberig: NEAR AI Cloud sent a response that is not JSON.', 'error');
        }
        completionId = j.id || null;
        rec.tokens = { in: (j.usage && j.usage.prompt_tokens) || 0, out: (j.usage && j.usage.completion_tokens) || 0 };
        const restored = M.restoreDeep(j, vault);
        if (route === 'messages') {
          const msg = T.openAIToAnthropic(restored, cfg.model);
          if (wantStream) {
            clearInterval(ping);
            for (const e of T.anthropicEventsFromMessage(msg)) res.write(S.formatSSE(e));
            res.end();
          } else sendJSON(res, 200, msg);
        } else if (wantStream) {
          clearInterval(ping);
          for (const c of T.openaiChunksFromCompletion(restored)) res.write(S.formatSSE({ data: c }));
          res.write('data: [DONE]\n\n');
          res.end();
        } else sendJSON(res, 200, restored);
      }
      rec.status = 200;
    } finally {
      if (ping) clearInterval(ping);
    }

    // The answer is delivered; now check its signature against the exact bytes.
    if (completionId) {
      const sig = await V.fetchSignature(cfg, completionId, { fetch: fetchImpl, retryMs: deps.retryMs, tries: deps.signatureTries });
      rec.signature = V.checkSignature(sig, { model: cfg.model, requestHash: rec.requestHash, responseHash: rec.responseHash, attestation: a });
      if (rec.signature.status === 'failed' && rec.signature.checks && !rec.signature.checks.signer) att = null; // re-attest before the next request
    } else rec.signature = { status: 'unavailable', reason: 'no completion id' };
    rec.verdict = verdictOf(rec);
    rec.ms = Date.now() - t0;
    return finish(rec);
  }

  function serveFile(res, route) {
    const [file, type] = FILES[route];
    try {
      const body = fs.readFileSync(file);
      res.writeHead(200, { 'content-type': type, ...SECURITY_HEADERS, ...(route === '/' ? { 'content-security-policy': CSP } : {}) });
      res.end(body);
    } catch {
      sendJSON(res, 500, { error: 'file missing' });
    }
  }

  function serveEvents(req, res) {
    sseHead(res);
    res.write(S.formatSSE({ event: 'hello', data: snapshot() }));
    const onReceipt = (r) => res.write(S.formatSSE({ event: 'receipt', data: { receipt: r, counters: counters() } }));
    const onAtt = (a) => res.write(S.formatSSE({ event: 'attestation', data: a }));
    const onScrub = () => res.write(S.formatSSE({ event: 'counters', data: counters() }));
    const onAnchor = (a) => res.write(S.formatSSE({ event: 'anchored', data: a }));
    events.on('receipt', onReceipt);
    events.on('attestation', onAtt);
    events.on('scrub', onScrub);
    events.on('anchored', onAnchor);
    const keep = setInterval(() => res.write(': ping\n\n'), 15000);
    req.on('close', () => { events.off('receipt', onReceipt); events.off('attestation', onAtt); events.off('scrub', onScrub); events.off('anchored', onAnchor); clearInterval(keep); });
  }

  const server = http.createServer(async (req, res) => {
    const controller = new AbortController();
    res.on('close', () => { if (!res.writableFinished) controller.abort(); });
    try {
      // Local requests only; block web pages (DNS rebinding and cross-site requests).
      const host = req.headers.host || '';
      if (!ALLOWED_HOST.test(host)) return sendJSON(res, 403, { error: 'Oberig only accepts requests addressed to localhost.' });
      const url = new URL(req.url, 'http://127.0.0.1');
      const p = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, '') : url.pathname;
      const origin = req.headers.origin;
      const ownPage = p === '/' || p.startsWith('/_oberig/');
      if (origin && !(ownPage && origin.toLowerCase() === `http://${host.toLowerCase()}`)) {
        return sendJSON(res, 403, { error: 'Oberig does not accept requests from web pages.' });
      }

      if (req.method === 'GET' && FILES[p]) return serveFile(res, p);
      if (req.method === 'GET' && p === '/_oberig/state') return sendJSON(res, 200, snapshot());
      if (req.method === 'GET' && p === '/_oberig/events') return serveEvents(req, res);
      if (req.method === 'GET' && p === '/_oberig/receipts') {
        // For "oberig anchor": every receipt hash of the session, oldest first, and the anchors so far.
        return sendJSON(res, 200, {
          receipts: book.items.slice().reverse().map((r) => ({ hash: r.hash, id: r.id, time: r.time, verdict: r.verdict })),
          anchors: anchors.map((a) => ({ ...publicAnchor(a), leaves: a.leaves })),
        });
      }
      if (req.method === 'GET' && (p === '/v1/models' || p === '/models')) {
        if (req.headers['anthropic-version']) {
          return sendJSON(res, 200, { data: [{ type: 'model', id: cfg.model, display_name: `${cfg.model} (NEAR AI, via Oberig)`, created_at: '2026-10-17T00:00:00Z' }], has_more: false, first_id: cfg.model, last_id: cfg.model });
        }
        return sendJSON(res, 200, { object: 'list', data: [{ id: cfg.model, object: 'model', created: 0, owned_by: 'nearai' }] });
      }

      const routes = { '/v1/messages': 'messages', '/v1/messages/count_tokens': 'count', '/v1/chat/completions': 'chat', '/chat/completions': 'chat', '/_oberig/scrubbed': 'scrubbed', '/_oberig/anchored': 'anchored' };
      const route = routes[p];
      if (!route) return sendJSON(res, 404, { error: `Oberig serves /v1/messages and /v1/chat/completions only (got ${req.method} ${p}).` });
      if (req.method !== 'POST') return sendJSON(res, 405, { error: 'use POST' });
      const ct = String(req.headers['content-type'] || '');
      if (!/^application\/json\b/i.test(ct)) return sendJSON(res, 415, { error: 'Oberig expects Content-Type: application/json' });
      const raw = await readBody(req);
      let body;
      try { body = JSON.parse(raw.toString('utf8')); } catch { return sendJSON(res, 400, errorBody(route === 'messages' ? 'messages' : 'chat', 400, 'invalid JSON body')); }
      if (!body || typeof body !== 'object' || Array.isArray(body)) return sendJSON(res, 400, { error: 'JSON object expected' });

      if (route === 'count') return sendJSON(res, 200, { input_tokens: Math.ceil(raw.length / 4) });
      if (route === 'scrubbed') {
        const files = Math.max(0, Math.min(1e6, Number(body.files) || 0));
        book.totals.scrubbedFiles += files;
        book.totals.scrubbedItems += Math.max(0, Math.min(1e9, Number(body.items) || 0));
        events.emit('scrub');
        return sendJSON(res, 200, { ok: true });
      }
      if (route === 'anchored') {
        const problem = validAnchor(body);
        if (problem) return sendJSON(res, 400, { error: `anchor refused: ${problem}` });
        const a = addAnchor(body);
        return sendJSON(res, 200, { ok: true, marked: a.hashes.length });
      }
      return await handleModel(route, req, res, body, controller.signal);
    } catch (err) {
      if (controller.signal.aborted) return;
      const status = err.status || 500;
      if (!res.headersSent) sendJSON(res, status, { error: `Oberig error: ${err.message}` });
      else { try { res.end(); } catch { /* closed */ } }
    }
  });

  return {
    server, cfg, vault, book, events, snapshot, ensureAttestation,
    get attestation() { return att; },
    get anchors() { return anchors.map(publicAnchor); },
    listen() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(cfg.port, '127.0.0.1', () => { server.off('error', reject); resolve(server.address()); });
      });
    },
    close() { return new Promise((resolve) => server.close(() => resolve())); },
  };
}

module.exports = { createGateway, shieldBody, detectClient, errorBody, validAnchor };
