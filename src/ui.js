'use strict';
// Terminal output: startup banner, per-request log line, the enclave receipt.

const Seal = require('./seal.js');
const { VERSION } = require('./config.js');
const { shortSigner } = require('./verify.js');

function colors(enabled) {
  const c = (code) => (s) => (enabled ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  return {
    red: c('38;2;229;65;47'),
    gold: c('38;2;232;176;74'),
    linen: c('38;2;241;234;219'),
    dim: c('38;2;150;143;132'),
    bold: c('1'),
  };
}

function useColor(stream = process.stdout, env = process.env) {
  return !!(stream && stream.isTTY) && !env.NO_COLOR && env.TERM !== 'dumb';
}

function pad(s, n) { s = String(s); return s + ' '.repeat(Math.max(0, n - s.length)); }

/** The startup banner. `state` = {model, attestation, cfg, address}. */
function banner(state, color = false) {
  const k = colors(color);
  const { cfg, attestation: a } = state;
  const x = k.red('×');
  let verified;
  if (a && a.ok) verified = `${k.gold('✓')} enclave attested · signer ${shortSigner(a.signer)}`;
  else if (a) verified = `${k.red('✗')} not attested · ${a.error || 'check failed'}`;
  else verified = 'checking…';
  const guard = (name, on, word) => `${name} ${on ? 'on' : word || 'off'}`;
  const lines = [
    `  ${x}   ${x}`,
    `${x}   ${x}   ${x}   ${k.bold('OBERIG')} v${VERSION}`,
    `  ${x}   ${x}     your agent's amulet`,
    `${pad('Enclave', 11)}NEAR AI · ${cfg.model}`,
    `${pad('Verified', 11)}${verified}`,
    `${pad('Guards', 11)}${[guard('mask', cfg.mask), cfg.shield === 'block' ? 'shield on' : `shield ${cfg.shield}`, 'seals on'].join(' · ')}`,
    `${pad('Privacy', 11)}runs only on this computer · stores nothing · no telemetry`,
  ];
  if (state.address) lines.push(`${pad('Address', 11)}${state.address}  ${k.dim('(dashboard: open it in a browser)')}`);
  if (!cfg.apiKey) lines.push(`${pad('Key', 11)}${k.red('missing')} · set NEARAI_API_KEY (or NEAR_AI_API_KEY) before starting`);
  if (a && !a.ok && cfg.requireAttestation) lines.push(`${pad('', 11)}${k.dim('nothing is sent until a check passes; Oberig retries on the next request')}`);
  return lines.join('\n');
}

function hhmmss(t) {
  const d = new Date(t);
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, '0')).join(':');
}

const VERDICT = {
  verified: ['✓', 'verified'],
  attested: ['✓', 'attested'],
  'bad-signature': ['✗', 'bad signature'],
  refused: ['✗', 'refused'],
  error: ['✗', 'error'],
  unverified: ['✗', 'unverified'],
};

/** One metadata-only line per request. */
function logLine(r, color = false) {
  const k = colors(color);
  const [sym, word] = VERDICT[r.verdict] || ['?', r.verdict];
  const mark = sym === '✓' ? k.gold(sym) : k.red(sym);
  const secs = ((r.ms || 0) / 1000).toFixed(1) + 's';
  return `${hhmmss(r.time)}  ${r.client} → near ${mark} ${word}  ${k.red('◆')} masked ${(r.masked && r.masked.total) || 0}  ${k.red('⚑')} ${r.shield && r.shield.mode === 'warn' ? 'flagged' : 'stopped'} ${(r.shield && r.shield.stopped) || 0}  ${r.status}  ${secs}  seal ${r.id}`;
}

/** The `oberig verify` receipt. */
function enclaveReceipt(rec, opts = {}) {
  const k = colors(!!opts.color);
  const a = rec.attestation;
  const out = [];
  out.push('');
  out.push(`  ${k.bold('OBERIG · enclave receipt')}`);
  out.push('');
  const row = (key, val) => out.push(`  ${pad(key, 10)}${val}`);
  row('model', a.model || '');
  row('service', 'NEAR AI Cloud · provider near');
  row('time', new Date(rec.time).toISOString().replace('T', ' ').slice(0, 19) + ' UTC');
  if (a.nonce) row('nonce', `${a.nonce.slice(0, 8)}…${a.nonce.slice(-8)} · fresh, 32 bytes`);
  if (a.signer) row('signer', `${shortSigner(a.signer)} · ${a.algo || ''}`);
  if (a.gatewaySigner) row('gateway', `${shortSigner(a.gatewaySigner)} · ${a.gateway && a.gateway.algo || ''}`);
  out.push('');
  for (const c of a.checks || []) {
    if (c.status === 'ok') out.push(`  ${k.gold('✓')}  ${c.label}${c.detail && opts.details ? k.dim('  ' + c.detail) : ''}`);
    else if (c.status === 'fail') out.push(`  ${k.red('✗')}  ${c.label}${c.detail ? k.dim('  ' + c.detail) : ''}`);
    else out.push(`  ·  ${c.label}: ${c.detail || 'not checked locally'}`);
  }
  if (!(a.checks || []).length && a.error) out.push(`  ${k.red('✗')}  ${a.error}`);
  if (rec.chat) {
    const s = rec.chat;
    if (s.status === 'verified') out.push(`  ${k.gold('✓')}  test answer signature verified (${s.kind === 'provider_tee' ? 'model TEE key' : 'gateway key'})`);
    else if (s.status === 'failed') out.push(`  ${k.red('✗')}  test answer signature: ${s.reason}`);
    else out.push(`  ·  test answer signature: ${s.reason || 'unavailable'}`);
  }
  out.push('');
  row('result', a.ok ? `${k.gold('✓')} enclave attested` : `${k.red('✗')} not attested · nothing would be sent`);
  if (a.ok) out.push(`  ${pad('', 10)}${k.dim('all instances of a model share one signing key; a signer match does not show which machine answered')}`);
  out.push('');
  out.push(Seal.ascii(rec.hash, { ansi: !!opts.color, indent: '  ' }));
  out.push('');
  out.push(`  seal ${k.gold(rec.id)}`);
  out.push('');
  return out.join('\n');
}

module.exports = { banner, logLine, enclaveReceipt, useColor, colors, hhmmss };
