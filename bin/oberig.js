#!/usr/bin/env node
'use strict';
// Oberig command line.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { VERSION, loadConfig } = require('../src/config.js');
const { createGateway } = require('../src/server.js');
const V = require('../src/verify.js');
const R = require('../src/receipt.js');
const ui = require('../src/ui.js');
const Shield = require('../src/shield.js');
const { scrubPath } = require('../src/scrub.js');

const HELP = `oberig ${VERSION}: your agent's amulet

A small local guard between your coding agent and NEAR AI Cloud. It sends
prompts only to an enclave it has verified, masks your secrets first, stops
hidden instructions before the model reads them, and seals every answer.

Usage
  oberig                     start the gateway on 127.0.0.1:8790
  oberig start [--port N]    same, on another port
  oberig verify [--chat]     check the NEAR AI enclave now and print a receipt
                             (--chat also sends one short test prompt and checks
                             its signature; needs a key and costs a tiny amount)
  oberig shield <file>       show hidden instructions found in a file
  oberig scrub <path> [--out <path>]
                             write sanitised copies of agent traces
  oberig setup               how to connect Claude Code, Codex and OpenCode
  oberig --version | --help

  Without installing: npx github:oberiglabs-dev/oberig [command]

Environment
  NEARAI_API_KEY             your NEAR AI Cloud key (NEAR_AI_API_KEY also works)
  OBERIG_MODEL               default deepseek-ai/DeepSeek-V4.1-Flash-1017
  OBERIG_PORT                default 8790
  OBERIG_SHIELD              block | warn | off (default block)
  OBERIG_REQUIRE_ATTESTATION 1 | 0 (default 1: nothing is sent unless the check passes)
  OBERIG_VERIFY              local | full (full adds Intel TCB status, QE identity
                             and CRLs from Intel PCS, and the NVIDIA GPU verdict)
  OBERIG_REQUIRE_TCB         warn | uptodate (full mode: refuse unless UpToDate)
  More in the README.
`;

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) out[a.slice(2, eq)] = a.slice(eq + 1);
      else if (['port', 'out'].includes(a.slice(2)) && argv[i + 1] && !argv[i + 1].startsWith('--')) out[a.slice(2)] = argv[++i];
      else out[a.slice(2)] = true;
    } else if (a === '-h') out.help = true;
    else if (a === '-v') out.version = true;
    else out._.push(a);
  }
  return out;
}

function die(msg, code = 1) {
  process.stderr.write(`oberig: ${msg}\n`);
  process.exit(code);
}

async function cmdStart(args) {
  const cfg = loadConfig(args.port ? { port: Number(args.port) } : {});
  const color = ui.useColor();
  const gw = createGateway(cfg, { log: (rec) => { if (!cfg.quiet) process.stdout.write(ui.logLine(rec, color) + '\n'); } });
  try {
    await gw.listen();
  } catch (err) {
    if (err.code === 'EADDRINUSE') die(`port ${cfg.port} is in use. Is Oberig already running? Use --port to pick another.`);
    die(err.message);
  }
  const a = await gw.ensureAttestation();
  const address = `http://127.0.0.1:${gw.server.address().port}`;
  process.stdout.write('\n' + ui.banner({ cfg, attestation: a, address }, color) + '\n\n');
  const stop = () => { gw.close().then(() => process.exit(0)); setTimeout(() => process.exit(0), 1500).unref(); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

async function testChat(cfg, a) {
  const body = { model: cfg.model, messages: [{ role: 'user', content: 'Reply with one word: sealed' }], max_tokens: 64 };
  const bytes = Buffer.from(JSON.stringify(body), 'utf8');
  const res = await fetch(`${cfg.nearUrl}/chat/completions`, {
    method: 'POST',
    headers: { authorization: `Bearer ${cfg.apiKey}`, 'content-type': 'application/json', accept: 'application/json', 'accept-encoding': 'identity', 'x-no-aliasing': 'true', 'user-agent': `oberig/${VERSION}` },
    body: bytes,
    signal: AbortSignal.timeout(120000),
  });
  const raw = Buffer.from(await res.arrayBuffer());
  if (!res.ok) return { status: 'failed', reason: `chat returned ${res.status}: ${raw.toString('utf8').slice(0, 200)}` };
  const j = JSON.parse(raw.toString('utf8'));
  const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
  const sig = await V.fetchSignature(cfg, j.id);
  const out = V.checkSignature(sig, { model: cfg.model, requestHash: sha(bytes), responseHash: sha(raw), attestation: a });
  out.answer = String((j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) || '').slice(0, 80);
  return out;
}

async function cmdVerify(args) {
  const cfg = loadConfig();
  const a = await V.attest(cfg);
  let chat = null;
  if (args.chat) {
    if (!cfg.apiKey) chat = { status: 'unavailable', reason: 'no key set (NEARAI_API_KEY), so no test prompt was sent' };
    else if (!a.ok) chat = { status: 'unavailable', reason: 'enclave not attested, so no test prompt was sent' };
    else {
      try { chat = await testChat(cfg, a); } catch (err) { chat = { status: 'failed', reason: err.message }; }
    }
  }
  const rec = R.seal({
    kind: 'enclave-receipt', time: Date.now(),
    attestation: { model: a.model, ok: !!a.ok, nonce: a.nonce, signer: a.signer, gatewaySigner: a.gatewaySigner, algo: a.algo, mode: cfg.verifyMode, tcb: a.tcb, error: a.error || null, checks: (a.checks || []).map((c) => ({ label: c.label, status: c.status, detail: c.detail })) },
    chat: chat ? { status: chat.status, kind: chat.kind || null, reason: chat.reason || null } : null,
  });
  if (args.json) process.stdout.write(JSON.stringify({ ...rec, attestation: { ...rec.attestation, gateway: undefined } }, null, 2) + '\n');
  else process.stdout.write(ui.enclaveReceipt({ ...rec, attestation: { ...rec.attestation, gateway: a.gateway } }, { color: ui.useColor(), details: !!args.details }));
  process.exitCode = a.ok ? 0 : 1;
}

function cmdShield(args) {
  const file = args._[1];
  if (!file) die('usage: oberig shield <file>');
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (err) { die(`cannot read ${file}: ${err.message}`); }
  const r = Shield.scan(text, { scope: 'full', mode: 'warn' });
  if (args.json) {
    process.stdout.write(JSON.stringify({ file, count: r.count, findings: r.findings }, null, 2) + '\n');
    process.exitCode = r.count ? 1 : 0;
    return;
  }
  const k = ui.colors(ui.useColor());
  const out = ['', `  ${k.bold('OBERIG · shield')}  ${path.basename(file)}`, ''];
  if (!r.count) out.push(`  ${k.gold('✓')} no hidden instructions found`);
  else {
    out.push(`  ${k.red('⚑')} ${r.count} hidden instruction${r.count === 1 ? '' : 's'} found`, '');
    for (const f of r.findings) {
      out.push(`  line ${String(f.line).padEnd(5)} ${f.label}`);
      if (f.hidden && f.rule === 'unicode-tags') out.push(`             hidden text: "${f.hidden.slice(0, 120)}"`);
      else out.push(`             ${k.dim(f.excerpt.replace(/\s+/g, ' ').slice(0, 110))}`);
    }
    out.push('', `  ${k.dim('The gateway (OBERIG_SHIELD=block) removes these parts before the model reads them.')}`);
  }
  out.push('');
  process.stdout.write(out.join('\n') + '\n');
  process.exitCode = r.count ? 1 : 0;
}

async function cmdScrub(args) {
  const target = args._[1];
  if (!target) die('usage: oberig scrub <file|folder> [--out <path>]');
  let s;
  try { s = scrubPath(target, { out: typeof args.out === 'string' ? args.out : undefined }); } catch (err) { die(err.message); }
  const k = ui.colors(ui.useColor());
  const c = s.counts;
  const size = s.bytes >= 1048576 ? (s.bytes / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(s.bytes / 1024)) + ' KB';
  const lines = [
    '', `  ${k.bold('OBERIG · scrub')}`, '',
    `  read      ${s.files} file${s.files === 1 ? '' : 's'} · ${size} · originals unchanged`,
    `  wrote     ${s.output}`,
    '',
    `  secrets   ${String(c.SECRET).padEnd(6)} emails  ${String(c.EMAIL).padEnd(6)} phones  ${String(c.PHONE).padEnd(6)} cards  ${c.CARD}`,
    `  paths     ${String(c.PATH).padEnd(6)} users   ${String(c.USER).padEnd(6)} hosts   ${c.HOST}`,
  ];
  if (s.skipped.length) lines.push(`  skipped   ${s.skipped.length} (${[...new Set(s.skipped.map((x) => x.reason))].join(', ')})`);
  lines.push('', `  ${k.dim('Read the copies before you share them. Pattern matching can miss things.')}`, '');
  process.stdout.write(lines.join('\n') + '\n');
  // Tell a running gateway (if any) so its dashboard counter moves. Metadata only.
  try {
    const port = Number(process.env.OBERIG_PORT || 8790);
    await fetch(`http://127.0.0.1:${port}/_oberig/scrubbed`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ files: s.files, items: s.items }), signal: AbortSignal.timeout(800),
    });
  } catch { /* no gateway running */ }
}

function cmdSetup() {
  const port = Number(process.env.OBERIG_PORT || 8790);
  const base = `http://127.0.0.1:${port}`;
  const model = process.env.OBERIG_MODEL || 'deepseek-ai/DeepSeek-V4.1-Flash-1017';
  process.stdout.write(`
  OBERIG · setup

  1. Start Oberig with your NEAR AI key in the environment

     PowerShell        $env:NEARAI_API_KEY = "<your key>"; npx github:oberiglabs-dev/oberig
     macOS / Linux     NEARAI_API_KEY="<your key>" npx github:oberiglabs-dev/oberig

     From a clone of the repo, use node bin/oberig.js instead of npx github:oberiglabs-dev/oberig.
     If PowerShell says running scripts is disabled, type npx.cmd instead of npx.

  2. Point your agent at it (any model name works; Oberig always uses
     ${model} on NEAR AI)

  Claude Code
     PowerShell        $env:ANTHROPIC_BASE_URL = "${base}"; $env:ANTHROPIC_AUTH_TOKEN = "oberig"; claude
     macOS / Linux     ANTHROPIC_BASE_URL=${base} ANTHROPIC_AUTH_TOKEN=oberig claude

  Codex (~/.codex/config.toml; the first two lines go above any [section])
     model = "${model}"
     model_provider = "oberig"

     [model_providers.oberig]
     name = "Oberig"
     base_url = "${base}/v1"

     Codex speaks the Responses API. Oberig serves it at /v1/responses.

  OpenCode (opencode.json)
     {
       "$schema": "https://opencode.ai/config.json",
       "model": "oberig/${model}",
       "providers": {
         "oberig": {
           "name": "Oberig",
           "package": "@opencode/ai/providers/openai-compatible",
           "settings": { "baseURL": "${base}/v1" },
           "models": { "${model}": {} }
         }
       }
     }

     OpenCode 1.x uses the older shape: "provider" with
     "npm": "@ai-sdk/openai-compatible" and "options": { "baseURL": "${base}/v1" }.

  Any other OpenAI-compatible tool: base URL ${base}/v1 (Chat Completions or Responses).
  The agent's own API key is ignored and never forwarded.

  Dashboard: ${base}/

`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];
  if (args.version) { process.stdout.write(`oberig ${VERSION}\n`); return; }
  if (args.help || cmd === 'help') { process.stdout.write(HELP); return; }
  try {
    if (!cmd || cmd === 'start') return await cmdStart(args);
    if (cmd === 'verify') return await cmdVerify(args);
    if (cmd === 'shield') return cmdShield(args);
    if (cmd === 'scrub') return await cmdScrub(args);
    if (cmd === 'setup') return cmdSetup();
  } catch (err) {
    die(err.message);
  }
  die(`unknown command "${cmd}". Try oberig --help`);
}

main();
