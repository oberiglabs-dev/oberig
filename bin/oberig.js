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
  oberig anchor [--send]     put the Merkle root of this session's receipt hashes on
                             NEAR (SocialDB, under your account). Without --send it is
                             a dry run that only reads from the chain.
        [--receipts <file>]  anchor receipts from a file instead of the gateway
        [--out <file>]       save the root and all leaves, to prove any receipt later
        [--network mainnet|testnet] [--account <id>]
  oberig anchor --check <receipt-hash|root> [--receipts <file> | --proof <file>]
                             check an anchor with a free view call (--out writes a proof)
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
  NEAR_ACCOUNT_ID            your NEAR account for oberig anchor (for example name.near)
  NEAR_PRIVATE_KEY           its key, ed25519:... (only for --send; never read from files)
  NEAR_RPC_URL               optional NEAR RPC address
  More in the README.
`;

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) out[a.slice(2, eq)] = a.slice(eq + 1);
      else if (['port', 'out', 'receipts', 'proof', 'network', 'account', 'check'].includes(a.slice(2)) && argv[i + 1] && !argv[i + 1].startsWith('--')) out[a.slice(2)] = argv[++i];
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
  gw.events.on('anchored', (a) => { if (!cfg.quiet) process.stdout.write(ui.anchorLine(a, color) + '\n'); });
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

// ---- oberig anchor ----

function anchorDeps() {
  return { A: require('../src/near/anchor.js'), N: require('../src/near/rpc.js'), T: require('../src/near/tx.js'), M: require('../src/near/merkle.js') };
}

function hostOf(url) { try { return new URL(url).host; } catch { return url; } }

function writeJson(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2) + '\n');
}

function planLines(p, { net, source, k, A }) {
  const c = p.cost;
  const row = (key, val) => `  ${key.padEnd(10)}${val}`;
  const out = [];
  out.push(row('receipts', `${p.count} from ${source}`));
  out.push(row('root', p.root));
  out.push(row('', k.dim('RFC 6962 Merkle tree (SHA-256) of the receipt hashes, oldest first')));
  out.push(row('network', `${net.name} · RPC ${hostOf(net.rpc[0])}`));
  out.push(row('contract', `${p.contract} · set (SocialDB)`));
  out.push(row('record', p.key));
  out.push(row('value', p.value));
  out.push('');
  out.push(row('account', p.account ? `${p.accountId} · ${A.near(p.balance)} NEAR` : `${p.accountId} · not found on ${net.name}`));
  let signer = 'NEAR_PRIVATE_KEY not set (only --send needs it)';
  if (p.signer) {
    const ak = p.accessKey;
    const perm = !ak ? 'not a key of this account' : ak.permission === 'FullAccess' ? 'full access' : 'function-call key';
    signer = `${p.signer} · ${perm}`;
  }
  out.push(row('signer', signer));
  out.push(row('socialdb', p.registered
    ? `registered · ${p.storage.available_bytes} prepaid bytes free`
    : 'not registered yet: the first write registers the account (0.02 NEAR minimum deposit)'));
  out.push('');
  out.push(row('cost', `storage  about ${A.near(c.keep)} NEAR stays in SocialDB for this record (about ${c.bytes} bytes)`));
  out.push(row('', c.deposit > 0n
    ? `deposit  ${A.near(c.deposit)} NEAR attached; the part the record does not use comes back in the same transaction`
    : 'deposit  none: the prepaid SocialDB storage covers it'));
  out.push(row('', `gas      about ${A.near(c.gasUsed)} NEAR used; ${A.near(c.gasHeld, 3)} NEAR is reserved while it runs, the rest comes back (${Number(c.gas / 1000000000000n)} TGas)`));
  out.push(row('', `needs    about ${A.near(c.needed, 3)} NEAR available in ${p.accountId}`));
  if (p.problems.length) {
    out.push('');
    for (const pr of p.problems) out.push(`  ${k.red('✗')} ${pr}`);
  }
  return out;
}

async function cmdAnchorCheck(args, ctx) {
  const { A, N, M } = anchorDeps();
  const k = ui.colors(ui.useColor());
  const X = String(args.check === true ? '' : args.check).trim().toLowerCase();
  if (!A.isHex64(X)) die('usage: oberig anchor --check <receipt-hash|root>  (64 hex characters)');
  const flagNet = typeof args.network === 'string' ? args.network : null;
  let found = { root: X, receipt: null, proof: null, account: ctx.accountId || null, network: flagNet || 'mainnet', note: null };
  const file = typeof args.proof === 'string' ? args.proof : typeof args.receipts === 'string' ? args.receipts : null;
  if (file) {
    let f;
    try { f = A.loadFile(file); } catch (err) { die(err.message); }
    if (f.kind === 'proof') {
      const pr = f.proof;
      const r = A.proofRoot(pr);
      if (!r || !A.isHex64(pr.root)) die(`${file} is not a valid proof file`);
      if (X !== pr.receipt && X !== pr.root) die(`${file} is a proof for another receipt`);
      if (r !== pr.root) {
        process.stdout.write(`\n  ${k.red('✗')} the proof in ${file} does not lead to its root. It proves nothing.\n\n`);
        process.exitCode = 1;
        return;
      }
      found = { root: pr.root, receipt: pr.receipt, proof: pr, account: ctx.flagAccount || pr.account, network: flagNet || pr.network || 'mainnet', note: `proof from ${path.basename(file)}` };
    } else {
      const { hashes, bad } = A.receiptHashes(f.items);
      if (bad.length) die(`${file}: ${bad.length} receipt(s) do not match their hash or are not receipt hashes (${bad.slice(0, 3).join(', ')})`);
      if (f.kind === 'anchor') {
        const a = f.anchor;
        if (!hashes.length || M.root(hashes).toString('hex') !== a.root) die(`${file} is damaged: its leaves do not give its root`);
        if (X !== a.root && !hashes.includes(X)) die(`this hash is neither the root nor a receipt in ${file}`);
        found = { root: a.root, receipt: X !== a.root ? X : null, proof: X !== a.root ? A.proofFor(hashes, X, a) : null, account: ctx.flagAccount || a.account, network: flagNet || a.network || 'mainnet', note: `leaves from ${path.basename(file)}` };
      } else if (hashes.includes(X)) {
        const meta = { network: flagNet || 'mainnet', account: ctx.accountId, contract: null };
        found = { root: M.root(hashes).toString('hex'), receipt: X, proof: A.proofFor(hashes, X, meta), account: ctx.accountId || null, network: meta.network, note: `root of all ${hashes.length} receipts in ${path.basename(file)}` };
      }
    }
  } else {
    const gw = await A.fromGateway(ctx.port);
    if (gw) {
      const hit = (gw.anchors || []).slice().reverse().find((a) => a.root === X || (a.leaves || []).includes(X));
      if (hit) {
        const isRoot = hit.root === X;
        found = { root: hit.root, receipt: isRoot ? null : X, proof: isRoot ? null : A.proofFor(hit.leaves, X, hit), account: ctx.flagAccount || hit.account, network: flagNet || hit.network, note: 'anchored earlier in this session' };
      } else if ((gw.receipts || []).some((r) => r.hash === X)) {
        process.stdout.write(`\n  ${k.red('✗')} this receipt is in the running session but has not been anchored yet. Run oberig anchor --send.\n\n`);
        process.exitCode = 1;
        return;
      }
    }
  }
  if (!found.account) die('which account anchored it? Pass --account <id> or set NEAR_ACCOUNT_ID');
  if (found.proof && A.proofRoot(found.proof) !== found.root) {
    process.stdout.write(`\n  ${k.red('✗')} the inclusion proof does not lead to the root. It proves nothing.\n\n`);
    process.exitCode = 1;
    return;
  }
  let net;
  try { net = N.network(found.network); } catch (err) { die(err.message); }
  const rpc = N.createRpc({ urls: net.rpc });
  if (found.proof && found.proof.contract == null) found.proof.contract = net.social;
  if (found.proof && found.proof.account == null) found.proof.account = found.account;
  let c;
  try { c = await A.check({ rpc, net, accountId: found.account, root: found.root }); } catch (err) { die(`view call failed: ${err.message}`); }
  if (typeof args.out === 'string' && found.proof) writeJson(args.out, found.proof);
  if (args.json) {
    process.stdout.write(JSON.stringify({ root: found.root, receipt: found.receipt, network: net.id, contract: net.social, account: found.account, found: c.found, key: c.key, blockHeight: c.blockHeight || null, record: c.record || null, proof: found.proof }, null, 2) + '\n');
    process.exitCode = c.found ? 0 : 1;
    return;
  }
  const row = (key, val) => `  ${key.padEnd(10)}${val}`;
  const out = ['', `  ${k.bold('OBERIG · anchor check')}`, ''];
  if (found.receipt) {
    out.push(row('receipt', found.receipt));
    out.push(row('', `${k.gold('✓')} leaf ${found.proof.index + 1} of ${found.proof.size}; its proof (${found.proof.path.length} hash${found.proof.path.length === 1 ? '' : 'es'}) leads to the root`));
  }
  out.push(row('root', found.root));
  if (found.note) out.push(row('', k.dim(found.note)));
  out.push(row('network', `${net.name} · ${net.social}`));
  out.push(row('record', c.key));
  out.push('');
  if (c.found) {
    const r = c.record || {};
    const when = typeof r.t === 'string' ? ` · sealed ${r.t.replace('T', ' ').replace('Z', ' UTC')}` : '';
    out.push(`  ${k.gold('✓')} anchored on chain${c.blockHeight ? ` at block ${c.blockHeight}` : ''}${r.n ? ` · ${r.n} receipt${r.n === 1 ? '' : 's'}` : ''}${when}`);
  } else {
    out.push(`  ${k.red('✗')} no anchor record for this root under ${found.account} on ${net.name}`);
  }
  out.push('', `  ${k.dim('Checked with a free view call (SocialDB get). Nothing was signed or paid.')}`);
  if (typeof args.out === 'string' && found.proof) out.push(`  ${k.dim('Proof written to ' + args.out + '; anyone can check it with oberig anchor --check <receipt> --proof <file>.')}`);
  else if (typeof args.out === 'string') out.push(`  ${k.dim('No proof written: --out saves a proof when you check a receipt, not a root.')}`);
  out.push('');
  process.stdout.write(out.join('\n') + '\n');
  process.exitCode = c.found ? 0 : 1;
}

async function cmdAnchor(args) {
  const { A, N, T } = anchorDeps();
  const k = ui.colors(ui.useColor());
  const port = Number(args.port || process.env.OBERIG_PORT || 8790);
  const flagAccount = typeof args.account === 'string' ? args.account.trim() : null;
  const accountId = flagAccount || String(process.env.NEAR_ACCOUNT_ID || '').trim();
  if (args.check !== undefined) return cmdAnchorCheck(args, { port, accountId, flagAccount });

  let net;
  try { net = N.network(typeof args.network === 'string' ? args.network : 'mainnet'); } catch (err) { die(err.message); }
  let items;
  let source;
  if (typeof args.receipts === 'string') {
    let f;
    try { f = A.loadFile(args.receipts); } catch (err) { die(err.message); }
    if (f.kind === 'proof') die('a proof file can be checked (--check), not anchored');
    items = f.items;
    source = args.receipts;
  } else {
    const gw = await A.fromGateway(port);
    if (!gw) die(`no Oberig gateway answered on 127.0.0.1:${port}, and no --receipts file was given. Start the gateway (oberig start) or pass --receipts <file>.`);
    items = gw.receipts;
    source = `the running gateway (127.0.0.1:${port})`;
  }
  const { hashes, bad } = A.receiptHashes(items);
  if (bad.length) die(`${bad.length} receipt(s) do not match their hash or are not receipt hashes (${bad.slice(0, 3).join(', ')}). Nothing was anchored.`);
  if (!hashes.length) die('no receipts to anchor yet. Each request through the gateway adds one.');
  if (!accountId) die('set NEAR_ACCOUNT_ID to your NEAR account (for example name.near) or pass --account <id>');
  if (!T.isAccountId(accountId)) die(`"${accountId}" is not a valid NEAR account id`);

  let signer = null;
  if (process.env.NEAR_PRIVATE_KEY) {
    try { signer = T.keyPairFromSecret(process.env.NEAR_PRIVATE_KEY); } catch (err) { die(err.message); }
  }
  if (args.send && !signer) die('--send needs NEAR_PRIVATE_KEY (ed25519:...) in the environment. Oberig never reads keys from files.');

  const rpc = N.createRpc({ urls: net.rpc });
  let p;
  try { p = await A.plan({ rpc, net, accountId, signer, hashes }); } catch (err) { die(`could not read from ${net.name}: ${err.message}`); }

  const head = ['', `  ${k.bold('OBERIG · anchor')}${args.send ? '' : '  ' + k.dim('dry run: only reads from the chain, nothing is signed or sent')}`, ''];
  if (!args.send) {
    if (typeof args.out === 'string') writeJson(args.out, A.anchorFile(p, null));
    if (args.json) {
      process.stdout.write(JSON.stringify(jsonPlan(p, net, A), null, 2) + '\n');
      return;
    }
    const lines = [...head, ...planLines(p, { net, source, k, A }), ''];
    lines.push(`  Nothing was sent. Add --send to sign with NEAR_PRIVATE_KEY and publish the root.`);
    if (typeof args.out === 'string') lines.push(`  ${k.dim('Root and leaves written to ' + args.out + '.')}`);
    lines.push('');
    process.stdout.write(lines.join('\n') + '\n');
    return;
  }

  if (p.problems.length) {
    process.stdout.write([...head, ...planLines(p, { net, source, k, A }), '', '  Nothing was sent.', ''].join('\n') + '\n');
    process.exitCode = 1;
    return;
  }
  if (!args.json) process.stdout.write([...head, ...planLines(p, { net, source, k, A }), '', `  signing with ${signer.publicKeyText} and sending…`, ''].join('\n') + '\n');
  let r;
  try { r = await A.send(p, { rpc, net, signer }); } catch (err) { die(err.message); }
  const anchor = { root: p.root, network: net.id, account: accountId, contract: net.social, tx: r.hash, block: r.blockHeight || null, leaves: hashes };
  let told = false;
  if (r.ok) {
    told = await A.tellGateway(port, anchor);
    if (typeof args.out === 'string') writeJson(args.out, A.anchorFile(p, r));
  }
  if (args.json) {
    process.stdout.write(JSON.stringify({ ...jsonPlan(p, net, A), dryRun: false, sent: true, ok: r.ok, tx: r.hash, explorer: r.explorer, blockHeight: r.blockHeight || null, confirmed: !!r.confirmed, reason: r.reason || null }, null, 2) + '\n');
    process.exitCode = r.ok ? 0 : 1;
    return;
  }
  const out = [];
  if (r.ok) {
    out.push(`  ${k.gold('✓')} anchored${r.blockHeight ? ` at block ${r.blockHeight}` : ''} · ${p.count} receipt${p.count === 1 ? '' : 's'} · root ${p.root.slice(0, 8)}…${p.root.slice(-8)}`);
    out.push(`  tx        ${r.hash}`);
    out.push(`  explorer  ${r.explorer}`);
    out.push(r.confirmed ? `  view      ${k.gold('✓')} the record reads back with a view call` : `  view      ${k.dim('not readable yet; it shows once the block is final (oberig anchor --check ' + p.root + ')')}`);
    if (told) out.push(`  ${k.dim('The dashboard now marks these receipts as anchored.')}`);
    if (typeof args.out === 'string') out.push(`  ${k.dim('Root and leaves written to ' + args.out + ': keep it to prove any receipt later.')}`);
    else out.push(`  ${k.dim('Tip: --out <file> saves the leaves, so you can prove a receipt after the gateway stops.')}`);
  } else {
    out.push(`  ${k.red('✗')} not anchored: ${r.reason}`);
    if (r.sent) out.push(`  tx        ${r.hash}`, `  explorer  ${r.explorer}`);
  }
  out.push('');
  process.stdout.write(out.join('\n') + '\n');
  process.exitCode = r.ok ? 0 : 1;
}

function jsonPlan(p, net, A) {
  const c = p.cost;
  return {
    dryRun: true, network: net.id, rpc: net.rpc[0], contract: p.contract, method: 'set', account: p.accountId,
    accountExists: !!p.account, balance: p.balance.toString(), signer: p.signer, accessKey: p.accessKey ? (p.accessKey.permission === 'FullAccess' ? 'FullAccess' : 'FunctionCall') : null,
    socialdbRegistered: p.registered, receipts: p.count, root: p.root, key: p.key, value: p.value,
    cost: { bytes: c.bytes, storageNear: A.near(c.keep), depositYocto: c.deposit.toString(), depositNear: A.near(c.deposit), gas: c.gas.toString(), gasUsedNear: A.near(c.gasUsed), gasHeldNear: A.near(c.gasHeld), neededNear: A.near(c.needed) },
    problems: p.problems,
  };
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
    if (cmd === 'anchor') return await cmdAnchor(args);
  } catch (err) {
    die(err.message);
  }
  die(`unknown command "${cmd}". Try oberig --help`);
}

main();
