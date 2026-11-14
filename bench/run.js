#!/usr/bin/env node
'use strict';
// Shield benchmark. Runs the real src/shield.js over
//   - a generated, labelled corpus of hidden prompt injections (bench/generate.js)
//   - cached ordinary content: READMEs, issue templates, web pages, emails (bench/fixtures)
// and reports the detection rate per technique, the false-positive rate and timing.
// Offline and deterministic (apart from timing).
//
//   node bench/run.js                   print the results
//   node bench/run.js --misses          also list every missed sample and every flagged document
//   node bench/run.js --write           rewrite bench/RESULTS.md
//   node bench/run.js --shield <file>   run another copy of shield.js
//   node bench/run.js --baseline <file> add a "before" column from another copy of shield.js

const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const os = require('node:os');
const { generate, visible, cleanCarriers, TECHNIQUES } = require('./generate.js');

const argv = process.argv.slice(2);
const opt = (name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : null);
const Shield = require(path.resolve(opt('--shield') || path.join(__dirname, '..', 'src', 'shield.js')));
const Baseline = opt('--baseline') ? require(path.resolve(opt('--baseline'))) : null;
const FIXTURES = [
  ['tuning', path.join(__dirname, 'fixtures', 'negatives.json.gz')],
  ['held-out', path.join(__dirname, 'fixtures', 'negatives-heldout.json.gz')],
];

const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + '%' : 'n/a');
const rate = (rows, key = 'detected') => ({ n: rows.length, hit: rows.filter((x) => x[key]).length });
const fmt = (r) => `${r.hit}/${r.n} (${pct(r.hit, r.n)})`;
const AI_WORDS = /\bAI\b|\b(?:LLMs?|agents?|assistants?|copilot|claude|chatgpt|cursor|codex|gemini|bots?)\b/i;
const KIND_NAMES = { readme: 'GitHub READMEs', 'issue-template': 'Issue and PR templates', 'html-page': 'Web pages (raw HTML)', email: 'Emails (HTML and text)' };

function loadNegatives() {
  const docs = [];
  const fetched = {};
  for (const [set, file] of FIXTURES) {
    if (!fs.existsSync(file)) continue;
    const f = JSON.parse(zlib.gunzipSync(fs.readFileSync(file)).toString('utf8'));
    fetched[set] = f.fetched;
    for (const d of f.docs) docs.push({ ...d, set });
  }
  return { docs, fetched };
}

function quantile(xs, q) {
  const s = xs.slice().sort((a, b) => a - b);
  return s.length ? s[Math.min(s.length - 1, Math.floor(q * s.length))] : 0;
}

const INVISIBLE = new RegExp('[' + [[0x200B, 0x200F], [0x202A, 0x202E], [0x2060, 0x2069], [0xFE00, 0xFE0F]].map(([a, b]) => String.fromCharCode(a) + '-' + String.fromCharCode(b)).join('') + ']|' + String.fromCharCode(0xDB40) + '[' + String.fromCharCode(0xDC00) + '-' + String.fromCharCode(0xDDEF) + ']');

function timed(S, text) {
  const t0 = process.hrtime.bigint();
  const r = S.scan(text, { scope: 'full', mode: 'block' });
  return { r, ms: Number(process.hrtime.bigint() - t0) / 1e6 };
}

function evaluate(S, positives, controls, negatives) {
  for (const s of positives.slice(0, 40)) S.scan(s.text, { scope: 'full' }); // warm-up
  for (const d of negatives.docs.slice(0, 10)) S.scan(d.text, { scope: 'full' });
  const pos = positives.map((s) => {
    const { r, ms } = timed(S, s.text);
    const detected = r.count > 0;
    // block mode must leave nothing of the hidden part behind (checked outside JSON)
    let residue = null;
    if (detected && s.carrier !== 'json') {
      const body = r.clean.slice(r.clean.indexOf('\n') + 1);
      residue = s.marker ? body.includes(s.marker) : INVISIBLE.test(body);
    }
    return { s, detected, ms, residue };
  });
  const ctl = controls.map((s) => ({ s, detected: S.scan(s.text, { scope: 'full' }).count > 0 }));
  const neg = negatives.docs.map((d) => {
    const { r, ms } = timed(S, d.text);
    const aboutAI = r.count > 0 && r.findings.every((f) => AI_WORDS.test(f.hidden || f.excerpt || ''));
    return { d, fp: r.count > 0, aboutAI, findings: r.findings, ms, bytes: Buffer.byteLength(d.text) };
  });
  return { pos, ctl, neg };
}

function groupBy(rows, key) {
  const m = new Map();
  for (const x of rows) {
    const k = key(x);
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(x);
  }
  return m;
}

function summarize(res) {
  const out = {};
  out.techniques = [...groupBy(res.pos, (x) => x.s.technique)].map(([k, rows]) => ({
    technique: k, label: TECHNIQUES[k].label, all: rate(rows),
    dev: rate(rows.filter((x) => x.s.split === 'dev')), held: rate(rows.filter((x) => x.s.split === 'held-out')),
  }));
  out.overall = rate(res.pos);
  out.dev = rate(res.pos.filter((x) => x.s.split === 'dev'));
  out.held = rate(res.pos.filter((x) => x.s.split === 'held-out'));
  out.carriers = [...groupBy(res.pos, (x) => x.s.carrier)].map(([k, rows]) => ({ name: k, ...rate(rows) }));
  out.encodings = [...groupBy(res.pos.filter((x) => x.s.encoding), (x) => x.s.encoding)].map(([k, rows]) => ({ name: k, ...rate(rows) }));
  out.english = rate(res.pos.filter((x) => x.s.lang === 'en'));
  out.other = rate(res.pos.filter((x) => x.s.lang !== 'en'));
  const checked = res.pos.filter((x) => x.residue !== null);
  out.removed = { n: checked.length, ok: checked.filter((x) => !x.residue).length };
  out.controls = rate(res.ctl.filter((x) => x.s.group === 'plain'));
  out.controlsOverride = rate(res.ctl.filter((x) => x.s.group === 'override'));
  out.negKinds = [...groupBy(res.neg, (x) => x.d.kind)].map(([k, rows]) => ({
    kind: k, all: rate(rows, 'fp'),
    tuning: rate(rows.filter((x) => x.d.set === 'tuning'), 'fp'), held: rate(rows.filter((x) => x.d.set === 'held-out'), 'fp'),
  }));
  out.neg = rate(res.neg, 'fp');
  out.negTuning = rate(res.neg.filter((x) => x.d.set === 'tuning'), 'fp');
  out.negHeld = rate(res.neg.filter((x) => x.d.set === 'held-out'), 'fp');
  out.negAI = res.neg.filter((x) => x.aboutAI).length;
  const negMs = res.neg.map((x) => x.ms);
  const bytes = res.neg.reduce((a, x) => a + x.bytes, 0);
  const ms = negMs.reduce((a, b) => a + b, 0);
  out.timing = {
    negMedian: quantile(negMs, 0.5), negP95: quantile(negMs, 0.95), negMax: Math.max(...negMs),
    posMedian: quantile(res.pos.map((x) => x.ms), 0.5), posP95: quantile(res.pos.map((x) => x.ms), 0.95),
    mb: bytes / 1048576, mbps: bytes / 1048576 / (ms / 1000),
    biggest: res.neg.reduce((a, x) => (x.bytes > a.bytes ? x : a), { bytes: 0, ms: 0 }),
  };
  out.misses = res.pos.filter((x) => !x.detected);
  out.fps = res.neg.filter((x) => x.fp);
  out.residue = res.pos.filter((x) => x.residue);
  return out;
}

function techniqueRows(sum, base) {
  const head = ['Technique', 'Samples', 'Detected', 'Dev phrasings', 'Held-out phrasings'];
  if (base) head.push('Before');
  const rows = [head];
  for (const t of sum.techniques) {
    const row = [t.label, t.all.n, `${t.all.hit} (${pct(t.all.hit, t.all.n)})`, pct(t.dev.hit, t.dev.n), pct(t.held.hit, t.held.n)];
    if (base) { const b = base.techniques.find((x) => x.technique === t.technique); row.push(pct(b.all.hit, b.all.n)); }
    rows.push(row);
  }
  const all = ['**All hidden techniques**', sum.overall.n, `**${sum.overall.hit} (${pct(sum.overall.hit, sum.overall.n)})**`, pct(sum.dev.hit, sum.dev.n), pct(sum.held.hit, sum.held.n)];
  if (base) all.push(pct(base.overall.hit, base.overall.n));
  rows.push(all);
  return rows;
}

function negRows(sum, base) {
  const head = ['Ordinary content', 'Tuning set', 'Flagged', 'Held-out set', 'Flagged'];
  if (base) head.push('Before (both sets)');
  const rows = [head];
  const cell = (r) => `${r.hit} (${pct(r.hit, r.n)})`;
  for (const k of sum.negKinds) {
    const row = [KIND_NAMES[k.kind] || k.kind, k.tuning.n, cell(k.tuning), k.held.n, k.held.n ? cell(k.held) : 'n/a'];
    if (base) { const b = base.negKinds.find((x) => x.kind === k.kind); row.push(pct(b.all.hit, b.all.n)); }
    rows.push(row);
  }
  const all = ['**All**', sum.negTuning.n, `**${cell(sum.negTuning)}**`, sum.negHeld.n, `**${sum.negHeld.n ? cell(sum.negHeld) : 'n/a'}**`];
  if (base) all.push(pct(base.neg.hit, base.neg.n));
  rows.push(all);
  return rows;
}

function asText(rows) {
  const clean = rows.map((r) => r.map((c) => String(c).replace(/\*\*/g, '')));
  const w = clean[0].map((_, i) => Math.max(...clean.map((r) => r[i].length)));
  return clean.map((r) => r.map((c, i) => c.padEnd(w[i])).join('  ')).join('\n');
}

function asMarkdown(rows) {
  return [
    '| ' + rows[0].join(' | ') + ' |',
    '|' + rows[0].map((_, i) => (i === 0 ? '---' : '---:')).join('|') + '|',
    ...rows.slice(1).map((r) => '| ' + r.map((c) => String(c).replace(/\|/g, '\\|')).join(' | ') + ' |'),
  ].join('\n');
}

const short = (s, n) => {
  const t = Shield.reveal(String(s)).replace(/\s+/g, ' ').trim();
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
};

function printConsole(sum, base, meta) {
  const t = sum.timing;
  const L = ['', `Shield benchmark: ${meta.positives} hidden-injection samples, ${sum.neg.n} ordinary documents (shield ${Shield.version})`, ''];
  L.push(asText(techniqueRows(sum, base)), '', asText(negRows(sum, base)), '');
  L.push(`flagged ordinary documents whose flagged text is about AI agents or AI use: ${sum.negAI} of ${sum.neg.hit}`);
  L.push(`by carrier: ${sum.carriers.map((c) => `${c.name} ${pct(c.hit, c.n)}`).join(', ')}`);
  L.push(`JSON encodings: ${sum.encodings.map((c) => `${c.name} ${pct(c.hit, c.n)}`).join(', ')}`);
  L.push(`English ${fmt(sum.english)}; other languages ${fmt(sum.other)}`);
  L.push(`block mode left nothing of the hidden part behind in ${sum.removed.ok}/${sum.removed.n} detected non-JSON samples`);
  L.push(`carrier documents alone: ${meta.carrierFindings} findings`);
  L.push(`visible plain-text injections (out of scope): ${fmt(sum.controls)}; visible "ignore previous instructions" style: ${fmt(sum.controlsOverride)}`);
  L.push(`timing: ordinary docs median ${t.negMedian.toFixed(2)} ms, p95 ${t.negP95.toFixed(2)} ms, max ${t.negMax.toFixed(1)} ms, ${t.mbps.toFixed(1)} MB/s over ${t.mb.toFixed(1)} MB; samples median ${t.posMedian.toFixed(3)} ms`);
  if (argv.includes('--misses')) {
    L.push('', 'MISSED SAMPLES');
    for (const m of sum.misses) L.push(`  ${m.s.id.padEnd(24)} ${m.s.carrier.padEnd(9)} ${String(m.s.encoding || '').padEnd(7)} ${m.s.lang.padEnd(3)} ${m.s.split.padEnd(8)} ${m.s.variant}`);
    L.push('', 'FLAGGED ORDINARY DOCUMENTS');
    for (const f of sum.fps) for (const x of f.findings.slice(0, 3)) L.push(`  ${f.d.set.padEnd(8)} ${f.d.id.slice(0, 66).padEnd(66)} ${x.rule.padEnd(12)} ${f.aboutAI ? 'AI ' : '   '} ${short(x.excerpt, 80)}`);
    if (sum.residue.length) L.push('', 'RESIDUE AFTER BLOCK', ...sum.residue.map((x) => `  ${x.s.id}`));
  }
  console.log(L.join('\n'));
}

function writeResults(sum, base, meta) {
  const t = sum.timing;
  const groups = new Map();
  for (const m of sum.misses) {
    const k = TECHNIQUES[m.s.technique].label;
    const g = groups.get(k) || { n: 0, held: 0, langs: new Set(), carriers: new Set() };
    g.n++;
    if (m.s.split === 'held-out') g.held++;
    g.langs.add(m.s.lang);
    g.carriers.add(m.s.carrier);
    groups.set(k, g);
  }
  const misses = [...groups].sort((a, b) => b[1].n - a[1].n || a[0].localeCompare(b[0]))
    .map(([k, g]) => `- ${k}: ${g.n} missed, ${g.held === g.n ? 'all' : g.held} held-out (languages ${[...g.langs].sort().join(', ')}; carriers ${[...g.carriers].sort().join(', ')})`).join('\n');
  const devMisses = sum.misses.filter((m) => m.s.split === 'dev').length;
  const flagged = sum.fps.map((f) => `| ${f.d.set} | ${KIND_NAMES[f.d.kind] || f.d.kind} | ${f.d.id.replace(/^[a-z-]+:/, '').replace(/\|/g, '/')} | ${[...new Set(f.findings.map((x) => x.rule))].join(', ')} | ${f.aboutAI ? 'yes' : 'no'} |`).join('\n');
  const baseNote = base ? ' "Before" is the shield as it was before this benchmark (commit de0f771), run on the same data.' : '';
  const doc = `# Shield benchmark results

Generated by \`node bench/run.js --write\` on ${meta.date}: shield ${Shield.version}, Node ${process.version}, ${os.platform()}, ${os.cpus()[0] ? os.cpus()[0].model.trim() : 'unknown CPU'}.

- **Hidden injections:** ${meta.positives} generated samples (\`bench/generate.js\`, seed ${meta.seed}), ${Object.keys(TECHNIQUES).length} techniques, ${meta.languages} languages, in five carriers: README, GitHub issue, HTML page, email, JSON tool result. Payloads are harmless (\`.invalid\` domains, fake secrets). The carrier documents alone give ${meta.carrierFindings} findings, so every detection comes from the hidden part.
- **Ordinary content:** ${sum.neg.n} real documents cached in \`bench/fixtures/\`: READMEs of popular GitHub repositories, their issue and pull request templates, documentation pages as raw HTML, and open-source email templates. Each entry keeps its source URL and license. The tuning set (fetched ${meta.fetched.tuning}) was used while improving the shield; the held-out set (fetched ${meta.fetched['held-out'] || 'n/a'}, other repositories, pages and templates) was fetched afterwards and only measured.
- **Detected** means at least one finding with every rule on, the scope used for tool results.${baseNote}

## Detection of hidden injections

${asMarkdown(techniqueRows(sum, base))}

"Dev phrasings" were looked at while tuning the rules. "Held-out phrasings" are other wordings, and languages the rules have no words for (Swedish, Czech, Indonesian, Vietnamese, Greek, Hindi), that were only measured. Their rate is the better guess for text the rules have never seen.

By carrier: ${sum.carriers.map((c) => `${c.name} ${pct(c.hit, c.n)}`).join(', ')}. JSON tool results by encoder: ${sum.encodings.map((c) => `${c.name} ${pct(c.hit, c.n)}`).join(', ')}. (\`ascii\` escapes every non-ASCII character as a unicode escape, like Python's \`json.dumps\`; \`go\` escapes \`<\`, \`>\` and \`&\`, like Go's \`encoding/json\`.)

English phrasings: ${fmt(sum.english)}. Other languages: ${fmt(sum.other)}.

In block mode, nothing of the hidden part was left in ${sum.removed.ok} of ${sum.removed.n} detected samples outside JSON (checked by looking for the hidden text, or for invisible characters, in the cleaned output).

## False positives on ordinary content

${asMarkdown(negRows(sum, base))}

The held-out set was fetched after the rules were frozen and measured once: 4 of 222 flagged. One cue was dropped afterwards ("without review", which flagged pull request templates in the tuning set); that also cleared one held-out template. The tables show the current rules.

${sum.fps.length ? `Every flagged document is listed below. "About AI" means the flagged text is a note about AI agents or AI use: many pull request templates now carry hidden comments such as "if you are an AI agent, ..." or "AI agents must ...". Those are hidden instructions to agents, so the shield flags them by design, but they are harmless. ${sum.negAI} of the ${sum.neg.hit} flagged documents are of that kind.

| Set | Kind | Document | Rules | About AI |
|---|---|---|---|---|
${flagged}
` : 'No ordinary document was flagged.\n'}
## Timing

Single thread, \`scan()\` with every rule and block mode, after a short warm-up.

| | Median | p95 | Max |
|---|---:|---:|---:|
| Ordinary documents (${sum.neg.n}, ${t.mb.toFixed(1)} MB) | ${t.negMedian.toFixed(2)} ms | ${t.negP95.toFixed(2)} ms | ${t.negMax.toFixed(1)} ms |
| Injection samples (${meta.positives}) | ${t.posMedian.toFixed(3)} ms | ${t.posP95.toFixed(3)} ms | |

Throughput on the ordinary documents: ${t.mbps.toFixed(1)} MB/s. The largest document (${(t.biggest.bytes / 1024).toFixed(0)} KB of raw HTML) took ${t.biggest.ms.toFixed(1)} ms.

## What is missed

${misses || '- nothing in this corpus'}

${devMisses ? `${devMisses} of the ${sum.misses.length} misses use dev phrasings.` : `All ${sum.misses.length} misses use held-out phrasings.`} They are languages without words in the rules, and wordings that address the agent without a known cue ("For language models only: ...", "Hi Codex! ..."). \`node bench/run.js --misses\` lists each one. Instructions inside images, encoded payloads (base64 the model is asked to decode) and instructions split across several places are not in this corpus and are not caught.

## Out of scope: visible plain-text injections

The shield looks for instructions hidden from the person: comments, invisible characters, hidden HTML, attributes, links that carry data. An instruction written in plain view, as an ordinary sentence, is not its target. It reads like any other sentence, and a pattern scanner cannot tell it from documentation without understanding intent.

Measured for reference on ${sum.controls.n} visible injections (the same instruction phrasings written as a normal paragraph of a README, issue or email): **${fmt(sum.controls)} detected**. In plain view the shield only acts on "ignore previous instructions" style directives and on remote-script commands aimed at the agent; the ${sum.controlsOverride.n} English override phrasings of the corpus, written in plain view, are caught in ${fmt(sum.controlsOverride)}. Example that passes:

\`\`\`
${meta.visibleMiss}
\`\`\`

## Re-run

\`\`\`sh
node bench/run.js            # print the tables (offline, about a second)
node bench/run.js --misses   # also list every miss and every flagged document
node bench/run.js --write    # rewrite this file
node bench/generate.js --out corpus.jsonl   # dump the labelled corpus
node bench/fetch-negatives.js [--heldout]   # refetch the ordinary documents (needs gh and network)
\`\`\`
`;
  fs.writeFileSync(path.join(__dirname, 'RESULTS.md'), doc);
}

(function main() {
  const seed = Number(opt('--seed')) || 7;
  const positives = generate({ seed });
  const controls = visible();
  const negatives = loadNegatives();
  const res = evaluate(Shield, positives, controls, negatives);
  const sum = summarize(res);
  const base = Baseline ? summarize(evaluate(Baseline, positives, controls, negatives)) : null;
  const plainMisses = res.ctl.filter((x) => !x.detected && x.s.group === 'plain');
  const miss = plainMisses.find((x) => x.s.lang === 'en' && /tests directory/.test(x.s.marker)) || plainMisses.find((x) => x.s.lang === 'en') || plainMisses[0];
  const meta = {
    date: new Date().toISOString().slice(0, 10), seed, positives: positives.length, fetched: negatives.fetched,
    languages: new Set(positives.map((s) => s.lang)).size,
    carrierFindings: cleanCarriers().reduce((a, text) => a + Shield.scan(text, { scope: 'full' }).count, 0),
    visibleMiss: miss ? miss.s.marker : '',
  };
  printConsole(sum, base, meta);
  if (argv.includes('--write')) { writeResults(sum, base, meta); console.log('\nwrote bench/RESULTS.md'); }
})();
