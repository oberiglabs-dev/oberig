#!/usr/bin/env node
'use strict';
// Builds the cached negative fixture: ordinary content with no injections.
//   - READMEs of popular GitHub repositories (top by stars, licensed, capped per language)
//   - a few README translations in right-to-left scripts (Arabic, Persian, Hebrew, Urdu)
//   - issue and pull request templates from the same repositories
//   - documentation and blog pages from openly licensed sites
//   - open-source email templates (HTML and plain text), placeholders filled with sample values
//
// Needs network access and the GitHub CLI (`gh`, logged in). The benchmark itself
// (`node bench/run.js`) runs offline from the saved fixture.
//
//   node bench/fetch-negatives.js             tuning set: negatives.json.gz
//   node bench/fetch-negatives.js --heldout   held-out set: negatives-heldout.json.gz
//
// The held-out set was fetched after the shield had been tuned on the tuning set:
// other repositories (less starred), other pages, other email templates.

const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { execFile } = require('node:child_process');

const argv = process.argv.slice(2);
const HELDOUT = argv.includes('--heldout');
const OUT = path.join(__dirname, 'fixtures', HELDOUT ? 'negatives-heldout.json.gz' : 'negatives.json.gz');
const WANT_READMES = HELDOUT ? 100 : 200;
const PER_LANGUAGE = HELDOUT ? 12 : 22;
const STARS = HELDOUT ? 'stars:6000..14999' : 'stars:>15000';
const UA = 'Mozilla/5.0 (compatible; fixture-fetch/1.0)';

function gh(args) {
  return new Promise((resolve, reject) => {
    execFile('gh', ['api', ...args], { maxBuffer: 64 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
      if (err) reject(new Error(String(stderr || err.message).trim().split('\n')[0]));
      else resolve(stdout);
    });
  });
}
const ghJson = async (args) => JSON.parse(await gh(args));
const b64 = (s) => Buffer.from(String(s || '').replace(/\s+/g, ''), 'base64').toString('utf8');

async function pool(items, n, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: n }, async () => {
    while (next < items.length) {
      const i = next++;
      try { out[i] = await fn(items[i], i); } catch (err) { out[i] = { error: err.message }; }
    }
  }));
  return out;
}

const OPEN_LICENSE = /^(?:MIT|MIT-0|Apache-2\.0|BSD-[234]-Clause.*|ISC|0BSD|Unlicense|CC0-1\.0|CC-BY-4\.0|CC-BY-SA-4\.0|MPL-2\.0|LGPL-[23]\.[01].*|GPL-[23]\.0.*|AGPL-3\.0.*|EPL-[12]\.0|Zlib|BSL-1\.0|Artistic-2\.0|PSF-2\.0|OFL-1\.1|WTFPL|Vim|PostgreSQL|Python-2\.0|BlueOak-1\.0\.0)$/;

async function topRepos() {
  const seen = new Map();
  for (let page = 1; page <= (HELDOUT ? 3 : 5); page++) {
    const r = await ghJson(['-X', 'GET', 'search/repositories', '-f', `q=${STARS}`, '-f', 'sort=stars', '-f', 'order=desc', '-f', 'per_page=100', '-f', `page=${page}`]);
    for (const it of r.items || []) {
      const lic = it.license && it.license.spdx_id;
      if (!lic || !OPEN_LICENSE.test(lic) || it.archived || it.disabled) continue;
      seen.set(it.full_name, { repo: it.full_name, license: lic, language: it.language || 'none', stars: it.stargazers_count, branch: it.default_branch });
    }
  }
  const perLang = {};
  const picked = [];
  for (const r of seen.values()) {
    perLang[r.language] = (perLang[r.language] || 0) + 1;
    if (perLang[r.language] > PER_LANGUAGE) continue;
    picked.push(r);
    if (picked.length >= WANT_READMES) break;
  }
  return picked;
}

async function readme(r) {
  const j = await ghJson([`repos/${r.repo}/readme`]);
  return { kind: 'readme', id: `readme:${r.repo}`, source: j.html_url, sha: j.sha, license: r.license, language: r.language, text: b64(j.content) };
}

async function templates(r) {
  const out = [];
  const tryFile = async (p) => {
    try {
      const j = await ghJson([`repos/${r.repo}/contents/${p}`]);
      if (j && j.type === 'file' && j.content) out.push({ kind: 'issue-template', id: `template:${r.repo}/${p}`, source: j.html_url, sha: j.sha, license: r.license, text: b64(j.content) });
    } catch (_) { /* absent */ }
  };
  try {
    const list = await ghJson([`repos/${r.repo}/contents/.github/ISSUE_TEMPLATE`]);
    const md = (Array.isArray(list) ? list : []).filter((f) => f.type === 'file' && /\.md$/i.test(f.name)).slice(0, 2);
    for (const f of md) await tryFile(f.path);
  } catch (_) { /* no issue templates */ }
  for (const p of ['.github/PULL_REQUEST_TEMPLATE.md', '.github/pull_request_template.md']) {
    if (out.some((o) => /pull_request_template/i.test(o.id))) break;
    await tryFile(p);
  }
  return out;
}

const TRANSLATIONS = [
  ['ziishaned/learn-regex', 'translations/README-fa.md', 'MIT'],
  ['ziishaned/learn-regex', 'translations/README-he.md', 'MIT'],
  ['jwasham/coding-interview-university', 'translations/README-ar.md', 'CC-BY-SA-4.0'],
  ['jwasham/coding-interview-university', 'translations/README-fa.md', 'CC-BY-SA-4.0'],
  ['jwasham/coding-interview-university', 'translations/README-he.md', 'CC-BY-SA-4.0'],
  ['jwasham/coding-interview-university', 'translations/README-ur.md', 'CC-BY-SA-4.0'],
  ['trekhleb/javascript-algorithms', 'README.ar-AR.md', 'MIT'],
  ['trekhleb/javascript-algorithms', 'README.he-IL.md', 'MIT'],
];

async function translation([repo, p, license]) {
  const j = await ghJson([`repos/${repo}/contents/${p}`]);
  return { kind: 'readme', id: `readme:${repo}/${p}`, source: j.html_url, sha: j.sha, license, language: 'rtl-translation', text: b64(j.content) };
}

// Documentation and blog pages, fetched as raw HTML (what `curl` or a raw fetch tool returns).
const PAGES = [
  ['https://nodejs.org/en/learn/getting-started/introduction-to-nodejs', 'MIT'],
  ['https://nodejs.org/api/fs.html', 'MIT'],
  ['https://docs.python.org/3/tutorial/venv.html', 'PSF-2.0'],
  ['https://docs.python.org/3/library/json.html', 'PSF-2.0'],
  ['https://go.dev/doc/install', 'CC-BY-4.0'],
  ['https://go.dev/doc/tutorial/getting-started', 'CC-BY-4.0'],
  ['https://go.dev/blog/', 'CC-BY-4.0'],
  ['https://www.rust-lang.org/tools/install', 'MIT OR Apache-2.0'],
  ['https://rustup.rs/', 'MIT OR Apache-2.0'],
  ['https://doc.rust-lang.org/book/ch01-01-installation.html', 'MIT OR Apache-2.0'],
  ['https://blog.rust-lang.org/', 'MIT OR Apache-2.0'],
  ['https://react.dev/learn', 'CC-BY-4.0'],
  ['https://vuejs.org/guide/quick-start.html', 'MIT'],
  ['https://svelte.dev/docs/svelte/overview', 'MIT'],
  ['https://expressjs.com/en/starter/installing.html', 'CC-BY-SA-3.0'],
  ['https://fastapi.tiangolo.com/tutorial/first-steps/', 'MIT'],
  ['https://flask.palletsprojects.com/en/stable/quickstart/', 'BSD-3-Clause'],
  ['https://docs.djangoproject.com/en/5.1/intro/tutorial01/', 'BSD-3-Clause'],
  ['https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/', 'CC-BY-4.0'],
  ['https://docs.docker.com/get-started/', 'Apache-2.0'],
  ['https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/details', 'CC-BY-SA-2.5'],
  ['https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Properties/display', 'CC-BY-SA-2.5'],
  ['https://en.wikipedia.org/wiki/Markdown', 'CC-BY-SA-4.0'],
  ['https://en.wikipedia.org/wiki/Git', 'CC-BY-SA-4.0'],
  ['https://en.wikipedia.org/wiki/Unicode', 'CC-BY-SA-4.0'],
  ['https://www.typescriptlang.org/docs/handbook/2/basic-types.html', 'CC-BY-4.0'],
  ['https://docs.github.com/en/get-started/git-basics/set-up-git', 'CC-BY-4.0'],
  ['https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent', 'CC-BY-4.0'],
  ['https://learn.microsoft.com/en-us/windows/wsl/install', 'CC-BY-4.0'],
  ['https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows', 'CC-BY-4.0'],
  ['https://docs.deno.com/runtime/getting_started/installation/', 'MIT'],
  ['https://bun.sh/docs/installation', 'MIT'],
  ['https://docs.astral.sh/uv/getting-started/installation/', 'MIT OR Apache-2.0'],
  ['https://brew.sh/', 'BSD-2-Clause'],
  ['https://pnpm.io/installation', 'MIT'],
  ['https://www.sqlite.org/about.html', 'public domain'],
  ['https://curl.se/docs/manpage.html', 'curl'],
  ['https://nginx.org/en/docs/beginners_guide.html', 'BSD-2-Clause'],
  ['https://www.postgresql.org/docs/current/tutorial-start.html', 'PostgreSQL'],
  ['https://getbootstrap.com/docs/5.3/getting-started/introduction/', 'CC-BY-3.0'],
  ['https://webpack.js.org/guides/getting-started/', 'CC-BY-4.0'],
  ['https://vite.dev/guide/', 'MIT'],
  ['https://kotlinlang.org/docs/getting-started.html', 'Apache-2.0'],
  ['https://docs.flutter.dev/get-started/install', 'CC-BY-4.0'],
  ['https://jquery.com/', 'MIT'],
  ['https://babeljs.io/docs/', 'MIT'],
];

const PAGES_HELDOUT = [
  ['https://docs.python.org/3/tutorial/introduction.html', 'PSF-2.0'],
  ['https://docs.python.org/3/library/os.html', 'PSF-2.0'],
  ['https://go.dev/doc/effective_go', 'CC-BY-4.0'],
  ['https://doc.rust-lang.org/book/ch03-01-variables-and-mutability.html', 'MIT OR Apache-2.0'],
  ['https://nodejs.org/en/download', 'MIT'],
  ['https://react.dev/learn/installation', 'CC-BY-4.0'],
  ['https://vuejs.org/guide/introduction.html', 'MIT'],
  ['https://docs.astral.sh/ruff/installation/', 'MIT'],
  ['https://kubernetes.io/docs/tasks/tools/install-kubectl-macos/', 'CC-BY-4.0'],
  ['https://docs.docker.com/engine/install/ubuntu/', 'Apache-2.0'],
  ['https://learn.microsoft.com/en-us/windows/package-manager/winget/', 'CC-BY-4.0'],
  ['https://docs.github.com/en/get-started/start-your-journey/hello-world', 'CC-BY-4.0'],
  ['https://en.wikipedia.org/wiki/Linux', 'CC-BY-SA-4.0'],
  ['https://en.wikipedia.org/wiki/JSON', 'CC-BY-SA-4.0'],
  ['https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/img', 'CC-BY-SA-2.5'],
  ['https://www.typescriptlang.org/download/', 'CC-BY-4.0'],
  ['https://tauri.app/start/prerequisites/', 'MIT OR Apache-2.0'],
  ['https://docs.brew.sh/Installation', 'BSD-2-Clause'],
  ['https://nixos.org/download/', 'MIT'],
  ['https://ohmyz.sh/', 'MIT'],
  ['https://pnpm.io/motivation', 'MIT'],
  ['https://yarnpkg.com/getting-started/install', 'BSD-2-Clause'],
  ['https://docs.flutter.dev/get-started/quick', 'CC-BY-4.0'],
  ['https://deno.com/', 'MIT'],
];

async function page([url, license]) {
  const res = await fetch(url, { headers: { 'user-agent': UA, accept: 'text/html' }, redirect: 'follow', signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  return { kind: 'html-page', id: `page:${url}`, source: url, license, text };
}

// Email templates (MIT / Apache-2.0). Placeholders are filled with sample values,
// the way a delivered email would read.
const EMAIL_REPOS = [
  { repo: 'ActiveCampaign/postmark-templates', ref: 'main', license: 'MIT', match: /^templates-inlined\/(?:basic|plain)\/[^/]+\/content\.(?:html|txt)$/ },
  { repo: 'sendwithus/templates', ref: 'master', license: 'Apache-2.0', match: /^templates\/[^/]+\/(?:welcome|invoice|confirm|invite|survey|progress)\.html$/, max: 24 },
  { repo: 'emailmonday/Cerberus', ref: 'main', license: 'MIT', match: /^cerberus-(?:fluid|hybrid|responsive)\.html$/ },
  { repo: 'leemunroe/responsive-html-email-template', ref: 'master', license: 'MIT', match: /^email(?:-inlined)?\.html$/ },
];
const EMAIL_REPOS_HELDOUT = [
  { repo: 'mailgun/transactional-email-templates', ref: 'master', license: 'MIT', match: /^templates\/inlined\/[^/]+\.html$/ },
  { repo: 'sendwithus/templates', ref: 'master', license: 'Apache-2.0', match: /^templates\/[^/]+\/(?!(?:welcome|invoice|confirm|invite|survey|progress)\.html$)[^/]+\.html$/, max: 30 },
];

const SAMPLE = { name: 'Sam', product_name: 'Acme', company_name: 'Acme Inc.', sender_name: 'The Acme Team', support_email: 'support@example.com', email: 'sam@example.com', username: 'sam', login_url: 'https://example.com/login', action_url: 'https://example.com/action', support_url: 'https://example.com/support', help_url: 'https://example.com/help', product_url: 'https://example.com', operating_system: 'macOS', browser_name: 'Firefox', trial_length: '14', trial_start_date: 'March 3', trial_end_date: 'March 17', invoice_id: 'INV-1042', date: 'March 3, 2026', total: '$49.00', due_date: 'March 17, 2026', amount: '$49.00', description: 'Pro plan', receipt_id: '84422', credit_card_brand: 'Visa', credit_card_last_four: '4242', billing_url: 'https://example.com/billing', commenter_name: 'Alex', body: 'Looks good to me.', invite_sender_name: 'Alex', invite_sender_organization_name: 'Acme', live_chat_url: 'https://example.com/chat', password_reset_url: 'https://example.com/reset', expiration_date: 'March 17', feedback_url: 'https://example.com/feedback', export_url: 'https://example.com/export', discussion_title: 'Release plan', notification_url: 'https://example.com/n', meta_info: 'Sent from Acme', company_address: '1 Main St, Springfield' };

function fillPlaceholders(s) {
  return s
    .replace(/\{\{#[^}]*\}\}|\{\{\/[^}]*\}\}|\{\{\^[^}]*\}\}|\{\{!--[\s\S]*?--\}\}|\{\{![^}]*\}\}/g, '')
    .replace(/\{\{\{?\s*([A-Za-z0-9_.]+)\s*\}?\}\}/g, (_, k) => {
      const key = k.split('.').pop();
      if (SAMPLE[key]) return SAMPLE[key];
      if (/url$/i.test(key)) return 'https://example.com/' + key.replace(/_url$/i, '');
      return 'sample';
    });
}

async function emailsFrom(src) {
  const tree = await ghJson([`repos/${src.repo}/git/trees/${src.ref}?recursive=1`]);
  const files = tree.tree.filter((f) => f.type === 'blob' && src.match.test(f.path)).slice(0, src.max || 100);
  return pool(files, 6, async (f) => {
    const j = await ghJson([`repos/${src.repo}/contents/${f.path}?ref=${src.ref}`]);
    let text = fillPlaceholders(b64(j.content));
    if (/\.txt$/.test(f.path)) text = `From: Acme <hello@example.com>\nTo: Sam <sam@example.com>\nSubject: A message from Acme\nDate: Tue, 3 Mar 2026 09:12:00 +0000\n\n${text}`;
    return { kind: 'email', id: `email:${src.repo}/${f.path}`, source: j.html_url, sha: j.sha, license: src.license, text };
  });
}

(async () => {
  const t0 = Date.now();
  const repos = await topRepos();
  console.log(`repos picked: ${repos.length}`);
  const readmes = await pool(repos, 8, readme);
  const extra = HELDOUT ? [] : await pool(TRANSLATIONS, 4, translation);
  const tpls = (await pool(repos, 8, templates)).flat();
  const pages = await pool(HELDOUT ? PAGES_HELDOUT : PAGES, 6, page);
  const emails = (await pool(HELDOUT ? EMAIL_REPOS_HELDOUT : EMAIL_REPOS, 2, emailsFrom)).flat();
  const all = [...readmes, ...extra, ...tpls, ...pages, ...emails];
  const failed = all.filter((d) => !d || d.error || !d.text);
  const docs = all.filter((d) => d && !d.error && d.text && d.text.trim().length > 40);
  for (const f of failed) if (f && f.error) console.log('skipped:', f.error);
  const fixture = {
    note: 'Ordinary content with no injections, for measuring false positives. Each entry keeps its source URL and license; the content belongs to its authors.',
    fetched: new Date().toISOString().slice(0, 10),
    docs,
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, zlib.gzipSync(Buffer.from(JSON.stringify(fixture)), { level: 9 }));
  const by = {};
  for (const d of docs) by[d.kind] = (by[d.kind] || 0) + 1;
  console.log(`saved ${docs.length} documents ${JSON.stringify(by)} to ${path.relative(process.cwd(), OUT)} in ${((Date.now() - t0) / 1000).toFixed(0)} s`);
})().catch((err) => { console.error(err); process.exit(1); });
