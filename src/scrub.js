'use strict';
// Scrub: makes sanitised copies of agent traces (Claude Code JSONL, Codex logs,
// any text or JSON) that are safer to share as open data. Masks secrets and
// personal data, home-folder paths, usernames, emails and hostnames.
// Originals are never changed. Nothing is uploaded.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Vault, newReport, maskText } = require('./mask.js');

const TEXT_EXT = new Set(['.jsonl', '.ndjson', '.json', '.txt', '.log', '.md', '.csv', '.tsv', '.yaml', '.yml', '.toml', '.xml', '.html', '.htm', '']);
const MAX_FILE = 64 * 1024 * 1024;
const GENERIC_USERS = new Set(['admin', 'user', 'users', 'root', 'dev', 'test', 'ubuntu', 'runner', 'home', 'shared', 'public', 'default', 'guest', 'owner']);

const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Home folders: C:\Users\name (also JSON-escaped C:\\Users\\name), /Users/name, /home/name
const HOME_RES = [
  /\b[A-Za-z]:(\\\\|\\|\/)(?:Users|Documents and Settings)\1([^\\/\s"'`:*?<>|]{1,64})/g,
  /(?<![\w.-])\/Users\/(?!Shared\b)([^/\s"'`:]{1,64})/g,
  /(?<![\w.-])\/home\/([^/\s"'`:]{1,64})/g,
];
const PRIVATE_IP = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g;
const LOCAL_HOST = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:local|lan|internal|corp|intranet|home\.arpa)\b/gi;

/** Creates the state for one scrub run (stable numbering across all files). */
function createContext(opts = {}) {
  const users = new Set();
  const hosts = new Set();
  const me = opts.username !== undefined ? opts.username : safe(() => os.userInfo().username);
  if (me && me.length >= 3 && !GENERIC_USERS.has(me.toLowerCase())) users.add(me);
  const host = opts.hostname !== undefined ? opts.hostname : safe(() => os.hostname());
  if (host && host.length >= 3 && host.toLowerCase() !== 'localhost') hosts.add(host);
  return {
    vault: new Vault(),
    report: newReport(),
    users,
    hosts,
    counts: { PATH: 0, USER: 0, HOST: 0 },
    cfg: { maskSecrets: true, maskPII: true, customTerms: opts.terms || [], allowEmails: ['users.noreply.github.com', 'noreply.github.com'] },
  };
}

function safe(fn) { try { return fn(); } catch { return null; } }

function scrubText(text, ctx) {
  if (typeof text !== 'string' || !text) return text;
  let s = text;
  // 1. Home folders become ~ (and their user names are remembered).
  s = s.replace(HOME_RES[0], (m, sep, name) => { noteUser(ctx, name); ctx.counts.PATH++; return '~'; });
  s = s.replace(HOME_RES[1], (m, name) => { noteUser(ctx, name); ctx.counts.PATH++; return '~'; });
  s = s.replace(HOME_RES[2], (m, name) => { noteUser(ctx, name); ctx.counts.PATH++; return '~'; });
  // 2. Secrets, emails, phones, cards.
  s = maskText(s, ctx.cfg, ctx.vault, ctx.report);
  // 3. Host names (machine name first, it often contains the user name), then user names.
  if (ctx.hosts.size) {
    const re = new RegExp(`(?<![A-Za-z0-9.-])(?:${[...ctx.hosts].map(escapeRegExp).join('|')})(?![A-Za-z0-9-])`, 'gi');
    s = s.replace(re, (m) => { ctx.counts.HOST++; return ctx.vault.tokenFor('HOST', m.toLowerCase()).token; });
  }
  s = s.replace(PRIVATE_IP, (m) => { ctx.counts.HOST++; return ctx.vault.tokenFor('HOST', m).token; });
  s = s.replace(LOCAL_HOST, (m) => { ctx.counts.HOST++; return ctx.vault.tokenFor('HOST', m.toLowerCase()).token; });
  if (ctx.users.size) {
    const re = new RegExp(`(?<![A-Za-z0-9])(?:${[...ctx.users].map(escapeRegExp).join('|')})(?![A-Za-z0-9])`, 'gi');
    s = s.replace(re, (m) => { ctx.counts.USER++; return ctx.vault.tokenFor('USER', m.toLowerCase()).token; });
  }
  return s;
}

function noteUser(ctx, name) {
  if (name && name.length >= 3 && !GENERIC_USERS.has(name.toLowerCase())) ctx.users.add(name);
}

function scrubValue(v, ctx) {
  if (typeof v === 'string') return scrubText(v, ctx);
  if (Array.isArray(v)) return v.map((x) => scrubValue(x, ctx));
  if (v && typeof v === 'object') {
    const out = {};
    for (const [k, val] of Object.entries(v)) out[scrubText(k, ctx)] = scrubValue(val, ctx);
    return out;
  }
  return v;
}

/** Scrubs file contents by type. JSON stays valid JSON; JSONL stays one object per line. */
function scrubContent(content, ext, ctx) {
  if (ext === '.jsonl' || ext === '.ndjson') {
    return content.split('\n').map((line) => {
      if (!line.trim()) return line;
      try { return JSON.stringify(scrubValue(JSON.parse(line), ctx)); } catch { return scrubText(line, ctx); }
    }).join('\n');
  }
  if (ext === '.json') {
    try {
      const v = JSON.parse(content);
      return JSON.stringify(scrubValue(v, ctx), null, content.includes('\n') ? 2 : 0) + (content.endsWith('\n') ? '\n' : '');
    } catch { /* fall through to text */ }
  }
  return scrubText(content, ctx);
}

function isBinary(buf) {
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

function listFiles(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) out.push(p);
    }
  };
  walk(dir);
  return out.sort();
}

/**
 * Scrubs a file or a folder into new copies.
 * opts.out: output file (for a file) or folder (for a folder).
 * Returns a summary. Throws if the output would touch the input.
 */
function scrubPath(target, opts = {}) {
  const src = path.resolve(target);
  const st = fs.statSync(src);
  const ctx = opts.ctx || createContext(opts);
  const summary = { input: src, output: null, files: 0, bytes: 0, skipped: [], written: [] };
  const isDir = st.isDirectory();
  let out;
  if (isDir) out = path.resolve(opts.out || src.replace(/[\\/]+$/, '') + '-scrubbed');
  else {
    const ext = path.extname(src);
    out = path.resolve(opts.out || path.join(path.dirname(src), path.basename(src, ext) + '.scrubbed' + ext));
  }
  const rel = path.relative(src, out);
  if (out === src || (isDir && rel && !rel.startsWith('..') && !path.isAbsolute(rel))) {
    throw new Error('the output must be outside the input, so the originals stay untouched');
  }
  summary.output = out;
  const files = isDir ? listFiles(src) : [src];
  for (const f of files) {
    const ext = path.extname(f).toLowerCase();
    const relName = isDir ? path.relative(src, f) : path.basename(f);
    if (isDir && !TEXT_EXT.has(ext)) { summary.skipped.push({ file: relName, reason: 'not a text format' }); continue; }
    const size = fs.statSync(f).size;
    if (size > MAX_FILE) { summary.skipped.push({ file: relName, reason: 'too large' }); continue; }
    const buf = fs.readFileSync(f);
    if (isBinary(buf)) { summary.skipped.push({ file: relName, reason: 'binary' }); continue; }
    const cleaned = scrubContent(buf.toString('utf8'), ext, ctx);
    const dest = isDir ? path.join(out, scrubText(relName, ctx).replace(/[[\]]/g, '_')) : out;
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, cleaned, { flag: 'w' });
    summary.files++;
    summary.bytes += size;
    summary.written.push(dest);
  }
  summary.counts = {
    SECRET: ctx.report.kinds.SECRET || 0,
    EMAIL: ctx.report.kinds.EMAIL || 0,
    PHONE: ctx.report.kinds.PHONE || 0,
    CARD: ctx.report.kinds.CARD || 0,
    PATH: ctx.counts.PATH,
    USER: ctx.counts.USER,
    HOST: ctx.counts.HOST,
  };
  summary.items = Object.values(summary.counts).reduce((a, b) => a + b, 0);
  return summary;
}

module.exports = { createContext, scrubText, scrubValue, scrubContent, scrubPath };
