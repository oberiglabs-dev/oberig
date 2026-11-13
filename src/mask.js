'use strict';
// Mask: finds secrets and personal data, swaps them for [[OBERIG_*]] placeholders
// before a request leaves, and puts the real values back into the answer.
// Everything stays in memory. Numbering is stable within a session.

const PLACEHOLDER_RE = /\[\[OBERIG_[A-Z]+_\d+\]\]/g;
const PLACEHOLDER_PREFIX = '[[OBERIG_';
const MAX_PLACEHOLDER_LEN = 40;

// Values that look like secrets but are obviously placeholders in docs and examples.
const NOT_SECRET = /^(?:true|false|null|undefined|none|changeme|change_me|password|secret|token|your[-_].*|<.*>|\$\{.*\}|\$\(.*\)|process\.env\..*|os\.environ.*|x{6,}|\*{4,}|\.{3,}|example.*|dummy.*|test|placeholder.*|\d{1,10})$/i;

const SECRET_RULES = [
  { name: 'private-key', re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g },
  { name: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: 'openai-style-key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/g },
  { name: 'aws-access-key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'github-token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})/g },
  { name: 'stripe-key', re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g },
  { name: 'slack-token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}/g },
  { name: 'near-private-key', re: /\bed25519:[1-9A-HJ-NP-Za-km-z]{60,100}\b/g },
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { name: 'db-password', re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?):\/\/[^:\s/@]+:([^@\s/]+)@/g, group: 1 },
  { name: 'bearer-token', re: /\bBearer\s+([A-Za-z0-9._~+/-]{24,}=*)/g, group: 1 },
  { name: 'seed-phrase', re: /\b(?:mnemonic|seed(?:[ _-]?phrase)?|recovery[ _-]?phrase|secret[ _-]?phrase|wallet[ _-]?words)\b[^\n]{0,12}?\b((?:[a-z]{3,8}[ \t]+){11,23}[a-z]{3,8})\b/gi, group: 1 },
  { name: 'wallet-private-key', re: /\b(?:private[ _-]?key|priv[ _-]?key|pk|wallet[ _-]?key)\b[^\n]{0,8}?\b((?:0x)?[a-fA-F0-9]{64})\b/gi, group: 1 },
  { name: 'env-secret', re: /\b(?:[A-Z0-9]+_)*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|KEY|CREDENTIALS?|MNEMONIC)(?:_[A-Z0-9]+)*\b\s*[=:]\s*["']?([^\s"'#,;]{8,})/g, group: 1 },
  { name: 'kv-secret', re: /["']?(?:api[_-]?key|apiKey|secret[_-]?key|secretKey|client[_-]?secret|clientSecret|access[_-]?token|accessToken|refresh[_-]?token|refreshToken|auth[_-]?token|authToken|password|privateKey)["']?\s*[:=]\s*["']([^"'\s]{8,})["']/gi, group: 1 },
];

const PII_RULES = [
  {
    name: 'email',
    kind: 'EMAIL',
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g,
    validate: (v, cfg) => {
      const [local, domain] = v.toLowerCase().split('@');
      if (['git', 'noreply', 'no-reply'].includes(local)) return false;
      return !(cfg.allowEmails || []).some((d) => domain === d || domain.endsWith('.' + d));
    },
  },
  { name: 'phone', kind: 'PHONE', re: /(?<![\w+])\+\d{1,3}[ .-]?\(?\d{1,4}\)?(?:[ .-]?\d{2,4}){2,4}\b/g },
  {
    name: 'card-number',
    kind: 'CARD',
    re: /\b(?:4\d{3}|5[1-5]\d{2}|2[2-7]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}\b/g,
    validate: (v) => luhn(v.replace(/\D/g, '')),
  },
];

function luhn(digits) {
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Maps real values to placeholders and back. Memory only. */
class Vault {
  constructor() {
    this.byValue = new Map();
    this.byToken = new Map();
    this.counters = {};
    this.kinds = new Map();
  }

  tokenFor(kind, value) {
    const existing = this.byValue.get(value);
    if (existing) return { token: existing, isNew: false };
    const n = (this.counters[kind] = (this.counters[kind] || 0) + 1);
    const token = `[[OBERIG_${kind}_${n}]]`;
    this.byValue.set(value, token);
    this.byToken.set(token, value);
    this.kinds.set(token, kind);
    return { token, isNew: true };
  }

  valueOf(token) { return this.byToken.get(token); }

  get size() { return this.byToken.size; }

  countKind(kind) {
    let n = 0;
    for (const k of this.kinds.values()) if (k === kind) n++;
    return n;
  }
}

function newReport() {
  return { total: 0, fresh: 0, kinds: {}, types: new Set() };
}

function reportToJSON(r) {
  return { total: r.total, fresh: r.fresh, kinds: { ...r.kinds }, types: [...r.types] };
}

function rulesFor(cfg) {
  const rules = [];
  if (cfg.maskSecrets !== false) for (const r of SECRET_RULES) rules.push({ ...r, kind: 'SECRET', category: 'secret' });
  if (cfg.maskPII !== false) for (const r of PII_RULES) rules.push({ ...r, category: 'pii' });
  const terms = (cfg.customTerms || []).filter((t) => typeof t === 'string' && t.trim().length >= 2);
  if (terms.length) {
    const re = new RegExp(`(?<![\\w])(?:${terms.map((t) => escapeRegExp(t.trim())).join('|')})(?![\\w])`, 'gi');
    rules.push({ name: 'custom-term', kind: 'TERM', category: 'pii', re });
  }
  for (const r of cfg.extraRules || []) rules.push(r);
  return rules;
}

const ruleCache = new WeakMap();
function cachedRules(cfg) {
  let r = ruleCache.get(cfg);
  if (!r) { r = rulesFor(cfg); ruleCache.set(cfg, r); }
  return r;
}

/** Finds sensitive spans in a string. Returns non-overlapping spans sorted by start. */
function findSpans(text, cfg) {
  if (typeof text !== 'string' || text.length < 2) return [];
  const spans = [];
  for (const rule of cachedRules(cfg)) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text)) !== null) {
      if (m[0].length === 0) { rule.re.lastIndex++; continue; }
      let value = m[0];
      let start = m.index;
      if (rule.group) {
        value = m[rule.group];
        if (value === undefined) continue;
        start = m.index + m[0].lastIndexOf(value);
      }
      if (value.includes(PLACEHOLDER_PREFIX)) continue;
      if (rule.category === 'secret' && rule.group && NOT_SECRET.test(value)) continue;
      if (rule.validate && !rule.validate(value, cfg)) continue;
      spans.push({ start, end: start + value.length, value, kind: rule.kind, category: rule.category, name: rule.name, replace: rule.replace });
    }
  }
  // Earlier first; at the same start, secrets win over personal data, then the longer match.
  const rank = (s) => (s.category === 'secret' ? 0 : 1);
  spans.sort((a, b) => a.start - b.start || rank(a) - rank(b) || (b.end - b.start) - (a.end - a.start));
  const out = [];
  let lastEnd = -1;
  for (const s of spans) {
    if (s.start >= lastEnd) { out.push(s); lastEnd = s.end; }
  }
  return out;
}

/** Masks one string and updates the report. */
function maskText(text, cfg, vault, report) {
  const spans = findSpans(text, cfg);
  if (!spans.length) return text;
  let out = '';
  let pos = 0;
  for (const s of spans) {
    let token;
    let isNew = false;
    if (typeof s.replace === 'string') token = s.replace;
    else ({ token, isNew } = vault.tokenFor(s.kind, s.value));
    out += text.slice(pos, s.start) + token;
    pos = s.end;
    if (report) {
      report.total++;
      if (isNew) report.fresh++;
      report.kinds[s.kind] = (report.kinds[s.kind] || 0) + 1;
      report.types.add(s.name);
    }
  }
  return out + text.slice(pos);
}

// Keys whose string values must never change (structure, ids, signatures, binary data).
const SKIP_KEYS = new Set([
  'model', 'role', 'type', 'id', 'tool_use_id', 'tool_call_id', 'name', 'media_type', 'data',
  'signature', 'cache_control', 'stop_reason', 'finish_reason', 'index', 'metadata', 'mime_type',
  'detail', 'format', 'encoding',
]);
const SKIP_BLOCK_TYPES = new Set(['thinking', 'redacted_thinking', 'image', 'document_base64']);

/** Masks every user-visible string inside a request body (Anthropic or OpenAI format). */
function maskDeep(value, cfg, vault, report, key = null) {
  if (typeof value === 'string') {
    if (key && SKIP_KEYS.has(key)) return value;
    if (key === 'url' && value.startsWith('data:')) return value;
    return maskText(value, cfg, vault, report);
  }
  if (Array.isArray(value)) return value.map((v) => maskDeep(v, cfg, vault, report, null));
  if (value && typeof value === 'object') {
    if (typeof value.type === 'string' && SKIP_BLOCK_TYPES.has(value.type)) return value;
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (k === 'metadata' || (k === 'tools' && Array.isArray(v))) { out[k] = v; continue; }
      out[k] = maskDeep(v, cfg, vault, report, k);
    }
    return out;
  }
  return value;
}

const jsonEscape = (s) => JSON.stringify(s).slice(1, -1);

/** Replaces placeholders with real values. json=true when the text is raw JSON (tool arguments). */
function restoreText(text, vault, json = false) {
  if (typeof text !== 'string' || !text.includes(PLACEHOLDER_PREFIX)) return text;
  return text.replace(PLACEHOLDER_RE, (tok) => {
    const v = vault.valueOf(tok);
    if (v === undefined) return tok;
    return json ? jsonEscape(v) : v;
  });
}

/** Restores placeholders inside a response object. */
function restoreDeep(value, vault, key = null) {
  if (typeof value === 'string') {
    if (key && ['signature', 'id', 'tool_use_id', 'tool_call_id', 'type', 'role'].includes(key)) return value;
    return restoreText(value, vault, key === 'arguments' || key === 'partial_json');
  }
  if (Array.isArray(value)) return value.map((v) => restoreDeep(v, vault));
  if (value && typeof value === 'object') {
    if (value.type === 'thinking' || value.type === 'redacted_thinking') return value;
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = restoreDeep(v, vault, k);
    return out;
  }
  return value;
}

/** Restores placeholders in streamed text that may be split across chunks. */
class StreamRestorer {
  constructor(vault, json = false) {
    this.vault = vault;
    this.json = json;
    this.buf = '';
  }

  push(chunk) {
    const text = this.buf + (chunk || '');
    let hold = 0;
    const open = text.lastIndexOf('[[');
    if (open !== -1 && text.indexOf(']]', open) === -1 && text.length - open <= MAX_PLACEHOLDER_LEN) hold = text.length - open;
    else if (text.endsWith('[')) hold = 1;
    const safe = text.slice(0, text.length - hold);
    this.buf = text.slice(text.length - hold);
    return restoreText(safe, this.vault, this.json);
  }

  flush() {
    const rest = this.buf;
    this.buf = '';
    return restoreText(rest, this.vault, this.json);
  }
}

module.exports = {
  Vault, newReport, reportToJSON, findSpans, maskText, maskDeep, restoreText, restoreDeep, StreamRestorer,
  PLACEHOLDER_RE, luhn,
};
