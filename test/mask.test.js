'use strict';
// Mask: placeholders out, real values back, including inside tool-call arguments.

const test = require('node:test');
const assert = require('node:assert/strict');
const M = require('../src/mask.js');
const S = require('../src/streams.js');
const { fake } = require('./helpers.js');

const cfg = { maskSecrets: true, maskPII: true, customTerms: ['Project Falcon'], allowEmails: ['example.com'] };

test('secrets, email, phone, card and terms become [[OBERIG_*]] placeholders', () => {
  const v = new M.Vault();
  const rep = M.newReport();
  const key = fake.openai();
  const text = `key ${key}, mail ana.k@mailbox.org, call +387 61 234 567, card 4111 1111 1111 1111, about Project Falcon, docs at team@example.com`;
  const out = M.maskText(text, cfg, v, rep);
  assert.ok(!out.includes(key));
  assert.match(out, /\[\[OBERIG_SECRET_1\]\]/);
  assert.match(out, /\[\[OBERIG_EMAIL_1\]\]/);
  assert.match(out, /\[\[OBERIG_PHONE_1\]\]/);
  assert.match(out, /\[\[OBERIG_CARD_1\]\]/);
  assert.match(out, /\[\[OBERIG_TERM_1\]\]/);
  assert.ok(out.includes('team@example.com'), 'allow-listed domains stay');
  assert.equal(rep.total, 5);
  assert.equal(M.restoreText(out, v), text);
});

test('numbering is stable within a session', () => {
  const v = new M.Vault();
  const a = M.maskText(`one ${fake.github()} two ${fake.aws()}`, cfg, v, null);
  const b = M.maskText(`again ${fake.aws()} and ${fake.github()}`, cfg, v, null);
  assert.equal(a, 'one [[OBERIG_SECRET_1]] two [[OBERIG_SECRET_2]]');
  assert.equal(b, 'again [[OBERIG_SECRET_2]] and [[OBERIG_SECRET_1]]');
});

test('maskDeep leaves ids, roles and tool names alone', () => {
  const v = new M.Vault();
  const body = { model: 'x', messages: [{ role: 'user', content: [{ type: 'text', text: `token ${fake.github()}` }, { type: 'tool_result', tool_use_id: 'toolu_1', content: 'mail me: ana.k@mailbox.org' }] }], tools: [{ name: 'Bash' }] };
  const out = M.maskDeep(body, cfg, v, M.newReport());
  assert.equal(out.messages[0].content[0].text, 'token [[OBERIG_SECRET_1]]');
  assert.equal(out.messages[0].content[1].tool_use_id, 'toolu_1');
  assert.equal(out.messages[0].content[1].content, 'mail me: [[OBERIG_EMAIL_1]]');
  assert.deepEqual(out.tools, body.tools);
});

test('restores inside tool-call arguments with JSON escaping', () => {
  const v = new M.Vault();
  const secret = 'Tr0ub4dor\\' + 'battery9staple'; // a backslash must survive JSON escaping
  M.maskText(`PASSWORD=${secret}`, cfg, v, null);
  const args = JSON.stringify({ cmd: 'login --password [[OBERIG_SECRET_1]]' });
  const restored = M.restoreDeep({ function: { name: 'login', arguments: args } }, v);
  assert.equal(JSON.parse(restored.function.arguments).cmd, `login --password ${secret}`);
  assert.equal(restored.function.name, 'login');
});

test('streamed placeholders split across chunks are restored', () => {
  const v = new M.Vault();
  M.maskText('mail ana.k@mailbox.org', cfg, v, null);
  const r = new M.StreamRestorer(v);
  const parts = ['Send to [[OBE', 'RIG_EMA', 'IL_1]] now', ' ['];
  const out = parts.map((p) => r.push(p)).join('') + r.flush();
  assert.equal(out, 'Send to ana.k@mailbox.org now [');
});

test('OpenAI stream restorer fixes tool-call argument deltas', () => {
  const v = new M.Vault();
  M.maskText(`key ${fake.github()}`, cfg, v, null);
  const restore = S.openaiRestorer(v);
  const c1 = restore({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '{"token":"[[OBERIG_SE' } }] } }] });
  const c2 = restore({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: 'CRET_1]]"}' } }] }, finish_reason: 'tool_calls' }] });
  const args = c1.choices[0].delta.tool_calls[0].function.arguments + c2.choices[0].delta.tool_calls[0].function.arguments;
  assert.equal(JSON.parse(args).token, fake.github());
});

test('placeholder-looking values from the model that are unknown stay as they are', () => {
  const v = new M.Vault();
  assert.equal(M.restoreText('see [[OBERIG_SECRET_9]]', v), 'see [[OBERIG_SECRET_9]]');
});

test('the default config masks example.com addresses and *_KEY= values, as the demos show', () => {
  const { loadConfig } = require('../src/config.js');
  const c = loadConfig({}, {});
  const v = new M.Vault();
  const email = ['maria', 'example.com'].join('@');
  const pass = ['Tr0ub', '4dor', '-77'].join('');
  const out = M.maskText(`  DB_PASSWORD=${pass}\n  owner ${email}`, c, v, M.newReport());
  assert.equal(out, '  DB_PASSWORD=[[OBERIG_SECRET_1]]\n  owner [[OBERIG_EMAIL_1]]');
  const stripe = 'STRIPE_KEY=' + ['sk', 'live', '51H'].join('_') + '…Q2x';
  assert.equal(M.maskText(stripe, c, v, M.newReport()), 'STRIPE_KEY=[[OBERIG_SECRET_2]]');
  assert.equal(M.maskText('MONKEY=bananas1234', c, v, M.newReport()), 'MONKEY=bananas1234');
});
