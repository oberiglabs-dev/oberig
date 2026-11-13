'use strict';
// Scrub on a sample Claude Code JSONL transcript.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scrubPath, createContext, scrubText } = require('../src/scrub.js');
const { fake } = require('./helpers.js');

function sampleTranscript() {
  const gh = fake.github();
  const lines = [
    { type: 'user', cwd: 'C:\\Users\\mirela\\code\\shop', sessionId: 'a1', message: { role: 'user', content: 'deploy with token ' + gh } },
    { type: 'assistant', cwd: '/Users/mirela/code/shop', message: { role: 'assistant', content: [{ type: 'tool_use', id: 'toolu_1', name: 'Bash', input: { command: 'cat /home/mirela/.ssh/config && ssh build@ci-runner.internal' } }] } },
    { type: 'user', message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'toolu_1', content: 'Host 192.168.1.20\nUser mirela\nmail mirela.k@mailbox.org, phone +387 61 234 567' }] } },
  ];
  return { gh, text: lines.map((l) => JSON.stringify(l)).join('\n') + '\n' };
}

test('scrub masks paths, users, hosts, emails, phones and secrets in a Claude Code JSONL', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oberig-scrub-'));
  try {
    const src = path.join(dir, 'traces');
    fs.mkdirSync(path.join(src, 'C--Users-mirela-code-shop'), { recursive: true });
    const { gh, text } = sampleTranscript();
    const file = path.join(src, 'C--Users-mirela-code-shop', 'session.jsonl');
    fs.writeFileSync(file, text);
    fs.writeFileSync(path.join(src, 'blob.bin'), Buffer.from([0, 1, 2, 3]));

    const s = scrubPath(src, { username: 'nobody-here', hostname: 'devbox-77' });
    assert.equal(fs.readFileSync(file, 'utf8'), text, 'original unchanged');
    assert.equal(s.files, 1);
    assert.equal(s.skipped.length, 1);
    const outFile = s.written[0];
    assert.ok(!outFile.toLowerCase().includes('mirela'), 'folder names are scrubbed too');
    const out = fs.readFileSync(outFile, 'utf8');
    for (const bad of ['mirela', gh, 'mailbox.org', '192.168.1.20', 'ci-runner.internal', '+387 61 234 567']) assert.ok(!out.includes(bad), `leaked: ${bad}`);
    const rows = out.trim().split('\n').map((l) => JSON.parse(l)); // still valid JSONL
    assert.equal(rows[0].cwd, '~\\code\\shop');
    assert.equal(rows[1].cwd, '~/code/shop');
    assert.match(rows[0].message.content, /\[\[OBERIG_SECRET_1\]\]/);
    assert.match(rows[2].message.content[0].content, /User \[\[OBERIG_USER_1\]\]/);
    assert.equal(rows[1].message.content[0].name, 'Bash');
    assert.ok(s.counts.PATH >= 3 && s.counts.USER >= 1 && s.counts.HOST >= 1 && s.counts.EMAIL >= 1 && s.counts.PHONE === 1 && s.counts.SECRET === 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('scrub refuses an output inside the input folder', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oberig-scrub-'));
  try {
    fs.writeFileSync(path.join(dir, 'a.txt'), 'hello');
    assert.throws(() => scrubPath(dir, { out: path.join(dir, 'inside') }), /outside the input/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('scrubText handles the current machine name and user', () => {
  const ctx = createContext({ username: 'korra', hostname: 'korra-laptop' });
  const out = scrubText('korra@korra-laptop:~$ ls /Users/korra/Desktop', ctx);
  assert.ok(!/korra/i.test(out), out);
});
