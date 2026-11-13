'use strict';
// Seal and stitch core: determinism, symmetry, colour balance, order, renderers.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const Seal = require('../src/seal.js');
const Stitch = require('../src/stitch.js');

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const HASHES = Array.from({ length: 240 }, (_, i) => sha('receipt ' + i));

function fresh(file) {
  const p = require.resolve(file);
  delete require.cache[p];
  return require(p);
}

test('same hash, same seal (also across fresh module loads)', () => {
  for (const h of HASHES.slice(0, 40)) {
    const a = Seal.grid(h);
    const b = Seal.grid(h);
    assert.deepEqual(a, b);
    a.cells[0].c = 'x'; // callers get copies, the cache stays clean
    assert.notEqual(Seal.grid(h).cells[0].c, 'x');
  }
  const again = fresh('../src/seal.js');
  for (const h of HASHES.slice(0, 20)) assert.deepEqual(again.grid(h), Seal.grid(h));
  assert.equal(Seal.svg(HASHES[3], { bg: 'night', progress: 0.37 }), again.svg(HASHES[3], { bg: 'night', progress: 0.37 }));
  assert.equal(Seal.ascii(HASHES[4]), again.ascii(HASHES[4]));
});

test('8-fold symmetry: mirrored on both axes and both diagonals', () => {
  for (const h of HASHES.slice(0, 80)) {
    const g = Seal.grid(h);
    const R = (g.size - 1) / 2;
    const at = new Map(g.cells.map((c) => [c.x + ',' + c.y, c.c]));
    for (const c of g.cells) {
      const dx = c.x - R, dy = c.y - R;
      const images = [[dx, dy], [-dx, dy], [dx, -dy], [-dx, -dy], [dy, dx], [-dy, dx], [dy, -dx], [-dy, -dx]];
      for (const [x, y] of images) assert.equal(at.get((x + R) + ',' + (y + R)), c.c, `seal ${h.slice(0, 6)} breaks symmetry at ${x},${y}`);
    }
  }
});

test('colours land near 70% red, 25% black, at most 5% gold', () => {
  let r = 0, k = 0, g = 0;
  for (const h of HASHES) {
    const s = Seal.stats(Seal.grid(h));
    assert.equal(s.r + s.k + s.g, s.total);
    assert.ok(s.g >= 1 && s.g / s.total <= 0.05, `gold ${s.g}/${s.total}`);
    assert.ok(s.r / s.total >= 0.55 && s.r / s.total <= 0.85, `red ${s.r}/${s.total}`);
    assert.ok(s.k / s.total >= 0.13 && s.k / s.total <= 0.37, `black ${s.k}/${s.total}`);
    assert.ok(s.total >= 60 && s.total <= 210, `lit cells ${s.total}`);
    r += s.r / s.total; k += s.k / s.total; g += s.g / s.total;
  }
  const n = HASHES.length;
  assert.ok(Math.abs(r / n - 0.70) < 0.05, `average red ${(r / n).toFixed(3)}`);
  assert.ok(Math.abs(k / n - 0.25) < 0.04, `average black ${(k / n).toFixed(3)}`);
  assert.ok(g / n <= 0.05);
});

test('stitch order runs from the centre outward, ring by ring', () => {
  for (const h of HASHES.slice(0, 40)) {
    const g = Seal.grid(h);
    const R = (g.size - 1) / 2;
    assert.equal(g.order.length, g.cells.length);
    assert.deepEqual([...g.order].sort((a, b) => a - b), g.cells.map((_, i) => i));
    const first = g.cells[g.order[0]];
    assert.deepEqual([first.x, first.y, first.c], [R, R, 'g']);
    let ring = 0;
    for (const i of g.order) {
      const c = g.cells[i];
      assert.equal(c.ring, Math.max(Math.abs(c.x - R), Math.abs(c.y - R)));
      assert.ok(c.ring >= ring);
      ring = c.ring;
    }
  }
});

test('different hashes give clearly different seals', () => {
  const key = (g) => g.cells.map((c) => c.x + '.' + c.y + c.c).join(' ');
  const seen = new Set(HASHES.map((h) => key(Seal.grid(h))));
  assert.ok(seen.size >= HASHES.length * 0.97, `${seen.size} unique of ${HASHES.length}`);
  const shapes = new Set(HASHES.map((h) => key(Seal.grid(h)).replace(/[rkg]/g, '')));
  assert.ok(shapes.size >= HASHES.length * 0.9, `${shapes.size} unique shapes`);
  // one changed character changes the seal
  const a = Seal.grid('7f3a' + '0'.repeat(60)), b = Seal.grid('7f3a' + '0'.repeat(59) + '1');
  assert.notEqual(key(a), key(b));
  // and several motif families show up
  const families = new Set(HASHES.map((h) => { const m = Seal.grid(h).motif; return m.centre + m.mid + m.border; }));
  assert.ok(families.size >= 30, `${families.size} motif families`);
});

test('grid options: size and odd sizes', () => {
  const g = Seal.grid(HASHES[0], { size: 17 });
  assert.equal(g.size, 17);
  for (const c of g.cells) assert.ok(c.x >= 0 && c.x < 17 && c.y >= 0 && c.y < 17 && 'rkg'.includes(c.c));
  assert.equal(Seal.grid(HASHES[0], { size: 20 }).size, 21);
  assert.equal(Seal.grid(HASHES[0], { size: 25 }).size, 25);
});

test('short id', () => {
  assert.equal(Seal.short('7f3a9c1b'), '7f3a');
  assert.equal(Seal.short('0x7F3A9C'), '7f3a');
  assert.match(Seal.short('zz'), /^[0-9a-f]{4}$/);
  assert.equal(Seal.grid('7f3a9c1b').id, '7f3a');
});

test('svg: progress stitches in order, backgrounds, no external refs', () => {
  const h = HASHES[7];
  const full = Seal.svg(h, { bg: 'night' });
  assert.match(full, /^<svg [^>]*viewBox="0 0 228 228"/);
  assert.match(full, /fill="#0d0c0b"/);
  assert.match(Seal.svg(h, { bg: 'linen' }), /fill="#f1eadb"/);
  assert.doesNotMatch(Seal.svg(h), /<rect/);
  assert.doesNotMatch(full.replace(/xmlns="[^"]*"/, ''), /href|url\(|https?:/);
  const none = Seal.svg(h, { progress: 0 });
  assert.doesNotMatch(none, /<path/);
  const len = (p) => (Seal.svg(h, { progress: p }).match(/[ML]/g) || []).length;
  assert.ok(len(0.2) < len(0.6) && len(0.6) < len(1));
  assert.match(Seal.svg(h, { cell: 20 }), /viewBox="0 0 380 380"/);
});

test('ascii: square terminal art, plain and coloured', () => {
  const h = HASHES[9];
  const plain = Seal.ascii(h);
  const lines = plain.split('\n');
  assert.equal(lines.length, 17);
  assert.ok(lines.every((l) => l.length <= 34));
  assert.match(plain, /×/);
  assert.doesNotMatch(plain, /\x1b/);
  const ansi = Seal.ascii(h, { ansi: true });
  assert.match(ansi, /\x1b\[38;2;229;65;47m×/);
  assert.match(Seal.ascii(h, { ansi: 256 }), /\x1b\[38;5;/);
  const g = Seal.grid(h);
  assert.equal((ansi.match(/×/g) || []).length, g.cells.length);
});

test('stitch font covers lowercase, digits and punctuation', () => {
  const need = 'abcdefghijklmnopqrstuvwxyz0123456789 .,:;!?\'"-_+=/\\|()[]<>*#%&@·×';
  for (const ch of need) {
    const g = Stitch.FONT[ch];
    assert.ok(g, `missing glyph ${JSON.stringify(ch)}`);
    assert.ok(g.length >= 7 && g.length <= 9);
    assert.ok(g.every((row) => /^[.#]+$/.test(row) && row.length <= 5));
  }
  const L = Stitch.layout('oberig');
  assert.equal(L.rows, 9);
  assert.equal(L.cols, 5 + 1 + 5 + 1 + 5 + 1 + 5 + 1 + 3 + 1 + 5);
  assert.equal(L.order.length, L.cells.length);
  assert.deepEqual(Stitch.layout('OBERIG').cells, L.cells);
});

test('stitch renderer is pure for a given progress', () => {
  const opts = { cell: 14, theme: 'night', needle: true };
  for (const p of [0, 0.13, 0.5, 0.87, 1]) {
    assert.equal(Stitch.svgText('oberig', { ...opts, progress: p }), Stitch.svgText('oberig', { ...opts, progress: p }));
    assert.equal(Stitch.svgSeal(HASHES[1], { ...opts, progress: p }), Stitch.svgSeal(HASHES[1], { ...opts, progress: p }));
  }
  const L = Stitch.layout('oberig');
  let prev = -1;
  for (let i = 0; i <= 50; i++) {
    const P = Stitch.plan(L, { progress: i / 50 });
    assert.ok(P.legs.length >= prev);
    prev = P.legs.length;
  }
  const done = Stitch.plan(L, { progress: 1 });
  assert.equal(done.legs.length, 2 * L.cells.length);
  assert.ok(done.legs.every((l) => l.done));
  assert.equal(done.front, null);
  assert.equal(Stitch.plan(L, { progress: 0 }).legs.length, 0);
  assert.ok(Stitch.plan(L, { progress: 0.5 }).front);
  // '/' is stitched before '\' in every cell
  const first = Stitch.plan(L, { progress: 1 }).legs.slice(0, 2);
  assert.ok(first[0].y1 > first[0].y2 && first[1].y1 < first[1].y2);
});

test('stitch canvas path draws without a browser', () => {
  const calls = [];
  const ctx = new Proxy({}, {
    get(t, k) {
      if (k in t) return t[k];
      if (k === 'createLinearGradient') return () => ({ addColorStop() {} });
      return (...a) => calls.push(k);
    },
    set(t, k, v) { t[k] = v; return true; }
  });
  const r = Stitch.drawText(ctx, 'oberig', { cell: 20, progress: 0.4, needle: true, fabric: true });
  assert.ok(r.width > 0 && r.front);
  const s = Stitch.drawSeal(ctx, HASHES[2], { cell: 10, theme: 'linen' });
  assert.equal(s.id, HASHES[2].slice(0, 4));
  assert.ok(calls.filter((c) => c === 'stroke').length > 10);
});

test('core modules use no Node APIs and say nothing about how they were made', () => {
  for (const f of ['seal.js', 'stitch.js']) {
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', f), 'utf8');
    assert.doesNotMatch(src, /process\.|Buffer|__dirname|fs\./);
    assert.doesNotMatch(src, new RegExp(String.fromCharCode(0x2014)));
    if (f === 'seal.js') assert.doesNotMatch(src, /require\(/);
  }
});
