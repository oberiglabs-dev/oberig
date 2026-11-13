/*
 * Oberig stitched seal.
 *
 * Turns a hash (any hex string) into a small cross-stitch motif in the
 * vyshyvanka tradition: 8-fold symmetry, an eight-pointed star or rhombus at
 * the heart, ram's horns, tree-of-life branches and a border band.
 *
 *   grid(hex, {size: 17})            -> {size, cells: [{x, y, c, ring}], order, motif}
 *   svg(hex, {bg, progress, cell})   -> SVG string
 *   ascii(hex, {ansi})               -> terminal art made of "×"
 *   short(hex)                       -> '7f3a'
 *
 * Colours: c is 'r' (red thread), 'k' (black thread) or 'g' (gold thread).
 * Pure and deterministic. No dependencies and no Node APIs (UMD).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.OberigSeal = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var THEMES = {
    night: { bg: '#0d0c0b', r: '#e5412f', k: '#b9b1a2', g: '#e8b04a', rl: '#ff9479', kl: '#f1eadb', gl: '#ffe0a3', rd: '#9e1b14', kd: '#5e574d', gd: '#8f6214' },
    linen: { bg: '#f1eadb', r: '#e5412f', k: '#151515', g: '#e8b04a', rl: '#ff8f74', kl: '#6a6661', gl: '#fff0c4', rd: '#9e1b14', kd: '#000000', gd: '#a8741f' }
  };

  function clean(hex) {
    var s = String(hex == null ? '' : hex).trim().toLowerCase();
    if (s.slice(0, 2) === '0x') s = s.slice(2);
    return s;
  }

  // Seeded generator: xmur3 string hash feeding sfc32.
  function rng(str) {
    for (var i = 0, h = 1779033703 ^ str.length; i < str.length; i++) {
      h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
      h = (h << 13) | (h >>> 19);
    }
    function next() {
      h = Math.imul(h ^ (h >>> 16), 2246822507);
      h = Math.imul(h ^ (h >>> 13), 3266489909);
      return (h ^= h >>> 16) >>> 0;
    }
    var a = next(), b = next(), c = next(), d = next();
    return function () {
      a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
      var t = (a + b) | 0;
      a = b ^ (b >>> 9);
      b = (c + (c << 3)) | 0;
      c = (c << 21) | (c >>> 11);
      d = (d + 1) | 0;
      t = (t + d) | 0;
      c = (c + t) | 0;
      return (t >>> 0) / 4294967296;
    };
  }

  function short(hex) {
    var s = clean(hex).replace(/[^0-9a-f]/g, '');
    if (s.length >= 4) return s.slice(0, 4);
    var r = rng('short:' + clean(hex));
    return ('0000' + Math.floor(r() * 65536).toString(16)).slice(-4);
  }

  var TAN = 0.41421356; // tan(22.5deg): the line between the petals of an eight-pointed star

  // Design in the fundamental triangle 0 <= b <= a <= R, where a = max(|dx|,|dy|)
  // and b = min(|dx|,|dy|). Anything drawn there is mirrored on both axes and both
  // diagonals, which is what gives the seal its embroidered look.
  function design(hex, size) {
    var R = (size - 1) >> 1;
    var K = R / 8;
    var rnd = rng('oberig-seal:' + clean(hex) + ':' + size);
    var int = function (n) { return Math.floor(rnd() * n); };
    var pick = function (arr) { return arr[int(arr.length)]; };
    var chance = function (p) { return rnd() < p; };
    var S = function (v) { return Math.max(1, Math.round(v * K)); };

    var F = {};
    var layers = [];
    var key = function (a, b) { return a * 1000 + b; };
    var fund = function (x, y) { x = Math.abs(x); y = Math.abs(y); return x >= y ? [x, y] : [y, x]; };

    function touches(a, b) {
      for (var dx = -1; dx <= 1; dx++) for (var dy = -1; dy <= 1; dy++) {
        if (!dx && !dy) continue;
        var f = fund(a + dx, b + dy);
        if (f[0] > R) continue;
        if (F[key(f[0], f[1])] !== undefined) return true;
      }
      return false;
    }
    // Add a motif layer. test(a, b) works on the fundamental triangle.
    // With gap, the layer keeps one empty cell between itself and earlier layers.
    function layer(name, pref, test, gap) {
      var id = layers.length, cells = [];
      for (var a = 0; a <= R; a++) for (var b = 0; b <= a; b++) {
        var k = key(a, b);
        if (F[k] !== undefined || !test(a, b)) continue;
        if (gap && touches(a, b)) continue;
        cells.push(k);
      }
      for (var i = 0; i < cells.length; i++) F[cells[i]] = id;
      layers.push({ name: name, pref: pref, cells: cells });
      return id;
    }
    // A quadrant shape (x >= 0, y >= 0) made symmetric across the diagonal.
    function quad(test) { return function (a, b) { return test(a, b) || test(b, a); }; }
    function onGap(a, b) { return a >= 2 && Math.abs(b - TAN * a) < 0.5; }

    var motif = {};
    var accents = []; // fundamental cells that may carry a little gold

    var border = pick(['teeth', 'wave', 'chain', 'frame', 'dots', 'hooks', 'wave', 'teeth']);
    var bpref = pick(['k', 'k', 'r']);
    var bo = int(2); // which beat of the border pattern lands on the axis
    var inner = border === 'chain' ? R - 3 : R - 2; // last ring the middle motif may use

    // The eye: one gold stitch in the middle, held by a small cross, ring or block.
    layer('eye', 'g', function (a) { return a === 0; });
    var heart = pick(['plus', 'plus', 'ring', 'block', 'x']);
    var hk = chance(0.75) ? 'k' : 'r';
    layer('heart', hk, function (a, b) {
      return heart === 'plus' ? a + b === 1 : heart === 'block' ? a === 1 : heart === 'x' ? a === 1 && b === 1 : a + b === 2;
    });
    motif.heart = heart;

    // 1. Centre motif.
    var centre = pick(['star', 'star', 'star', 'rhombus', 'flower', 'cross']);
    var big = centre === 'star' && chance(0.55);
    var reach; // how far the centre motif goes, in rings
    motif.centre = centre;
    if (centre === 'star') {
      var Ls = big ? Math.min(inner + 1, S(pick([6, 7]))) : S(pick([4, 5]));
      var Lq = big ? S(pick([3, 4])) : S(pick([2, 3]));
      if (2 * Lq <= Ls) Lq = Math.ceil((Ls + 1) / 2);
      if (Lq >= Ls) Lq = Ls - 1;
      var hollow = chance(0.35);
      var inStar = function (a, b) { return (a + b <= Ls || a <= Lq) && !onGap(a, b) && !(hollow && a + b === 3); };
      var split = chance(0.6);
      var pa = pick(['r', 'r', 'k']);
      layer('star-axis', pa, function (a, b) { return a >= 2 && b < TAN * a && inStar(a, b); });
      layer('star-diag', split ? (pa === 'r' ? 'k' : 'r') : pa, function (a, b) { return a >= 1 && b > TAN * a && inStar(a, b); });
      accents.push([Lq, Lq], [Ls, 0]);
      reach = Math.max(Ls, Lq + 1);
      motif.star = [Ls, Lq, hollow ? 1 : 0];
    } else if (centre === 'rhombus') {
      var r1 = S(pick([3, 4]));
      layer('rhombus', pick(['r', 'k']), function (a, b) { var s = a + b; return s >= 3 && s <= r1 + 1 && s !== r1 + (r1 > 3 ? -1 : 9); });
      var rays = pick(['none', 'axis', 'diag', 'axis']);
      if (rays === 'axis') layer('rays', 'r', function (a, b) { return b === 0 && a > r1 + 1 && a <= r1 + 3; }, true);
      if (rays === 'diag') layer('rays', 'r', function (a, b) { return a === b && a + b > r1 + 2 && a <= Math.ceil((r1 + 6) / 2); }, true);
      accents.push([r1 + 3, 0]);
      reach = r1 + (rays === 'none' ? 2 : 3);
    } else if (centre === 'flower') {
      // four rhombic petals with open eyes, and buds on the diagonals
      var pc = S(3);
      layer('petals', pick(['r', 'r', 'k']), quad(function (x, y) { return Math.abs(x - pc) + y === 1; }));
      if (chance(0.6)) layer('tips', 'r', function (a, b) { return b === 0 && a === pc + 2; }, true);
      layer('buds', pick(['r', 'k']), function (a, b) { return (a === 2 && b === 2) || (a === 3 && b === 2); }, true);
      accents.push([pc + 2, 0], [pc, 0]);
      reach = pc + 2;
    } else {
      var arm = S(pick([4, 5]));
      layer('cross', 'r', function (a, b) { return b === 0 && a >= 2 && a <= arm; });
      var tw = chance(0.5);
      layer('twigs', pick(['k', 'r']), function (a, b) {
        return tw ? ((b === 1 && (a === 3 || a === arm)) || (b === 2 && a === arm + 1)) : ((b === 1 && a === arm - 1) || (b === 2 && a === arm));
      }, true);
      layer('cross-diag', pick(['r', 'k']), function (a, b) { return a === b && a >= 2 && a <= 3; }, true);
      accents.push([arm, 0]);
      reach = arm + 1;
    }

    // 2. Middle motif, between the centre and the border.
    var mid = big ? pick(['rhombus', 'horns', 'buds', 'seeds', 'none']) : pick(['rhombus', 'horns', 'tree', 'buds', 'rhombus-horns', 'rhombus']);
    motif.mid = mid;
    if (mid === 'rhombus' || mid === 'rhombus-horns') {
      var rr = Math.max(reach + 2, S(7)) + (chance(0.3) ? 1 : 0);
      var ring = pick(border === 'dots' ? ['plain', 'toothed', 'double'] : ['plain', 'toothed', 'double', 'dotted']);
      motif.ring = ring;
      layer('ring', pick(['k', 'r']), function (a, b) {
        var s = a + b;
        if (a > inner) return false;
        if (ring === 'plain') return s === rr;
        if (ring === 'toothed') return s === rr || (s === rr + 1 && (a - b) % 4 === 1);
        if (ring === 'double') return s === rr || s === rr + 2;
        return s === rr && a % 2 === 0;
      }, true);
    }
    if (mid === 'horns' || mid === 'rhombus-horns') {
      var shapes = [
        [[0, 0], [1, 0], [2, 0], [2, -1], [2, -2], [1, -2]],
        [[0, 0], [1, 1], [2, 1], [2, 0], [1, -1]],
        [[0, 0], [1, 0], [2, 1], [3, 1], [3, 0]]
      ];
      var hs = int(shapes.length), horn = shapes[hs];
      var hp = big ? inner - 2 : Math.min(inner - 2, Math.max(S(3), reach - 1));
      if (hs === 2) hp = Math.min(hp, inner - 3);
      motif.horn = hs;
      layer('horns', pick(['r', 'k']), quad(function (x, y) {
        for (var i = 0; i < horn.length; i++) if (x === hp + horn[i][0] && y === hp + horn[i][1]) return true;
        return false;
      }), true);
    }
    if (mid === 'tree') {
      var t0 = Math.min(reach + 1, inner - 2);
      var forked = chance(0.5);
      layer('tree', pick(['r', 'k']), function (a, b) {
        return (b === 0 && a >= t0 && a <= inner) || (b === 1 && a === inner - 1) || (b === 2 && a === inner) || (forked && b === 1 && a === t0 + 1 && a < inner - 2);
      }, true);
      layer('leaves', pick(['r', 'k']), function (a, b) { return a === b && a >= Math.max(2, t0 - 2) && a <= t0 - 1; }, true);
    }
    if (mid === 'buds') {
      var bc = inner - 1, solid = chance(0.4);
      layer('buds', pick(['k', 'r']), quad(function (x, y) {
        var d1 = Math.abs(x - bc) + y, d2 = Math.abs(x - bc + 2) + Math.abs(y - bc + 2);
        return (solid ? d1 <= 1 : d1 === 1) || (d2 === 1 && bc - 2 > reach);
      }), true);
      accents.push([bc, 0]);
    }

    // 3. Border band.
    motif.border = border;
    if (border === 'teeth') {
      layer('band', bpref, function (a) { return a === R; });
      layer('teeth', bpref === 'k' ? 'r' : 'k', function (a, b) { return a === R - 1 && (b + bo) % 2 === 0; });
    } else if (border === 'wave') {
      layer('band', bpref, function (a, b) { return (a === R && (b + bo) % 2 === 0) || (a === R - 1 && (b + bo) % 2 === 1); });
    } else if (border === 'chain') {
      // a running chain of small rhombi
      layer('band', bpref, function (a, b) { return ((a === R || a === R - 2) && (b + bo) % 2 === 0) || (a === R - 1 && (b + bo) % 2 === 1); });
    } else if (border === 'dots') {
      layer('band', bpref, function (a, b) { return (a === R && (b + bo) % 2 === 0) || (a === R - 1 && b === R - 1); });
      layer('corners', bpref === 'k' ? 'r' : 'k', function (a, b) { return a === R && b === R - 1; });
    } else if (border === 'hooks') {
      layer('band', bpref, function (a, b) { return a === R && (b <= 2 || b >= R - 1); });
      layer('corners', bpref === 'k' ? 'r' : 'k', function (a, b) { return (a === R - 2 && (b === R - 2 || b === R - 3)) || (a === R - 1 && b === R - 3); });
    } else {
      layer('band', bpref, function (a, b) { return a === R && (b <= 1 || b >= R - 3); });
      layer('corners', bpref === 'k' ? 'r' : 'k', function (a, b) { return (a === R - 2 && b === R - 2) || (a === R - 1 && b === R - 3); });
    }

    // 4. Seeds: single stitches on the axes or diagonals, in open space.
    // (never on top of an already dotted design, where they would read as noise)
    var seeds = mid === 'seeds' ? 3 : border === 'dots' || motif.ring === 'dotted' ? 0 : int(3);
    for (var sd = 0; sd < seeds; sd++) {
      var free = [];
      for (var sa = 2; sa < R; sa++) for (var sb = 0; sb <= sa; sb++) {
        if (F[key(sa, sb)] === undefined && !touches(sa, sb)) free.push([sa, sb]);
      }
      if (!free.length) break;
      var fc = free[int(free.length)];
      layer('seed', pick(['r', 'k']), function (a, b) { return a === fc[0] && b === fc[1]; });
    }

    return { R: R, F: F, layers: layers, accents: accents, motif: motif, rnd: rnd };
  }

  function orbit(a, b) { return a === 0 ? 1 : (b === 0 || a === b ? 4 : 8); }

  // Pick a colour per layer so the seal lands near 70% red, 25% black, at most 5% gold.
  function colour(d) {
    var layers = [];
    var total = 0;
    var i, j;
    for (i = 0; i < d.layers.length; i++) {
      var L = d.layers[i];
      if (L.pref === 'g') continue;
      var w = 0;
      for (j = 0; j < L.cells.length; j++) w += orbit(Math.floor(L.cells[j] / 1000), L.cells[j] % 1000);
      if (w) layers.push({ id: i, pref: L.pref, w: w, cells: L.cells });
      total += w;
    }
    // Split very large layers into outline and fill, a classic black outline on red.
    var out = [];
    for (i = 0; i < layers.length; i++) {
      var Ly = layers[i];
      if (Ly.w <= total * 0.3) { out.push(Ly); continue; }
      var set = {};
      for (j = 0; j < Ly.cells.length; j++) set[Ly.cells[j]] = 1;
      var edge = [], fill = [], we = 0, wf = 0;
      for (j = 0; j < Ly.cells.length; j++) {
        var c = Ly.cells[j], a = Math.floor(c / 1000), b = c % 1000;
        var lit = function (x, y) {
          x = Math.abs(x); y = Math.abs(y);
          var aa = Math.max(x, y), bb = Math.min(x, y);
          return d.F[aa * 1000 + bb] !== undefined;
        };
        var isEdge = !lit(a + 1, b) || !lit(a - 1, b) || !lit(a, b + 1) || !lit(a, b - 1);
        if (isEdge) { edge.push(c); we += orbit(a, b); } else { fill.push(c); wf += orbit(a, b); }
      }
      if (edge.length && fill.length) {
        out.push({ id: Ly.id, pref: 'k', w: we, cells: edge });
        out.push({ id: Ly.id, pref: 'r', w: wf, cells: fill });
      } else out.push(Ly);
    }
    var target = 0.23 + d.rnd() * 0.04;
    var best = null, bestScore = Infinity;
    var n = Math.min(out.length, 12);
    for (var mask = 0; mask < (1 << n); mask++) {
      var black = 0, miss = 0;
      for (i = 0; i < n; i++) {
        var isK = (mask >> i) & 1;
        if (isK) black += out[i].w;
        if ((isK ? 'k' : 'r') !== out[i].pref) miss += 1;
      }
      var score = Math.abs(black / total - target) + 0.012 * miss + 0.02 * d.rnd();
      if (score < bestScore) { bestScore = score; best = mask; }
    }
    var col = {};
    for (i = 0; i < out.length; i++) {
      var cc = i < n && ((best >> i) & 1) ? 'k' : 'r';
      for (j = 0; j < out[i].cells.length; j++) col[out[i].cells[j]] = cc;
    }
    // Gold: the eye, plus one accent orbit of four when the seal is large enough.
    var lit = total + 1;
    col[0] = 'g';
    var gold = 1;
    for (i = 0; i < d.accents.length; i++) {
      var acc = d.accents[i], ak = acc[0] * 1000 + acc[1];
      if (d.F[ak] === undefined || col[ak] === 'g') continue;
      var ow = orbit(acc[0], acc[1]);
      if ((gold + ow) / lit <= 0.05 && d.rnd() < 0.7) { col[ak] = 'g'; gold += ow; break; }
    }
    return col;
  }

  var cache = {};
  var cacheKeys = [];

  function grid(hex, opts) {
    var size = (opts && opts.size) | 0 || 17;
    if (size < 9) size = 9;
    if (size % 2 === 0) size += 1;
    var ck = clean(hex) + ':' + size;
    if (cache[ck]) return copy(cache[ck]);
    var d = design(hex, size);
    var col = colour(d);
    var R = d.R;
    var cells = [];
    for (var y = 0; y < size; y++) for (var x = 0; x < size; x++) {
      var dx = x - R, dy = y - R;
      var ax = Math.abs(dx), ay = Math.abs(dy);
      var a = Math.max(ax, ay), b = Math.min(ax, ay);
      var k = a * 1000 + b;
      if (d.F[k] === undefined) continue;
      cells.push({ x: x, y: y, c: col[k] || 'r', ring: a });
    }
    // Centre outward, ring by ring; clockwise from twelve o'clock inside a ring.
    var ang = cells.map(function (c) {
      var t = Math.atan2(c.x - R, -(c.y - R));
      return t < 0 ? t + Math.PI * 2 : t;
    });
    var order = cells.map(function (_, i) { return i; });
    order.sort(function (i, j) { return cells[i].ring - cells[j].ring || ang[i] - ang[j] || i - j; });
    var g = { size: size, cells: cells, order: order, hex: clean(hex), id: short(hex), motif: d.motif };
    cache[ck] = g;
    cacheKeys.push(ck);
    if (cacheKeys.length > 256) delete cache[cacheKeys.shift()];
    return copy(g);
  }

  function copy(g) {
    return {
      size: g.size,
      cells: g.cells.map(function (c) { return { x: c.x, y: c.y, c: c.c, ring: c.ring }; }),
      order: g.order.slice(),
      hex: g.hex,
      id: g.id,
      motif: { centre: g.motif.centre, mid: g.motif.mid, border: g.motif.border }
    };
  }

  function stats(g) {
    var n = { r: 0, k: 0, g: 0, total: g.cells.length };
    for (var i = 0; i < g.cells.length; i++) n[g.cells[i].c]++;
    return n;
  }

  function f2(v) { return Math.round(v * 100) / 100; }

  // SVG of the seal as cross-stitches. progress in [0,1] stitches cells in order,
  // each cell as '/' then '\'. bg: 'night' (glowing thread), 'linen' (flat thread)
  // or 'none' (transparent, night colours).
  function svg(hex, opts) {
    opts = opts || {};
    var g = hex && hex.cells ? hex : grid(hex, { size: opts.size });
    var bgName = opts.bg === 'linen' ? 'linen' : 'night';
    var T = THEMES[bgName];
    var cell = opts.cell || 12;
    var pad = opts.pad == null ? cell : opts.pad;
    var p = opts.progress == null ? 1 : Math.max(0, Math.min(1, +opts.progress || 0));
    var glow = opts.glow == null ? bgName === 'night' : !!opts.glow;
    var W = g.size * cell + pad * 2;
    var ins = cell * 0.17;
    var legs = p * g.order.length * 2;
    var d = { r: '', k: '', g: '' }, sh = { r: '', k: '', g: '' };
    for (var i = 0; i < g.order.length; i++) {
      var done = legs - i * 2;
      if (done <= 0) break;
      var c = g.cells[g.order[i]];
      var x0 = pad + c.x * cell + ins, y0 = pad + c.y * cell + ins;
      var x1 = pad + (c.x + 1) * cell - ins, y1 = pad + (c.y + 1) * cell - ins;
      var f1 = Math.min(1, done), f2b = Math.max(0, Math.min(1, done - 1));
      d[c.c] += 'M' + f2(x0) + ' ' + f2(y1) + 'L' + f2(x0 + (x1 - x0) * f1) + ' ' + f2(y1 - (y1 - y0) * f1);
      if (f1 >= 1) sh[c.c] += 'M' + f2(x0 + (x1 - x0) * 0.3) + ' ' + f2(y1 - (y1 - y0) * 0.3 - cell * 0.05) + 'L' + f2(x0 + (x1 - x0) * 0.62) + ' ' + f2(y1 - (y1 - y0) * 0.62 - cell * 0.05);
      if (f2b > 0) {
        d[c.c] += 'M' + f2(x0) + ' ' + f2(y0) + 'L' + f2(x0 + (x1 - x0) * f2b) + ' ' + f2(y0 + (y1 - y0) * f2b);
        if (f2b >= 1) sh[c.c] += 'M' + f2(x0 + (x1 - x0) * 0.38) + ' ' + f2(y0 + (y1 - y0) * 0.38 - cell * 0.05) + 'L' + f2(x0 + (x1 - x0) * 0.7) + ' ' + f2(y0 + (y1 - y0) * 0.7 - cell * 0.05);
      }
    }
    var lw = f2(cell * 0.26);
    var out = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + W + ' ' + W + '" width="' + W + '" height="' + W + '" role="img" aria-label="Seal ' + g.id + '">';
    if (opts.bg === 'night' || opts.bg === 'linen') out += '<rect width="' + W + '" height="' + W + '" fill="' + T.bg + '"/>';
    out += '<g fill="none" stroke-linecap="round">';
    var keys = ['k', 'r', 'g'];
    for (var j = 0; j < keys.length; j++) {
      var kc = keys[j];
      if (!d[kc]) continue;
      if (glow && (kc !== 'k')) {
        out += '<path d="' + d[kc] + '" stroke="' + T[kc] + '" stroke-width="' + f2(cell * 0.8) + '" opacity="0.07"/>';
        out += '<path d="' + d[kc] + '" stroke="' + T[kc] + '" stroke-width="' + f2(cell * 0.48) + '" opacity="0.13"/>';
      } else if (bgName === 'linen') {
        out += '<path d="' + d[kc] + '" stroke="#5a3b1c" stroke-width="' + f2(cell * 0.3) + '" opacity="0.2" transform="translate(' + f2(cell * 0.04) + ' ' + f2(cell * 0.06) + ')"/>';
      }
      out += '<path d="' + d[kc] + '" stroke="' + T[kc + 'd'] + '" stroke-width="' + f2(cell * 0.3) + '"/>';
      out += '<path d="' + d[kc] + '" stroke="' + T[kc] + '" stroke-width="' + lw + '"/>';
      if (sh[kc]) out += '<path d="' + sh[kc] + '" stroke="' + T[kc + 'l'] + '" stroke-width="' + f2(cell * 0.08) + '" opacity="0.6"/>';
    }
    out += '</g></svg>';
    return out;
  }

  var ANSI = {
    dark: { r: '\x1b[38;2;229;65;47m', k: '\x1b[38;2;185;177;162m', g: '\x1b[38;2;232;176;74m' },
    light: { r: '\x1b[38;2;200;48;32m', k: '\x1b[38;2;21;21;21m', g: '\x1b[38;2;168;116;31m' },
    c256: { r: '\x1b[38;5;203m', k: '\x1b[38;5;250m', g: '\x1b[38;5;179m' }
  };
  var PLAIN = { r: '×', k: '+', g: '*' };

  // Terminal art. Each cell is two columns wide so the seal stays square.
  // opts.ansi: true (24-bit colour for dark terminals), 'light', 256, or false (plain).
  function ascii(hex, opts) {
    opts = opts || {};
    var g = hex && hex.cells ? hex : grid(hex, { size: opts.size });
    var ansi = opts.ansi;
    var pal = ansi === 'light' ? ANSI.light : ansi === 256 || ansi === '256' ? ANSI.c256 : ANSI.dark;
    var indent = opts.indent || '';
    var map = {};
    for (var i = 0; i < g.cells.length; i++) map[g.cells[i].y * g.size + g.cells[i].x] = g.cells[i].c;
    var lines = [];
    for (var y = 0; y < g.size; y++) {
      var line = '';
      for (var x = 0; x < g.size; x++) {
        var c = map[y * g.size + x];
        if (!c) { line += '  '; continue; }
        line += ansi ? pal[c] + '×\x1b[0m ' : PLAIN[c] + ' ';
      }
      lines.push(indent + line.replace(/\s+$/, ''));
    }
    return lines.join('\n');
  }

  return { grid: grid, svg: svg, ascii: ascii, short: short, stats: stats, themes: THEMES, version: '0.1.0' };
});
