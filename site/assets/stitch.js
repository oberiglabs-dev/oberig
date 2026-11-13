/*
 * Oberig stitch renderer.
 *
 * Draws cross-stitch on a canvas 2D context or as an SVG string: text in a
 * 5x7 stitch font (with descenders) and seals from seal.js. Every lit cell is
 * a "×" made of two thread strokes, '/' first and then '\', with round caps,
 * a little sheen, a seeded wobble and a few loose thread ends.
 *
 * Pure and deterministic for a given progress p in [0,1], so a video can
 * render frame by frame and the site can animate at 60 fps.
 * No dependencies and no Node APIs (UMD: window.OberigStitch).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    var seal = null;
    try { seal = require('./seal.js'); } catch (e) { seal = null; }
    module.exports = factory(seal, root);
  } else {
    root.OberigStitch = factory(null, root);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (sealModule, root) {
  'use strict';

  function Seal() { return sealModule || (root && root.OberigSeal) || null; }

  // Thread colours. main / light (sheen) / dark (edge) / glow.
  var THEMES = {
    night: {
      bg: '#0d0c0b', hole: 'rgba(241,234,219,0.05)', glow: true, shadow: null,
      r: ['#e5412f', '#ff9a80', '#8f1a12'],
      k: ['#b9b1a2', '#fbf6ea', '#5e574d'],
      g: ['#e8b04a', '#fff0c2', '#8f6214']
    },
    linen: {
      bg: '#f1eadb', hole: 'rgba(60,40,20,0.11)', glow: false, shadow: 'rgba(84,52,22,0.24)',
      r: ['#e0402d', '#ff9a80', '#9e1b14'],
      k: ['#151515', '#6d6964', '#000000'],
      g: ['#e3a93f', '#fff3cc', '#9a6a1a']
    }
  };

  // 5x7 stitch font. Rows 0-6 sit on the baseline, rows 7-8 are descenders.
  // Glyphs may be narrower than 5 columns.
  var FONT = {
    a: ['.....', '.....', '.###.', '....#', '.####', '#...#', '.####'],
    b: ['#....', '#....', '####.', '#...#', '#...#', '#...#', '####.'],
    c: ['.....', '.....', '.###.', '#....', '#....', '#...#', '.###.'],
    d: ['....#', '....#', '.####', '#...#', '#...#', '#...#', '.####'],
    e: ['.....', '.....', '.###.', '#...#', '#####', '#....', '.###.'],
    f: ['..##', '.#..', '.#..', '###.', '.#..', '.#..', '.#..'],
    g: ['.....', '.....', '.####', '#...#', '#...#', '#...#', '.####', '....#', '.###.'],
    h: ['#....', '#....', '#.##.', '##..#', '#...#', '#...#', '#...#'],
    i: ['.#.', '...', '##.', '.#.', '.#.', '.#.', '###'],
    j: ['...#', '....', '..##', '...#', '...#', '...#', '...#', '#..#', '.##.'],
    k: ['#...', '#...', '#..#', '#.#.', '##..', '#.#.', '#..#'],
    l: ['##.', '.#.', '.#.', '.#.', '.#.', '.#.', '###'],
    m: ['.....', '.....', '##.#.', '#.#.#', '#.#.#', '#.#.#', '#...#'],
    n: ['.....', '.....', '#.##.', '##..#', '#...#', '#...#', '#...#'],
    o: ['.....', '.....', '.###.', '#...#', '#...#', '#...#', '.###.'],
    p: ['.....', '.....', '####.', '#...#', '#...#', '#...#', '####.', '#....', '#....'],
    q: ['.....', '.....', '.####', '#...#', '#...#', '#...#', '.####', '....#', '....#'],
    r: ['.....', '.....', '#.##.', '##..#', '#....', '#....', '#....'],
    s: ['.....', '.....', '.####', '#....', '.###.', '....#', '####.'],
    t: ['.#..', '.#..', '###.', '.#..', '.#..', '.#.#', '..#.'],
    u: ['.....', '.....', '#...#', '#...#', '#...#', '#..##', '.##.#'],
    v: ['.....', '.....', '#...#', '#...#', '#...#', '.#.#.', '..#..'],
    w: ['.....', '.....', '#...#', '#...#', '#.#.#', '#.#.#', '.#.#.'],
    x: ['.....', '.....', '#...#', '.#.#.', '..#..', '.#.#.', '#...#'],
    y: ['.....', '.....', '#...#', '#...#', '#...#', '#...#', '.####', '....#', '.###.'],
    z: ['.....', '.....', '#####', '...#.', '..#..', '.#...', '#####'],
    '0': ['.###.', '#...#', '#..##', '#.#.#', '##..#', '#...#', '.###.'],
    '1': ['.#.', '##.', '.#.', '.#.', '.#.', '.#.', '###'],
    '2': ['.###.', '#...#', '....#', '...#.', '..#..', '.#...', '#####'],
    '3': ['#####', '...#.', '..#..', '...#.', '....#', '#...#', '.###.'],
    '4': ['...#.', '..##.', '.#.#.', '#..#.', '#####', '...#.', '...#.'],
    '5': ['#####', '#....', '####.', '....#', '....#', '#...#', '.###.'],
    '6': ['..##.', '.#...', '#....', '####.', '#...#', '#...#', '.###.'],
    '7': ['#####', '....#', '...#.', '..#..', '.#...', '.#...', '.#...'],
    '8': ['.###.', '#...#', '#...#', '.###.', '#...#', '#...#', '.###.'],
    '9': ['.###.', '#...#', '#...#', '.####', '....#', '...#.', '.##..'],
    ' ': ['...', '...', '...', '...', '...', '...', '...'],
    '.': ['.', '.', '.', '.', '.', '.', '#'],
    ',': ['..', '..', '..', '..', '..', '..', '.#', '#.'],
    ':': ['.', '.', '.', '#', '.', '.', '#'],
    ';': ['..', '..', '..', '.#', '..', '..', '.#', '#.'],
    '!': ['#', '#', '#', '#', '#', '.', '#'],
    '?': ['.###.', '#...#', '....#', '...#.', '..#..', '.....', '..#..'],
    "'": ['#', '#', '.', '.', '.', '.', '.'],
    '"': ['#.#', '#.#', '...', '...', '...', '...', '...'],
    '-': ['....', '....', '....', '....', '####', '....', '....'],
    '_': ['.....', '.....', '.....', '.....', '.....', '.....', '.....', '#####'],
    '+': ['.....', '.....', '..#..', '..#..', '#####', '..#..', '..#..'],
    '=': ['....', '....', '....', '####', '....', '####', '....'],
    '/': ['....#', '....#', '...#.', '..#..', '.#...', '#....', '#....'],
    '\\': ['#....', '#....', '.#...', '..#..', '...#.', '....#', '....#'],
    '|': ['#', '#', '#', '#', '#', '#', '#', '#'],
    '(': ['..#', '.#.', '#..', '#..', '#..', '.#.', '..#'],
    ')': ['#..', '.#.', '..#', '..#', '..#', '.#.', '#..'],
    '[': ['###', '#..', '#..', '#..', '#..', '#..', '###'],
    ']': ['###', '..#', '..#', '..#', '..#', '..#', '###'],
    '<': ['...#', '..#.', '.#..', '#...', '.#..', '..#.', '...#'],
    '>': ['#...', '.#..', '..#.', '...#', '..#.', '.#..', '#...'],
    '*': ['.....', '..#..', '#.#.#', '.###.', '#.#.#', '..#..', '.....'],
    '#': ['.#.#.', '.#.#.', '#####', '.#.#.', '#####', '.#.#.', '.#.#.'],
    '%': ['##..#', '##..#', '...#.', '..#..', '.#...', '#..##', '#..##'],
    '&': ['.##..', '#..#.', '#.#..', '.#...', '#.#.#', '#..#.', '.##.#'],
    '@': ['.###.', '#...#', '#.###', '#.#.#', '#.###', '#....', '.###.'],
    '$': ['..#..', '.####', '#.#..', '.###.', '..#.#', '####.', '..#..'],
    '·': ['.', '.', '.', '.', '#', '.', '.'],
    '×': ['.....', '.....', '#...#', '.#.#.', '..#..', '.#.#.', '#...#'],
    '✓': ['.....', '.....', '....#', '...#.', '#.#..', '.#...', '.....'],
    '→': ['.....', '.....', '...#.', '....#', '#####', '....#', '...#.'],
    '↗': ['.....', '.####', '...##', '..#.#', '.#..#', '#....', '.....']
  };
  var ROWS = 9;     // glyph box height including descenders
  var BASE = 7;     // rows above the baseline

  function glyph(ch) {
    var g = FONT[ch];
    if (!g && ch.toLowerCase() !== ch) g = FONT[ch.toLowerCase()];
    return g || FONT['?'];
  }
  function glyphWidth(g) {
    var w = 0;
    for (var i = 0; i < g.length; i++) w = Math.max(w, g[i].length);
    return w;
  }

  // Lay text out on the stitch grid. Uppercase falls back to lowercase.
  // Returns {cols, rows, cells: [{x, y, c}], order} with order = glyph by glyph,
  // row by row, back and forth like a real stitcher.
  function layout(text, opts) {
    opts = opts || {};
    var tracking = opts.tracking == null ? 1 : opts.tracking;
    var lineGap = opts.lineGap == null ? 2 : opts.lineGap;
    var color = opts.color || 'r';
    var lines = String(text == null ? '' : text).split('\n');
    var cells = [], cols = 0;
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li], x = 0, y0 = li * (ROWS + lineGap);
      for (var i = 0; i < line.length; i++) {
        var g = glyph(line[i]), w = glyphWidth(g);
        for (var r = 0; r < g.length; r++) {
          var row = g[r], xs = [];
          for (var c = 0; c < row.length; c++) if (row[c] === '#') xs.push(c);
          if (r % 2) xs.reverse();
          for (var k = 0; k < xs.length; k++) cells.push({ x: x + xs[k], y: y0 + r, c: color });
        }
        x += w + (i < line.length - 1 ? tracking : 0);
      }
      cols = Math.max(cols, x);
    }
    var order = new Array(cells.length);
    for (var j = 0; j < cells.length; j++) order[j] = j;
    return { cols: cols, rows: lines.length * ROWS + (lines.length - 1) * lineGap, baseline: BASE, cells: cells, order: order };
  }

  function measure(text, opts) {
    var L = layout(text, opts);
    var cell = (opts && opts.cell) || 12;
    return { cols: L.cols, rows: L.rows, width: L.cols * cell, height: L.rows * cell };
  }

  // A seal grid from seal.js, from a hash or an existing grid.
  function sealGrid(hexOrGrid, opts) {
    if (hexOrGrid && hexOrGrid.cells) return hexOrGrid;
    var S = Seal();
    if (!S) throw new Error('OberigSeal is not loaded');
    return S.grid(hexOrGrid, { size: (opts && opts.size) || 17 });
  }

  // Small integer hash -> [0,1). Same inputs, same wobble, every frame.
  function h01(a, b, c, d) {
    var h = Math.imul(a | 0, 374761393) ^ Math.imul(b | 0, 668265263) ^ Math.imul(c | 0, 2246822519) ^ Math.imul(d | 0, 3266489917);
    h = Math.imul(h ^ (h >>> 13), 1274126177);
    h ^= h >>> 16;
    return (h >>> 0) / 4294967296;
  }

  // Ease out with a short overshoot: the thread lands a touch past the hole and settles.
  function land(u) {
    var c1 = 0.9, c3 = c1 + 1, v = u - 1;
    return 1 + c3 * v * v * v + c1 * v * v;
  }

  function hexRgb(hex) {
    var h = hex.replace('#', '');
    if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
    var n = parseInt(h, 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  }
  function mix(hex, to, t) {
    var a = hexRgb(hex), b = hexRgb(to);
    var r = function (i) { return Math.round(a[i] + (b[i] - a[i]) * t); };
    return 'rgb(' + r(0) + ',' + r(1) + ',' + r(2) + ')';
  }
  function threadOf(theme, c) {
    if (theme[c]) return theme[c];
    if (typeof c === 'string' && c[0] === '#') return [c, mix(c, '#ffffff', 0.45), mix(c, '#000000', 0.45)];
    return theme.r;
  }

  // Geometry shared by the canvas and SVG painters.
  function plan(input, opts) {
    opts = opts || {};
    var cells = input.cells || input;
    var order = input.order || null;
    var n = cells.length;
    var s = opts.cell || 12;
    var X = opts.x || 0, Y = opts.y || 0;
    var theme = THEMES[opts.theme] || THEMES.night;
    var seed = opts.seed == null ? 7 : opts.seed | 0;
    var p = opts.progress == null ? 1 : Math.max(0, Math.min(1, +opts.progress || 0));
    var win = opts.window == null ? 3 : Math.max(1, opts.window);
    var total = 2 * n;
    var t = p >= 1 ? Infinity : p * (total - 1 + win);
    var ins = s * 0.15;
    var wob = s * (opts.wobble == null ? 0.035 : opts.wobble);
    var legs = [], ends = [], front = null, last = null;
    var count = p >= 1 ? n : Math.min(n, Math.ceil(t / 2));
    for (var i = 0; i < count; i++) {
      var c = cells[order ? order[i] : i];
      var bx = X + c.x * s, by = Y + c.y * s;
      var cx = c.x | 0, cy = c.y | 0;
      for (var L = 0; L < 2; L++) {
        var j = 2 * i + L;
        var u = (t - j) / win;
        if (u <= 0) break;
        if (u > 1) u = 1;
        var w1 = (h01(cx, cy, seed, L * 4 + 1) - 0.5) * 2 * wob, w2 = (h01(cx, cy, seed, L * 4 + 2) - 0.5) * 2 * wob;
        var w3 = (h01(cx, cy, seed, L * 4 + 3) - 0.5) * 2 * wob, w4 = (h01(cx, cy, seed, L * 4 + 4) - 0.5) * 2 * wob;
        var x1, y1, x2, y2;
        if (L === 0) { x1 = bx + ins + w1; y1 = by + s - ins + w2; x2 = bx + s - ins + w3; y2 = by + ins + w4; }
        else { x1 = bx + ins + w1; y1 = by + ins + w2; x2 = bx + s - ins + w3; y2 = by + s - ins + w4; }
        var e = u >= 1 ? 1 : land(u);
        var leg = { c: c.c || 'r', x1: x1, y1: y1, x2: x1 + (x2 - x1) * e, y2: y1 + (y2 - y1) * e, done: u >= 1, fx: x2, fy: y2 };
        legs.push(leg);
        if (u < 1) front = leg;
        last = leg;
      }
      // A few loose thread ends, only on finished cells.
      if (opts.ends !== false && i < count && (p >= 1 || t - (2 * i + 1) >= win) && h01(cx, cy, seed, 99) < (opts.endRate == null ? 0.05 : opts.endRate)) {
        var corner = h01(cx, cy, seed, 98) < 0.5;
        var sx = corner ? bx + s - ins : bx + ins, sy = by + s - ins;
        var dir = corner ? 1 : -1;
        var len = s * (0.35 + 0.25 * h01(cx, cy, seed, 97));
        ends.push({ c: c.c || 'r', x1: sx, y1: sy, cx: sx + dir * len * 0.9, cy: sy + len * 0.15, x2: sx + dir * len * 0.55, y2: sy + len * 0.75 });
      }
    }
    if (!front && p < 1 && p > 0 && last) front = last;
    return { legs: legs, ends: ends, front: p > 0 && p < 1 ? front : null, s: s, theme: theme, lw: s * (opts.weight || 0.25), opts: opts };
  }

  function groupBy(legs) {
    var g = {}, keys = [];
    for (var i = 0; i < legs.length; i++) {
      var k = legs[i].c;
      if (!g[k]) { g[k] = []; keys.push(k); }
      g[k].push(legs[i]);
    }
    // black first, gold last, so the warm threads sit on top
    keys.sort(function (a, b) { return rank(a) - rank(b); });
    return { g: g, keys: keys };
    function rank(k) { return k === 'k' ? 0 : k === 'r' ? 1 : k === 'g' ? 3 : 2; }
  }

  // ---------- canvas ----------

  function strokeLegs(ctx, list, part, lw) {
    ctx.beginPath();
    for (var i = 0; i < list.length; i++) {
      var l = list[i];
      if (part === 'sheen') {
        if (!l.done) continue;
        var dx = l.x2 - l.x1, dy = l.y2 - l.y1, off = lw * 0.22;
        ctx.moveTo(l.x1 + dx * 0.26, l.y1 + dy * 0.26 - off);
        ctx.lineTo(l.x1 + dx * 0.62, l.y1 + dy * 0.62 - off);
      } else {
        ctx.moveTo(l.x1, l.y1);
        ctx.lineTo(l.x2, l.y2);
      }
    }
    ctx.stroke();
  }

  function fabric(ctx, opts, cols, rows) {
    var s = opts.cell || 12, X = opts.x || 0, Y = opts.y || 0;
    var theme = THEMES[opts.theme] || THEMES.night;
    var m = opts.fabricMargin == null ? 1 : opts.fabricMargin;
    ctx.fillStyle = theme.hole;
    var r = Math.max(0.6, s * 0.055);
    for (var y = -m; y <= rows + m; y++) for (var x = -m; x <= cols + m; x++) {
      ctx.fillRect(X + x * s - r, Y + y * s - r, r * 2, r * 2);
    }
  }

  function draw(ctx, input, opts) {
    opts = opts || {};
    var P = plan(input, opts);
    var s = P.s, lw = P.lw, theme = P.theme;
    var glow = opts.glow == null ? theme.glow : !!opts.glow;
    if (opts.fabric) {
      var cells = input.cells || input, cols = input.cols || input.size, rows = input.rows || input.size;
      if (!cols) { cols = 0; rows = 0; for (var q = 0; q < cells.length; q++) { cols = Math.max(cols, cells[q].x + 1); rows = Math.max(rows, cells[q].y + 1); } }
      fabric(ctx, opts, cols, rows);
    }
    var G = groupBy(P.legs);
    ctx.save();
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    for (var i = 0; i < G.keys.length; i++) {
      var k = G.keys[i], list = G.g[k], th = threadOf(theme, k);
      if (glow) {
        ctx.globalAlpha = k === 'k' ? 0.035 : 0.075;
        ctx.strokeStyle = th[0];
        ctx.lineWidth = lw * 3.4;
        strokeLegs(ctx, list);
        ctx.globalAlpha = k === 'k' ? 0.06 : 0.14;
        ctx.lineWidth = lw * 1.9;
        strokeLegs(ctx, list);
      } else if (theme.shadow) {
        ctx.save();
        ctx.translate(s * 0.035, s * 0.055);
        ctx.globalAlpha = 1;
        ctx.strokeStyle = theme.shadow;
        ctx.lineWidth = lw * 1.12;
        strokeLegs(ctx, list);
        ctx.restore();
      }
      ctx.globalAlpha = 1;
      ctx.strokeStyle = th[2];
      ctx.lineWidth = lw * 1.18;
      strokeLegs(ctx, list);
      ctx.strokeStyle = th[0];
      ctx.lineWidth = lw;
      strokeLegs(ctx, list);
      if (opts.sheen !== false && s >= 6) {
        ctx.globalAlpha = glow ? 0.6 : 0.45;
        ctx.strokeStyle = th[1];
        ctx.lineWidth = Math.max(0.6, lw * 0.3);
        strokeLegs(ctx, list, 'sheen', lw);
      }
    }
    // loose ends
    if (P.ends.length) {
      ctx.globalAlpha = 0.9;
      ctx.lineWidth = Math.max(0.6, lw * 0.38);
      for (var e = 0; e < P.ends.length; e++) {
        var en = P.ends[e];
        ctx.strokeStyle = threadOf(theme, en.c)[0];
        ctx.beginPath();
        ctx.moveTo(en.x1, en.y1);
        ctx.quadraticCurveTo(en.cx, en.cy, en.x2, en.y2);
        ctx.stroke();
      }
    }
    ctx.restore();
    if (opts.needle && P.front) needle(ctx, P, glow);
    return P;
  }

  // The needle sits at the tip of the stitch being made; the thread trails from its eye.
  function needleGeom(P) {
    var f = P.front, s = P.s;
    var len = s * (P.opts.needleLength || 2.6);
    var ang = -1.05 + Math.sin((f.x1 + f.y1) * 0.07) * 0.12;
    var ux = Math.cos(ang), uy = Math.sin(ang);
    var tip = { x: f.x2, y: f.y2 };
    var eye = { x: tip.x + ux * len, y: tip.y + uy * len };
    var start = { x: f.x1, y: f.y1 };
    var ctrl = { x: eye.x + s * 0.9, y: (start.y + eye.y) / 2 + s * 1.6 };
    return { tip: tip, eye: eye, ux: ux, uy: uy, len: len, start: start, ctrl: ctrl, c: f.c };
  }

  function needle(ctx, P, glow) {
    var N = needleGeom(P), s = P.s, th = threadOf(P.theme, N.c);
    ctx.save();
    ctx.lineCap = 'round';
    // trailing thread
    ctx.strokeStyle = th[0];
    ctx.globalAlpha = 0.95;
    ctx.lineWidth = Math.max(0.8, P.lw * 0.42);
    ctx.beginPath();
    ctx.moveTo(N.start.x, N.start.y);
    ctx.quadraticCurveTo(N.ctrl.x, N.ctrl.y, N.eye.x - N.ux * s * 0.25, N.eye.y - N.uy * s * 0.25);
    ctx.stroke();
    // needle body: a long taper, light steel
    var hw = Math.max(0.9, s * 0.065);
    var px = -N.uy, py = N.ux;
    if (glow) {
      ctx.globalAlpha = 0.12;
      ctx.strokeStyle = '#fff6e6';
      ctx.lineWidth = hw * 6;
      ctx.beginPath(); ctx.moveTo(N.tip.x, N.tip.y); ctx.lineTo(N.eye.x, N.eye.y); ctx.stroke();
    }
    ctx.globalAlpha = 1;
    var grad = ctx.createLinearGradient(N.tip.x + px * hw, N.tip.y + py * hw, N.tip.x - px * hw, N.tip.y - py * hw);
    grad.addColorStop(0, '#fbf8f2');
    grad.addColorStop(0.5, '#cfc8bb');
    grad.addColorStop(1, '#7d776d');
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.moveTo(N.tip.x, N.tip.y);
    ctx.lineTo(N.tip.x + N.ux * N.len * 0.3 + px * hw, N.tip.y + N.uy * N.len * 0.3 + py * hw);
    ctx.lineTo(N.eye.x + px * hw, N.eye.y + py * hw);
    ctx.arc(N.eye.x, N.eye.y, hw, Math.atan2(py, px), Math.atan2(py, px) + Math.PI, true);
    ctx.lineTo(N.tip.x + N.ux * N.len * 0.3 - px * hw, N.tip.y + N.uy * N.len * 0.3 - py * hw);
    ctx.closePath();
    ctx.fill();
    // the eye
    ctx.strokeStyle = P.theme.bg;
    ctx.lineWidth = Math.max(0.6, hw * 0.7);
    ctx.beginPath();
    ctx.moveTo(N.eye.x - N.ux * s * 0.32, N.eye.y - N.uy * s * 0.32);
    ctx.lineTo(N.eye.x - N.ux * s * 0.08, N.eye.y - N.uy * s * 0.08);
    ctx.stroke();
    ctx.restore();
  }

  function drawText(ctx, text, opts) {
    var L = layout(text, opts);
    var P = draw(ctx, L, opts);
    var s = (opts && opts.cell) || 12;
    return { cols: L.cols, rows: L.rows, width: L.cols * s, height: L.rows * s, front: P.front ? needleGeom(P).tip : null };
  }

  function drawSeal(ctx, hexOrGrid, opts) {
    var g = sealGrid(hexOrGrid, opts);
    var input = { cells: g.cells, order: g.order, cols: g.size, rows: g.size };
    var P = draw(ctx, input, opts);
    var s = (opts && opts.cell) || 12;
    return { size: g.size, width: g.size * s, height: g.size * s, id: g.id, front: P.front ? needleGeom(P).tip : null };
  }

  // ---------- SVG ----------

  function n2(v) { return Math.round(v * 10) / 10; }

  function svgPath(list, part, lw) {
    var d = '';
    for (var i = 0; i < list.length; i++) {
      var l = list[i];
      if (part === 'sheen') {
        if (!l.done) continue;
        var dx = l.x2 - l.x1, dy = l.y2 - l.y1;
        d += 'M' + n2(l.x1 + dx * 0.26) + ' ' + n2(l.y1 + dy * 0.26 - lw * 0.22) + 'L' + n2(l.x1 + dx * 0.62) + ' ' + n2(l.y1 + dy * 0.62 - lw * 0.22);
      } else d += 'M' + n2(l.x1) + ' ' + n2(l.y1) + 'L' + n2(l.x2) + ' ' + n2(l.y2);
    }
    return d;
  }

  // Returns the inner SVG markup (no <svg> wrapper); see svg() for a full document.
  function svgBody(input, opts) {
    opts = opts || {};
    var P = plan(input, opts);
    var s = P.s, lw = P.lw, theme = P.theme;
    var glow = opts.glow == null ? theme.glow : !!opts.glow;
    var G = groupBy(P.legs);
    var out = '<g fill="none" stroke-linecap="round">';
    for (var i = 0; i < G.keys.length; i++) {
      var k = G.keys[i], list = G.g[k], th = threadOf(theme, k);
      var d = svgPath(list, null, lw);
      if (glow) {
        out += '<path d="' + d + '" stroke="' + th[0] + '" stroke-width="' + n2(lw * 3.4) + '" opacity="' + (k === 'k' ? 0.035 : 0.075) + '"/>';
        out += '<path d="' + d + '" stroke="' + th[0] + '" stroke-width="' + n2(lw * 1.9) + '" opacity="' + (k === 'k' ? 0.06 : 0.14) + '"/>';
      } else if (theme.shadow) {
        out += '<path d="' + d + '" stroke="' + theme.shadow + '" stroke-width="' + n2(lw * 1.12) + '" transform="translate(' + n2(s * 0.035) + ' ' + n2(s * 0.055) + ')"/>';
      }
      out += '<path d="' + d + '" stroke="' + th[2] + '" stroke-width="' + n2(lw * 1.18) + '"/>';
      out += '<path d="' + d + '" stroke="' + th[0] + '" stroke-width="' + n2(lw) + '"/>';
      if (opts.sheen !== false && s >= 6) {
        var sd = svgPath(list, 'sheen', lw);
        if (sd) out += '<path d="' + sd + '" stroke="' + th[1] + '" stroke-width="' + n2(Math.max(0.6, lw * 0.3)) + '" opacity="' + (glow ? 0.6 : 0.45) + '"/>';
      }
    }
    for (var e = 0; e < P.ends.length; e++) {
      var en = P.ends[e];
      out += '<path d="M' + n2(en.x1) + ' ' + n2(en.y1) + 'Q' + n2(en.cx) + ' ' + n2(en.cy) + ' ' + n2(en.x2) + ' ' + n2(en.y2) + '" stroke="' + threadOf(theme, en.c)[0] + '" stroke-width="' + n2(Math.max(0.6, lw * 0.38)) + '" opacity="0.9"/>';
    }
    if (opts.needle && P.front) {
      var N = needleGeom(P), th2 = threadOf(theme, N.c), hw = Math.max(0.9, s * 0.065);
      out += '<path d="M' + n2(N.start.x) + ' ' + n2(N.start.y) + 'Q' + n2(N.ctrl.x) + ' ' + n2(N.ctrl.y) + ' ' + n2(N.eye.x - N.ux * s * 0.25) + ' ' + n2(N.eye.y - N.uy * s * 0.25) + '" stroke="' + th2[0] + '" stroke-width="' + n2(Math.max(0.8, lw * 0.42)) + '"/>';
      out += '<path d="M' + n2(N.tip.x) + ' ' + n2(N.tip.y) + 'L' + n2(N.eye.x) + ' ' + n2(N.eye.y) + '" stroke="#d9d2c5" stroke-width="' + n2(hw * 1.8) + '"/>';
      out += '<path d="M' + n2(N.eye.x - N.ux * s * 0.32) + ' ' + n2(N.eye.y - N.uy * s * 0.32) + 'L' + n2(N.eye.x - N.ux * s * 0.08) + ' ' + n2(N.eye.y - N.uy * s * 0.08) + '" stroke="' + theme.bg + '" stroke-width="' + n2(Math.max(0.6, hw * 0.7)) + '"/>';
    }
    return out + '</g>';
  }

  function svg(input, opts) {
    opts = opts || {};
    var s = opts.cell || 12;
    var pad = opts.pad == null ? s : opts.pad;
    var cells = input.cells || input;
    var cols = input.cols || input.size, rows = input.rows || input.size;
    if (!cols) { cols = 0; rows = 0; for (var i = 0; i < cells.length; i++) { cols = Math.max(cols, cells[i].x + 1); rows = Math.max(rows, cells[i].y + 1); } }
    var W = n2(cols * s + pad * 2), H = n2(rows * s + pad * 2);
    var o = {};
    for (var k in opts) o[k] = opts[k];
    o.x = pad; o.y = pad;
    var theme = THEMES[opts.theme] || THEMES.night;
    var label = opts.label ? ' role="img" aria-label="' + String(opts.label).replace(/[<>&"]/g, '') + '"' : ' aria-hidden="true"';
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + W + ' ' + H + '" width="' + W + '" height="' + H + '"' + label + '>' +
      (opts.background ? '<rect width="' + W + '" height="' + H + '" fill="' + theme.bg + '"/>' : '') +
      svgBody(input, o) + '</svg>';
  }

  function svgText(text, opts) {
    var o = {};
    for (var k in (opts || {})) o[k] = opts[k];
    if (!o.label) o.label = String(text);
    return svg(layout(text, o), o);
  }

  function svgSeal(hexOrGrid, opts) {
    var g = sealGrid(hexOrGrid, opts);
    var o = {};
    for (var k in (opts || {})) o[k] = opts[k];
    if (!o.label) o.label = 'Seal ' + g.id;
    return svg({ cells: g.cells, order: g.order, cols: g.size, rows: g.size }, o);
  }

  // How long a piece takes at a steady pace, in legs: handy for timing videos.
  function legsOf(input) { return 2 * ((input.cells || input).length); }

  return {
    FONT: FONT,
    THEMES: THEMES,
    layout: layout,
    measure: measure,
    plan: plan,
    draw: draw,
    drawText: drawText,
    drawSeal: drawSeal,
    svg: svg,
    svgBody: svgBody,
    svgText: svgText,
    svgSeal: svgSeal,
    legsOf: legsOf,
    land: land,
    version: '0.1.0'
  };
});
