/* Oberig site shell: stitched type, section navigation, start tabs, copy buttons, FAQ,
   hero parallax and needle trail, and still fallbacks for the scene mounts.
   Classic script. Needs assets/seal.js and assets/stitch.js loaded first. */
(function () {
  'use strict';

  var d = document, w = window, html = d.documentElement;
  var St = w.OberigStitch, Seal = w.OberigSeal;

  function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }
  function dpr() { return Math.min(2, w.devicePixelRatio || 1); }
  function mq(q) { try { return w.matchMedia(q); } catch (e) { return null; } }
  function each(sel, fn, root) { Array.prototype.forEach.call((root || d).querySelectorAll(sel), fn); }

  var frozen = null;
  try {
    var qs = new URLSearchParams(location.search);
    if (qs.has('p')) { frozen = parseFloat(qs.get('p')); frozen = isNaN(frozen) ? 1 : clamp(frozen, 0, 1); }
  } catch (e) {}

  var mqReduce = mq('(prefers-reduced-motion: reduce)');
  var mqDesk = mq('(min-width: 820px)');
  var mqFine = mq('(hover: hover) and (pointer: fine)');
  function motionOn() { return html.classList.contains('motion'); }
  function isDesk() { return !mqDesk || mqDesk.matches; }

  var sections = Array.prototype.slice.call(d.querySelectorAll('main > .sec'));

  // Demo receipt hashes: fixed strings so the page looks the same on every visit.
  function demoHash(i) {
    var s = 'receipt-' + i, out = '';
    for (var j = 0; j < 8; j++) {
      var h = 2166136261 ^ (j * 0x9e3779b9);
      for (var k = 0; k < s.length; k++) { h ^= s.charCodeAt(k); h = Math.imul(h, 16777619); }
      h ^= h >>> 15; h = Math.imul(h, 0x2c1b3c6d); h ^= h >>> 12; h = Math.imul(h, 0x297a2d39); h ^= h >>> 15;
      out += ('00000000' + (h >>> 0).toString(16)).slice(-8);
    }
    return out;
  }

  var api = w.OberigSite = {
    motion: motionOn(),
    frozen: frozen,
    sections: sections,
    active: sections[0] ? sections[0].id : null,
    isDesk: isDesk,
    demoHash: demoHash
  };

  // ---------- one animation loop ----------

  var tasks = [], rafId = 0;
  function kick() { if (!rafId) rafId = w.requestAnimationFrame(loop); }
  function loop(now) {
    rafId = 0;
    var keep = [];
    for (var i = 0; i < tasks.length; i++) {
      var ok = false;
      try { ok = tasks[i](now); } catch (e) { ok = false; }
      if (ok) keep.push(tasks[i]);
    }
    tasks = keep;
    if (tasks.length) kick();
  }
  function addTask(fn) { if (tasks.indexOf(fn) < 0) tasks.push(fn); kick(); }

  // ---------- stitched type ----------

  var stitched = [];

  function wrapWords(text, maxCols) {
    var words = text.split(' '), lines = [], cur = '';
    for (var i = 0; i < words.length; i++) {
      var next = cur ? cur + ' ' + words[i] : words[i];
      if (!cur || St.measure(next, { cell: 1 }).cols <= maxCols) cur = next;
      else { lines.push(cur); cur = words[i]; }
    }
    if (cur) lines.push(cur);
    return lines.join('\n');
  }

  function availOf(it) {
    return Math.max(120, it.el.clientWidth || (it.el.parentNode && it.el.parentNode.clientWidth) || 300);
  }

  // Smallest width (in grid columns) that wraps the text into at most maxLines lines.
  function fitCols(text, maxLines) {
    var full = St.measure(text, { cell: 1 }).cols;
    var words = text.split(' '), lo = 0;
    for (var i = 0; i < words.length; i++) lo = Math.max(lo, St.measure(words[i], { cell: 1 }).cols);
    for (var c = lo; c < full; c++) {
      var t = wrapWords(text, c);
      if (t.split('\n').length <= maxLines) return St.measure(t, { cell: 1 }).cols;
    }
    return full;
  }

  // All section titles share one stitch size: the largest that keeps every title within its lines.
  var titleCell = 6;
  function computeTitleCell() {
    var cell = isDesk() ? (w.innerHeight < 780 ? 5.6 : 6.6) : 4.4;
    var maxLines = isDesk() ? 2 : 3;
    for (var i = 0; i < stitched.length; i++) {
      var it = stitched[i];
      if (it.kind !== 'title') continue;
      cell = Math.min(cell, (availOf(it) - 4) / fitCols(it.text, maxLines));
    }
    titleCell = Math.max(3.25, Math.floor(cell * 4) / 4);
  }

  function layoutItem(it) {
    var text = it.text, cell;
    var avail = availOf(it);
    if (it.kind === 'mini') {
      cell = 3.2;
    } else if (it.kind === 'mark') {
      var cols = St.measure(text, { cell: 1 }).cols;
      cell = clamp(avail / (cols + 3), 7, isDesk() ? (w.innerHeight < 780 ? 13 : 15.5) : 11);
    } else {
      cell = titleCell;
      text = wrapWords(it.text, Math.floor((avail - 4) / cell));
    }
    if (it.kind !== 'title') cell = Math.round(cell * 4) / 4;
    var m = St.measure(text, { cell: cell });
    var pl = cell * 1, pr = cell * 2.5, pt = cell * 3, pb = cell * 2.5;
    var W = Math.ceil(m.width + pl + pr), H = Math.ceil(m.height + pt + pb), r = dpr();
    it.cv.width = Math.round(W * r);
    it.cv.height = Math.round(H * r);
    it.cv.style.width = W + 'px';
    it.cv.style.height = H + 'px';
    it.cv.style.margin = (-pt) + 'px ' + (-pr) + 'px ' + (-pb) + 'px ' + (-pl) + 'px';
    it.ctx = it.cv.getContext('2d');
    it.ctx.setTransform(r, 0, 0, r, 0, 0);
    it.W = W; it.H = H; it.pl = pl; it.pt = pt;
    it.cell = cell; it.lines = text;
    it.cells = St.layout(text, {}).cells.length;
  }

  function paint(it) {
    if (!it.ctx) return;
    it.ctx.clearRect(0, 0, it.W, it.H);
    var p = it.p;
    St.drawText(it.ctx, it.lines, {
      x: it.pl, y: it.pt, cell: it.cell, theme: 'night',
      progress: p, needle: p > 0 && p < 1, seed: 7,
      sheen: it.cell >= 6
    });
  }

  function sew(it, delay) {
    if (it.state !== 'idle') return;
    if (frozen !== null || !motionOn()) {
      it.state = 'done'; it.p = frozen !== null ? frozen : 1; paint(it); return;
    }
    it.state = 'run';
    it.t0 = performance.now() + (delay || 0);
    it.dur = it.kind === 'mark' ? 2200 : clamp(it.cells * 9, 1100, 1800);
    addTask(function step(now) {
      if (it.state !== 'run' || !it.el.isConnected) return false;
      var t = clamp((now - it.t0) / it.dur, 0, 1);
      it.p = 1 - Math.pow(1 - t, 1.35);
      if (t >= 1) { it.p = 1; it.state = 'done'; }
      paint(it);
      return it.state === 'run';
    });
  }

  function setupStitched() {
    if (!St) return;
    each('[data-stitch]', function (el) {
      var kind = el.classList.contains('wordmark') ? 'mark' : el.classList.contains('foot-mark') ? 'mini' : 'title';
      var cv = d.createElement('canvas');
      cv.className = 'stitch-canvas';
      cv.setAttribute('aria-hidden', 'true');
      el.appendChild(cv);
      el.classList.add('has-stitch');
      var it = { el: el, cv: cv, text: el.getAttribute('data-stitch'), kind: kind, state: 'idle', p: 1 };
      if (kind === 'mini') it.state = 'done';
      else it.p = frozen !== null ? frozen : (motionOn() ? 0 : 1);
      stitched.push(it);
    });
    relayout();
  }

  function relayout() {
    computeTitleCell();
    stitched.forEach(function (it) { layoutItem(it); paint(it); });
  }

  // ---------- sections, dots, reveal ----------

  var dots = {};

  function setActive(id) {
    if (!id) return;
    var changed = api.active !== id;
    api.active = id;
    for (var k in dots) {
      if (k === id) dots[k].setAttribute('aria-current', 'true');
      else dots[k].removeAttribute('aria-current');
    }
    html.setAttribute('data-section', id);
    if (changed) {
      try { d.dispatchEvent(new CustomEvent('oberig:section', { detail: { id: id } })); } catch (e) {}
    }
  }

  function enter(sec) {
    if (sec.classList.contains('is-in')) return;
    sec.classList.add('is-in');
    for (var i = 0; i < stitched.length; i++) {
      var it = stitched[i];
      if (it.kind !== 'mini' && sec.contains(it.el)) sew(it, it.kind === 'mark' ? 250 : 120);
    }
  }

  function setupSections() {
    each('[data-dot]', function (a) { dots[a.getAttribute('data-dot')] = a; });
    if (!sections.length) return;
    setActive(sections[0].id);
    if (!('IntersectionObserver' in w)) { sections.forEach(enter); return; }
    var mid = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) setActive(e.target.id); });
    }, { rootMargin: '-48% 0px -51% 0px', threshold: 0 });
    var seen = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { enter(e.target); seen.unobserve(e.target); }
      });
    }, { rootMargin: '0px 0px -22% 0px', threshold: 0 });
    sections.forEach(function (s) { mid.observe(s); seen.observe(s); });
  }

  // ---------- keyboard: one section per key on desktop ----------

  var navTarget = -1, navTimer = 0;

  function nearest() {
    var y = w.scrollY, best = 0, bd = Infinity;
    for (var i = 0; i < sections.length; i++) {
      var dd = Math.abs(sections[i].offsetTop - y);
      if (dd < bd) { bd = dd; best = i; }
    }
    return best;
  }

  function go(i) {
    i = clamp(i, 0, sections.length - 1);
    navTarget = i;
    clearTimeout(navTimer);
    navTimer = setTimeout(function () { navTarget = -1; }, 850);
    var s = sections[i];
    w.scrollTo({ top: s.offsetTop, behavior: motionOn() ? 'smooth' : 'auto' });
    try { s.focus({ preventScroll: true }); } catch (e) {}
  }

  function snapping() { return isDesk() && w.innerHeight > 600; }

  d.addEventListener('keydown', function (e) {
    if (e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
    if (!snapping() || !sections.length) return;
    var t = e.target;
    if (t && t.closest && t.closest('input, textarea, select, [contenteditable=""], [contenteditable="true"], [role="tablist"], [role="slider"], [role="listbox"], [role="menu"], [role="textbox"]')) return;
    var k = e.key, dir = 0;
    if (k === 'ArrowDown' || k === 'PageDown') dir = 1;
    else if (k === 'ArrowUp' || k === 'PageUp') dir = -1;
    else if (k === 'Home') { e.preventDefault(); go(0); return; }
    else if (k === 'End') { e.preventDefault(); go(sections.length - 1); return; }
    if (!dir) return;
    var cur = navTarget >= 0 ? navTarget : nearest();
    if (navTarget < 0) {
      // A section taller than the screen scrolls normally until its edge.
      var s = sections[cur];
      if (dir > 0 && s.offsetTop + s.offsetHeight > w.scrollY + w.innerHeight + 8) return;
      if (dir < 0 && s.offsetTop < w.scrollY - 8) return;
    }
    e.preventDefault();
    go(cur + dir);
  });

  // ---------- start: tabs and copy ----------

  function setupTabs() {
    each('[data-tabs]', function (root) {
      var tabs = Array.prototype.slice.call(root.querySelectorAll('[role="tab"]'));
      function select(tab, focus) {
        tabs.forEach(function (t) {
          var on = t === tab;
          t.setAttribute('aria-selected', on ? 'true' : 'false');
          t.tabIndex = on ? 0 : -1;
          var panel = d.getElementById(t.getAttribute('aria-controls'));
          if (panel) panel.hidden = !on;
        });
        if (focus) tab.focus();
      }
      tabs.forEach(function (tab, i) {
        tab.addEventListener('click', function () {
          select(tab, false);
          try { localStorage.setItem('oberig-shell', tab.id); } catch (e) {}
        });
        tab.addEventListener('keydown', function (e) {
          var n = tabs.length, j = -1;
          if (e.key === 'ArrowRight') j = (i + 1) % n;
          else if (e.key === 'ArrowLeft') j = (i - 1 + n) % n;
          else if (e.key === 'Home') j = 0;
          else if (e.key === 'End') j = n - 1;
          if (j < 0) return;
          e.preventDefault();
          select(tabs[j], true);
          try { localStorage.setItem('oberig-shell', tabs[j].id); } catch (e2) {}
        });
      });
      var saved = null;
      try { saved = localStorage.getItem('oberig-shell'); } catch (e) {}
      var byId = saved && d.getElementById(saved);
      var isWin = /Win/i.test(navigator.platform || '') || /Windows/i.test(navigator.userAgent || '');
      select(byId && tabs.indexOf(byId) >= 0 ? byId : (isWin ? tabs[0] : tabs[tabs.length - 1]), false);
    });
  }

  function execCopy(text) {
    var ta = d.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '0';
    ta.style.opacity = '0';
    d.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = d.execCommand('copy'); } catch (e) {}
    d.body.removeChild(ta);
    return ok;
  }

  function copyText(text) {
    return new Promise(function (resolve, reject) {
      function fallback() { if (execCopy(text)) resolve(); else reject(); }
      if (navigator.clipboard && w.isSecureContext) navigator.clipboard.writeText(text).then(resolve, fallback);
      else fallback();
    });
  }

  function setupCopy() {
    var status = d.getElementById('copy-status');
    d.addEventListener('click', function (e) {
      var b = e.target && e.target.closest && e.target.closest('.copy-btn');
      if (!b) return;
      var code = b.parentNode.querySelector('code');
      if (!code) return;
      var label = b.getAttribute('data-label') || b.textContent;
      b.setAttribute('data-label', label);
      function show(txt, ok) {
        b.textContent = txt;
        b.classList.toggle('is-done', ok);
        if (status) status.textContent = ok ? 'Command copied' : 'Command selected';
        clearTimeout(b._t);
        b._t = setTimeout(function () { b.textContent = label; b.classList.remove('is-done'); }, 1800);
      }
      copyText(code.textContent).then(function () { show('Copied', true); }, function () {
        try {
          var range = d.createRange(); range.selectNodeContents(code);
          var sel = w.getSelection(); sel.removeAllRanges(); sel.addRange(range);
        } catch (err) {}
        show('Selected', false);
      });
    });
  }

  function setupFaq() {
    var items = Array.prototype.slice.call(d.querySelectorAll('.faq details'));
    items.forEach(function (dt) {
      dt.addEventListener('toggle', function () {
        if (!dt.open) return;
        items.forEach(function (o) { if (o !== dt && o.open) o.open = false; });
      });
    });
  }

  // ---------- hero: parallax and needle trail ----------

  var hero = null, trailCv = null, trailCtx = null;

  function sizeTrail() {
    if (!trailCv || !hero) return;
    var r = dpr();
    trailCv.width = Math.round(hero.clientWidth * r);
    trailCv.height = Math.round(hero.clientHeight * r);
    trailCtx.setTransform(r, 0, 0, r, 0, 0);
  }

  function setupHero() {
    hero = d.getElementById('top');
    if (!hero) return;
    var stage = hero.querySelector('.stage'), mark = hero.querySelector('.wordmark');
    trailCv = hero.querySelector('.trail');
    trailCtx = trailCv && trailCv.getContext ? trailCv.getContext('2d') : null;
    if (!trailCtx) trailCv = null;
    sizeTrail();
    var pts = [], cur = { x: 0, y: 0 }, tgt = { x: 0, y: 0 }, visible = true;
    var LIFE = 620;

    function enabled() { return motionOn() && isDesk() && (!mqFine || mqFine.matches) && frozen === null; }

    if ('IntersectionObserver' in w) {
      new IntersectionObserver(function (es) {
        visible = es[es.length - 1].isIntersecting;
        if (!visible) { pts.length = 0; if (trailCtx) trailCtx.clearRect(0, 0, hero.clientWidth, hero.clientHeight); }
      }).observe(hero);
    }

    function drawTrail(now) {
      if (!trailCtx) return;
      var c = trailCtx;
      c.clearRect(0, 0, hero.clientWidth, hero.clientHeight);
      var n = pts.length;
      if (n < 2) return;
      c.save();
      c.lineCap = 'round';
      c.lineJoin = 'round';
      for (var i = 1; i < n; i++) {
        var a = pts[i - 1], b = pts[i];
        var life = 1 - (now - b.t) / LIFE;
        if (life <= 0) continue;
        var k = life * (i / n);
        c.strokeStyle = 'rgba(229,65,47,' + (0.07 * k).toFixed(3) + ')';
        c.lineWidth = 5;
        c.beginPath(); c.moveTo(a.x, a.y); c.lineTo(b.x, b.y); c.stroke();
        c.strokeStyle = 'rgba(229,65,47,' + (0.55 * k).toFixed(3) + ')';
        c.lineWidth = 1.3;
        c.beginPath(); c.moveTo(a.x, a.y); c.lineTo(b.x, b.y); c.stroke();
      }
      // the needle leads the thread
      var h = pts[n - 1], q = pts[Math.max(0, n - 4)];
      var dx = h.x - q.x, dy = h.y - q.y, len = Math.sqrt(dx * dx + dy * dy);
      var lifeH = 1 - (now - h.t) / LIFE;
      if (len > 2 && lifeH > 0) {
        var ux = dx / len, uy = dy / len, L = 17;
        c.globalAlpha = Math.min(1, lifeH * 1.6) * 0.85;
        c.strokeStyle = '#d9d2c5';
        c.lineWidth = 1.6;
        c.beginPath(); c.moveTo(h.x + ux * 4, h.y + uy * 4); c.lineTo(h.x - ux * L, h.y - uy * L); c.stroke();
        c.strokeStyle = '#0d0c0b';
        c.lineWidth = 0.8;
        c.beginPath(); c.moveTo(h.x - ux * (L - 4.5), h.y - uy * (L - 4.5)); c.lineTo(h.x - ux * (L - 1.5), h.y - uy * (L - 1.5)); c.stroke();
      }
      c.restore();
    }

    function step(now) {
      cur.x += (tgt.x - cur.x) * 0.075;
      cur.y += (tgt.y - cur.y) * 0.075;
      if (stage) stage.style.transform = 'translate3d(' + (cur.x * 14).toFixed(2) + 'px,' + (cur.y * 10).toFixed(2) + 'px,0)';
      if (mark) mark.style.transform = 'translate3d(' + (cur.x * -5).toFixed(2) + 'px,' + (cur.y * -4).toFixed(2) + 'px,0)';
      while (pts.length && now - pts[0].t > LIFE) pts.shift();
      drawTrail(now);
      var moving = Math.abs(tgt.x - cur.x) > 0.0015 || Math.abs(tgt.y - cur.y) > 0.0015;
      return visible && enabled() && (moving || pts.length > 0);
    }

    hero.addEventListener('pointermove', function (e) {
      if (e.pointerType && e.pointerType !== 'mouse') return;
      if (!enabled()) return;
      var r = hero.getBoundingClientRect();
      var x = e.clientX - r.left, y = e.clientY - r.top;
      tgt.x = x / r.width - 0.5;
      tgt.y = y / r.height - 0.5;
      pts.push({ x: x, y: y, t: performance.now() });
      if (pts.length > 42) pts.shift();
      addTask(step);
    });
    hero.addEventListener('pointerleave', function () {
      tgt.x = 0; tgt.y = 0;
      if (enabled()) addTask(step);
    });
  }

  // ---------- still fallbacks inside empty scene mounts ----------

  function paintFallbacks() {
    if (!St || !Seal) return;
    each('canvas.fb-seal', function (cv) {
      var size = cv.clientWidth;
      if (!size) return;
      var r = dpr();
      cv.width = Math.round(size * r); cv.height = Math.round(size * r);
      var ctx = cv.getContext('2d');
      ctx.setTransform(r, 0, 0, r, 0, 0);
      ctx.clearRect(0, 0, size, size);
      var cell = size / 19;
      St.drawSeal(ctx, cv.getAttribute('data-seal'), { x: cell, y: cell, cell: cell, theme: 'night' });
    });
    each('canvas.fb-seals', function (cv) {
      var W = cv.clientWidth, H = cv.clientHeight;
      if (!W || !H) return;
      var n = parseInt(cv.getAttribute('data-count'), 10) || 6, r = dpr();
      cv.width = Math.round(W * r); cv.height = Math.round(H * r);
      var ctx = cv.getContext('2d');
      ctx.setTransform(r, 0, 0, r, 0, 0);
      ctx.clearRect(0, 0, W, H);
      var cell = Math.min(H / 19, W / (n * 19));
      var total = n * 19 * cell, x0 = (W - total) / 2 + cell, y0 = (H - 17 * cell) / 2;
      for (var i = 0; i < n; i++) {
        St.drawSeal(ctx, demoHash(i), { x: x0 + i * 19 * cell, y: y0, cell: cell, theme: 'night', sheen: cell >= 6, ends: false });
      }
    });
  }

  // ---------- resize, reduced motion ----------

  var rT = 0, lastW = w.innerWidth, lastH = w.innerHeight;
  w.addEventListener('resize', function () {
    clearTimeout(rT);
    rT = setTimeout(function () {
      if (w.innerWidth === lastW && Math.abs(w.innerHeight - lastH) < 120) { sizeTrail(); return; }
      lastW = w.innerWidth; lastH = w.innerHeight;
      relayout();
      paintFallbacks();
      sizeTrail();
    }, 160);
  });

  if (mqReduce && mqReduce.addEventListener) {
    mqReduce.addEventListener('change', function () {
      if (mqReduce.matches) {
        html.classList.remove('motion');
        stitched.forEach(function (it) { it.state = 'done'; it.p = 1; paint(it); });
      } else if (frozen === null) {
        html.classList.add('motion');
      }
      api.motion = motionOn();
    });
  }

  // ---------- start ----------

  setupStitched();
  setupSections();
  setupTabs();
  setupCopy();
  setupFaq();
  setupHero();
  paintFallbacks();
  html.classList.add('ready');

  // ?p=1 (or any p) gives a still page: scenes freeze on their finished frame.
  if (frozen !== null) {
    d.addEventListener('DOMContentLoaded', function () {
      if (w.OberigScenes && typeof w.OberigScenes.freeze === 'function') w.OberigScenes.freeze('still');
    });
  }
})();
