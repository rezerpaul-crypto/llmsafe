/* ==========================================================================
   LiquidJournal landing page — behaviour
   Plain script (no modules / no build) so index.html also works from file://.
   Every feature activates only when its markup exists, and the page stays
   fully readable without any of it.
   ========================================================================== */
(function () {
  'use strict';

  var doc = document;
  var root = doc.documentElement;
  var $ = function (s, r) { return (r || doc).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || doc).querySelectorAll(s)); };
  var clamp = function (v, a, b) { return Math.min(b === undefined ? 1 : b, Math.max(a === undefined ? 0 : a, v)); };
  var smooth = function (t) { return t * t * (3 - 2 * t); };
  var mqReduce = window.matchMedia('(prefers-reduced-motion: reduce)');
  var reduced = function () { return mqReduce.matches; };
  var hasIO = 'IntersectionObserver' in window;

  /* ---------- toast ---------- */
  var toastEl = $('#toast');
  var toastTimer;
  function toast(msg) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.classList.add('is-on');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastEl.classList.remove('is-on'); }, 2400);
  }

  /* ---------- theme ---------- */
  var themeBtn = $('#theme-toggle');
  function setTheme(t, persist) {
    root.dataset.theme = t;
    if (themeBtn) {
      themeBtn.setAttribute('aria-pressed', String(t === 'dark'));
      themeBtn.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    }
    if (persist) { try { localStorage.setItem('lj-theme', t); } catch (e) { /* storage blocked */ } }
  }
  setTheme(root.dataset.theme === 'dark' ? 'dark' : 'light', false);
  if (themeBtn) themeBtn.addEventListener('click', function () { setTheme(root.dataset.theme === 'dark' ? 'light' : 'dark', true); });

  /* ---------- nav: stuck state, drawer, scroll-spy ---------- */
  var nav = $('#nav');
  var drawer = $('#drawer');
  var burger = $('#burger');
  function closeDrawer() {
    if (!drawer) return;
    drawer.classList.remove('is-open');
    if (burger) burger.setAttribute('aria-expanded', 'false');
  }
  if (burger && drawer) {
    burger.addEventListener('click', function () {
      var open = !drawer.classList.contains('is-open');
      drawer.classList.toggle('is-open', open);
      burger.setAttribute('aria-expanded', String(open));
    });
    drawer.addEventListener('click', function (e) { if (e.target.closest('a')) closeDrawer(); });
    doc.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeDrawer(); });
    window.addEventListener('resize', function () { if (window.innerWidth > 980) closeDrawer(); });
  }

  var spyLinks = $$('[data-spy]');
  var spyMap = {};
  spyLinks.forEach(function (a) { spyMap[a.dataset.spy] = a; });
  function setSpy(id) {
    spyLinks.forEach(function (a) {
      if (a.dataset.spy === id) a.setAttribute('aria-current', 'true'); else a.removeAttribute('aria-current');
    });
  }
  /* ordered so the *last* section whose top has passed the probe line wins */
  var spyOrder = ['story', 'showcase', 'community', 'reviews', 'pricing', 'affiliate'];
  var spyEnds = { story: 'scene', showcase: 'proof', community: 'reviews', reviews: 'compare', pricing: 'links', affiliate: 'dock' };
  function updateSpy() {
    var probe = window.innerHeight * 0.38;
    var current = null;
    spyOrder.forEach(function (id) {
      var el = doc.getElementById(id);
      if (!el) return;
      var r = el.getBoundingClientRect();
      var endEl = doc.getElementById(spyEnds[id]);
      var endTop = endEl ? endEl.getBoundingClientRect().top : r.bottom;
      if (r.top <= probe && endTop > probe) current = id;
    });
    setSpy(current);
  }

  /* ---------- word-by-word blur reveal (scrubbed by scroll) ---------- */
  var reveals = [];
  function splitWords(el) {
    var full = el.textContent.replace(/\s+/g, ' ').trim();
    var walker = doc.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    var nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    var words = [];
    nodes.forEach(function (node) {
      var parts = node.nodeValue.split(/(\s+)/);
      var frag = doc.createDocumentFragment();
      parts.forEach(function (p) {
        if (!p) return;
        if (/^\s+$/.test(p)) { frag.appendChild(doc.createTextNode(p)); return; }
        var s = doc.createElement('span');
        s.className = 'w';
        s.textContent = p;
        if (node.parentNode.closest('.sel, .hl')) s.classList.add('is-sel');
        frag.appendChild(s);
        words.push(s);
      });
      node.parentNode.replaceChild(frag, node);
    });
    /* assistive tech reads one clean string instead of dozens of fragments */
    var sr = doc.createElement('span');
    sr.className = 'sr-only';
    sr.textContent = full;
    var wrap = doc.createElement('span');
    wrap.setAttribute('aria-hidden', 'true');
    while (el.firstChild) wrap.appendChild(el.firstChild);
    el.appendChild(sr);
    el.appendChild(wrap);
    return words;
  }
  function initReveal() {
    $$('[data-reveal]').forEach(function (el) {
      var words = splitWords(el);
      reveals.push({ el: el, words: words, sels: $$('.sel', el), last: -1, near: !hasIO });
    });
    if (hasIO) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
          var item = reveals.filter(function (r) { return r.el === en.target; })[0];
          if (item) item.near = en.isIntersecting;
        });
        onScroll(); /* an element can become 'near' without any scroll event */
      }, { rootMargin: '25% 0px 25% 0px' });
      reveals.forEach(function (r) { io.observe(r.el); });
    }
  }
  function updateReveals() {
    var vh = window.innerHeight;
    var start = vh * 0.93, end = vh * 0.45, K = 4;
    reveals.forEach(function (r) {
      if (!r.near) return;
      var p = reduced() ? 1 : clamp((start - r.el.getBoundingClientRect().top) / (start - end));
      if (Math.abs(p - r.last) < 0.004) return;
      r.last = p;
      var n = r.words.length;
      for (var i = 0; i < n; i++) {
        r.words[i].style.setProperty('--w', clamp((p * (n + K) - i) / K).toFixed(3));
      }
      var on = p > 0.92;
      for (var j = 0; j < r.sels.length; j++) r.sels[j].classList.toggle('is-on', on);
    });
  }

  /* ---------- fade-up blocks ---------- */
  function initRise() {
    var els = $$('.rise');
    if (!hasIO || reduced()) { els.forEach(function (e) { e.classList.add('is-in'); }); return; }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add('is-in'); io.unobserve(en.target); } });
    }, { rootMargin: '0px 0px -8% 0px' });
    els.forEach(function (e) { io.observe(e); });
  }

  /* ---------- hero headline rotator ---------- */
  function initRotator() {
    var h = $('[data-rotator]');
    if (!h) return;
    var vs = $$('.hero__variant', h);
    if (vs.length < 2 || reduced()) return;
    var i = 0, swaps = 0, timer, hovering = false;
    function step() {
      if (hovering || doc.hidden) return;
      vs[i].classList.remove('is-active'); vs[i].setAttribute('aria-hidden', 'true');
      i = (i + 1) % vs.length;
      vs[i].classList.add('is-active'); vs[i].removeAttribute('aria-hidden');
      if (++swaps >= 6) clearInterval(timer); /* settles after a few loops: no endless motion */
    }
    timer = setInterval(step, 5200);
    h.addEventListener('pointerenter', function () { hovering = true; });
    h.addEventListener('pointerleave', function () { hovering = false; });
  }

  /* ---------- marquees ---------- */
  function initMarquees() {
    $$('[data-marquee]').forEach(function (m) {
      var track = $('.carousel__track, .logos__track', m);
      if (!track) return;
      var items = Array.prototype.slice.call(track.children);
      /* make one half at least as wide as the viewport, then duplicate it */
      var guard = 0;
      while (track.scrollWidth < window.innerWidth * 1.3 && guard++ < 6) {
        items.forEach(function (it) { var c = it.cloneNode(true); c.setAttribute('aria-hidden', 'true'); track.appendChild(c); });
      }
      var half = Array.prototype.slice.call(track.children);
      half.forEach(function (it) { var c = it.cloneNode(true); c.setAttribute('aria-hidden', 'true'); c.removeAttribute('id'); track.appendChild(c); });
      var speed = parseFloat(m.dataset.speed) || 40; /* px per second */
      track.style.setProperty('--dur', (track.scrollWidth / 2 / speed).toFixed(1) + 's');
      $$('a, button', track).forEach(function (el, idx, all) { if (idx >= all.length / 2) el.tabIndex = -1; });
    });
    var pause = $('#logos-pause');
    if (pause) {
      pause.addEventListener('click', function () {
        var on = pause.getAttribute('aria-pressed') !== 'true';
        pause.setAttribute('aria-pressed', String(on));
        pause.setAttribute('aria-label', on ? 'Play scrolling logos' : 'Pause scrolling logos');
        var use = pause.querySelector('use');
        if (use) use.setAttribute('href', on ? '#i-play' : '#i-pause');
        $$('.logos [data-marquee]').forEach(function (m) { m.classList.toggle('is-paused', on); });
      });
    }
  }

  /* ---------- penguin scene ---------- */
  var scene, sceneStage, sceneLines;
  function initScene() {
    scene = $('[data-scene]');
    if (!scene) return;
    if (reduced()) { scene.classList.add('scene--static'); return; }
    sceneStage = $('.scene__stage', scene);
    sceneLines = $$('.scene__line', scene);
  }
  function updateScene() {
    if (!scene || scene.classList.contains('scene--static')) return;
    var r = scene.getBoundingClientRect();
    var navH = nav ? nav.offsetHeight : 64;
    if (r.bottom < -200 || r.top > window.innerHeight + 200) return;
    var total = r.height - sceneStage.offsetHeight;
    var p = clamp((navH - r.top) / total);
    scene.style.setProperty('--p', p.toFixed(4));
    var edges = [0, 0.25, 0.5, 0.75, 1];
    sceneLines.forEach(function (ln, k) {
      var oIn = k === 0 ? 1 : smooth(clamp((p - (edges[k] - 0.035)) / 0.07));
      var oOut = k === sceneLines.length - 1 ? 1 : 1 - smooth(clamp((p - (edges[k + 1] - 0.035)) / 0.07));
      var o = oIn * oOut;
      ln.style.setProperty('--o', o.toFixed(3));
      ln.style.setProperty('--b', ((1 - o) * 16).toFixed(1) + 'px');
      ln.style.setProperty('--y', ((1 - oIn) * 26 - (1 - oOut) * 26).toFixed(1) + 'px');
      ln.setAttribute('aria-hidden', o < 0.4 ? 'true' : 'false');
    });
  }

  /* ---------- count-up numbers ---------- */
  function initCounts() {
    var els = $$('[data-count]');
    if (!els.length) return;
    function run(el) {
      var target = parseFloat(el.dataset.count);
      var t0 = null, dur = 1500;
      function frame(t) {
        if (t0 === null) t0 = t;
        var k = clamp((t - t0) / dur);
        var eased = k === 1 ? 1 : 1 - Math.pow(2, -10 * k);
        el.textContent = Math.round(target * eased).toLocaleString('en-US');
        if (k < 1) requestAnimationFrame(frame);
      }
      requestAnimationFrame(frame);
    }
    if (!hasIO || reduced()) return;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { run(en.target); io.unobserve(en.target); } });
    }, { threshold: 0.6 });
    els.forEach(function (el) { el.textContent = '0'; io.observe(el); });
  }

  /* ---------- tabs (showcase) ---------- */
  function initShowcase() {
    var sec = $('#showcase');
    if (!sec) return;
    var tabs = $$('[role="tab"]', sec);
    if (!tabs.length) return;
    var panels = $$('[role="tabpanel"]', sec);
    var panes = $$('[data-pane]', sec);
    var title = $('#win-title', sec);
    var win = $('.win', sec);
    function select(tab, focus) {
      var id = tab.dataset.tab;
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute('aria-selected', String(on));
        t.tabIndex = on ? 0 : -1;
      });
      panels.forEach(function (p) { p.hidden = p.dataset.panel !== id; });
      panes.forEach(function (p) { p.hidden = p.dataset.pane !== id; });
      if (title) title.textContent = tab.dataset.title || tab.textContent.trim();
      $$('.mk-menu [data-m]', sec).forEach(function (m) { m.classList.toggle('on', m.dataset.m === id); });
      if (win) win.dataset.view = id;
      if (focus) tab.focus();
    }
    tabs.forEach(function (t, i) {
      t.addEventListener('click', function () { select(t, false); });
      t.addEventListener('keydown', function (e) {
        var n = tabs.length, j = -1;
        if (e.key === 'ArrowDown' || e.key === 'ArrowRight') j = (i + 1) % n;
        else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') j = (i - 1 + n) % n;
        else if (e.key === 'Home') j = 0;
        else if (e.key === 'End') j = n - 1;
        if (j > -1) { e.preventDefault(); select(tabs[j], true); }
      });
    });
    var skin = $$('[data-skin]', sec);
    skin.forEach(function (b) {
      b.addEventListener('click', function () {
        skin.forEach(function (o) { o.setAttribute('aria-pressed', String(o === b)); });
        if (win) win.dataset.skin = b.dataset.skin;
      });
    });
  }

  /* ---------- small disclosure widgets ---------- */
  function initDisclosures() {
    $$('[data-toggle]').forEach(function (btn) {
      var target = doc.getElementById(btn.dataset.toggle);
      if (!target) return;
      btn.addEventListener('click', function () {
        var open = btn.getAttribute('aria-expanded') !== 'true';
        btn.setAttribute('aria-expanded', String(open));
        target.hidden = !open;
        var host = btn.closest('[data-host]');
        if (host) host.classList.toggle('is-open', open);
      });
    });
  }

  /* ---------- reviews: show more ---------- */
  function initReviews() {
    var list = $('#review-list');
    if (!list) return;
    var btns = $$('[data-reviews-toggle]');
    function set(open) {
      list.classList.toggle('is-open', open);
      btns.forEach(function (b) {
        b.setAttribute('aria-expanded', String(open));
        b.textContent = open ? 'Show less' : 'Show more';
      });
    }
    btns.forEach(function (b) {
      b.addEventListener('click', function () {
        var open = !list.classList.contains('is-open');
        set(open);
        if (!open) list.scrollIntoView({ block: 'start', behavior: reduced() ? 'auto' : 'smooth' });
      });
    });
  }

  /* ---------- comparison table ---------- */
  function initCompare() {
    var btn = $('#cmp-toggle');
    var table = $('#cmp');
    if (!btn || !table) return;
    var extra = $$('tr[data-extra]', table);
    extra.forEach(function (r) { r.hidden = true; });
    btn.addEventListener('click', function () {
      var open = btn.getAttribute('aria-expanded') !== 'true';
      btn.setAttribute('aria-expanded', String(open));
      extra.forEach(function (r) { r.hidden = !open; });
      btn.textContent = open ? 'Show fewer rows' : 'Show all ' + (extra.length + (table.rows.length - 1 - extra.length)) + ' rows';
    });
  }

  /* ---------- pricing ---------- */
  var PRICES = {
    usd: { sym: '$', dec: 2, prestige: [14.99, 24.99], apex: [35.99, 59.99] },
    eur: { sym: '€', dec: 2, prestige: [13.99, 22.99], apex: [32.99, 54.99] },
    jpy: { sym: '¥', dec: 0, prestige: [2300, 3800], apex: [5400, 8900] }
  };
  function money(cur, v) {
    var c = PRICES[cur];
    return c.dec ? c.sym + v.toFixed(2) : c.sym + Math.round(v).toLocaleString('en-US');
  }
  /* yearly billing is exactly 33% cheaper per month (kept honest next to the "Save 33%" badge) */
  function annual(cur, v) {
    return PRICES[cur].dec ? Math.round(v * 0.67 * 100) / 100 : Math.round((v * 0.67) / 10) * 10;
  }
  function initPricing() {
    var sec = $('#pricing');
    if (!sec) return;
    var state = { cur: 'usd', yearly: false };
    var curBtns = $$('[data-cur]', sec);
    var sw = $('#billing-switch', sec);
    function render(animate) {
      ['prestige', 'apex'].forEach(function (plan) {
        var base = PRICES[state.cur][plan];
        var now = state.yearly ? annual(state.cur, base[0]) : base[0];
        var was = state.yearly ? annual(state.cur, base[1]) : base[1];
        $$('[data-price="' + plan + '"]', sec).forEach(function (el) {
          var next = money(state.cur, el.dataset.kind === 'was' ? was : now);
          if (el.textContent === next) return;
          el.textContent = next;
          if (animate && !reduced()) { el.classList.remove('is-swap'); void el.offsetWidth; el.classList.add('is-swap'); }
        });
        var note = $('[data-note="' + plan + '"]', sec);
        if (note) {
          note.textContent = state.yearly
            ? '10 days free, then ' + money(state.cur, now * 12) + ' a year (' + money(state.cur, now) + '/mo). Cancel anytime.'
            : '10 days free, then ' + money(state.cur, now) + ' a month. Cancel anytime.';
        }
      });
      var zero = $('[data-price="free"]', sec);
      if (zero) zero.textContent = money(state.cur, 0);
      $$('[data-sale]').forEach(function (el) { /* these chips live in the mentor section, outside #pricing */
        var pct = parseFloat(el.dataset.sale);
        var apex = PRICES[state.cur].apex;
        var monthly = pct === 40 ? apex[0] : Math.round(apex[1] * (1 - pct / 100) * 100) / 100;
        el.textContent = money(state.cur, state.yearly ? annual(state.cur, monthly) : monthly);
      });
    }
    curBtns.forEach(function (b) {
      b.addEventListener('click', function () {
        state.cur = b.dataset.cur;
        curBtns.forEach(function (o) { o.setAttribute('aria-pressed', String(o === b)); });
        render(true);
      });
    });
    if (sw) {
      sw.addEventListener('click', function () {
        state.yearly = sw.getAttribute('aria-checked') !== 'true';
        sw.setAttribute('aria-checked', String(state.yearly));
        $$('[data-bill]', sec).forEach(function (l) { l.classList.toggle('is-on', (l.dataset.bill === 'yearly') === state.yearly); });
        render(true);
      });
    }
    /* collapsible feature lists */
    $$('.feat', sec).forEach(function (ul) {
      var extra = $$('li.is-extra', ul);
      var btn = ul.parentNode.querySelector('.more');
      if (!btn || !extra.length) return;
      var label = '+' + extra.length + ' more';
      btn.firstChild.nodeValue = label + ' ';
      extra.forEach(function (li) { li.hidden = true; });
      btn.addEventListener('click', function () {
        var open = btn.getAttribute('aria-expanded') !== 'true';
        btn.setAttribute('aria-expanded', String(open));
        extra.forEach(function (li) { li.hidden = !open; });
        btn.firstChild.nodeValue = (open ? 'Show less' : label) + ' ';
      });
    });
    render(false);
  }

  /* ---------- copy promo code ---------- */
  function initCopy() {
    $$('[data-copy]').forEach(function (b) {
      b.addEventListener('click', function () {
        var code = b.dataset.copy;
        var done = function () { toast('Code ' + code + ' copied'); };
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(code).then(done, function () { toast('Code: ' + code); });
        else toast('Code: ' + code);
      });
    });
  }

  /* ---------- dock magnification ---------- */
  function initDock() {
    var dock = $('.dock');
    if (!dock || reduced()) return;
    var icons = $$('.dock__icon', dock);
    dock.addEventListener('pointermove', function (e) {
      icons.forEach(function (ic) {
        var r = ic.getBoundingClientRect();
        var d = Math.abs(e.clientX - (r.left + r.width / 2));
        var s = 1 + 0.42 * Math.max(0, 1 - d / 120);
        ic.style.transform = 'translateY(' + (-(s - 1) * 22).toFixed(1) + 'px) scale(' + s.toFixed(3) + ')';
      });
    });
    dock.addEventListener('pointerleave', function () { icons.forEach(function (ic) { ic.style.transform = ''; }); });
  }

  /* ---------- dead demo links ---------- */
  doc.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('a[href^="#"]');
    if (!a) return;
    var id = a.getAttribute('href').slice(1);
    if (id && !doc.getElementById(id)) {
      e.preventDefault();
      toast('Demo build: this link is not wired up yet');
    } else if (id === '' ) {
      e.preventDefault();
    }
  });

  /* ---------- scroll loop ---------- */
  var ticking = false;
  function onScroll() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(function () {
      ticking = false;
      if (nav) nav.classList.toggle('is-stuck', window.scrollY > 8);
      updateReveals();
      updateScene();
      updateSpy();
    });
  }

  function init() {
    initReveal();
    initRise();
    initRotator();
    initMarquees();
    initScene();
    initCounts();
    initShowcase();
    initDisclosures();
    initReviews();
    initCompare();
    initPricing();
    initCopy();
    initDock();
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll);
    mqReduce.addEventListener && mqReduce.addEventListener('change', function () { reveals.forEach(function (r) { r.last = -1; }); onScroll(); });
    /* fonts change line breaks, so re-measure once they are in */
    if (doc.fonts && doc.fonts.ready) doc.fonts.ready.then(onScroll);
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', init); else init();
})();
