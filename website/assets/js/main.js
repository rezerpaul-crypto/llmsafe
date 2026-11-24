/* ==========================================================================
   Prop Firm OS landing page — behaviour
   One plain script (no modules, no build step). Every feature activates only
   when its markup exists, and the page is fully readable without any of it.
   ========================================================================== */
(function () {
  'use strict';

  /* Put the download address here once there is a public build. While it is empty,
     the last section says that the app is in early access instead of offering a button. */
  var GET_URL = '';

  var doc = document;
  var root = doc.documentElement;
  var $ = function (s, r) { return (r || doc).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || doc).querySelectorAll(s)); };
  var clamp = function (v, a, b) { return Math.min(b === undefined ? 1 : b, Math.max(a === undefined ? 0 : a, v)); };
  var smooth = function (t) { return t * t * (3 - 2 * t); };
  var mqReduce = window.matchMedia('(prefers-reduced-motion: reduce)');
  var mqDark = window.matchMedia('(prefers-color-scheme: dark)');
  var hasIO = 'IntersectionObserver' in window;
  /* Scroll-driven effects are skipped when motion is reduced, and when the page is laid
     out at its full height (some embeds do that): then nothing ever scrolls inside it. */
  var calm = function () { return mqReduce.matches || window.innerHeight > 2600; };

  /* ---------- toast ---------- */
  var toastEl = $('#toast');
  var toastTimer;
  function toast(msg) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.classList.add('is-on');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastEl.classList.remove('is-on'); }, 2600);
  }

  /* ---------- theme ---------- */
  var themeBtn = $('#theme-toggle');
  function currentTheme() {
    var t = root.dataset.theme;
    return t === 'dark' || t === 'light' ? t : (mqDark.matches ? 'dark' : 'light');
  }
  function syncThemeButton() {
    if (!themeBtn) return;
    var dark = currentTheme() === 'dark';
    themeBtn.setAttribute('aria-pressed', String(dark));
    themeBtn.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
  }
  if (themeBtn) {
    themeBtn.addEventListener('click', function () {
      var next = currentTheme() === 'dark' ? 'light' : 'dark';
      root.dataset.theme = next;
      try { localStorage.setItem('pfos-theme', next); } catch (e) { /* choice lasts for this visit */ }
      syncThemeButton();
    });
    if (mqDark.addEventListener) mqDark.addEventListener('change', syncThemeButton);
    syncThemeButton();
  }

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
    window.addEventListener('resize', function () { if (window.innerWidth > 1080) closeDrawer(); });
  }

  var spyLinks = $$('[data-spy]');
  /* each nav item owns the page from its section down to the start of the next one */
  var spyEnds = { showcase: 'briefing', briefing: 'math', math: 'compare-lead', compare: 'statuses-lead', statuses: 'local', local: 'prompts' };
  function updateSpy() {
    if (!spyLinks.length) return;
    var probe = window.innerHeight * 0.38;
    var current = null;
    spyLinks.forEach(function (a) {
      var id = a.dataset.spy;
      var el = doc.getElementById(id);
      if (!el) return;
      var endEl = doc.getElementById(spyEnds[id]);
      var top = el.getBoundingClientRect().top;
      var end = endEl ? endEl.getBoundingClientRect().top : el.getBoundingClientRect().bottom;
      if (top <= probe && end > probe) current = id;
    });
    spyLinks.forEach(function (a) {
      if (a.dataset.spy === current) a.setAttribute('aria-current', 'true'); else a.removeAttribute('aria-current');
    });
  }

  /* ---------- headline reveal ----------
     Headings are sharp at rest. Only those below the fold are scrubbed, word by word,
     while they travel up through the viewport; once sharp they stay sharp. */
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
    if (!hasIO || calm()) return;
    $$('[data-reveal]').forEach(function (el) {
      if (el.getBoundingClientRect().top < window.innerHeight) return; /* already on screen: leave it complete */
      reveals.push({ el: el, words: splitWords(el), near: false, done: false, last: -1 });
    });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        var item = reveals.filter(function (r) { return r.el === en.target; })[0];
        if (!item || item.done) return;
        item.near = en.isIntersecting;
        if (en.isIntersecting) item.el.classList.add('is-live'); /* still below the fold, so the switch is unseen */
      });
      onScroll();
    }, { rootMargin: '0px 0px 30% 0px' });
    reveals.forEach(function (r) { io.observe(r.el); });
  }
  function updateReveals() {
    var vh = window.innerHeight;
    var start = vh * 0.93, end = vh * 0.45, K = 4;
    reveals.forEach(function (r) {
      if (r.done || !r.near) return;
      var p = clamp((start - r.el.getBoundingClientRect().top) / (start - end));
      if (Math.abs(p - r.last) < 0.004) return;
      r.last = p;
      var n = r.words.length;
      for (var i = 0; i < n; i++) r.words[i].style.setProperty('--w', clamp((p * (n + K) - i) / K).toFixed(3));
      if (p >= 1) {
        r.done = true;
        r.el.classList.add('is-done');
        for (var j = 0; j < n; j++) r.words[j].style.removeProperty('--w');
      }
    });
  }

  /* ---------- blocks fade up once, when they first scroll into view ---------- */
  function initRise() {
    if (!hasIO || calm()) return;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        en.target.classList.add('rise-in');
        io.unobserve(en.target);
      });
    });
    $$('.rise').forEach(function (el) {
      if (el.getBoundingClientRect().top < window.innerHeight) return; /* visible at load: no entrance */
      io.observe(el);
    });
  }

  /* ---------- hero headline rotator ---------- */
  function initRotator() {
    var h = $('[data-rotator]');
    if (!h || mqReduce.matches) return;
    var vs = $$('.hero__variant', h);
    if (vs.length < 2) return;
    var i = 0, swaps = 0, hovering = false;
    var timer = setInterval(function () {
      if (hovering || doc.hidden) return;
      vs[i].classList.remove('is-active'); vs[i].setAttribute('aria-hidden', 'true');
      i = (i + 1) % vs.length;
      vs[i].classList.add('is-active'); vs[i].removeAttribute('aria-hidden');
      if (++swaps >= 6) clearInterval(timer); /* settles after a few loops: no endless motion */
    }, 5200);
    h.addEventListener('pointerenter', function () { hovering = true; });
    h.addEventListener('pointerleave', function () { hovering = false; });
  }

  /* ---------- marquees ---------- */
  function initMarquees() {
    if (mqReduce.matches) return; /* reduced motion: plain scrollable rows, no duplicates */
    $$('[data-marquee]').forEach(function (m) {
      var track = $('.carousel__track, .logos__track', m);
      if (!track) return;
      var items = Array.prototype.slice.call(track.children);
      /* make one half at least as wide as the viewport, then duplicate it */
      var guard = 0;
      while (track.scrollWidth < window.innerWidth * 1.3 && guard++ < 6) {
        items.forEach(function (it) { var c = it.cloneNode(true); c.setAttribute('aria-hidden', 'true'); track.appendChild(c); });
      }
      Array.prototype.slice.call(track.children).forEach(function (it) {
        var c = it.cloneNode(true); c.setAttribute('aria-hidden', 'true'); track.appendChild(c);
      });
      var speed = parseFloat(m.dataset.speed) || 40; /* px per second */
      track.style.setProperty('--dur', (track.scrollWidth / 2 / speed).toFixed(1) + 's');
    });
    var pause = $('#logos-pause');
    if (pause) {
      pause.addEventListener('click', function () {
        var on = pause.getAttribute('aria-pressed') !== 'true';
        pause.setAttribute('aria-pressed', String(on));
        pause.setAttribute('aria-label', on ? 'Play the scrolling rows' : 'Pause the scrolling rows');
        var use = pause.querySelector('use');
        if (use) use.setAttribute('href', on ? '#i-play' : '#i-pause');
        $$('.logos [data-marquee]').forEach(function (m) { m.classList.toggle('is-paused', on); });
      });
    }
  }

  /* ---------- summit scene ---------- */
  var scene, sceneStage, sceneLines;
  function initScene() {
    scene = $('[data-scene]');
    if (!scene) return;
    if (calm()) { scene.classList.add('scene--static'); return; }
    sceneStage = $('.scene__stage', scene);
    sceneLines = $$('.scene__line', scene);
  }
  function updateScene() {
    if (!scene || !sceneStage) return;
    var r = scene.getBoundingClientRect();
    if (r.bottom < -200 || r.top > window.innerHeight + 200) return;
    var total = r.height - sceneStage.offsetHeight;
    var stickyTop = parseFloat(getComputedStyle(sceneStage).top) || 0;
    var p = clamp((stickyTop - r.top) / total);
    scene.style.setProperty('--p', p.toFixed(4));
    var n = sceneLines.length;
    sceneLines.forEach(function (ln, k) {
      var oIn = k === 0 ? 1 : smooth(clamp((p - (k / n - 0.035)) / 0.07));
      var oOut = k === n - 1 ? 1 : 1 - smooth(clamp((p - ((k + 1) / n - 0.035)) / 0.07));
      var o = oIn * oOut;
      ln.style.setProperty('--o', o.toFixed(3));
      ln.style.setProperty('--b', ((1 - o) * 16).toFixed(1) + 'px');
      ln.style.setProperty('--y', ((1 - oIn) * 26 - (1 - oOut) * 26).toFixed(1) + 'px');
      ln.setAttribute('aria-hidden', o < 0.4 ? 'true' : 'false');
    });
  }

  /* ---------- workspace tabs ---------- */
  var selectTab = function () {};
  function initShowcase() {
    var sec = $('#showcase');
    if (!sec) return;
    var tabs = $$('[role="tab"]', sec);
    if (!tabs.length) return;
    var panels = $$('[role="tabpanel"]', sec);
    var panes = $$('[data-pane]', sec);
    var title = $('#win-title', sec);
    var win = $('.win', sec);
    selectTab = function (id, focus) {
      var tab = tabs.filter(function (t) { return t.dataset.tab === id; })[0];
      if (!tab) return;
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute('aria-selected', String(on));
        t.tabIndex = on ? 0 : -1;
      });
      panels.forEach(function (p) { p.hidden = p.dataset.panel !== id; });
      panes.forEach(function (p) { p.hidden = p.dataset.pane !== id; });
      if (title) title.textContent = tab.dataset.title || tab.textContent.trim();
      $$('.mk-menu [data-m]', sec).forEach(function (m) { m.classList.toggle('on', m.dataset.m === id); });
      if (focus) tab.focus();
      if (tab.scrollIntoView && tab.parentNode.scrollWidth > tab.parentNode.clientWidth) tab.scrollIntoView({ block: 'nearest', inline: 'center' });
    };
    tabs.forEach(function (t, i) {
      t.addEventListener('click', function () { selectTab(t.dataset.tab, false); });
      t.addEventListener('keydown', function (e) {
        var n = tabs.length, j = -1;
        if (e.key === 'ArrowDown' || e.key === 'ArrowRight') j = (i + 1) % n;
        else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') j = (i - 1 + n) % n;
        else if (e.key === 'Home') j = 0;
        else if (e.key === 'End') j = n - 1;
        if (j > -1) { e.preventDefault(); selectTab(tabs[j].dataset.tab, true); }
      });
    });
    var skins = $$('[data-skin]', sec);
    skins.forEach(function (b) {
      b.addEventListener('click', function () {
        skins.forEach(function (o) { o.setAttribute('aria-pressed', String(o === b)); });
        if (win) win.dataset.skin = b.dataset.skin;
        $$('.mk-look [data-look]', sec).forEach(function (l) { l.classList.toggle('on', l.dataset.look === b.dataset.skin); });
      });
    });
    /* links elsewhere on the page can open a specific workspace */
    $$('[data-open-tab]').forEach(function (a) {
      a.addEventListener('click', function () { selectTab(a.dataset.openTab, false); });
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
      });
    });
  }

  /* ---------- the math: show more ---------- */
  function initMath() {
    var list = $('#math-list');
    if (!list) return;
    var btns = $$('[data-math-toggle]');
    btns.forEach(function (b) {
      b.addEventListener('click', function () {
        var open = !list.classList.contains('is-open');
        list.classList.toggle('is-open', open);
        btns.forEach(function (o) {
          o.setAttribute('aria-expanded', String(open));
          o.textContent = open ? 'Show fewer rules' : 'Show all 12 rules';
        });
        if (!open) list.scrollIntoView({ block: 'start', behavior: mqReduce.matches ? 'auto' : 'smooth' });
      });
    });
  }

  /* ---------- comparison table ---------- */
  function initCompare() {
    var btn = $('#cmp-toggle');
    var table = $('#cmp');
    if (!btn || !table) return;
    var extra = $$('tr[data-extra]', table);
    var total = $$('tbody tr', table).length;
    extra.forEach(function (r) { r.hidden = true; });
    btn.hidden = false;
    btn.addEventListener('click', function () {
      var open = btn.getAttribute('aria-expanded') !== 'true';
      btn.setAttribute('aria-expanded', String(open));
      extra.forEach(function (r) { r.hidden = !open; });
      btn.textContent = open ? 'Show fewer rows' : 'Show all ' + total + ' rows';
    });
  }

  /* ---------- risk monitor demo: the same rule the app applies ---------- */
  function initRisk() {
    var box = $('#risk-demo');
    if (!box) return;
    var range = $('#rd-net', box);
    var limitBtns = $$('[data-limit]', box);
    var money = function (v) { return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(v); };
    var limit = 1000;
    function render() {
      var net = Number(range.value);
      var state = net <= -limit ? 'breached' : net <= -limit * 0.75 ? 'warning' : 'safe';
      var remaining = Math.max(0, limit + net);
      var used = clamp(-net / limit);
      box.dataset.state = state;
      $('#rd-net-out', box).textContent = (net > 0 ? '+' : '') + money(net);
      $('#rd-line', box).textContent = money(net) + ' today · ' + money(limit) + ' limit';
      $('#rd-remaining', box).textContent = state === 'breached' ? 'Limit reached' : money(remaining) + ' remaining';
      $('#rd-bar', box).style.width = (used * 100).toFixed(1) + '%';
      $('#rd-pill', box).textContent = state === 'breached' ? '1 ALERT' : state === 'warning' ? '1 NEAR LIMIT' : 'ALL CLEAR';
      $('#rd-explain', box).textContent = net >= 0
        ? 'No loss today. The room is the limit plus what you made.'
        : Math.round(used * 100) + '% of the daily limit used.' + (state === 'warning' ? ' The warning starts at 75%.' : '');
      range.setAttribute('aria-valuetext', money(net) + ' today, ' + (state === 'breached' ? 'limit reached' : money(remaining) + ' remaining'));
    }
    range.addEventListener('input', render);
    limitBtns.forEach(function (b) {
      b.addEventListener('click', function () {
        limit = Number(b.dataset.limit);
        limitBtns.forEach(function (o) { o.setAttribute('aria-pressed', String(o === b)); });
        render();
      });
    });
    render();
  }

  /* ---------- dock magnification ---------- */
  function initDock() {
    var dock = $('.dock');
    if (!dock || mqReduce.matches) return;
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

  /* ---------- download button, once GET_URL is set ---------- */
  function initGet() {
    var btn = $('#get-button');
    if (!GET_URL || !btn) return;
    btn.href = GET_URL;
    btn.hidden = false;
    ['#get-note', '#get-tour'].forEach(function (s) { var el = $(s); if (el) el.hidden = true; });
  }

  /* ---------- safety net: an in-page link without a target says so instead of doing nothing ---------- */
  doc.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('a[href^="#"]');
    if (!a) return;
    var id = a.getAttribute('href').slice(1);
    if (id && !doc.getElementById(id)) { e.preventDefault(); toast('This link is not set up yet'); }
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
    initShowcase();
    initDisclosures();
    initMath();
    initCompare();
    initRisk();
    initDock();
    initGet();
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll);
    /* fonts change line breaks, so re-measure once they are in */
    if (doc.fonts && doc.fonts.ready) doc.fonts.ready.then(onScroll);
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', init); else init();
})();
