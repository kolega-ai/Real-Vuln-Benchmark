/* ============================================================
   RealVuln — landing leaderboard + precision/recall scatter
   Data: window.RV (realvuln-data.js). Primary metric: F3 (strict).
   ============================================================ */
(function () {
  'use strict';
  if (!window.RV) return;
  var SC = window.RV.SCANNERS, COL = window.RV.COL,
      CAT_SHORT = window.RV.CAT_SHORT, CAT_LABEL = window.RV.CAT_LABEL;

  var state = { metric: 'f3', mode: 'strict', sortKey: 'f3', sortDir: -1 };

  function mk(base) { return state.mode === 'strict' ? base + 's' : base; }   // metric/recall key for mode
  function val(s, base) { return s[mk(base)]; }
  function activeF(s) { return val(s, state.metric); }
  function fmt(v) { return v.toFixed(1); }

  // Gold-by-score gradient: bright warm gold for the field leader, fading to a
  // faint muted brown at the bottom. t in [0,1] (1 = highest active score).
  function lerp(a, b, t) { return Math.round(a + (b - a) * t); }
  function goldFor(t, alpha) {
    t = Math.max(0, Math.min(1, t));
    var e = Math.pow(t, 0.72); // ease so mid-table still reads as gold, not mud
    var r = lerp(110, 240, e), g = lerp(86, 201, e), b = lerp(40, 122, e);
    return 'rgba(' + r + ',' + g + ',' + b + ',' + (alpha == null ? 1 : alpha) + ')';
  }

  var tbody = document.getElementById('lb-body');

  function render() {
    if (!tbody) return;
    var rows = SC.slice().sort(function (a, b) { return activeF(b) - activeF(a); });
    var maxA = Math.max.apply(null, SC.map(activeF));
    var minA = Math.min.apply(null, SC.map(activeF));
    var span = (maxA - minA) || 1;
    var leadName = rows[0].name, leadVer = rows[0].ver;

    tbody.innerHTML = '';
    rows.forEach(function (s, i) {
      var d = document.createElement('a');
      var isLead = s.name === leadName && s.ver === leadVer;
      d.className = 'lbr' + (isLead ? ' leader' : '');
      d.href = 'dashboard.html';
      var pct = Math.round((activeF(s) / maxA) * 100);
      var t = (activeF(s) - minA) / span;                 // color scale across the field
      var fill = goldFor(t), text = goldFor(Math.max(t, 0.42));
      var reposTxt = s.repos < 26
        ? '<span class="repos-bad">' + s.repos + '/26</span> repos'
        : s.repos + ' repos';
      var sd = s.sd != null ? '<span class="lbr-sd">stdev ' + s.sd.toFixed(1) + '</span>' : '';

      d.innerHTML =
        '<span class="lbr-rank">' + (i + 1) + '</span>' +
        '<span class="lbr-name"><span class="nm">' + s.name +
          (isLead ? ' <span class="crown">▲</span>' : '') + '</span>' +
          '<span class="meta">' + CAT_SHORT[s.cat] + ' · ' + s.ver + ' · ' + reposTxt + '</span></span>' +
        '<span class="lbr-bar"><span class="lbr-fill" style="width:' + pct + '%;background:' + fill + '"></span></span>' +
        '<span class="lbr-val"><span class="sc" style="color:' + text + '">' + fmt(activeF(s)) + '</span>' +
          '<span class="sub">' + (val(s, 'rec') * 100).toFixed(1) + '% recall · ' + (s.prec * 100).toFixed(1) + '% prec</span>' + sd +
        '</span>' +
        '<span class="lbr-chev">→</span>';
      tbody.appendChild(d);
    });
  }

  document.querySelectorAll('.metric-toggle [data-metric]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.metric-toggle [data-metric]').forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      state.metric = btn.getAttribute('data-metric');
      render();
    });
  });
  document.querySelectorAll('.mode-toggle [data-mode]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.mode-toggle [data-mode]').forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      state.mode = btn.getAttribute('data-mode');
      render(); renderScatter();
    });
  });

  render();

  // ---------------------------------------------------------
  // precision–recall scatter
  // ---------------------------------------------------------
  var NS = 'http://www.w3.org/2000/svg';
  function el(tag, attrs, txt) { var e = document.createElementNS(NS, tag); for (var a in attrs) e.setAttribute(a, attrs[a]); if (txt != null) e.textContent = txt; return e; }

  function renderScatter() {
    var svg = document.getElementById('scatter'); if (!svg) return;
    svg.innerHTML = '';
    var W = 760, H = 460, m = { t: 24, r: 28, b: 52, l: 58 };
    var pw = W - m.l - m.r, ph = H - m.t - m.b;
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    function X(v) { return m.l + v * pw; }
    function Y(v) { return m.t + (1 - v) * ph; }
    var frag = document.createDocumentFragment();
    [0, .2, .4, .6, .8, 1].forEach(function (t) {
      frag.appendChild(el('line', { class: 'gridline', x1: X(t), y1: m.t, x2: X(t), y2: m.t + ph }));
      frag.appendChild(el('line', { class: 'gridline', x1: m.l, y1: Y(t), x2: m.l + pw, y2: Y(t) }));
      frag.appendChild(el('text', { class: 'tick', x: X(t), y: m.t + ph + 18, 'text-anchor': 'middle' }, t.toFixed(1)));
      frag.appendChild(el('text', { class: 'tick', x: m.l - 10, y: Y(t) + 3, 'text-anchor': 'end' }, t.toFixed(1)));
    });
    frag.appendChild(el('line', { class: 'axis', x1: m.l, y1: m.t + ph, x2: m.l + pw, y2: m.t + ph }));
    frag.appendChild(el('line', { class: 'axis', x1: m.l, y1: m.t, x2: m.l, y2: m.t + ph }));
    frag.appendChild(el('text', { class: 'axis-label', x: m.l + pw / 2, y: H - 8, 'text-anchor': 'middle' }, 'Recall  →  vulnerabilities found'));
    frag.appendChild(el('text', { class: 'axis-label', x: 16, y: m.t + ph / 2, 'text-anchor': 'middle', transform: 'rotate(-90 16 ' + (m.t + ph / 2) + ')' }, 'Precision  →  less noise'));

    SC.forEach(function (s) {
      var cx = X(val(s, 'rec')), cy = Y(s.prec);
      var lead = s.cat === 'sec';
      var c = el('circle', { class: 'pt', cx: cx, cy: cy, r: lead ? 7 : 5, fill: COL[s.cat], 'fill-opacity': lead ? 0.95 : 0.72, stroke: lead ? '#0b0a0e' : 'none', 'stroke-width': lead ? 2 : 0 });
      c.appendChild(el('title', {}, s.name + ' — P ' + s.prec.toFixed(2) + ', R ' + val(s, 'rec').toFixed(2) + ', F3 ' + fmt(val(s, 'f3'))));
      frag.appendChild(c);
    });
    // label only the notable points to avoid clutter (24 scanners)
    var notable = {};
    ['Kolega Enterprise', 'Kolega.Dev', 'GPT-5.5', 'Grok 4.20 Reasoning', 'Semgrep', 'Snyk Code', 'SonarQube'].forEach(function (n) { notable[n] = 1; });
    var OFF = { 'Kolega Enterprise': [-9, -9, 'end'], 'Kolega.Dev': [9, 12, 'start'], 'GPT-5.5': [9, -7, 'start'], 'Grok 4.20 Reasoning': [-9, -7, 'end'], 'Semgrep': [0, 16, 'middle'], 'Snyk Code': [9, 13, 'start'], 'SonarQube': [9, -7, 'start'] };
    SC.forEach(function (s) {
      if (!notable[s.name]) return;
      var cx = X(val(s, 'rec')), cy = Y(s.prec), o = OFF[s.name] || [8, 4, 'start'];
      frag.appendChild(el('text', { class: 'pt-label', x: cx + o[0], y: cy + o[1], 'text-anchor': o[2], fill: s.cat === 'sec' ? '#cfa45c' : '#b2aa9d' }, s.name));
    });
    svg.appendChild(frag);
  }
  renderScatter();

  // ---------------------------------------------------------
  // mobile nav
  // ---------------------------------------------------------
  var toggle = document.querySelector('.nav-toggle'), menu = document.getElementById('mobile-menu');
  if (toggle && menu) {
    toggle.addEventListener('click', function () {
      var o = menu.classList.toggle('open');
      document.body.classList.toggle('no-scroll', o);
      toggle.textContent = o ? '✕' : '≡';
    });
    menu.querySelectorAll('a').forEach(function (a) { a.addEventListener('click', function () { menu.classList.remove('open'); document.body.classList.remove('no-scroll'); toggle.textContent = '≡'; }); });
  }
})();
