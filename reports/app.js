/* ============================================================
   RealVuln — landing leaderboard + precision/recall scatter
   Data: window.RV (realvuln-data.js). Primary metric: F3 (strict).
   ============================================================ */
(function () {
  'use strict';
  if (!window.RV) return;
  var SC = window.RV.SCANNERS, COL = window.RV.COL;
  var REPO_TOTAL = (window.RV.DATASET && window.RV.DATASET.repos) || 26;

  var state = { metric: 'f3', mode: 'strict', sortKey: 'f3', sortDir: -1 };

  var METRIC_LABEL = { f2: 'F2', f3: 'F3' };
  function mk(base) { return state.mode === 'strict' ? base + 's' : base; }   // metric/recall key for mode
  function val(s, base) { return s[mk(base)]; }
  function activeF(s) { return val(s, state.metric); }
  function fmt(v) { return v.toFixed(1); }
  // explicit vendor-site link on the tag line, labeled with the domain
  function extLink(s) {
    if (!s.url) return '';
    var host = s.url.replace('https://', '').replace('www.', '').split('/')[0];
    return ' <span class="dim">·</span> <a class="sc-ext" href="' + s.url + '" target="_blank" rel="noopener">' + host + ' ↗</a>';
  }

  var tbody = document.getElementById('lb-body');

  function render() {
    if (!tbody) return;
    var rows = SC.slice();
    var k = state.sortKey, dir = state.sortDir;
    rows.sort(function (a, b) {
      // partial-coverage entries always sink below fully-covered ones
      if (!a.partial !== !b.partial) return a.partial ? 1 : -1;
      if (k === 'name') return dir * a.name.localeCompare(b.name);
      if (k === 'prec') return dir * (a.prec - b.prec);
      if (k === 'repos') return dir * (a.repos - b.repos);
      if (k === 'cost') { var ac = a.cost == null ? -1 : a.cost, bc = b.cost == null ? -1 : b.cost; return dir * (ac - bc); }
      if (k === 'recall') return dir * (val(a, 'rec') - val(b, 'rec'));
      return dir * (val(a, k) - val(b, k)); // f2 / f3
    });

    var ranked = SC.filter(function (s) { return !s.partial; });
    if (!ranked.length) ranked = SC;
    var maxA = Math.max.apply(null, ranked.map(activeF));
    var leadName = ranked.reduce(function (m, s) { return activeF(s) > activeF(m) ? s : m; }, ranked[0]).name;

    tbody.innerHTML = '';
    var rankNo = 0;
    rows.forEach(function (s) {
      var tr = document.createElement('tr');
      var isLead = s.name === leadName && s.ver === SC.filter(function (x) { return x.name === leadName; })[0].ver;
      if (isLead && !s.partial) tr.className = 'leader';
      if (s.partial) tr.classList.add('partial');
      var pct = Math.min(100, Math.round((activeF(s) / maxA) * 100));
      var reposCls = s.repos < REPO_TOTAL ? ' class="repos-bad"' : '';
      var rankCell = s.partial
        ? '<span class="rank" title="Unranked — scanned fewer than 95% of the corpus; score not comparable">—</span>'
        : '<span class="rank">' + String(++rankNo).padStart(2, '0') + '</span>';

      tr.innerHTML =
        '<td class="l">' + rankCell + '</td>' +
        '<td class="l"><a class="sc-name sc-link" href="scanners/' + s.slug + '.html">' + s.name + '</a>' +
          '<div class="cat-tag">' + s.ver + extLink(s) + '</div></td>' +
        '<td class="metric-cell"><span class="bar-wrap"><span class="bar-track"><span class="bar-fill" style="width:' + pct + '%"></span></span><span>' + fmt(activeF(s)) + '</span></span></td>' +
        '<td>' + (val(s, 'rec') * 100).toFixed(1) + '</td>' +
        '<td>' + (s.prec * 100).toFixed(1) + '</td>' +
        '<td><span' + reposCls + '>' + s.repos + '</span><span class="dim">/' + REPO_TOTAL + '</span></td>' +
        '<td class="dim"' + (s.est ? ' title="Estimated cost — 2× Claude Opus 4.8; these runs were interactive and unmetered"' : '') + '>' + (s.cost == null ? '—' : (s.est ? '~$' : '$') + s.cost.toFixed(0)) + '</td>';
      tbody.appendChild(tr);
    });

    var mth = document.querySelector('table.lb th.metric-th');
    if (mth) { mth.setAttribute('data-key', state.metric); mth.firstChild.nodeValue = METRIC_LABEL[state.metric] + ' '; }

    document.querySelectorAll('table.lb thead th[data-key]').forEach(function (th) {
      var key = th.getAttribute('data-key');
      th.classList.toggle('sorted', key === state.sortKey);
      var ar = th.querySelector('.arrow'); if (ar) ar.textContent = state.sortDir === -1 ? '▼' : '▲';
    });
  }

  document.querySelectorAll('.metric-toggle [data-metric]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.metric-toggle [data-metric]').forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      state.metric = btn.getAttribute('data-metric');
      state.sortKey = state.metric; state.sortDir = -1;
      render();
    });
  });
  document.querySelectorAll('table.lb thead th[data-key]').forEach(function (th) {
    th.addEventListener('click', function () {
      var key = th.getAttribute('data-key'); if (!key) return;
      if (state.sortKey === key) state.sortDir *= -1;
      else { state.sortKey = key; state.sortDir = key === 'name' ? 1 : -1; }
      render();
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
