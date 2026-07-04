/* ============================================================
   RealVuln dashboard — interactive console
   Data: window.RV (realvuln-data.js). Primary metric: F3 (strict).
   ============================================================ */
(function () {
  'use strict';
  if (!window.RV) return;
  var COL = window.RV.COL,
      CAT_LABEL = window.RV.CAT_LABEL,
      CWE = window.RV.CWE;
  var BY_TAB = window.RV.SCANNERS_BY_TAB || { all: window.RV.SCANNERS };
  var TAB_TOTALS = window.RV.TAB_TOTALS || { all: (window.RV.SCANNERS || []).length };
  var METRIC_LABEL = { f2: 'F2', f3: 'F3' };

  var state = { tab: 'all', metric: 'f3', mode: 'strict', sortKey: 'f3', sortDir: -1, cats: { sec: true, llm: true, rule: true } };
  // active scanner list + repo total for the selected corpus tab (reassigned on tab switch)
  var SC = BY_TAB[state.tab] || window.RV.SCANNERS;
  function tabTotal() { return TAB_TOTALS[state.tab] || SC.length; }

  function mk(base) { return state.mode === 'strict' ? base + 's' : base; }
  function val(s, base) { return s[mk(base)]; }
  function activeF(s) { return val(s, state.metric); }
  function on(s) { return state.cats[s.cat]; }
  function fmt(v) { return v.toFixed(1); }
  function leaderName() { return SC.reduce(function (m, s) { return activeF(s) > activeF(m) ? s : m; }, SC[0]).name; }
  // explicit vendor-site link on the tag line, labeled with the domain
  function extLink(s) {
    if (!s.url) return '';
    var host = s.url.replace('https://', '').replace('www.', '').split('/')[0];
    return ' <span class="dim">·</span> <a class="sc-ext" href="' + s.url + '" target="_blank" rel="noopener">' + host + ' ↗</a>';
  }

  var NS = 'http://www.w3.org/2000/svg';
  function svgEl(t, a, x) { var e = document.createElementNS(NS, t); for (var k in a) e.setAttribute(k, a[k]); if (x != null) e.textContent = x; return e; }

  var tip = document.getElementById('dash-tip');
  function showTip(h, x, y) { if (!tip) return; tip.innerHTML = h; tip.style.opacity = '1'; tip.style.left = (x + 14) + 'px'; tip.style.top = (y + 14) + 'px'; }
  function hideTip() { if (tip) tip.style.opacity = '0'; }

  // ---- KPIs ----
  function setText(id, v) { var e = document.getElementById(id); if (e) e.textContent = v; }
  function renderKPIs() {
    var lead = SC[0]; SC.forEach(function (s) { if (activeF(s) > activeF(lead)) lead = s; });
    setText('kpi-metric-val', fmt(activeF(lead)));
    setText('kpi-metric-lbl', 'Best ' + METRIC_LABEL[state.metric] + ' (' + state.mode + ')');
    setText('kpi-metric-sub', lead.name);
    // corpus-tab-dependent KPIs
    setText('kpi-scanners-val', SC.length);
    setText('kpi-repos-val', tabTotal());
    setText('kpi-repos-sub', window.RV.TAB_LABELS ? window.RV.TAB_LABELS[state.tab] : 'All apps');
    var recLead = SC[0];
    SC.forEach(function (s) { if (val(s, 'rec') > val(recLead, 'rec')) recLead = s; });
    setText('kpi-recall-val', (val(recLead, 'rec') * 100).toFixed(1));
    setText('kpi-recall-sub', recLead.name);
    var loc = (window.RV.DATASET && window.RV.DATASET.loc) || 0;
    setText('kpi-loc-val', loc.toLocaleString());
    setText('kpi-loc-sub', 'across all repos');
  }

  // ---- leaderboard ----
  var tbody = document.getElementById('dlb-body');
  function renderLeaderboard() {
    if (!tbody) return;
    var rows = SC.slice(), k = state.sortKey, dir = state.sortDir;
    rows.sort(function (a, b) {
      if (k === 'name') return dir * a.name.localeCompare(b.name);
      if (k === 'prec') return dir * (a.prec - b.prec);
      if (k === 'noise') return dir * ((1 - a.prec) - (1 - b.prec));
      if (k === 'repos') return dir * (a.repos - b.repos);
      if (k === 'cost') { var ac = a.cost == null ? -1 : a.cost, bc = b.cost == null ? -1 : b.cost; return dir * (ac - bc); }
      if (k === 'cpv') { var av = a.cpv == null ? -1 : a.cpv, bv = b.cpv == null ? -1 : b.cpv; return dir * (av - bv); }
      if (k === 'tp') return dir * ((a.tp || 0) - (b.tp || 0));
      if (k === 'fp') return dir * ((a.fp || 0) - (b.fp || 0));
      if (k === 'fptp') { var ar = a.tp ? a.fp / a.tp : Infinity, br = b.tp ? b.fp / b.tp : Infinity; return dir * (ar - br); }
      if (k === 'recall') return dir * (val(a, 'rec') - val(b, 'rec'));
      return dir * (val(a, k) - val(b, k));
    });
    var maxA = Math.max.apply(null, SC.map(activeF));
    var lead = leaderName();
    tbody.innerHTML = '';
    rows.forEach(function (s, i) {
      var tr = document.createElement('tr');
      if (s.name === lead) tr.className = 'leader';
      tr.style.opacity = on(s) ? '1' : '0.24';
      var pct = Math.round((activeF(s) / maxA) * 100);
      var total = tabTotal();
      var reposCls = s.repos < total ? ' class="repos-bad"' : '';
      tr.innerHTML =
        '<td class="l"><span class="rank">' + String(i + 1).padStart(2, '0') + '</span></td>' +
        '<td class="l"><a class="sc-name sc-link" href="scanners/' + s.slug + '.html">' + s.name + '</a>' +
          '<div class="cat-tag">' + s.ver + extLink(s) + '</div></td>' +
        '<td class="metric-cell"><span class="bar-wrap"><span class="bar-track"><span class="bar-fill" style="width:' + pct + '%"></span></span><span>' + fmt(activeF(s)) + '</span></span></td>' +
        '<td>' + (val(s, 'rec') * 100).toFixed(1) + '</td>' +
        '<td title="Real vulnerabilities found (true positives)">' + (s.tp == null ? '—' : s.tp.toLocaleString()) + '</td>' +
        '<td title="False positives — flagged but not a real vulnerability">' + (s.fp == null ? '—' : s.fp.toLocaleString()) + '</td>' +
        '<td title="False positives per true positive (FP ÷ TP) — lower is better">' + (s.tp ? (s.fp / s.tp).toFixed(2) : '—') + '</td>' +
        '<td>' + (s.prec * 100).toFixed(1) + '</td>' +
        '<td title="Noise — share of findings that were false alarms (100% − precision)">' + (100 - s.prec * 100).toFixed(1) + '</td>' +
        '<td><span' + reposCls + '>' + s.repos + '</span><span class="dim">/' + total + '</span></td>' +
        '<td class="dim"' + (s.est ? ' title="Estimated cost — 2× Claude Opus 4.8; these runs were interactive and unmetered"' : ' title="API spend per 100,000 lines of code scanned"') + '>' + (s.cost == null ? '—' : s.cost === 0 ? 'Free' : (s.est ? '~$' : '$') + s.cost.toLocaleString()) + '</td>' +
        '<td class="dim" title="API spend per 100 real vulnerabilities found">' + (s.cpv == null ? '—' : s.cpv === 0 ? 'Free' : '$' + s.cpv.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2})) + '</td>';
      tbody.appendChild(tr);
    });
    var mth = document.querySelector('#dlb th.metric-th');
    if (mth) { mth.setAttribute('data-key', state.metric); mth.firstChild.nodeValue = METRIC_LABEL[state.metric] + ' '; }

    document.querySelectorAll('#dlb thead th[data-key]').forEach(function (th) {
      var key = th.getAttribute('data-key');
      th.classList.toggle('sorted', key === state.sortKey);
      var ar = th.querySelector('.arrow'); if (ar) ar.textContent = state.sortDir === -1 ? '▼' : '▲';
    });
  }

  // ---- scatter ----
  function renderScatter(id, cfg) {
    var svg = document.getElementById(id); if (!svg) return;
    svg.innerHTML = '';
    var W = 560, H = 380, m = { t: 18, r: 20, b: 46, l: 50 };
    var pw = W - m.l - m.r, ph = H - m.t - m.b;
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    function X(v) { return m.l + (v / cfg.xMax) * pw; }
    function Y(v) { return m.t + (1 - v / cfg.yMax) * ph; }
    var frag = document.createDocumentFragment();
    cfg.xTicks.forEach(function (t) {
      frag.appendChild(svgEl('line', { class: 'gridline', x1: X(t), y1: m.t, x2: X(t), y2: m.t + ph }));
      frag.appendChild(svgEl('text', { class: 'tick', x: X(t), y: m.t + ph + 17, 'text-anchor': 'middle' }, cfg.xFmt(t)));
    });
    cfg.yTicks.forEach(function (t) {
      frag.appendChild(svgEl('line', { class: 'gridline', x1: m.l, y1: Y(t), x2: m.l + pw, y2: Y(t) }));
      frag.appendChild(svgEl('text', { class: 'tick', x: m.l - 9, y: Y(t) + 3, 'text-anchor': 'end' }, cfg.yFmt(t)));
    });
    frag.appendChild(svgEl('line', { class: 'axis', x1: m.l, y1: m.t + ph, x2: m.l + pw, y2: m.t + ph }));
    frag.appendChild(svgEl('line', { class: 'axis', x1: m.l, y1: m.t, x2: m.l, y2: m.t + ph }));
    frag.appendChild(svgEl('text', { class: 'axis-label', x: m.l + pw / 2, y: H - 6, 'text-anchor': 'middle' }, cfg.xLabel));
    frag.appendChild(svgEl('text', { class: 'axis-label', x: 14, y: m.t + ph / 2, 'text-anchor': 'middle', transform: 'rotate(-90 14 ' + (m.t + ph / 2) + ')' }, cfg.yLabel));
    cfg.points.forEach(function (s) {
      var cx = X(cfg.x(s)), cy = Y(cfg.y(s)), lead = s.cat === 'sec';
      var c = svgEl('circle', { class: 'pt' + (on(s) ? '' : ' dimmed'), cx: cx, cy: cy, r: lead ? 7 : 5, fill: COL[s.cat], 'fill-opacity': lead ? 0.95 : 0.78, stroke: lead ? '#0b0a0e' : 'none', 'stroke-width': lead ? 2 : 0 });
      c.addEventListener('mousemove', function (e) { showTip('<div class="tt-name">' + s.name + '</div><div class="tt-cat">' + CAT_LABEL[s.cat] + ' · ' + s.ver + '</div>' + cfg.tip(s), e.clientX, e.clientY); });
      c.addEventListener('mouseleave', hideTip);
      frag.appendChild(c);
    });
    svg.appendChild(frag);
  }
  function renderPR() {
    renderScatter('pr-scatter', {
      points: SC, x: function (s) { return val(s, 'rec'); }, y: function (s) { return s.prec; },
      xMax: 1, yMax: 1, xTicks: [0, .2, .4, .6, .8, 1], yTicks: [0, .2, .4, .6, .8, 1],
      xFmt: function (t) { return t.toFixed(1); }, yFmt: function (t) { return t.toFixed(1); },
      xLabel: 'Recall →', yLabel: 'Precision →',
      tip: function (s) { return 'P ' + s.prec.toFixed(2) + ' · R ' + val(s, 'rec').toFixed(2) + ' · F3 ' + fmt(val(s, 'f3')); }
    });
  }
  function renderCost() {
    var pts = SC.filter(function (s) { return s.cost != null; });
    // round the axis up to a clean ceiling above the priciest scanner
    var maxCost = pts.reduce(function (m, s) { return Math.max(m, s.cost); }, 0);
    var step = maxCost > 400 ? 200 : maxCost > 200 ? 100 : maxCost > 100 ? 50 : 20;
    var xMax = Math.max(step, Math.ceil(maxCost / step) * step);
    var xTicks = []; for (var t = 0; t <= xMax; t += step) xTicks.push(t);
    renderScatter('cost-scatter', {
      points: pts,
      x: function (s) { return s.cost; }, y: function (s) { return activeF(s); },
      xMax: xMax, yMax: 100, xTicks: xTicks, yTicks: [0, 25, 50, 75, 100],
      xFmt: function (t) { return '$' + t.toLocaleString(); }, yFmt: function (t) { return String(t); },
      xLabel: 'Cost per 100k LOC (USD) →', yLabel: METRIC_LABEL[state.metric] + ' →',
      tip: function (s) { return METRIC_LABEL[state.metric] + ' ' + fmt(activeF(s)) + ' · ' + (s.est ? '~$' : '$') + s.cost.toLocaleString() + '/100k LOC' + (s.est ? ' (est.)' : ''); }
    });
    var tag = document.getElementById('cost-metric-tag'); if (tag) tag.textContent = METRIC_LABEL[state.metric] + ' vs cost/100k LOC';
  }

  // ---- ranking bars ----
  function renderRanking(id, getter, fmtFn) {
    var host = document.getElementById(id); if (!host) return;
    var rows = SC.slice().sort(function (a, b) { return getter(b) - getter(a); });
    var max = Math.max.apply(null, rows.map(getter));
    host.innerHTML = '';
    rows.forEach(function (s) {
      var d = document.createElement('div');
      d.className = 'hbar'; d.style.opacity = on(s) ? '1' : '0.24';
      d.innerHTML = '<span class="hn"><span class="hd" style="background:' + COL[s.cat] + '"></span>' + s.name + '</span>' +
        '<span class="ht"><span class="hf" style="width:' + (getter(s) / max * 100) + '%;background:' + COL[s.cat] + '"></span></span>' +
        '<span class="hv">' + fmtFn(getter(s)) + '</span>';
      host.appendChild(d);
    });
  }
  function renderRankings() {
    renderRanking('rank-recall', function (s) { return val(s, 'rec'); }, function (v) { return (v * 100).toFixed(1); });
    renderRanking('rank-prec', function (s) { return s.prec; }, function (v) { return (v * 100).toFixed(1); });
  }

  // ---- category breakdown ----
  function renderCategory() {
    var host = document.getElementById('cat-stats'); if (!host) return;
    host.innerHTML = '';
    ['sec', 'llm', 'rule'].forEach(function (cat) {
      var grp = SC.filter(function (s) { return s.cat === cat; });
      var arr = grp.map(activeF).sort(function (a, b) { return a - b; });
      var best = Math.max.apply(null, arr);
      var med = arr.length % 2 ? arr[(arr.length - 1) / 2] : (arr[arr.length / 2 - 1] + arr[arr.length / 2]) / 2;
      var recs = grp.map(function (s) { return val(s, 'rec'); });
      var d = document.createElement('div');
      d.className = 'catstat';
      d.style.borderLeftColor = COL[cat];
      d.style.opacity = on({ cat: cat }) ? '1' : '0.3';
      d.innerHTML =
        '<div class="ctop"><span class="cname">' + CAT_LABEL[cat] + '</span><span class="ccount">' + grp.length + (grp.length > 1 ? ' systems' : ' system') + '</span></div>' +
        '<div class="cmetrics">' +
          '<div class="cm"><div class="v">' + fmt(best) + '</div><div class="l">Best ' + METRIC_LABEL[state.metric] + '</div></div>' +
          '<div class="cm"><div class="v">' + fmt(med) + '</div><div class="l">Median ' + METRIC_LABEL[state.metric] + '</div></div>' +
          '<div class="cm"><div class="v">' + (Math.min.apply(null, recs) * 100).toFixed(0) + '–' + (Math.max.apply(null, recs) * 100).toFixed(0) + '%</div><div class="l">Recall</div></div>' +
        '</div>';
      host.appendChild(d);
    });
  }

  // ---- per-CWE class bars ----
  function renderCWE() {
    var host = document.getElementById('class-bars'); if (!host) return;
    host.innerHTML = '';
    CWE.forEach(function (c) {
      var row = document.createElement('div');
      row.className = 'classrow';
      row.innerHTML =
        '<div class="clabel"><span>' + c.label + '</span><span class="cwe">' + c.cwe + '</span></div>' +
        '<div class="gbar">' +
          '<div class="gr"><span class="gn">LLM-based</span><span class="gt"><span class="gf" style="width:' + c.llm + '%;background:var(--tier-llm)"></span></span><span class="gv">' + c.llm + '%</span></div>' +
          '<div class="gr"><span class="gn">Rule-based</span><span class="gt"><span class="gf" style="width:' + c.rule + '%;background:var(--tier-rule)"></span></span><span class="gv">' + c.rule + '%</span></div>' +
        '</div>';
      host.appendChild(row);
    });
  }

  // ---- controls ----
  function rerenderAll() { renderKPIs(); renderLeaderboard(); renderPR(); renderCost(); renderRankings(); renderCategory(); }

  // ---- corpus tabs (All / Intentionally Vulnerable / Vibe Coded) ----
  document.querySelectorAll('#corpus-tabs .ctab').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var tab = btn.getAttribute('data-tab');
      if (!BY_TAB[tab] || tab === state.tab) return;
      document.querySelectorAll('#corpus-tabs .ctab').forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      state.tab = tab;
      SC = BY_TAB[tab];
      rerenderAll();
    });
  });

  document.querySelectorAll('.metric-toggle [data-metric]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.metric-toggle [data-metric]').forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      state.metric = btn.getAttribute('data-metric'); state.sortKey = state.metric; state.sortDir = -1;
      rerenderAll();
    });
  });
  document.querySelectorAll('#dlb thead th[data-key]').forEach(function (th) {
    th.addEventListener('click', function () {
      var key = th.getAttribute('data-key'); if (!key) return;
      if (state.sortKey === key) state.sortDir *= -1;
      else { state.sortKey = key; state.sortDir = key === 'name' ? 1 : -1; }
      renderLeaderboard();
    });
  });

  // ---- mobile nav ----
  var toggle = document.querySelector('.nav-toggle'), menu = document.getElementById('mobile-menu');
  if (toggle && menu) {
    toggle.addEventListener('click', function () { var o = menu.classList.toggle('open'); document.body.classList.toggle('no-scroll', o); toggle.textContent = o ? '✕' : '≡'; });
    menu.querySelectorAll('a').forEach(function (a) { a.addEventListener('click', function () { menu.classList.remove('open'); document.body.classList.remove('no-scroll'); toggle.textContent = '≡'; }); });
  }

  // ---- init ----
  rerenderAll(); renderCWE();
})();
