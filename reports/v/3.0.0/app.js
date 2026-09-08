/* ============================================================
   RealVuln — landing leaderboard + precision/recall scatter
   Data: window.RV (realvuln-data.js). Primary metric: F3 (strict).
   ============================================================ */
(function () {
  'use strict';
  if (!window.RV) return;
  var BY_TAB = window.RV.SCANNERS_BY_TAB || { all: window.RV.SCANNERS };
  var TAB_TOTALS = window.RV.TAB_TOTALS || {};
  var LANG_LABELS = window.RV.LANG_LABELS || { all: 'Overall' };
  var SHORT_LANG = { python: 'Python', tsjs: 'TS/JS', java: 'Java' };
  var lang = 'all';
  var SC = BY_TAB[lang] || window.RV.SCANNERS, COL = window.RV.COL;
  var REPO_TOTAL = TAB_TOTALS[lang] || (window.RV.DATASET && window.RV.DATASET.repos) || 26;
  function langBadges(s) {
    if (!s.langs || s.full !== false) return '';
    return s.langs.map(function (l) {
      return '<span class="lang-badge limited" title="Language-limited run — scored on ' + (LANG_LABELS[l] || l) + ' repositories only">' + (SHORT_LANG[l] || l) + '</span>';
    }).join('');
  }

  var state = { metric: 'f3', mode: 'strict', sortKey: 'f3', sortDir: -1 };

  var METRIC_LABEL = { f2: 'F2', f3: 'F3' };
  function mk(base) { return state.mode === 'strict' ? base + 's' : base; }   // metric/recall key for mode
  function val(s, base) { return s[mk(base)]; }

  // ---- severity filter (investigative): affects TP/FN-derived numbers only,
  // never precision/FP (false positives carry no ground-truth severity) ----
  var ALL_SEV = ['critical', 'high', 'medium', 'low'];
  var sevSel = { critical: true, high: true, medium: true, low: true };
  function sevAllOn() { return ALL_SEV.every(function (k) { return sevSel[k]; }); }
  function sevAgg(s) {
    if (!s.sev) return null;
    var tp = 0, fn = 0, any = false;
    ALL_SEV.forEach(function (k) {
      if (!sevSel[k]) return;
      var d = s.sev[k]; if (!d) return;
      any = true; tp += d[0]; fn += d[2];
    });
    return any ? { tp: tp, fn: fn } : { tp: 0, fn: 0 };
  }
  function effFn(s) {
    if (sevAllOn() || !s.sev) return s.fn || 0;
    return sevAgg(s).fn;
  }
  function effTotal(s) {
    if (sevAllOn() || !s.sev) return (s.tp || 0) + (s.fn || 0);
    var agg = sevAgg(s);
    return agg.tp + agg.fn;
  }
  function sevFilterVisible() {
    var el = document.getElementById('sev-filter');
    return !!el && !el.hidden;
  }
  function effF3(s) {
    if (sevAllOn() || !s.sev) return val(s, state.metric);
    var agg = sevAgg(s), fp = s.fp || 0;
    var p = (agg.tp + fp) > 0 ? agg.tp / (agg.tp + fp) : 0;
    var r = (agg.tp + agg.fn) > 0 ? agg.tp / (agg.tp + agg.fn) : 0;
    var beta2 = state.metric === 'f2' ? 4 : 9;
    var denom = beta2 * p + r;
    return denom === 0 ? 0 : (100 * (1 + beta2) * p * r / denom);
  }
  function activeF(s) { return effF3(s); }
  function fmt(v) { return v.toFixed(1); }
  // per-language F3 (only present on cross-language tabs): [standard, strict]
  function langF(s, lk) { var v = s.lf && s.lf[lk]; return v ? v[state.mode === 'strict' ? 1 : 0] : null; }
  function langCols() { return lang === 'all'; }
  function toggleLangCols(table) {
    table.querySelectorAll('th.lang-col').forEach(function (th) { th.hidden = !langCols(); });
  }
  // explicit vendor-site link on the tag line, labeled with the domain
  function extLink(s) {
    if (!s.url) return '';
    var host = s.url.replace('https://', '').replace('www.', '').split('/')[0];
    return ' <span class="dim">·</span> <a class="sc-ext" href="' + s.url + '" target="_blank" rel="noopener">' + host + ' ↗</a>';
  }

  var tbody = document.getElementById('lb-body');

  // tier cards follow the selected leaderboard (fully-covered rows only)
  var TG_EX = {
    sec: function (g) { return 'recall to ' + Math.max.apply(null, g.map(function (s) { return val(s, 'rec'); })).toFixed(2) + '<br>breadth-driven'; },
    llm: function (g) { return 'range ' + fmt(Math.min.apply(null, g.map(activeF))) + '\u2013' + fmt(Math.max.apply(null, g.map(activeF))) + '<br>high variance'; },
    rule: function (g) { return 'recall \u2264 ' + Math.max.apply(null, g.map(function (s) { return val(s, 'rec'); })).toFixed(2) + '<br>syntactic only'; }
  };
  function renderTiers() {
    var box = document.getElementById('tier-glance');
    if (!box) return;
    var ranked = SC.filter(function (s) { return !s.partial; });
    box.querySelectorAll('.tg-row').forEach(function (row) {
      var cat = row.getAttribute('data-cat');
      var g = ranked.filter(function (s) { return s.cat === cat; });
      var n = row.querySelector('[data-tg="n"]'), best = row.querySelector('[data-tg="best"]'), ex = row.querySelector('[data-tg="ex"]');
      n.textContent = g.length;
      var unit = row.querySelector('[data-tg="unit"]'); unit.textContent = g.length === 1 ? unit.getAttribute('data-one') : unit.getAttribute('data-one') + 's';
      row.classList.toggle('empty', !g.length);
      if (!g.length) { best.textContent = '\u2014'; ex.innerHTML = 'no full-coverage run<br>on this leaderboard'; return; }
      best.textContent = fmt(Math.max.apply(null, g.map(activeF)));
      ex.innerHTML = TG_EX[cat](g);
    });
    var cap = document.getElementById('tier-cap');
    if (cap) cap.textContent = 'Tier figures follow the selected leaderboard (' + (LANG_LABELS[lang] || lang) + ', ' + REPO_TOTAL + ' repositories, ' + ranked.length + ' scanner' + (ranked.length === 1 ? '' : 's') + ').';
  }

  function render() {
    renderTiers();
    if (!tbody) return;
    var rows = SC.slice();
    var k = state.sortKey, dir = state.sortDir;
    rows.sort(function (a, b) {
      // partial-coverage entries always sink below fully-covered ones
      if (!a.partial !== !b.partial) return a.partial ? 1 : -1;
      if (k === 'name') return dir * a.name.localeCompare(b.name);
      if (k === 'fp') return dir * ((a.fp || 0) - (b.fp || 0));
      if (k === 'repos') return dir * (a.repos - b.repos);
      if (k === 'cost') { var ac = a.cost == null ? -1 : a.cost, bc = b.cost == null ? -1 : b.cost; return dir * (ac - bc); }
      if (k === 'fn') return dir * (effFn(a) - effFn(b));
      if (k.indexOf('lf:') === 0) { var lk = k.slice(3), av = langF(a, lk), bv = langF(b, lk); return dir * ((av == null ? -1 : av) - (bv == null ? -1 : bv)); }
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
        '<td class="l"><a class="sc-name sc-link" href="scanners/' + s.slug + '.html">' + s.name + '</a>' + langBadges(s) +
          '<div class="cat-tag">' + s.ver + extLink(s) + '</div></td>' +
        '<td class="metric-cell"><span class="bar-wrap"><span class="bar-track"><span class="bar-fill" style="width:' + pct + '%"></span></span><span>' + fmt(activeF(s)) + '</span></span></td>' +
        (langCols() ? ['python', 'tsjs'].map(function (lk) { var v = langF(s, lk); return '<td class="lang-col">' + (v == null ? '<span class="dim">—</span>' : fmt(v)) + '</td>'; }).join('') : '') +
        '<td title="real vulnerabilities missed (false negatives)' + (sevAllOn() ? '' : ' — filtered to selected severities') + '">' + effFn(s) + (sevFilterVisible() ? ' <span class="dim">of ' + effTotal(s) + '</span>' : '') + '</td>' +
        '<td title="findings that did not match a real vulnerability (false positives)">' + (s.fp || 0) + '</td>' +
        '<td><span' + reposCls + '>' + s.repos + '</span><span class="dim">/' + REPO_TOTAL + '</span></td>' +
        '<td class="dim"' + (s.est ? ' title="Estimated cost — 2× Claude Opus 4.8; these runs were interactive and unmetered"' : '') + '>' + (s.cost == null ? '—' : (s.est ? '~$' : '$') + (s.cost < 10 ? s.cost.toFixed(2) : s.cost.toFixed(0))) + '</td>';
      tbody.appendChild(tr);
    });

    toggleLangCols(document.querySelector('table.lb'));
    var mth = document.querySelector('table.lb th.metric-th');
    if (mth) { mth.setAttribute('data-key', state.metric); mth.firstChild.nodeValue = METRIC_LABEL[state.metric] + ' '; }

    document.querySelectorAll('table.lb thead th[data-key]').forEach(function (th) {
      var key = th.getAttribute('data-key');
      th.classList.toggle('sorted', key === state.sortKey);
      var ar = th.querySelector('.arrow'); if (ar) ar.textContent = state.sortDir === -1 ? '▼' : '▲';
    });
  }

  // homepage language tabs (Overall / Python / TS-JS / ...), built from the data file
  var langHost = document.getElementById('home-lang-tabs');
  if (langHost) {
    Object.keys(LANG_LABELS).forEach(function (lk) {
      if (lk === 'all' || !BY_TAB[lk]) return;
      var b = document.createElement('button');
      b.className = 'ltab'; b.setAttribute('data-lang', lk); b.setAttribute('role', 'tab');
      b.textContent = LANG_LABELS[lk];
      langHost.appendChild(b);
    });
    langHost.querySelectorAll('.ltab').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var lk = btn.getAttribute('data-lang');
        if (lk === lang || !BY_TAB[lk]) return;
        langHost.querySelectorAll('.ltab').forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');
        lang = lk; SC = BY_TAB[lk]; REPO_TOTAL = TAB_TOTALS[lk] || REPO_TOTAL;
        render(); if (typeof renderScatter === 'function') renderScatter();
      });
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
  document.querySelectorAll('#sev-filter input[data-sev]').forEach(function (cb) {
    cb.addEventListener('change', function () {
      sevSel[cb.getAttribute('data-sev')] = cb.checked;
      render(); if (typeof renderScatter === 'function') renderScatter();
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
