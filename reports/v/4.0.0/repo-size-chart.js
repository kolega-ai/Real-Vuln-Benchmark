(function () {
  'use strict';
  var NS = 'http://www.w3.org/2000/svg';
  function svgEl(t, a, x) { var e = document.createElementNS(NS, t); for (var k in a) e.setAttribute(k, a[k]); if (x != null) e.textContent = x; return e; }
  var tip = document.createElement('div'); tip.className = 'dash-tip'; document.body.appendChild(tip);
  function showTip(name, detail, x, y) {
    tip.replaceChildren();
    var title = document.createElement('div'); title.className = 'tt-name'; title.textContent = name;
    var meta = document.createElement('div'); meta.className = 'tt-cat'; meta.textContent = detail;
    tip.append(title, meta);
    tip.style.opacity='1'; tip.style.left=(x+14)+'px'; tip.style.top=(y+14)+'px';
  }
  function hideTip() { tip.style.opacity='0'; }
  // ---- repository size / smoothed per-repository F3 ----
  var sizeHighlight = '';
  function smoothSizeRows(rows, slug) {
    // Distance in log10(LOC) keeps the large, sparse repositories local to
    // each other instead of averaging them with dozens of tiny repositories.
    return rows.map(function (target) {
      var center = Math.log10(target.loc), weight = 0, weight2 = 0, total = 0;
      rows.forEach(function (row) {
        var z = (Math.log10(row.loc) - center) / 0.5;
        var w = Math.exp(-0.5 * z * z);
        weight += w; weight2 += w * w; total += w * row.scores[slug];
      });
      return { score: total / weight, count: Math.round(weight * weight / weight2) };
    });
  }
  function selectSizeScanner(slug) {
    sizeHighlight = slug;
    var svg = document.getElementById('size-chart');
    svg.classList.toggle('focused', !!slug);
    svg.querySelectorAll('.size-series').forEach(function (g) {
      g.classList.toggle('active', g.getAttribute('data-slug') === slug);
    });
    document.getElementById('size-chart-scanner').value = slug;
    document.querySelectorAll('#size-chart-legend .size-legend-item').forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-slug') === slug && !!slug));
    });
  }
  window.renderRepoSizeChart = function (chartTab, chartScanners) {
    var svg = document.getElementById('size-chart');
    var picker = document.getElementById('size-chart-scanner');
    var legend = document.getElementById('size-chart-legend');
    if (!svg || !picker || !legend) return;
    var points = (window.RV.REPO_SIZE_POINTS || []).filter(function (p) {
      return p.tabs.indexOf(chartTab) !== -1;
    });
    var scanners = chartScanners;
    if (!scanners.some(function (s) { return s.slug === sizeHighlight; })) sizeHighlight = '';
    picker.replaceChildren();
    picker.add(new Option('All scanners', ''));
    scanners.forEach(function (s) { picker.add(new Option(s.name, s.slug)); });
    picker.value = sizeHighlight;
    svg.replaceChildren();
    legend.replaceChildren();
    if (!points.length || !scanners.length) return;

    var W = 1150, H = 390, m = { t: 18, r: 25, b: 54, l: 57 };
    var pw = W - m.l - m.r, ph = H - m.t - m.b;
    var lo = Math.floor(Math.log10(Math.min.apply(null, points.map(function (p) { return p.loc; }))));
    var hi = Math.ceil(Math.log10(Math.max.apply(null, points.map(function (p) { return p.loc; }))));
    if (hi === lo) hi++;
    function X(loc) { return m.l + (Math.log10(loc) - lo) / (hi - lo) * pw; }
    function Y(score) { return m.t + (1 - score) * ph; }
    function focus(slug) {
      svg.classList.toggle('focused', !!slug);
      svg.querySelectorAll('.size-series').forEach(function (g) {
        g.classList.toggle('active', g.getAttribute('data-slug') === slug);
      });
    }
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.classList.toggle('few', scanners.length <= 6);
    svg.classList.toggle('focused', !!sizeHighlight);
    for (var y = 0; y <= 100; y += 20) {
      svg.appendChild(svgEl('line', { class: 'size-grid', x1: m.l, y1: Y(y / 100), x2: W - m.r, y2: Y(y / 100) }));
      svg.appendChild(svgEl('text', { class: 'size-axis', x: m.l - 10, y: Y(y / 100) + 4, 'text-anchor': 'end' }, y + '%'));
    }
    for (var power = lo; power <= hi; power++) {
      var loc = Math.pow(10, power);
      svg.appendChild(svgEl('line', { class: 'size-grid', x1: X(loc), y1: m.t, x2: X(loc), y2: H - m.b }));
      svg.appendChild(svgEl('text', { class: 'size-axis', x: X(loc), y: H - m.b + 19, 'text-anchor': 'middle' }, loc >= 1000000 ? (loc / 1000000) + 'M' : loc >= 1000 ? (loc / 1000) + 'k' : String(loc)));
    }
    svg.appendChild(svgEl('text', { class: 'size-axis', x: m.l + pw / 2, y: H - 7, 'text-anchor': 'middle' }, 'Repository size · source LOC (log scale)'));
    svg.appendChild(svgEl('text', { class: 'size-axis', x: 13, y: m.t + ph / 2, 'text-anchor': 'middle', transform: 'rotate(-90 13 ' + (m.t + ph / 2) + ')' }, 'F3 per repository'));

    scanners.forEach(function (s, i) {
      var rows = points.filter(function (p) { return p.scores[s.slug] != null; });
      if (!rows.length) return;
      var averaged = smoothSizeRows(rows, s.slug);
      var color = 'hsl(' + ((34 + i * 137.508) % 360) + ' 58% 67%)';
      var button = document.createElement('button');
      button.type = 'button'; button.className = 'size-legend-item';
      button.setAttribute('data-slug', s.slug);
      button.setAttribute('aria-pressed', String(s.slug === sizeHighlight));
      var swatch = document.createElement('span');
      swatch.className = 'size-legend-swatch'; swatch.style.backgroundColor = color;
      button.appendChild(swatch);
      button.appendChild(document.createTextNode(s.name));
      button.addEventListener('click', function () { selectSizeScanner(sizeHighlight === s.slug ? '' : s.slug); });
      legend.appendChild(button);
      var g = svgEl('g', { class: 'size-series' + (s.slug === sizeHighlight ? ' active' : ''), 'data-slug': s.slug });
      var d = rows.map(function (p, j) { return (j ? 'L' : 'M') + X(p.loc).toFixed(2) + ',' + Y(averaged[j].score).toFixed(2); }).join(' ');
      g.appendChild(svgEl('path', { d: d, stroke: color }));
      var hit = svgEl('path', { class: 'size-hit', d: d, stroke: color });
      hit.addEventListener('mousemove', function (e) {
        focus(s.slug);
        var x = (e.clientX - svg.getBoundingClientRect().left) / svg.getBoundingClientRect().width * W;
        var nearest = 0;
        for (var j = 1; j < rows.length; j++) {
          if (Math.abs(X(rows[j].loc) - x) < Math.abs(X(rows[nearest].loc) - x)) nearest = j;
        }
        var support = 'log-local · ~' + averaged[nearest].count + ' effective repos';
        showTip(s.name, support + ' · ' + rows[nearest].loc.toLocaleString() + ' LOC · ' + (averaged[nearest].score * 100).toFixed(1) + '% F3', e.clientX, e.clientY);
      });
      hit.addEventListener('mouseleave', function () { hideTip(); focus(sizeHighlight); });
      g.appendChild(hit);
      svg.appendChild(g);
    });
  };
  var sizePicker = document.getElementById('size-chart-scanner');
  if (sizePicker) sizePicker.addEventListener('change', function () {
    selectSizeScanner(sizePicker.value);
  });

})();
