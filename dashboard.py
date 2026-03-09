#!/usr/bin/env python3
"""Multi-Scanner Dashboard — compare F2 scores across all repos and scanners.

Usage:
    python -m evals.realvuln.dashboard                          # baseline scanners
    python -m evals.realvuln.dashboard --scanner-group all      # all discovered scanners
    python -m evals.realvuln.dashboard --repos realvuln-pygoat realvuln-dvpwa
    python -m evals.realvuln.dashboard -o custom.html --json custom.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from parsers import get_parser
from scorer.matcher import load_ground_truth, match_findings
from scorer.metrics import compute_scorecard

BASELINE_SCANNERS = {"semgrep", "snyk", "sonarqube"}


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover_repos(gt_dir: Path) -> list[str]:
    """Find all repos that have a ground-truth.json."""
    repos = []
    for d in sorted(gt_dir.iterdir()):
        if d.is_dir() and (d / "ground-truth.json").exists():
            repos.append(d.name)
    return repos


def discover_all_scanners(scan_dir: Path, repos: list[str]) -> list[str]:
    """Union of scanner slugs across all repos."""
    scanners: set[str] = set()
    for repo in repos:
        repo_dir = scan_dir / repo
        if repo_dir.is_dir():
            for d in repo_dir.iterdir():
                if d.is_dir():
                    scanners.add(d.name)
    return sorted(scanners)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _find_result_files(scanner_dir: Path) -> list[Path]:
    """Find JSON result files for a scanner."""
    if not scanner_dir.is_dir():
        return []
    return sorted(scanner_dir.glob("*.json"))


def score_all(
    repos: list[str],
    scanners: list[str],
    gt_dir: Path,
    scan_dir: Path,
    cwe_families: dict,
) -> dict[str, dict[str, dict | None]]:
    """Score every (repo, scanner) pair.

    Returns grid[repo][scanner] = scorecard.to_dict() or None.
    """
    grid: dict[str, dict[str, dict | None]] = {}
    timestamp = datetime.now(timezone.utc).isoformat()

    for repo in repos:
        gt_path = gt_dir / repo / "ground-truth.json"
        if not gt_path.exists():
            continue
        ground_truth = load_ground_truth(str(gt_path))
        repo_id = ground_truth["repo_id"]
        grid[repo] = {}

        for scanner in scanners:
            scanner_dir = scan_dir / repo / scanner
            result_files = _find_result_files(scanner_dir)
            if not result_files:
                grid[repo][scanner] = None
                continue

            parser = get_parser(scanner)
            try:
                findings = parser.parse(str(result_files[0]))
                results = match_findings(findings, ground_truth)
                card = compute_scorecard(
                    repo_id, scanner, timestamp, results, cwe_families
                )
                grid[repo][scanner] = card.to_dict()
            except Exception as e:
                print(f"Warning: Failed to score {repo}/{scanner}: {e}", file=sys.stderr)
                grid[repo][scanner] = None

    return grid


# ---------------------------------------------------------------------------
# Aggregates
# ---------------------------------------------------------------------------

def _safe_div(n: float, d: float) -> float:
    return n / d if d > 0 else 0.0


def compute_aggregates(
    grid: dict[str, dict[str, dict | None]],
    scanners: list[str],
) -> dict[str, dict]:
    """Compute micro-avg and macro-avg per scanner.

    Returns {scanner: {"micro": {...}, "macro": {...}, "repos_scored": int}}.
    """
    agg: dict[str, dict] = {}

    for scanner in scanners:
        total_tp = total_fp = total_fn = total_tn = 0
        f2_scores: list[float] = []

        for repo in grid:
            cell = grid[repo].get(scanner)
            if cell is None:
                continue
            total_tp += cell["tp"]
            total_fp += cell["fp"]
            total_fn += cell["fn"]
            total_tn += cell["tn"]
            f2_scores.append(cell["f2_score"])

        micro_prec = _safe_div(total_tp, total_tp + total_fp)
        micro_rec = _safe_div(total_tp, total_tp + total_fn)
        micro_f2 = _safe_div(
            5.0 * micro_prec * micro_rec, 4.0 * micro_prec + micro_rec
        )

        agg[scanner] = {
            "micro": {
                "tp": total_tp,
                "fp": total_fp,
                "fn": total_fn,
                "tn": total_tn,
                "precision": round(micro_prec, 4),
                "recall": round(micro_rec, 4),
                "f2_score": round(micro_f2 * 100, 1),
            },
            "macro": {
                "f2_score": round(
                    sum(f2_scores) / len(f2_scores), 1
                ) if f2_scores else 0.0,
            },
            "repos_scored": len(f2_scores),
        }

    return agg


# ---------------------------------------------------------------------------
# Color mapping
# ---------------------------------------------------------------------------

def f2_color(score: float | None) -> str:
    """Map F2 score to a background color."""
    if score is None:
        return "#334155"  # grey — no data
    if score >= 80:
        return "#16a34a"  # green
    if score >= 60:
        return "#65a30d"  # lime
    if score >= 40:
        return "#ca8a04"  # yellow
    if score >= 20:
        return "#ea580c"  # orange
    return "#dc2626"      # red


def f2_text_color(score: float | None) -> str:
    """Text color for readability on the background."""
    if score is None:
        return "#64748b"
    return "#fff"


# ---------------------------------------------------------------------------
# HTML Dashboard
# ---------------------------------------------------------------------------

def _common_css() -> str:
    """Shared CSS for all dashboard pages."""
    return """
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  background: #0f172a; color: #e2e8f0; padding: 24px;
}
a { color: #3b82f6; text-decoration: none; }
a:hover { text-decoration: underline; }
h1 { font-size: 24px; font-weight: 700; margin-bottom: 4px; }
h2 { font-size: 16px; font-weight: 600; margin: 28px 0 12px 0; color: #f8fafc; }
.subtitle { color: #94a3b8; font-size: 13px; margin-bottom: 24px; }
.back-link { display: inline-block; margin-bottom: 16px; font-size: 13px; color: #3b82f6; }
.back-link:hover { text-decoration: underline; }

/* Summary cards */
.summary-cards {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px; margin-bottom: 28px;
}
.summary-card {
  background: #1e293b; border-radius: 8px; padding: 16px;
  border: 1px solid #334155;
}
.summary-card .sc-label { font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px; }
.summary-card .sc-value { font-size: 28px; font-weight: 700; }
.summary-card .sc-sub { font-size: 11px; color: #64748b; margin-top: 2px; }

/* Metric toggle */
.metric-toggle {
  display: inline-flex; gap: 0; margin-bottom: 12px; border-radius: 6px; overflow: hidden;
  border: 1px solid #334155;
}
.metric-toggle button {
  background: #1e293b; color: #94a3b8; border: none; padding: 6px 16px; font-size: 12px;
  cursor: pointer; font-weight: 500; transition: all 0.15s;
}
.metric-toggle button:hover { background: #334155; }
.metric-toggle button.active { background: #3b82f6; color: #fff; }

/* Legend */
.legend {
  display: flex; gap: 16px; margin-bottom: 12px; font-size: 11px;
  flex-wrap: wrap; align-items: center;
}
.legend-item { display: flex; align-items: center; gap: 5px; }
.legend-box { width: 16px; height: 16px; border-radius: 3px; display: inline-block; }

/* Table */
.container { overflow-x: auto; }
table { border-collapse: collapse; font-size: 12px; white-space: nowrap; width: 100%; }
th, td { padding: 6px 10px; text-align: center; }
th {
  position: sticky; top: 0; background: #0f172a; z-index: 2;
  border-bottom: 2px solid #334155; cursor: pointer; user-select: none;
}
th:hover { background: #1e293b; }
th .sort-arrow { font-size: 10px; margin-left: 3px; color: #64748b; }
.repo-name {
  text-align: left; padding: 6px 10px; font-weight: 500;
  position: sticky; left: 0; background: #0f172a; z-index: 1;
  border-right: 2px solid #334155; max-width: 260px;
  overflow: hidden; text-overflow: ellipsis;
}
.repo-name code {
  font-family: 'SF Mono', 'Fira Code', monospace; font-size: 11px; color: #e2e8f0;
}
.cell {
  min-width: 72px; font-weight: 600; font-size: 12px;
  font-variant-numeric: tabular-nums; border-radius: 3px; position: relative;
}
.cell-inner {
  padding: 4px 8px; border-radius: 3px; display: inline-block; min-width: 48px;
}
.agg-row td { border-top: 2px solid #475569; }
.agg-row .repo-name { font-weight: 700; color: #f8fafc; }
tbody tr:hover { background: #1e293b; }
tbody tr:hover .repo-name { background: #1e293b; }
/* Tooltip */
.tooltip {
  display: none; position: absolute; z-index: 100;
  background: #1e293b; border: 1px solid #475569; border-radius: 6px;
  padding: 10px 14px; font-size: 11px; text-align: left;
  white-space: pre-line; color: #e2e8f0; min-width: 200px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.4); pointer-events: none;
  left: 50%; transform: translateX(-50%); top: 100%;
}
.cell:hover .tooltip { display: block; }
.tooltip .tt-title { font-weight: 700; font-size: 12px; margin-bottom: 6px; }
.tooltip .tt-row { display: flex; justify-content: space-between; gap: 16px; }
.tooltip .tt-label { color: #94a3b8; }
.tooltip .tt-val { font-weight: 600; }
.tooltip .tt-sep { border-top: 1px solid #334155; margin: 4px 0; }

/* Scanner link in table header */
th a { color: #e2e8f0; }
th a:hover { color: #3b82f6; text-decoration: underline; }
"""


def _plotly_theme_js() -> str:
    """Shared Plotly theme constants."""
    return """
  const darkBg = '#0f172a';
  const panelBg = '#1e293b';
  const gridColor = '#334155';
  const textColor = '#e2e8f0';
  const mutedText = '#94a3b8';
  const colors = ['#3b82f6','#10b981','#a855f7','#f59e0b','#ec4899','#06b6d4','#ef4444','#84cc16','#f97316','#14b8a6'];
"""


def _metric_toggle_sort_js() -> str:
    """Shared JS for metric toggle and table sorting."""
    return """
(function() {
  const table = document.getElementById('dashboard-table');
  if (!table) return;
  const thead = table.querySelector('thead');
  const tbody = table.querySelector('tbody');
  let sortCol = null;
  let sortAsc = true;
  let currentMetric = 'f2';

  function metricColor(score, metric) {
    if (score === null || score === undefined || isNaN(score)) return '#334155';
    if (metric === 'precision') {
      if (score >= 60) return '#16a34a';
      if (score >= 40) return '#65a30d';
      if (score >= 25) return '#ca8a04';
      if (score >= 10) return '#ea580c';
      return '#dc2626';
    }
    if (score >= 80) return '#16a34a';
    if (score >= 60) return '#65a30d';
    if (score >= 40) return '#ca8a04';
    if (score >= 20) return '#ea580c';
    return '#dc2626';
  }

  var toggle = document.querySelector('.metric-toggle');
  if (toggle) {
    toggle.addEventListener('click', function(e) {
      const btn = e.target.closest('button');
      if (!btn) return;
      currentMetric = btn.dataset.metric;
      document.querySelectorAll('.metric-toggle button').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      updateCells();
    });
  }

  function updateCells() {
    table.querySelectorAll('td.cell').forEach(td => {
      const val = td.dataset[currentMetric];
      const inner = td.querySelector('.cell-inner');
      if (!inner) return;
      if (val === '' || val === undefined) {
        inner.style.background = '#334155';
        inner.style.color = '#64748b';
        inner.innerHTML = '&mdash;';
      } else {
        const num = parseFloat(val);
        inner.style.background = metricColor(num, currentMetric);
        inner.style.color = '#fff';
        inner.textContent = num.toFixed(1);
      }
    });
  }

  thead.addEventListener('click', function(e) {
    const th = e.target.closest('th');
    if (!th) return;
    const col = th.dataset.col;
    if (col === undefined || col === null) return;
    if (sortCol === col) { sortAsc = !sortAsc; }
    else { sortCol = col; sortAsc = true; }

    const rows = Array.from(tbody.querySelectorAll('tr'));
    const dataRows = rows.filter(r => !r.classList.contains('agg-row'));
    const aggRows = rows.filter(r => r.classList.contains('agg-row'));

    dataRows.sort(function(a, b) {
      if (col === 'repo') {
        const va = a.cells[0].textContent.trim().toLowerCase();
        const vb = b.cells[0].textContent.trim().toLowerCase();
        return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
      }
      const idx = parseInt(col) + 1;
      const ca = a.cells[idx];
      const cb = b.cells[idx];
      const va = ca ? parseFloat(ca.dataset[currentMetric]) || -1 : -1;
      const vb = cb ? parseFloat(cb.dataset[currentMetric]) || -1 : -1;
      return sortAsc ? va - vb : vb - va;
    });

    dataRows.forEach(r => tbody.appendChild(r));
    aggRows.forEach(r => tbody.appendChild(r));

    thead.querySelectorAll('.sort-arrow').forEach(s => s.textContent = '');
    th.querySelector('.sort-arrow').textContent = sortAsc ? ' \\u25B2' : ' \\u25BC';
  });
})();
"""


def _legend_html() -> str:
    """Build legend HTML."""
    parts = []
    for label, color in [
        ("80-100", "#16a34a"), ("60-79", "#65a30d"), ("40-59", "#ca8a04"),
        ("20-39", "#ea580c"), ("0-19", "#dc2626"), ("No data", "#334155"),
    ]:
        parts.append(f'  <div class="legend-item"><div class="legend-box" style="background:{color}"></div> {label}</div>')
    return '<div class="legend">' + "\n".join(parts) + "</div>"


def build_html(
    grid: dict[str, dict[str, dict | None]],
    scanners: list[str],
    aggregates: dict[str, dict],
    repos: list[str],
    detail_dir: str = "scanners",
) -> str:
    """Build standalone HTML index dashboard with links to scanner detail pages."""
    total_repos = len(repos)
    total_scanners = len(scanners)

    # Build summary bar chart data
    chart_data = []
    for scanner in scanners:
        sa = aggregates.get(scanner, {})
        micro = sa.get("micro", {})
        chart_data.append({
            "label": scanner,
            "f2": micro.get("f2_score", 0),
            "recall": round(micro.get("recall", 0) * 100, 1),
            "precision": round(micro.get("precision", 0) * 100, 1),
            "tp": micro.get("tp", 0),
            "fp": micro.get("fp", 0),
            "fn": micro.get("fn", 0),
            "repos": sa.get("repos_scored", 0),
        })
    chart_data.sort(key=lambda x: x["f2"], reverse=True)

    lines: list[str] = []
    w = lines.append

    w("<!DOCTYPE html>")
    w('<html lang="en">')
    w("<head>")
    w('<meta charset="UTF-8">')
    w("<title>RealVuln Multi-Scanner Dashboard</title>")
    w(f"<style>{_common_css()}</style>")
    w("</head>")
    w("<body>")
    w("<h1>RealVuln Multi-Scanner Dashboard</h1>")
    w(f'<div class="subtitle">{total_repos} repositories &middot; {total_scanners} scanners &middot; generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</div>')

    # ── Summary cards ──
    best = chart_data[0] if chart_data else None
    if best:
        w('<div class="summary-cards">')
        w(f'<div class="summary-card"><div class="sc-label">Best Scanner (F2)</div><div class="sc-value" style="color:#3b82f6"><a href="{detail_dir}/{best["label"]}.html">{best["label"]}</a></div><div class="sc-sub">micro-F2 = {best["f2"]:.1f}</div></div>')
        w(f'<div class="summary-card"><div class="sc-label">Best F2</div><div class="sc-value" style="color:#16a34a">{best["f2"]:.1f}</div><div class="sc-sub">Recall {best["recall"]:.1f}% &middot; Prec {best["precision"]:.1f}%</div></div>')
        total_gt = sum(d["tp"] + d["fn"] for d in chart_data[:1])
        w(f'<div class="summary-card"><div class="sc-label">Ground Truth</div><div class="sc-value">{total_gt}</div><div class="sc-sub">vulnerabilities across {best["repos"]} repos</div></div>')
        w(f'<div class="summary-card"><div class="sc-label">Scanners Compared</div><div class="sc-value">{total_scanners}</div><div class="sc-sub">click any scanner for details</div></div>')
        w('</div>')

    # ── Plotly charts ──
    scatter_json = json.dumps(chart_data)
    bar_data_reversed = list(reversed(chart_data))
    bar_json = json.dumps(bar_data_reversed)

    w('<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>')

    w('<h2>Precision vs Recall</h2>')
    w('<div id="pr-scatter" style="width:100%;height:520px;margin-bottom:28px"></div>')

    w('<h2>Scanner Comparison (Micro-Averaged)</h2>')
    w('<div id="metric-bars" style="width:100%;height:400px;margin-bottom:28px"></div>')

    w('<h2>Finding Breakdown (TP / FP / FN)</h2>')
    w('<div id="finding-bars" style="width:100%;height:380px;margin-bottom:28px"></div>')

    # ── Heatmap with metric toggle ──
    w('<h2>Per-Repository Heatmap</h2>')
    w('<div class="metric-toggle">')
    w('<button class="active" data-metric="f2">F2 Score</button>')
    w('<button data-metric="recall">Recall</button>')
    w('<button data-metric="precision">Precision</button>')
    w('</div>')

    w(_legend_html())

    # Table
    w('<div class="container">')
    w('<table id="dashboard-table">')

    # Header — scanner names are clickable links
    w("<thead><tr>")
    w('<th class="repo-name" data-col="repo">Repository <span class="sort-arrow"></span></th>')
    for i, scanner in enumerate(scanners):
        w(f'<th data-col="{i}"><a href="{detail_dir}/{scanner}.html">{scanner}</a> <span class="sort-arrow"></span></th>')
    w("</tr></thead>")

    # Body
    w("<tbody>")
    for repo in repos:
        w("<tr>")
        short_repo = repo.replace("realvuln-", "").replace("Reavuln-", "").replace("RealVuln-", "")
        w(f'<td class="repo-name"><code>{short_repo}</code></td>')
        for scanner in scanners:
            cell = grid.get(repo, {}).get(scanner)
            if cell is None:
                w(f'<td class="cell" data-f2="" data-recall="" data-precision=""><span class="cell-inner" style="background:#334155;color:#64748b">&mdash;</span></td>')
            else:
                f2_val = cell["f2_score"]
                rec_val = round(cell["recall"] * 100, 1)
                prec_val = round(cell["precision"] * 100, 1)
                bg = f2_color(f2_val)
                fg = f2_text_color(f2_val)
                tooltip = _build_tooltip_html(repo, scanner, cell)
                w(f'<td class="cell" data-f2="{f2_val}" data-recall="{rec_val}" data-precision="{prec_val}"><span class="cell-inner" style="background:{bg};color:{fg}">{f2_val:.1f}</span>{tooltip}</td>')
        w("</tr>")

    # Aggregate rows
    for agg_label, agg_key in [("MICRO-AVG", "micro"), ("MACRO-AVG", "macro")]:
        w('<tr class="agg-row">')
        w(f'<td class="repo-name"><code>{agg_label}</code></td>')
        for scanner in scanners:
            sa = aggregates.get(scanner, {})
            agg_data = sa.get(agg_key, {})
            score = agg_data.get("f2_score")
            repos_scored = sa.get("repos_scored", 0)
            if score is None or repos_scored == 0:
                w(f'<td class="cell" data-f2="" data-recall="" data-precision=""><span class="cell-inner" style="background:#334155;color:#64748b">&mdash;</span></td>')
            else:
                bg = f2_color(score)
                fg = f2_text_color(score)
                micro = sa.get("micro", {})
                rec_agg = round(micro.get("recall", 0) * 100, 1) if agg_key == "micro" else ""
                prec_agg = round(micro.get("precision", 0) * 100, 1) if agg_key == "micro" else ""
                tooltip_lines = f'<div class="tt-title">{agg_label}</div>'
                tooltip_lines += f'<div class="tt-row"><span class="tt-label">Repos scored</span><span class="tt-val">{repos_scored}</span></div>'
                if agg_key == "micro":
                    tooltip_lines += f'<div class="tt-sep"></div>'
                    tooltip_lines += f'<div class="tt-row"><span class="tt-label">F2</span><span class="tt-val">{score:.1f}</span></div>'
                    tooltip_lines += f'<div class="tt-row"><span class="tt-label">Recall</span><span class="tt-val">{micro["recall"]:.1%}</span></div>'
                    tooltip_lines += f'<div class="tt-row"><span class="tt-label">Precision</span><span class="tt-val">{micro["precision"]:.1%}</span></div>'
                    tooltip_lines += f'<div class="tt-sep"></div>'
                    tooltip_lines += f'<div class="tt-row"><span class="tt-label">TP / FP / FN</span><span class="tt-val">{micro["tp"]} / {micro["fp"]} / {micro["fn"]}</span></div>'
                w(f'<td class="cell" data-f2="{score}" data-recall="{rec_agg}" data-precision="{prec_agg}"><span class="cell-inner" style="background:{bg};color:{fg}">{score:.1f}</span><div class="tooltip">{tooltip_lines}</div></td>')
        w("</tr>")

    w("</tbody>")
    w("</table>")
    w("</div>")

    # JavaScript
    w("<script>")
    w(_metric_toggle_sort_js())
    w("</script>")
    w("<script>")
    w(f"const chartData = {scatter_json};")
    w(f"const barData = {bar_json};")
    # Scanner detail links for Plotly click-through
    scanner_links = {d["label"]: f"{detail_dir}/{d['label']}.html" for d in chart_data}
    w(f"const scannerLinks = {json.dumps(scanner_links)};")
    w("(function() {")
    w(_plotly_theme_js())
    w("""
  // ── 1. Precision-Recall Scatter with F2 iso-lines ──
  const scatterTraces = [];
  const f2Vals = [20, 30, 40, 50, 60, 80];
  const f2LineColors = ['#dc262640','#ea580c50','#ca8a0450','#65a30d50','#16a34a50','#16a34a30'];
  f2Vals.forEach((f2v, idx) => {
    const f2 = f2v / 100;
    const rr = [], pp = [];
    for (let r = 1; r <= 100; r += 0.5) {
      const denom = 5 * (r/100) - 4 * f2;
      if (denom <= 0) continue;
      const p = (f2 * (r/100) / denom) * 100;
      if (p > 0 && p <= 100) { rr.push(r); pp.push(p); }
    }
    scatterTraces.push({
      x: rr, y: pp, mode: 'lines', line: {color: f2LineColors[idx], width: 1.5, dash: 'dot'},
      name: 'F2=' + f2v, showlegend: false, hoverinfo: 'skip'
    });
  });

  chartData.forEach((d, i) => {
    scatterTraces.push({
      x: [d.recall], y: [d.precision], mode: 'markers+text',
      marker: {size: 16, color: colors[i % colors.length], line: {color: darkBg, width: 2}},
      text: [d.label], textposition: 'top center',
      textfont: {color: colors[i % colors.length], size: 12, family: 'system-ui'},
      name: d.label,
      customdata: [[d.f2, d.tp, d.fp, d.fn]],
      hovertemplate: '<b>%{text}</b><br>Recall: %{x:.1f}%<br>Precision: %{y:.1f}%<br>F2: %{customdata[0]:.1f}<br>TP:%{customdata[1]} FP:%{customdata[2]} FN:%{customdata[3]}<extra></extra>'
    });
  });

  const annotations = f2Vals.map(f2v => {
    const f2 = f2v / 100;
    for (let r = 98; r >= 10; r--) {
      const denom = 5 * (r/100) - 4 * f2;
      if (denom <= 0) continue;
      const p = (f2 * (r/100) / denom) * 100;
      if (p > 3 && p < 95) {
        return {x: r, y: p, text: 'F2=' + f2v, showarrow: false,
          font: {size: 10, color: mutedText}, xanchor: 'left', yanchor: 'bottom'};
      }
    }
    return null;
  }).filter(Boolean);

  const prScatter = document.getElementById('pr-scatter');
  Plotly.newPlot(prScatter, scatterTraces, {
    paper_bgcolor: darkBg, plot_bgcolor: panelBg,
    xaxis: {title: {text: 'Recall (%)', font: {color: textColor, size: 13}},
      range: [0, 105], gridcolor: gridColor, zerolinecolor: gridColor,
      tickfont: {color: mutedText, size: 11}, dtick: 10},
    yaxis: {title: {text: 'Precision (%)', font: {color: textColor, size: 13}},
      range: [0, null], gridcolor: gridColor, zerolinecolor: gridColor,
      tickfont: {color: mutedText, size: 11}},
    legend: {font: {color: textColor, size: 11}, bgcolor: 'rgba(0,0,0,0)', x: 0.01, y: 0.99},
    margin: {l: 60, r: 30, t: 30, b: 50},
    annotations: annotations,
    hoverlabel: {bgcolor: panelBg, bordercolor: gridColor, font: {color: textColor, size: 12}}
  }, {responsive: true, displayModeBar: false});

  // Click on scatter points to navigate to scanner detail
  prScatter.on('plotly_click', function(data) {
    const label = data.points[0].data.name;
    if (scannerLinks[label]) window.location.href = scannerLinks[label];
  });

  // ── 2. Grouped horizontal bar: F2 / Recall / Precision ──
  const barLabels = barData.map(d => d.label);
  Plotly.newPlot('metric-bars', [
    {y: barLabels, x: barData.map(d => d.f2), type: 'bar', orientation: 'h',
      name: 'F2', marker: {color: '#3b82f6'}, text: barData.map(d => d.f2.toFixed(1)),
      textposition: 'outside', textfont: {color: '#3b82f6', size: 11}},
    {y: barLabels, x: barData.map(d => d.recall), type: 'bar', orientation: 'h',
      name: 'Recall', marker: {color: '#10b981'}, text: barData.map(d => d.recall.toFixed(1)),
      textposition: 'outside', textfont: {color: '#10b981', size: 11}},
    {y: barLabels, x: barData.map(d => d.precision), type: 'bar', orientation: 'h',
      name: 'Precision', marker: {color: '#a855f7'}, text: barData.map(d => d.precision.toFixed(1)),
      textposition: 'outside', textfont: {color: '#a855f7', size: 11}},
  ], {
    paper_bgcolor: darkBg, plot_bgcolor: panelBg, barmode: 'group', bargap: 0.25, bargroupgap: 0.1,
    xaxis: {range: [0, 105], gridcolor: gridColor, zerolinecolor: gridColor,
      tickfont: {color: mutedText, size: 11}, ticksuffix: '%'},
    yaxis: {tickfont: {color: textColor, size: 12}, automargin: true},
    legend: {font: {color: textColor, size: 11}, bgcolor: 'rgba(0,0,0,0)', orientation: 'h', y: 1.12},
    margin: {l: 140, r: 50, t: 40, b: 30},
    hoverlabel: {bgcolor: panelBg, bordercolor: gridColor, font: {color: textColor}}
  }, {responsive: true, displayModeBar: false});

  // ── 3. TP/FP/FN stacked horizontal bar ──
  Plotly.newPlot('finding-bars', [
    {y: barLabels, x: barData.map(d => d.tp), type: 'bar', orientation: 'h',
      name: 'True Positives', marker: {color: '#16a34a'},
      hovertemplate: '%{y}<br>TP: %{x}<extra></extra>'},
    {y: barLabels, x: barData.map(d => d.fp), type: 'bar', orientation: 'h',
      name: 'False Positives', marker: {color: '#dc2626'},
      hovertemplate: '%{y}<br>FP: %{x}<extra></extra>'},
    {y: barLabels, x: barData.map(d => d.fn), type: 'bar', orientation: 'h',
      name: 'False Negatives', marker: {color: '#ea580c'},
      hovertemplate: '%{y}<br>FN: %{x}<extra></extra>'},
  ], {
    paper_bgcolor: darkBg, plot_bgcolor: panelBg, barmode: 'stack',
    xaxis: {title: {text: 'Count', font: {color: textColor, size: 13}},
      gridcolor: gridColor, zerolinecolor: gridColor, tickfont: {color: mutedText, size: 11}},
    yaxis: {tickfont: {color: textColor, size: 12}, automargin: true},
    legend: {font: {color: textColor, size: 11}, bgcolor: 'rgba(0,0,0,0)', orientation: 'h', y: 1.1},
    margin: {l: 140, r: 30, t: 30, b: 50},
    hoverlabel: {bgcolor: panelBg, bordercolor: gridColor, font: {color: textColor}}
  }, {responsive: true, displayModeBar: false});
""")
    w("})();")
    w("</script>")
    w("</body></html>")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Scanner Detail Page
# ---------------------------------------------------------------------------

def build_scanner_detail_html(
    scanner: str,
    grid: dict[str, dict[str, dict | None]],
    repos: list[str],
    aggregates: dict[str, dict],
) -> str:
    """Build a detail page for a single scanner."""
    sa = aggregates.get(scanner, {})
    micro = sa.get("micro", {})
    macro = sa.get("macro", {})
    repos_scored = sa.get("repos_scored", 0)

    # Collect per-repo data for this scanner
    repo_data = []
    for repo in repos:
        cell = grid.get(repo, {}).get(scanner)
        if cell is not None:
            repo_data.append((repo, cell))

    # Collect all CWE families seen across repos
    all_families: dict[str, str] = {}  # slug -> label
    for _, cell in repo_data:
        for fam_slug, fam_info in cell.get("per_family", {}).items():
            if fam_slug not in all_families:
                all_families[fam_slug] = fam_info.get("label", fam_slug)
    family_slugs = sorted(all_families.keys())

    # Collect all severities
    all_severities: list[str] = []
    sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
    sev_set: set[str] = set()
    for _, cell in repo_data:
        for sev in cell.get("per_severity", {}).keys():
            sev_set.add(sev)
    all_severities = [s for s in sev_order if s in sev_set]

    lines: list[str] = []
    w = lines.append

    w("<!DOCTYPE html>")
    w('<html lang="en">')
    w("<head>")
    w('<meta charset="UTF-8">')
    w(f"<title>{scanner} — RealVuln Scanner Detail</title>")
    w(f"<style>{_common_css()}")
    # Additional detail-page CSS
    w("""
/* Detail page extras */
.family-name {
  text-align: left; padding: 6px 10px; font-weight: 500;
  position: sticky; left: 0; background: #0f172a; z-index: 1;
  border-right: 2px solid #334155; max-width: 200px;
  overflow: hidden; text-overflow: ellipsis; font-size: 11px;
}
.family-name code { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 11px; color: #e2e8f0; }
.severity-card {
  background: #1e293b; border-radius: 8px; padding: 16px; border: 1px solid #334155;
  display: inline-block; min-width: 140px; text-align: center; margin: 0 8px 8px 0;
}
.severity-card .sev-label { font-size: 11px; color: #94a3b8; text-transform: uppercase; margin-bottom: 4px; }
.severity-card .sev-recall { font-size: 24px; font-weight: 700; }
.severity-card .sev-counts { font-size: 11px; color: #64748b; margin-top: 4px; }
""")
    w("</style>")
    w("</head>")
    w("<body>")
    w('<a href="../dashboard.html" class="back-link">&larr; Back to Dashboard</a>')
    w(f"<h1>{scanner}</h1>")
    w(f'<div class="subtitle">Scanner detail &middot; {repos_scored} repositories scored &middot; generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</div>')

    # ── Summary cards ──
    f2_val = micro.get("f2_score", 0)
    rec_val = round(micro.get("recall", 0) * 100, 1)
    prec_val = round(micro.get("precision", 0) * 100, 1)
    tp_total = micro.get("tp", 0)
    fp_total = micro.get("fp", 0)
    fn_total = micro.get("fn", 0)

    w('<div class="summary-cards">')
    w(f'<div class="summary-card"><div class="sc-label">Micro F2 Score</div><div class="sc-value" style="color:{f2_color(f2_val)}">{f2_val:.1f}</div><div class="sc-sub">macro-F2 = {macro.get("f2_score", 0):.1f}</div></div>')
    w(f'<div class="summary-card"><div class="sc-label">Recall</div><div class="sc-value" style="color:#10b981">{rec_val:.1f}%</div><div class="sc-sub">found {tp_total} of {tp_total + fn_total} vulns</div></div>')
    w(f'<div class="summary-card"><div class="sc-label">Precision</div><div class="sc-value" style="color:#a855f7">{prec_val:.1f}%</div><div class="sc-sub">{fp_total} false positives</div></div>')
    w(f'<div class="summary-card"><div class="sc-label">Repos Scored</div><div class="sc-value">{repos_scored}</div><div class="sc-sub">TP {tp_total} &middot; FP {fp_total} &middot; FN {fn_total}</div></div>')
    w('</div>')

    w('<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>')

    # ── Per-repo TP/FP/FN chart ──
    w('<h2>Per-Repository Breakdown</h2>')
    w('<div id="repo-bars" style="width:100%;height:' + str(max(300, len(repo_data) * 28 + 80)) + 'px;margin-bottom:28px"></div>')

    # ── Per-repo metric table ──
    w('<h2>Per-Repository Scores</h2>')
    w('<div class="metric-toggle">')
    w('<button class="active" data-metric="f2">F2 Score</button>')
    w('<button data-metric="recall">Recall</button>')
    w('<button data-metric="precision">Precision</button>')
    w('</div>')
    w(_legend_html())
    w('<div class="container">')
    w('<table id="dashboard-table">')
    w('<thead><tr>')
    w('<th class="repo-name" data-col="repo">Repository <span class="sort-arrow"></span></th>')
    w(f'<th data-col="0">F2 <span class="sort-arrow"></span></th>')
    w(f'<th data-col="1">Recall <span class="sort-arrow"></span></th>')
    w(f'<th data-col="2">Precision <span class="sort-arrow"></span></th>')
    w(f'<th data-col="3">TP <span class="sort-arrow"></span></th>')
    w(f'<th data-col="4">FP <span class="sort-arrow"></span></th>')
    w(f'<th data-col="5">FN <span class="sort-arrow"></span></th>')
    w('</tr></thead>')
    w('<tbody>')
    for repo, cell in repo_data:
        short_repo = repo.replace("realvuln-", "").replace("Reavuln-", "").replace("RealVuln-", "")
        f2 = cell["f2_score"]
        rec = round(cell["recall"] * 100, 1)
        prec = round(cell["precision"] * 100, 1)
        bg = f2_color(f2)
        fg = f2_text_color(f2)
        w("<tr>")
        w(f'<td class="repo-name"><code>{short_repo}</code></td>')
        w(f'<td class="cell" data-f2="{f2}" data-recall="{rec}" data-precision="{prec}"><span class="cell-inner" style="background:{bg};color:{fg}">{f2:.1f}</span></td>')
        w(f'<td class="cell" data-f2="{f2}" data-recall="{rec}" data-precision="{prec}"><span class="cell-inner" style="background:{f2_color(rec)};color:#fff">{rec:.1f}</span></td>')
        w(f'<td class="cell" data-f2="{f2}" data-recall="{rec}" data-precision="{prec}"><span class="cell-inner" style="background:{f2_color(prec)};color:#fff">{prec:.1f}</span></td>')
        w(f'<td style="color:#16a34a;font-weight:600">{cell["tp"]}</td>')
        w(f'<td style="color:#dc2626;font-weight:600">{cell["fp"]}</td>')
        w(f'<td style="color:#ea580c;font-weight:600">{cell["fn"]}</td>')
        w("</tr>")
    w('</tbody>')
    w('</table>')
    w('</div>')

    # ── Severity breakdown ──
    # Aggregate severity across repos (computed regardless for chart JS below)
    sev_agg: dict[str, dict] = {}
    for _, cell in repo_data:
        for sev, sdata in cell.get("per_severity", {}).items():
            if sev not in sev_agg:
                sev_agg[sev] = {"tp": 0, "fp": 0, "fn": 0}
            sev_agg[sev]["tp"] += sdata["tp"]
            sev_agg[sev]["fp"] += sdata["fp"]
            sev_agg[sev]["fn"] += sdata["fn"]

    if all_severities:
        w('<h2>Detection by Severity</h2>')
        w('<div id="severity-bars" style="width:100%;height:300px;margin-bottom:16px"></div>')

        w('<div style="display:flex;flex-wrap:wrap;margin-bottom:20px">')
        for sev in all_severities:
            if sev in sev_agg:
                sd = sev_agg[sev]
                sev_recall = sd["tp"] / (sd["tp"] + sd["fn"]) if (sd["tp"] + sd["fn"]) > 0 else 0
                sev_color = f2_color(sev_recall * 100)
                w(f'<div class="severity-card"><div class="sev-label">{sev}</div><div class="sev-recall" style="color:{sev_color}">{sev_recall:.0%}</div><div class="sev-counts">TP {sd["tp"]} / FP {sd["fp"]} / FN {sd["fn"]}</div></div>')
        w('</div>')

    # ── CWE Family Heatmap ──
    if family_slugs:
        w('<h2>CWE Family Heatmap (Recall by Repository)</h2>')
        w(_legend_html())
        w('<div class="container">')
        w('<table>')
        w('<thead><tr>')
        w('<th class="repo-name">Repository</th>')
        for fam_slug in family_slugs:
            label = all_families[fam_slug]
            short_label = label if len(label) <= 18 else label[:16] + ".."
            w(f'<th title="{label}" style="font-size:10px;max-width:80px;overflow:hidden;text-overflow:ellipsis">{short_label}</th>')
        w('</tr></thead>')
        w('<tbody>')
        for repo, cell in repo_data:
            short_repo = repo.replace("realvuln-", "").replace("Reavuln-", "").replace("RealVuln-", "")
            w("<tr>")
            w(f'<td class="repo-name"><code>{short_repo}</code></td>')
            per_fam = cell.get("per_family", {})
            for fam_slug in family_slugs:
                fam_data = per_fam.get(fam_slug)
                if fam_data is None:
                    w('<td class="cell"><span class="cell-inner" style="background:#334155;color:#64748b">&mdash;</span></td>')
                else:
                    recall_pct = round(fam_data["recall"] * 100, 1)
                    bg = f2_color(recall_pct)
                    tp_fn = fam_data["tp"] + fam_data["fn"]
                    title_text = f'{all_families[fam_slug]}: {fam_data["tp"]}/{tp_fn} found'
                    w(f'<td class="cell" title="{title_text}"><span class="cell-inner" style="background:{bg};color:#fff">{recall_pct:.0f}%</span></td>')
            w("</tr>")
        w('</tbody>')
        w('</table>')
        w('</div>')

        # ── Aggregate CWE Family chart ──
        w('<h2>CWE Family Detection (Aggregate)</h2>')
        w('<div id="family-bars" style="width:100%;height:' + str(max(300, len(family_slugs) * 28 + 80)) + 'px;margin-bottom:28px"></div>')

    # ── Plotly JS ──
    w('<script>')
    w('(function() {')
    w(_plotly_theme_js())

    # Repo breakdown bar chart data
    repo_labels_json = json.dumps([r.replace("realvuln-", "").replace("Reavuln-", "").replace("RealVuln-", "") for r, _ in reversed(repo_data)])
    repo_tp_json = json.dumps([c["tp"] for _, c in reversed(repo_data)])
    repo_fp_json = json.dumps([c["fp"] for _, c in reversed(repo_data)])
    repo_fn_json = json.dumps([c["fn"] for _, c in reversed(repo_data)])

    w(f'  const repoLabels = {repo_labels_json};')
    w(f'  const repoTP = {repo_tp_json};')
    w(f'  const repoFP = {repo_fp_json};')
    w(f'  const repoFN = {repo_fn_json};')

    w("""
  Plotly.newPlot('repo-bars', [
    {y: repoLabels, x: repoTP, type: 'bar', orientation: 'h', name: 'TP', marker: {color: '#16a34a'},
      hovertemplate: '%{y}<br>TP: %{x}<extra></extra>'},
    {y: repoLabels, x: repoFP, type: 'bar', orientation: 'h', name: 'FP', marker: {color: '#dc2626'},
      hovertemplate: '%{y}<br>FP: %{x}<extra></extra>'},
    {y: repoLabels, x: repoFN, type: 'bar', orientation: 'h', name: 'FN', marker: {color: '#ea580c'},
      hovertemplate: '%{y}<br>FN: %{x}<extra></extra>'},
  ], {
    paper_bgcolor: darkBg, plot_bgcolor: panelBg, barmode: 'stack',
    xaxis: {title: {text: 'Count', font: {color: textColor, size: 13}},
      gridcolor: gridColor, zerolinecolor: gridColor, tickfont: {color: mutedText, size: 11}},
    yaxis: {tickfont: {color: textColor, size: 11}, automargin: true},
    legend: {font: {color: textColor, size: 11}, bgcolor: 'rgba(0,0,0,0)', orientation: 'h', y: 1.08},
    margin: {l: 160, r: 30, t: 30, b: 50},
    hoverlabel: {bgcolor: panelBg, bordercolor: gridColor, font: {color: textColor}}
  }, {responsive: true, displayModeBar: false});
""")

    # Severity chart
    if all_severities:
        sev_labels_json = json.dumps([s.title() for s in all_severities])
        sev_tp_json = json.dumps([sev_agg.get(s, {}).get("tp", 0) for s in all_severities])
        sev_fp_json = json.dumps([sev_agg.get(s, {}).get("fp", 0) for s in all_severities])
        sev_fn_json = json.dumps([sev_agg.get(s, {}).get("fn", 0) for s in all_severities])

        w(f'  const sevLabels = {sev_labels_json};')
        w(f'  const sevTP = {sev_tp_json};')
        w(f'  const sevFP = {sev_fp_json};')
        w(f'  const sevFN = {sev_fn_json};')

        w("""
  Plotly.newPlot('severity-bars', [
    {x: sevLabels, y: sevTP, type: 'bar', name: 'TP', marker: {color: '#16a34a'}},
    {x: sevLabels, y: sevFP, type: 'bar', name: 'FP', marker: {color: '#dc2626'}},
    {x: sevLabels, y: sevFN, type: 'bar', name: 'FN', marker: {color: '#ea580c'}},
  ], {
    paper_bgcolor: darkBg, plot_bgcolor: panelBg, barmode: 'group', bargap: 0.3,
    xaxis: {tickfont: {color: textColor, size: 12}},
    yaxis: {title: {text: 'Count', font: {color: textColor, size: 13}},
      gridcolor: gridColor, zerolinecolor: gridColor, tickfont: {color: mutedText, size: 11}},
    legend: {font: {color: textColor, size: 11}, bgcolor: 'rgba(0,0,0,0)', orientation: 'h', y: 1.1},
    margin: {l: 50, r: 30, t: 30, b: 40},
    hoverlabel: {bgcolor: panelBg, bordercolor: gridColor, font: {color: textColor}}
  }, {responsive: true, displayModeBar: false});
""")

    # Family aggregate chart
    if family_slugs:
        fam_agg: dict[str, dict] = {}
        for _, cell in repo_data:
            for fam_slug, fam_info in cell.get("per_family", {}).items():
                if fam_slug not in fam_agg:
                    fam_agg[fam_slug] = {"tp": 0, "fp": 0, "fn": 0}
                fam_agg[fam_slug]["tp"] += fam_info["tp"]
                fam_agg[fam_slug]["fp"] += fam_info["fp"]
                fam_agg[fam_slug]["fn"] += fam_info["fn"]

        # Sort families by recall descending
        sorted_fams = sorted(family_slugs, key=lambda s: fam_agg.get(s, {}).get("tp", 0) / max(fam_agg.get(s, {}).get("tp", 0) + fam_agg.get(s, {}).get("fn", 0), 1))
        fam_labels_json = json.dumps([all_families[s] for s in sorted_fams])
        fam_tp_json = json.dumps([fam_agg.get(s, {}).get("tp", 0) for s in sorted_fams])
        fam_fp_json = json.dumps([fam_agg.get(s, {}).get("fp", 0) for s in sorted_fams])
        fam_fn_json = json.dumps([fam_agg.get(s, {}).get("fn", 0) for s in sorted_fams])

        w(f'  const famLabels = {fam_labels_json};')
        w(f'  const famTP = {fam_tp_json};')
        w(f'  const famFP = {fam_fp_json};')
        w(f'  const famFN = {fam_fn_json};')

        w("""
  Plotly.newPlot('family-bars', [
    {y: famLabels, x: famTP, type: 'bar', orientation: 'h', name: 'TP', marker: {color: '#16a34a'},
      hovertemplate: '%{y}<br>TP: %{x}<extra></extra>'},
    {y: famLabels, x: famFP, type: 'bar', orientation: 'h', name: 'FP', marker: {color: '#dc2626'},
      hovertemplate: '%{y}<br>FP: %{x}<extra></extra>'},
    {y: famLabels, x: famFN, type: 'bar', orientation: 'h', name: 'FN', marker: {color: '#ea580c'},
      hovertemplate: '%{y}<br>FN: %{x}<extra></extra>'},
  ], {
    paper_bgcolor: darkBg, plot_bgcolor: panelBg, barmode: 'stack',
    xaxis: {title: {text: 'Count', font: {color: textColor, size: 13}},
      gridcolor: gridColor, zerolinecolor: gridColor, tickfont: {color: mutedText, size: 11}},
    yaxis: {tickfont: {color: textColor, size: 11}, automargin: true},
    legend: {font: {color: textColor, size: 11}, bgcolor: 'rgba(0,0,0,0)', orientation: 'h', y: 1.06},
    margin: {l: 200, r: 30, t: 30, b: 50},
    hoverlabel: {bgcolor: panelBg, bordercolor: gridColor, font: {color: textColor}}
  }, {responsive: true, displayModeBar: false});
""")

    w('})();')
    w('</script>')

    # Table sort JS
    w('<script>')
    w(_metric_toggle_sort_js())
    w('</script>')

    w("</body></html>")

    return "\n".join(lines)


def _build_tooltip_html(repo: str, scanner: str, cell: dict) -> str:
    """Build tooltip div for a cell."""
    short_repo = repo.replace("realvuln-", "").replace("Reavuln-", "").replace("RealVuln-", "")
    short_scanner = scanner
    lines = f'<div class="tt-title">{short_repo} / {short_scanner}</div>'
    lines += '<div class="tt-sep"></div>'
    lines += f'<div class="tt-row"><span class="tt-label">F2 Score</span><span class="tt-val">{cell["f2_score"]:.1f}</span></div>'
    lines += f'<div class="tt-row"><span class="tt-label">Recall</span><span class="tt-val">{cell["recall"]:.1%}</span></div>'
    lines += f'<div class="tt-row"><span class="tt-label">Precision</span><span class="tt-val">{cell["precision"]:.1%}</span></div>'
    lines += '<div class="tt-sep"></div>'
    lines += f'<div class="tt-row"><span class="tt-label">TP</span><span class="tt-val" style="color:#16a34a">{cell["tp"]}</span></div>'
    lines += f'<div class="tt-row"><span class="tt-label">FP</span><span class="tt-val" style="color:#dc2626">{cell["fp"]}</span></div>'
    lines += f'<div class="tt-row"><span class="tt-label">FN</span><span class="tt-val" style="color:#ea580c">{cell["fn"]}</span></div>'
    return f'<div class="tooltip">{lines}</div>'


# ---------------------------------------------------------------------------
# JSON Report
# ---------------------------------------------------------------------------

def build_json_report(
    grid: dict[str, dict[str, dict | None]],
    scanners: list[str],
    aggregates: dict[str, dict],
) -> dict:
    """Build machine-readable JSON report."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanners": scanners,
        "repos": list(grid.keys()),
        "grid": {
            repo: {
                scanner: cell
                for scanner, cell in repo_data.items()
            }
            for repo, repo_data in grid.items()
        },
        "aggregates": aggregates,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Multi-Scanner Dashboard — compare F2 scores across repos"
    )
    parser.add_argument(
        "-o", "--output",
        default=str(SCRIPT_DIR / "reports" / "dashboard.html"),
        help="HTML output path (default: reports/dashboard.html)",
    )
    parser.add_argument(
        "--json",
        default=str(SCRIPT_DIR / "reports" / "dashboard.json"),
        help="JSON output path (default: reports/dashboard.json)",
    )
    parser.add_argument(
        "--repos",
        nargs="+",
        help="Specific repo slugs to include",
    )
    parser.add_argument(
        "--scanners",
        nargs="+",
        help="Specific scanner slugs to include",
    )
    parser.add_argument(
        "--exclude-scanners",
        nargs="+",
        default=[],
        help="Scanner slugs to exclude",
    )
    parser.add_argument(
        "--scanner-group",
        choices=["baseline", "all"],
        default="baseline",
        help="Scanner group: baseline (4 scanners) or all (default: baseline)",
    )
    parser.add_argument(
        "--min-repos",
        type=int,
        default=0,
        help="Exclude scanners that scored fewer than N repos (default: 0 = no filter)",
    )
    args = parser.parse_args()

    gt_dir = SCRIPT_DIR / "ground-truth"
    scan_dir = SCRIPT_DIR / "scan-results"

    # Discover repos
    if args.repos:
        repos = args.repos
    else:
        repos = discover_repos(gt_dir)
    # Filter to repos that also have scan-results
    repos = [r for r in repos if (scan_dir / r).is_dir()]

    if not repos:
        print("Error: No repos found with both ground-truth and scan-results.", file=sys.stderr)
        return 1

    # Discover scanners
    if args.scanners:
        scanners = args.scanners
    elif args.scanner_group == "all":
        scanners = discover_all_scanners(scan_dir, repos)
    else:
        # baseline — discover all, then filter to baseline set
        all_scanners = discover_all_scanners(scan_dir, repos)
        scanners = [s for s in all_scanners if s in BASELINE_SCANNERS]

    # Apply exclusions
    exclude = set(args.exclude_scanners)
    scanners = [s for s in scanners if s not in exclude]

    if not scanners:
        print("Error: No scanners to score.", file=sys.stderr)
        return 1

    print(f"Scoring {len(repos)} repos x {len(scanners)} scanners...")

    # Load CWE families
    families_path = SCRIPT_DIR / "config" / "cwe-families.json"
    with open(families_path) as f:
        cwe_families = json.load(f)

    # Score everything
    grid = score_all(repos, scanners, gt_dir, scan_dir, cwe_families)

    aggregates = compute_aggregates(grid, scanners)

    # Filter scanners by minimum repo count
    if args.min_repos > 0:
        before = len(scanners)
        scanners = [
            s for s in scanners
            if aggregates.get(s, {}).get("repos_scored", 0) >= args.min_repos
        ]
        dropped = before - len(scanners)
        if dropped:
            print(f"Dropped {dropped} scanners with < {args.min_repos} repos")

    # Build outputs
    output_path = Path(args.output)
    detail_dir_name = "scanners"
    html = build_html(grid, scanners, aggregates, repos, detail_dir=detail_dir_name)
    report = build_json_report(grid, scanners, aggregates)

    # Write main dashboard
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
    print(f"HTML dashboard: {output_path}")

    # Write scanner detail pages
    scanner_detail_dir = output_path.parent / detail_dir_name
    scanner_detail_dir.mkdir(parents=True, exist_ok=True)
    for scanner in scanners:
        detail_html = build_scanner_detail_html(scanner, grid, repos, aggregates)
        detail_path = scanner_detail_dir / f"{scanner}.html"
        detail_path.write_text(detail_html)
    print(f"Scanner detail pages: {scanner_detail_dir}/ ({len(scanners)} pages)")

    json_path = Path(args.json)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"JSON report: {json_path}")

    # Print summary
    print()
    for scanner in scanners:
        sa = aggregates.get(scanner, {})
        micro = sa.get("micro", {})
        macro = sa.get("macro", {})
        n = sa.get("repos_scored", 0)
        print(
            f"  {scanner:<20} micro-F2={micro.get('f2_score', 0):>5.1f}  "
            f"macro-F2={macro.get('f2_score', 0):>5.1f}  "
            f"repos={n}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
