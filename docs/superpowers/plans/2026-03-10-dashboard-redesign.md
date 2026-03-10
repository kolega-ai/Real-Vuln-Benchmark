# Dashboard Redesign Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the RealVuln dashboard with Kolega Comply design system — leaderboard-first main page, analytical scanner detail pages.

**Architecture:** Single-file modification to `dashboard.py`. Replace CSS, rebuild HTML generation functions, add CWE coverage aggregation. Keep all existing data pipeline (scoring, aggregation, Plotly) intact.

**Tech Stack:** Python, Plotly.js, HTML/CSS (Google Fonts: Space Grotesk, Inter, Source Code Pro)

**Spec:** `docs/superpowers/specs/2026-03-10-dashboard-redesign-design.md`
**Mockup:** `.superpowers/brainstorm/19569-1773125930/dashboard-mockup-v3.html`

---

## Chunk 1: CSS and Theme Foundation

### Task 1: Replace `_common_css()` with Kolega Comply theme

**Files:**
- Modify: `dashboard.py:208-321` (`_common_css()` function)

- [ ] **Step 1: Replace the CSS custom properties and base styles**

Replace the entire `_common_css()` function body with Kolega Comply tokens. Key changes:
- Google Fonts import for Space Grotesk, Inter, Source Code Pro
- CSS custom properties using Kolega tokens (`--bg-primary: #000000`, `--bg-secondary: #171717`, etc.)
- `body` uses `font-family: 'Inter'`, `background: var(--bg-primary)`, `max-width: 1152px`, `margin: 0 auto`
- `h1, h2, h3` use `font-family: 'Space Grotesk'`
- Cards use `border-radius: 16px`, borders use `var(--border-secondary)`
- Score color scale: `--score-great: #22c55e`, `--score-good: #84cc16`, `--score-ok: #eab308`, `--score-poor: #f97316`, `--score-bad: #ef4444`

Full CSS to write (replacing existing `_common_css` return value):

```python
def _common_css() -> str:
    """Shared CSS — Kolega Comply design system."""
    return """
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;500;600;700&family=Source+Code+Pro:wght@400;500;600&display=swap');

:root {
  --bg-primary: #000000;
  --bg-secondary: #171717;
  --bg-tertiary: #262626;
  --text-primary: #FFFFFF;
  --text-secondary: #B3B3B3;
  --text-tertiary: #808080;
  --text-muted: #666666;
  --border-primary: #404040;
  --border-secondary: #262626;
  --accent-lime: #C4F03E;
  --accent-lime-dark: #ADDD30;
  --accent-purple: #7E22CE;
  --accent-purple-light: #A076F9;
  --hover-bg: #262626;
  --score-great: #22c55e;
  --score-good: #84cc16;
  --score-ok: #eab308;
  --score-poor: #f97316;
  --score-bad: #ef4444;
}

* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  background: var(--bg-primary); color: var(--text-primary);
  line-height: 1.5; font-size: 14px;
  max-width: 1152px; margin: 0 auto; padding: 32px 24px;
}
h1, h2, h3 { font-family: 'Space Grotesk', sans-serif; }
a { color: var(--accent-lime); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Page header */
.page-header { margin-bottom: 32px; }
.page-header h1 {
  font-size: 28px; font-weight: 700; display: flex; align-items: center; gap: 12px;
  letter-spacing: -0.02em; margin-bottom: 6px;
}
.badge {
  font-family: 'Inter', sans-serif;
  background: var(--accent-lime); color: #000; font-size: 11px;
  font-weight: 600; padding: 2px 10px; border-radius: 6px;
  text-transform: uppercase; letter-spacing: 0.05em;
}
.subtitle { font-size: 14px; color: var(--text-secondary); }
.back-link { display: inline-block; margin-bottom: 16px; font-size: 13px; color: var(--accent-lime); }

/* Section titles */
.section-title {
  font-family: 'Space Grotesk', sans-serif;
  font-size: 20px; font-weight: 600; margin-bottom: 16px;
  display: flex; align-items: baseline; gap: 10px;
}
.section-title .dim {
  font-family: 'Inter', sans-serif;
  color: var(--text-tertiary); font-weight: 400; font-size: 13px;
}

/* Hero stat cards */
.hero-stats {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px; margin-bottom: 32px;
}
.stat-card {
  background: var(--bg-secondary); border: 1px solid var(--border-secondary);
  border-radius: 16px; padding: 20px;
  display: flex; align-items: center; gap: 14px;
}
.stat-icon {
  width: 40px; height: 40px; border-radius: 8px;
  display: flex; align-items: center; justify-content: center; font-size: 18px;
}
.stat-value {
  font-family: 'Space Grotesk', sans-serif;
  font-size: 24px; font-weight: 700;
}
.stat-label { font-size: 12px; color: var(--text-secondary); font-weight: 500; }

/* Leaderboard */
.leaderboard { margin-bottom: 32px; }
.lb-row {
  display: flex; align-items: center; gap: 16px;
  padding: 16px 20px; background: var(--bg-secondary);
  border: 1px solid var(--border-secondary); border-radius: 16px;
  margin-bottom: 8px; cursor: pointer; transition: all 0.3s;
  text-decoration: none; color: var(--text-primary);
}
.lb-row:hover {
  border-color: var(--border-primary); background: var(--hover-bg);
  box-shadow: 0 4px 16px rgba(0,0,0,0.3); text-decoration: none;
}
.lb-row.first { border-color: var(--accent-lime-dark); }
.lb-row.first:hover { border-color: var(--accent-lime); background: rgba(196,240,62,0.04); }
.lb-rank {
  font-family: 'Space Grotesk', sans-serif;
  font-size: 14px; font-weight: 700; width: 28px; text-align: center;
  color: var(--text-muted);
}
.lb-row.first .lb-rank { color: var(--accent-lime); }
.lb-name {
  font-family: 'Space Grotesk', sans-serif;
  font-size: 14px; font-weight: 600; width: 240px; flex-shrink: 0;
}
.lb-bar-wrap { flex: 1; }
.lb-bar-track {
  height: 24px; background: var(--bg-tertiary); border-radius: 6px; overflow: hidden;
}
.lb-bar-fill { height: 100%; border-radius: 6px; transition: width 0.5s ease; }
.lb-score {
  font-family: 'Space Grotesk', sans-serif;
  font-size: 22px; font-weight: 700; width: 60px; text-align: right;
  font-variant-numeric: tabular-nums;
}
.lb-meta {
  font-size: 12px; color: var(--text-tertiary); width: 190px;
  font-variant-numeric: tabular-nums;
}
.lb-meta strong { color: var(--text-secondary); font-weight: 500; }
.lb-arrow { color: var(--text-muted); font-size: 20px; transition: color 0.15s; }
.lb-row:hover .lb-arrow { color: var(--accent-lime); }

/* Chart card container */
.chart-card {
  background: var(--bg-secondary); border: 1px solid var(--border-secondary);
  border-radius: 16px; padding: 24px; margin-bottom: 32px;
}

/* Finding breakdown bars */
.fb-section { margin-bottom: 32px; }
.fb-legend { display: flex; gap: 20px; margin-bottom: 14px; }
.fb-legend-item {
  display: flex; align-items: center; gap: 6px;
  font-size: 12px; color: var(--text-tertiary); font-weight: 500;
}
.fb-legend-dot { width: 10px; height: 10px; border-radius: 3px; }
.fb-row { display: flex; align-items: center; gap: 14px; margin-bottom: 8px; }
.fb-label {
  width: 200px; text-align: right; font-size: 13px;
  color: var(--text-secondary); font-weight: 500; flex-shrink: 0;
}
.fb-track {
  flex: 1; height: 22px; display: flex; border-radius: 4px;
  overflow: hidden; background: var(--bg-tertiary);
}
.fb-seg-tp { background: var(--score-great); }
.fb-seg-fp { background: var(--score-bad); }
.fb-seg-fn { background: var(--score-poor); opacity: 0.7; }
.fb-counts {
  font-size: 11px; color: var(--text-muted); width: 120px;
  font-variant-numeric: tabular-nums;
}

/* CWE coverage cards */
.cwe-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 10px; margin-bottom: 32px;
}
.cwe-card {
  background: var(--bg-secondary); border: 1px solid var(--border-secondary);
  border-radius: 12px; padding: 16px; transition: all 0.3s;
}
.cwe-card:hover { border-color: var(--border-primary); box-shadow: 0 4px 16px rgba(0,0,0,0.3); }
.cwe-name {
  font-family: 'Space Grotesk', sans-serif;
  font-size: 13px; font-weight: 600; margin-bottom: 4px;
}
.cwe-stat { font-size: 11px; color: var(--text-tertiary); margin-bottom: 10px; }
.cwe-bar { height: 4px; background: var(--bg-tertiary); border-radius: 2px; overflow: hidden; }
.cwe-bar-fill { height: 100%; border-radius: 2px; }

/* Heatmap table */
.heatmap-wrap {
  background: var(--bg-secondary); border: 1px solid var(--border-secondary);
  border-radius: 16px; overflow: hidden; margin-bottom: 32px;
}
.heatmap-table { border-collapse: collapse; width: 100%; font-size: 12px; }
.heatmap-table thead th {
  padding: 12px 10px; font-size: 11px; color: var(--text-tertiary);
  font-weight: 500; text-transform: uppercase; letter-spacing: 0.04em;
  text-align: center; white-space: nowrap;
  border-bottom: 1px solid var(--border-secondary); cursor: pointer; user-select: none;
}
.heatmap-table thead th:first-child { text-align: left; padding-left: 20px; }
.heatmap-table thead th:hover { color: var(--text-secondary); }
.heatmap-table thead th .sort-arrow { font-size: 10px; margin-left: 3px; color: var(--text-muted); }
.heatmap-table tbody tr {
  border-bottom: 1px solid var(--border-secondary); transition: background 0.15s;
}
.heatmap-table tbody tr:last-child { border-bottom: none; }
.heatmap-table tbody tr:hover { background: var(--hover-bg); }
.heatmap-table td {
  padding: 10px; text-align: center; font-weight: 600; font-variant-numeric: tabular-nums;
}
.heatmap-table td:first-child {
  text-align: left; padding-left: 20px;
  font-family: 'Source Code Pro', monospace; font-size: 12px;
  color: var(--text-secondary); font-weight: 500;
}
.hm-cell {
  display: inline-block; min-width: 44px; padding: 3px 8px;
  border-radius: 6px; font-size: 11px;
}

/* Metric toggle */
.metric-toggle {
  display: inline-flex; gap: 0; margin-bottom: 12px; border-radius: 8px; overflow: hidden;
  border: 1px solid var(--border-primary);
}
.metric-toggle button {
  background: var(--bg-secondary); color: var(--text-tertiary); border: none;
  padding: 6px 16px; font-size: 12px; cursor: pointer; font-weight: 500;
  font-family: 'Inter', sans-serif; transition: all 0.15s;
}
.metric-toggle button:hover { background: var(--bg-tertiary); }
.metric-toggle button.active { background: var(--accent-lime); color: #000; }

/* Tooltip */
.tooltip {
  display: none; position: absolute; z-index: 100;
  background: var(--bg-secondary); border: 1px solid var(--border-primary); border-radius: 12px;
  padding: 12px 16px; font-size: 11px; text-align: left;
  white-space: pre-line; min-width: 200px;
  box-shadow: 0 4px 16px rgba(0,0,0,0.4); pointer-events: none;
  left: 50%; transform: translateX(-50%); top: 100%;
}
.cell:hover .tooltip { display: block; }
.tooltip .tt-title { font-weight: 700; font-size: 12px; margin-bottom: 6px; font-family: 'Space Grotesk', sans-serif; }
.tooltip .tt-row { display: flex; justify-content: space-between; gap: 16px; }
.tooltip .tt-label { color: var(--text-tertiary); }
.tooltip .tt-val { font-weight: 600; }
.tooltip .tt-sep { border-top: 1px solid var(--border-secondary); margin: 4px 0; }

/* Scanner detail page extras */
.severity-card {
  background: var(--bg-secondary); border-radius: 12px; padding: 16px;
  border: 1px solid var(--border-secondary);
  display: inline-block; min-width: 140px; text-align: center; margin: 0 8px 8px 0;
}
.severity-card .sev-label {
  font-size: 11px; color: var(--text-tertiary); text-transform: uppercase; margin-bottom: 4px;
}
.severity-card .sev-recall {
  font-family: 'Space Grotesk', sans-serif; font-size: 24px; font-weight: 700;
}
.severity-card .sev-counts { font-size: 11px; color: var(--text-muted); margin-top: 4px; }

/* Footer */
.page-footer {
  text-align: center; padding: 32px 0; margin-top: 16px;
  border-top: 1px solid var(--border-secondary); font-size: 12px; color: var(--text-muted);
}
.page-footer a { color: var(--text-tertiary); }
.page-footer a:hover { color: var(--accent-lime); }
"""
```

- [ ] **Step 2: Update `f2_color()` and `f2_text_color()` to use new score colors**

```python
def f2_color(score: float | None) -> str:
    """Map F2 score to a background color."""
    if score is None:
        return "#262626"      # tertiary bg — no data
    if score >= 80:
        return "#16a34a"      # great (green-600)
    if score >= 60:
        return "#65a30d"      # good (lime-600)
    if score >= 40:
        return "#a16207"      # ok (amber-700)
    if score >= 20:
        return "#c2410c"      # poor (orange-700)
    return "#b91c1c"          # bad (red-700)


def f2_text_color(score: float | None) -> str:
    """Text color for readability on the background."""
    if score is None:
        return "#666666"      # text-muted
    return "#fff"
```

- [ ] **Step 3: Update `_plotly_theme_js()` to use Kolega tokens**

```python
def _plotly_theme_js() -> str:
    """Shared Plotly theme constants — Kolega Comply."""
    return """
  const darkBg = '#000000';
  const panelBg = '#171717';
  const gridColor = '#262626';
  const textColor = '#B3B3B3';
  const mutedText = '#808080';
  const colors = ['#C4F03E','#22c55e','#A076F9','#f59e0b','#ec4899','#06b6d4','#ef4444','#84cc16','#f97316','#14b8a6'];
"""
```

- [ ] **Step 4: Run dashboard generation to verify CSS compiles**

Run: `python dashboard.py --scanner-group all 2>&1 | head -5`
Expected: "Scoring N repos x N scanners..." (no Python errors)

- [ ] **Step 5: Commit**

```bash
git add dashboard.py
git commit -m "feat(dashboard): replace CSS with Kolega Comply design system"
```

---

## Chunk 2: Main Dashboard HTML Rebuild

### Task 2: Rebuild `build_html()` — header, hero stats, leaderboard

**Files:**
- Modify: `dashboard.py:441-724` (`build_html()` function)

- [ ] **Step 1: Replace the header and summary cards HTML**

In `build_html()`, replace the existing header (`<h1>`, `.subtitle`, `.summary-cards`) with:

```python
w("<body>")
w('<div class="page-header">')
w('<h1>RealVuln Benchmark <span class="badge">Open Source</span></h1>')
w(f'<div class="subtitle">Security scanner evaluation against ground-truth vulnerabilities in real-world Python code</div>')
w('</div>')
```

- [ ] **Step 2: Replace summary cards with hero stats grid**

Replace the existing summary-cards block with 4 stat cards using the Kolega pattern:

```python
# Hero stats
w('<div class="hero-stats">')
w(f'<div class="stat-card"><div class="stat-icon" style="background:rgba(239,68,68,0.1);color:#ef4444">&#9888;</div><div><div class="stat-value" style="color:#ef4444">{gt_total_vulns}</div><div class="stat-label">Vulnerabilities</div></div></div>')
w(f'<div class="stat-card"><div class="stat-icon" style="background:rgba(234,179,8,0.1);color:#eab308">&#9678;</div><div><div class="stat-value" style="color:#eab308">{gt_total_traps}</div><div class="stat-label">FP Traps</div></div></div>')
w(f'<div class="stat-card"><div class="stat-icon" style="background:rgba(168,85,247,0.1);color:#A076F9">&#9881;</div><div><div class="stat-value" style="color:#A076F9">{gt_total_repos}</div><div class="stat-label">Repositories</div></div></div>')
w(f'<div class="stat-card"><div class="stat-icon" style="background:rgba(196,240,62,0.1);color:#C4F03E">&#9733;</div><div><div class="stat-value" style="color:#C4F03E">{total_scanners}</div><div class="stat-label">Scanners Tested</div></div></div>')
w('</div>')
```

Note: This requires adding `gt_total_traps` parameter to `build_html()`. Add it alongside the existing `gt_total_vulns` parameter.

- [ ] **Step 3: Replace scanner-directory cards with leaderboard**

Remove the entire `Scanner Directory` section (`scanner-directory` div with `scanner-card` elements). Replace with:

```python
# Leaderboard
w('<div class="leaderboard">')
w('<div class="section-title">Scanner Leaderboard <span class="dim">ranked by F2 Score</span></div>')
for rank, d in enumerate(chart_data, 1):
    row_class = "lb-row first" if rank == 1 else "lb-row"
    score_color = f2_color(d["f2"])
    bar_gradient = f"linear-gradient(90deg,{score_color},{score_color}88)"
    w(f'<a href="{detail_dir}/{d["slug"]}.html" class="{row_class}">')
    w(f'  <div class="lb-rank">{rank}</div>')
    w(f'  <div class="lb-name">{d["label"]}</div>')
    w(f'  <div class="lb-bar-wrap"><div class="lb-bar-track"><div class="lb-bar-fill" style="width:{d["f2"]}%;background:{bar_gradient}"></div></div></div>')
    w(f'  <div class="lb-score" style="color:{score_color}">{d["f2"]:.1f}</div>')
    w(f'  <div class="lb-meta"><strong>{d["recall"]:.1f}%</strong> recall &middot; <strong>{d["precision"]:.1f}%</strong> prec</div>')
    w(f'  <div class="lb-arrow">&rsaquo;</div>')
    w(f'</a>')
w('</div>')
```

- [ ] **Step 4: Update `build_html` signature to accept `gt_total_traps`**

Add `gt_total_traps: int = 0` parameter. In `main()`, compute it alongside `gt_total_vulns`:

```python
gt_total_traps = 0
# Inside the existing loop:
gt_total_traps += sum(1 for f in gt_data["findings"] if not f["is_vulnerable"])
```

Pass it to `build_html()`.

- [ ] **Step 5: Run and verify**

Run: `python dashboard.py --scanner-group all`
Open `reports/dashboard.html` in browser. Verify header, stats, and leaderboard render.

- [ ] **Step 6: Commit**

```bash
git add dashboard.py
git commit -m "feat(dashboard): add hero stats and leaderboard sections"
```

### Task 3: Rebuild scatter, TP/FP/FN bars, and heatmap sections

**Files:**
- Modify: `dashboard.py:441-724` (`build_html()` continued)

- [ ] **Step 1: Wrap Plotly scatter in chart-card container**

Replace the existing scatter section:

```python
w('<div class="section-title">Precision vs Recall <span class="dim">each dot is a scanner &middot; dashed lines are F2 iso-curves</span></div>')
w('<div class="chart-card">')
w('<div id="pr-scatter" style="width:100%;height:420px"></div>')
w('</div>')
```

- [ ] **Step 2: Replace Plotly TP/FP/FN bars with pure HTML/CSS bars**

Remove the existing `Finding Breakdown` Plotly chart div and its JS. Replace with static HTML bars:

```python
# Finding breakdown — pure HTML
w('<div class="fb-section">')
w('<div class="section-title">Finding Breakdown <span class="dim">TP / FP / FN per scanner</span></div>')
w('<div class="fb-legend">')
w('<div class="fb-legend-item"><div class="fb-legend-dot" style="background:var(--score-great)"></div> True Positives</div>')
w('<div class="fb-legend-item"><div class="fb-legend-dot" style="background:var(--score-bad)"></div> False Positives</div>')
w('<div class="fb-legend-item"><div class="fb-legend-dot" style="background:var(--score-poor);opacity:0.7"></div> False Negatives</div>')
w('</div>')
for d in chart_data:
    total = d["tp"] + d["fp"] + d["fn"]
    if total == 0:
        total = 1
    tp_pct = d["tp"] / total * 100
    fp_pct = d["fp"] / total * 100
    fn_pct = d["fn"] / total * 100
    w(f'<div class="fb-row">')
    w(f'  <div class="fb-label">{d["label"]}</div>')
    w(f'  <div class="fb-track"><div class="fb-seg-tp" style="width:{tp_pct:.1f}%"></div><div class="fb-seg-fp" style="width:{fp_pct:.1f}%"></div><div class="fb-seg-fn" style="width:{fn_pct:.1f}%"></div></div>')
    w(f'  <div class="fb-counts">{d["tp"]} / {d["fp"]} / {d["fn"]}</div>')
    w(f'</div>')
w('</div>')
```

- [ ] **Step 3: Replace Plotly metric-bars JS**

Remove the `metric-bars` Plotly chart div and its JS block (the grouped horizontal bar chart). This is replaced by the HTML bars above.

- [ ] **Step 4: Wrap heatmap table in new container**

Replace the existing heatmap container markup. Change `<div class="container">` and `<table id="dashboard-table">` to:

```python
w('<div class="section-title">Per-Repository Heatmap <span class="dim">F2 Score &middot; click headers to sort</span></div>')
# metric toggle stays the same
w('<div class="heatmap-wrap">')
w('<table class="heatmap-table" id="dashboard-table">')
```

Update cell rendering to use `hm-cell` spans:

```python
# In the cell rendering loop, wrap values in hm-cell spans:
# For cells with data:
hm_class = _hm_class(f2_val)
w(f'<td class="cell" data-f2="{f2_val}" data-recall="{rec_val}" data-precision="{prec_val}"><span class="hm-cell {hm_class}">{f2_val:.1f}</span>{tooltip}</td>')
# For empty cells:
w(f'<td class="cell" data-f2="" data-recall="" data-precision=""><span class="hm-cell" style="background:var(--bg-tertiary);color:var(--text-muted)">&mdash;</span></td>')
```

Add helper function:

```python
def _hm_class(score: float | None) -> str:
    """Return CSS class for heatmap cell."""
    if score is None:
        return ""
    if score >= 80:
        return "hm-great"
    if score >= 60:
        return "hm-good"
    if score >= 40:
        return "hm-ok"
    if score >= 20:
        return "hm-poor"
    return "hm-bad"
```

- [ ] **Step 5: Add footer**

Replace the closing `</body></html>` with:

```python
w('<div class="page-footer">')
w(f'RealVuln Benchmark &middot; Generated {datetime.now(timezone.utc).strftime("%Y-%m-%d")} &middot; <a href="https://github.com/nicksavill/RealVulnBenchmark">GitHub</a> &middot; <a href="https://kolega.dev">kolega.dev</a>')
w('</div>')
w("</body></html>")
```

- [ ] **Step 6: Update metric toggle JS for new cell structure**

In `_metric_toggle_sort_js()`, update the `updateCells` function to work with `hm-cell` spans instead of `cell-inner` spans. Change `td.querySelector('.cell-inner')` to `td.querySelector('.hm-cell')` and update the color function to use the new score colors.

- [ ] **Step 7: Run and verify**

Run: `python dashboard.py --scanner-group all`
Open `reports/dashboard.html`. Verify all sections render correctly.

- [ ] **Step 8: Commit**

```bash
git add dashboard.py
git commit -m "feat(dashboard): rebuild scatter, finding bars, and heatmap with Kolega styling"
```

### Task 4: Add CWE Detection Coverage section

**Files:**
- Modify: `dashboard.py` — `build_html()` function and `compute_aggregates()` or new helper

- [ ] **Step 1: Add CWE family aggregation helper**

Add a new function after `compute_aggregates()`:

```python
def compute_cwe_coverage(
    grid: dict[str, dict[str, dict | None]],
    scanners: list[str],
    cwe_families: dict,
) -> list[dict]:
    """Compute per-CWE-family detection stats across all scanners.

    Returns list of {family, label, scanners_detecting, total_scanners,
    avg_recall, total_tp, total_fn} sorted by avg_recall descending.
    """
    family_stats: dict[str, dict] = {}

    for scanner in scanners:
        for repo in grid:
            cell = grid[repo].get(scanner)
            if cell is None:
                continue
            for fam_slug, fam_info in cell.get("per_family", {}).items():
                if fam_slug not in family_stats:
                    # Look up display label from cwe_families config
                    label = fam_slug.replace("_", " ").title()
                    for fam_key, fam_val in cwe_families.items():
                        if fam_key == fam_slug:
                            label = fam_val.get("label", label)
                            break
                    family_stats[fam_slug] = {
                        "family": fam_slug,
                        "label": label,
                        "scanner_tp": {},  # scanner -> total_tp
                        "total_tp": 0,
                        "total_fn": 0,
                    }
                fs = family_stats[fam_slug]
                fs["total_tp"] += fam_info["tp"]
                fs["total_fn"] += fam_info["fn"]
                if fam_info["tp"] > 0:
                    fs["scanner_tp"][scanner] = fs["scanner_tp"].get(scanner, 0) + fam_info["tp"]

    result = []
    total_scanners = len(scanners)
    for fs in family_stats.values():
        total = fs["total_tp"] + fs["total_fn"]
        avg_recall = fs["total_tp"] / total if total > 0 else 0
        result.append({
            "family": fs["family"],
            "label": fs["label"],
            "scanners_detecting": len(fs["scanner_tp"]),
            "total_scanners": total_scanners,
            "avg_recall": round(avg_recall * 100, 1),
            "total_tp": fs["total_tp"],
            "total_fn": fs["total_fn"],
        })

    result.sort(key=lambda x: x["avg_recall"], reverse=True)
    return result
```

- [ ] **Step 2: Call the helper and render CWE cards in `build_html()`**

After the finding breakdown section and before the heatmap, add:

```python
# CWE Detection Coverage
cwe_coverage = compute_cwe_coverage(grid, scanners, cwe_families)
if cwe_coverage:
    w('<div class="section-title">CWE Detection Coverage <span class="dim">across all scanners</span></div>')
    w('<div class="cwe-grid">')
    for cwe in cwe_coverage:
        bar_color = f2_color(cwe["avg_recall"])
        w(f'<div class="cwe-card">')
        w(f'  <div class="cwe-name">{cwe["label"]}</div>')
        w(f'  <div class="cwe-stat">{cwe["scanners_detecting"]}/{cwe["total_scanners"]} scanners &middot; {cwe["avg_recall"]:.0f}% avg recall</div>')
        w(f'  <div class="cwe-bar"><div class="cwe-bar-fill" style="width:{cwe["avg_recall"]}%;background:{bar_color}"></div></div>')
        w(f'</div>')
    w('</div>')
```

This requires passing `cwe_families` to `build_html()`. Add it as a parameter.

- [ ] **Step 3: Update `build_html()` signature and `main()` call**

Add `cwe_families: dict = None` parameter to `build_html()`. Pass `cwe_families` from `main()`.

- [ ] **Step 4: Run and verify**

Run: `python dashboard.py --scanner-group all`
Open `reports/dashboard.html`. Verify CWE coverage cards render between finding bars and heatmap.

- [ ] **Step 5: Commit**

```bash
git add dashboard.py
git commit -m "feat(dashboard): add CWE detection coverage section"
```

---

## Chunk 3: Scanner Detail Pages Restyle

### Task 5: Restyle `build_scanner_detail_html()` to match Kolega theme

**Files:**
- Modify: `dashboard.py:731-1040` (`build_scanner_detail_html()`)

- [ ] **Step 1: Update header and summary cards**

Replace the existing header markup with the new pattern:

```python
w("<body>")
w('<a href="../dashboard.html" class="back-link">&larr; Back to Dashboard</a>')
w('<div class="page-header">')
w(f'<h1>{display_name(scanner)}</h1>')
w(f'<div class="subtitle">Scanner detail &middot; {repos_scored} repositories scored &middot; generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</div>')
w('</div>')
```

Update summary cards to use `stat-card` pattern (same as hero stats but with F2, Recall, Precision, Repos Scored).

- [ ] **Step 2: Update section headings to use `section-title` class**

Replace all `<h2>` tags with:

```python
w('<div class="section-title">Section Name <span class="dim">context</span></div>')
```

- [ ] **Step 3: Update the per-repo scores table**

Change from `<table id="dashboard-table">` with `cell` / `cell-inner` to the new `heatmap-table` / `hm-cell` pattern. Wrap in `heatmap-wrap` div.

- [ ] **Step 4: Update severity cards to use new styling**

The CSS already has `.severity-card` in the new style. Just verify the HTML markup matches.

- [ ] **Step 5: Update CWE family heatmap table**

Same as main page heatmap — wrap in `heatmap-wrap`, use `heatmap-table` class, `hm-cell` spans.

- [ ] **Step 6: Add footer**

```python
w('<div class="page-footer">')
w(f'RealVuln Benchmark &middot; <a href="https://kolega.dev">kolega.dev</a>')
w('</div>')
w("</body></html>")
```

- [ ] **Step 7: Run and verify**

Run: `python dashboard.py --scanner-group all`
Open a scanner detail page in browser (e.g., `reports/scanners/semgrep.html`). Verify all sections render.

- [ ] **Step 8: Commit**

```bash
git add dashboard.py
git commit -m "feat(dashboard): restyle scanner detail pages with Kolega theme"
```

---

## Chunk 4: Cleanup and Polish

### Task 6: Remove dead code and verify

**Files:**
- Modify: `dashboard.py`

- [ ] **Step 1: Remove unused `_legend_html()` function**

The old color legend is no longer used (heatmap cells are self-explanatory with the color scale). Remove `_legend_html()` and any calls to it.

- [ ] **Step 2: Remove the old Plotly `finding-bars` and `metric-bars` JS**

Since TP/FP/FN bars are now pure HTML, remove the Plotly JS blocks that rendered `finding-bars` and `metric-bars` divs.

- [ ] **Step 3: Run full generation and verify both page types**

Run: `python dashboard.py --scanner-group all`
Open `reports/dashboard.html` and at least 2 scanner detail pages. Verify:
- All 6 main page sections render
- Leaderboard click-through works
- Scatter chart is interactive
- Heatmap metric toggle works
- Heatmap column sorting works
- Tooltips appear on hover
- Scanner detail pages render all sections

- [ ] **Step 4: Run existing tests**

Run: `pytest -v`
Expected: All tests pass (no test changes needed — tests cover scorer/matcher/parsers, not HTML)

- [ ] **Step 5: Commit**

```bash
git add dashboard.py
git commit -m "refactor(dashboard): remove dead code from pre-redesign"
```

### Task 7: Regenerate and commit dashboard artifacts

**Files:**
- Regenerate: `reports/dashboard.html`, `reports/dashboard.json`

- [ ] **Step 1: Regenerate dashboard**

Run: `python dashboard.py --scanner-group all`

- [ ] **Step 2: Verify output**

Open `reports/dashboard.html` in browser for final visual check.

- [ ] **Step 3: Commit artifacts**

```bash
git add reports/dashboard.html reports/dashboard.json
git commit -m "chore: regenerate dashboard with Kolega Comply redesign"
```
