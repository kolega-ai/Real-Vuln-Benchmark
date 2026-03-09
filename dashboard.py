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
from parsers.semgrep import SemgrepParser
from scorer.matcher import load_ground_truth, match_findings
from scorer.metrics import compute_scorecard

BASELINE_SCANNERS = {"our-scanner", "semgrep", "snyk", "sonarqube"}

PROMPT_EVAL_DIR = SCRIPT_DIR.parent / "prompt_eval" / "results"

# Map prompt_eval short repo names -> realvuln GT directory names
PROMPT_EVAL_REPO_MAP = {
    "dvpwa": "realvuln-dvpwa",
    "vampi": "realvuln-VAmPI",
    "dsvw": "RealVuln-DSVW",
    "dvga": "Reavuln-Damn-Vulnerable-GraphQL-Application",
    "oss-oopssec-store": "realvuln-oss-oopssec-store",
    "pygoat": "realvuln-pygoat",
    "vulpy": "realvuln-vulpy",
    "vulnerable-flask-app": "realvuln-Vulnerable-Flask-App",
    "djangoat": "realvuln-DjanGoat",
    "vulnpy": "realvuln-vulnpy",
    "vulnerable-api": "realvuln-Vulnerable-API",
    "threatbyte": "realvuln-ThreatByte",
    "dvblab": "realvuln-DVBLab",
    "lets-be-bad-guys": "realvuln-lets-be-bad-guys",
    "dsvpwa": "realvuln-DSVPWA",
    "vulnerable-tornado-app": "realvuln-Vulnerable_Tornado_App",
    "vfapi": "realvuln-vfapi",
    "pythonssti": "realvuln-PythonSSTI",
    "python-insecure-app": "realvuln-python-insecure-app",
    "damn-vulnerable-flask": "realvuln-Damn-Vulnerable-Flask-Application",
    "extremely-vulnerable-flask": "realvuln-extremely-vulnerable-flask-app",
    "insecure-web": "realvuln-insecure-web",
    "owasp-web-playground": "realvuln-OWASP-Web-Playground-",
    "ivpa": "realvuln-Intentionally-Vulnerable-Python-Application",
    "python-app": "realvuln-python-app",
    "defdev-app": "realvuln-defdev-app",
    "flask-xss": "realvuln-Flask_XSS",
    "vulnerable-python-apps": "realvuln-Vulnerable_Python_Apps",
}


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


def _get_parser_safe(slug: str):
    """Get parser, falling back to SemgrepParser for unknown scanners."""
    try:
        return get_parser(slug)
    except ValueError:
        return SemgrepParser(scanner_slug=slug)


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

            parser = _get_parser_safe(scanner)
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
# Prompt eval integration
# ---------------------------------------------------------------------------

def load_prompt_eval_manifest(experiment_id: str) -> dict | None:
    """Load a prompt_eval manifest.json by experiment ID."""
    manifest_path = PROMPT_EVAL_DIR / experiment_id / "manifest.json"
    if not manifest_path.exists():
        return None
    with open(manifest_path) as f:
        return json.load(f)


def inject_prompt_eval(
    grid: dict[str, dict[str, dict | None]],
    experiment_ids: list[str],
) -> list[str]:
    """Load prompt_eval manifests and inject into grid.

    Returns list of scanner slugs added.
    """
    added_scanners: list[str] = []

    for eid in experiment_ids:
        manifest = load_prompt_eval_manifest(eid)
        if manifest is None:
            print(f"Warning: no manifest for prompt_eval '{eid}' at {PROMPT_EVAL_DIR / eid}", file=sys.stderr)
            continue

        scanner_slug = eid  # Use experiment ID as the scanner name
        added_scanners.append(scanner_slug)

        # Support both manifest formats:
        #   - "repos" as dict with per-category "totals" (run_eval format)
        #   - "repos_detail" as dict with flat tp/fp/fn (kimi format)
        repos_dict = manifest.get("repos", {})
        if isinstance(repos_dict, list):
            repos_dict = manifest.get("repos_detail", {})

        for short_repo, repo_data in repos_dict.items():
            gt_repo = PROMPT_EVAL_REPO_MAP.get(short_repo)
            if gt_repo is None:
                continue

            # Flat format (tp/fp/fn at top level) or nested (totals sub-dict)
            if "totals" in repo_data:
                totals = repo_data["totals"]
            else:
                totals = repo_data
            tp = totals.get("tp", 0)
            fp = totals.get("fp", 0)
            fn = totals.get("fn", 0)

            prec = _safe_div(tp, tp + fp)
            rec = _safe_div(tp, tp + fn)
            f2 = _safe_div(5.0 * prec * rec, 4.0 * prec + rec)

            cell = {
                "scanner": scanner_slug,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": 0,
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(_safe_div(2.0 * prec * rec, prec + rec), 4),
                "f2": round(f2, 4),
                "f2_score": round(f2 * 100, 1),
                "tpr": round(rec, 4),
                "fpr": 0.0,
                "youden_j": round(rec, 4),
                "per_family": {},
                "per_severity": {},
                "details": [],
            }

            if gt_repo not in grid:
                grid[gt_repo] = {}
            grid[gt_repo][scanner_slug] = cell

    return added_scanners


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

def build_html(
    grid: dict[str, dict[str, dict | None]],
    scanners: list[str],
    aggregates: dict[str, dict],
    repos: list[str],
) -> str:
    """Build standalone HTML dashboard."""
    total_repos = len(repos)
    total_scanners = len(scanners)

    # Build summary bar chart data
    chart_data = []
    for scanner in scanners:
        sa = aggregates.get(scanner, {})
        micro = sa.get("micro", {})
        chart_data.append({
            "label": scanner.replace("kolega.dev-", ""),
            "f2": micro.get("f2_score", 0),
            "recall": round(micro.get("recall", 0) * 100, 1),
            "precision": round(micro.get("precision", 0) * 100, 1),
            "tp": micro.get("tp", 0),
            "fp": micro.get("fp", 0),
            "fn": micro.get("fn", 0),
            "repos": sa.get("repos_scored", 0),
        })
    # Sort chart_data by F2 descending
    chart_data.sort(key=lambda x: x["f2"], reverse=True)

    lines: list[str] = []
    w = lines.append

    w("<!DOCTYPE html>")
    w('<html lang="en">')
    w("<head>")
    w('<meta charset="UTF-8">')
    w("<title>RealVuln Multi-Scanner Dashboard</title>")
    w("<style>")
    w("""
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  background: #0f172a; color: #e2e8f0; padding: 24px;
}
h1 { font-size: 24px; font-weight: 700; margin-bottom: 4px; }
h2 { font-size: 16px; font-weight: 600; margin: 28px 0 12px 0; color: #f8fafc; }
.subtitle { color: #94a3b8; font-size: 13px; margin-bottom: 24px; }

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

/* Bar charts */
.charts-grid {
  display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 28px;
}
@media (max-width: 900px) { .charts-grid { grid-template-columns: 1fr; } }
.chart-panel {
  background: #1e293b; border-radius: 8px; padding: 16px; border: 1px solid #334155;
}
.chart-panel h3 { font-size: 13px; font-weight: 600; margin-bottom: 12px; color: #f8fafc; }
.bar-chart { display: flex; flex-direction: column; gap: 6px; }
.bar-row { display: flex; align-items: center; gap: 8px; font-size: 11px; }
.bar-label { width: 120px; text-align: right; color: #94a3b8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 0; }
.bar-track { flex: 1; height: 20px; background: #0f172a; border-radius: 3px; position: relative; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 3px; transition: width 0.3s; display: flex; align-items: center; justify-content: flex-end; padding-right: 6px; }
.bar-fill span { font-size: 10px; font-weight: 700; color: #fff; text-shadow: 0 1px 2px rgba(0,0,0,0.5); }

/* TP/FP/FN stacked bar */
.stacked-bar { display: flex; height: 100%; border-radius: 3px; overflow: hidden; }
.stacked-bar .seg-tp { background: #16a34a; }
.stacked-bar .seg-fp { background: #dc2626; }
.stacked-bar .seg-fn { background: #ea580c; }
.stacked-legend { display: flex; gap: 12px; margin-top: 8px; font-size: 10px; color: #94a3b8; }
.stacked-legend .sl-dot { width: 8px; height: 8px; border-radius: 2px; display: inline-block; margin-right: 3px; }

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
""")
    w("</style>")
    w("</head>")
    w("<body>")
    w("<h1>RealVuln Multi-Scanner Dashboard</h1>")
    w(f'<div class="subtitle">{total_repos} repositories &middot; {total_scanners} scanners &middot; generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</div>')

    # ── Summary cards for best scanner ──
    best = chart_data[0] if chart_data else None
    if best:
        w('<div class="summary-cards">')
        w(f'<div class="summary-card"><div class="sc-label">Best Scanner (F2)</div><div class="sc-value" style="color:#3b82f6">{best["label"]}</div><div class="sc-sub">micro-F2 = {best["f2"]:.1f}</div></div>')
        w(f'<div class="summary-card"><div class="sc-label">Best F2</div><div class="sc-value" style="color:#16a34a">{best["f2"]:.1f}</div><div class="sc-sub">Recall {best["recall"]:.1f}% · Prec {best["precision"]:.1f}%</div></div>')
        total_gt = sum(d["tp"] + d["fn"] for d in chart_data[:1])
        w(f'<div class="summary-card"><div class="sc-label">Ground Truth</div><div class="sc-value">{total_gt}</div><div class="sc-sub">vulnerabilities across {best["repos"]} repos</div></div>')
        w(f'<div class="summary-card"><div class="sc-label">Scanners Compared</div><div class="sc-value">{total_scanners}</div><div class="sc-sub">incl. baselines & optimized</div></div>')
        w('</div>')

    # ── Plotly-based charts ──
    scatter_json = json.dumps(chart_data)
    bar_data_reversed = list(reversed(chart_data))
    bar_json = json.dumps(bar_data_reversed)

    w('<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>')

    # Precision-Recall scatter
    w('<h2>Precision vs Recall</h2>')
    w('<div id="pr-scatter" style="width:100%;height:520px;margin-bottom:28px"></div>')

    # Grouped bar: F2 / Recall / Precision
    w('<h2>Scanner Comparison (Micro-Averaged)</h2>')
    w('<div id="metric-bars" style="width:100%;height:400px;margin-bottom:28px"></div>')

    # TP/FP/FN stacked bar
    w('<h2>Finding Breakdown (TP / FP / FN)</h2>')
    w('<div id="finding-bars" style="width:100%;height:380px;margin-bottom:28px"></div>')

    # ── Heatmap with metric toggle ──
    w('<h2>Per-Repository Heatmap</h2>')
    w('<div class="metric-toggle">')
    w('<button class="active" data-metric="f2">F2 Score</button>')
    w('<button data-metric="recall">Recall</button>')
    w('<button data-metric="precision">Precision</button>')
    w('</div>')

    # Legend
    w('<div class="legend">')
    for label, color in [
        ("80-100", "#16a34a"), ("60-79", "#65a30d"), ("40-59", "#ca8a04"),
        ("20-39", "#ea580c"), ("0-19", "#dc2626"), ("No data", "#334155"),
    ]:
        w(f'  <div class="legend-item"><div class="legend-box" style="background:{color}"></div> {label}</div>')
    w("</div>")

    # Table — embed all three metrics as data attributes
    w('<div class="container">')
    w('<table id="dashboard-table">')

    # Header
    w("<thead><tr>")
    w('<th class="repo-name" data-col="repo">Repository <span class="sort-arrow"></span></th>')
    for i, scanner in enumerate(scanners):
        short = scanner.replace("kolega.dev-", "")
        w(f'<th data-col="{i}">{short} <span class="sort-arrow"></span></th>')
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

    # JavaScript: sort + metric toggle
    w("<script>")
    w("""
(function() {
  const table = document.getElementById('dashboard-table');
  const thead = table.querySelector('thead');
  const tbody = table.querySelector('tbody');
  let sortCol = null;
  let sortAsc = true;
  let currentMetric = 'f2';

  // Color mapping
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

  // Metric toggle
  document.querySelector('.metric-toggle').addEventListener('click', function(e) {
    const btn = e.target.closest('button');
    if (!btn) return;
    currentMetric = btn.dataset.metric;
    document.querySelectorAll('.metric-toggle button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    updateCells();
  });

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

  // Sort
  thead.addEventListener('click', function(e) {
    const th = e.target.closest('th');
    if (!th) return;
    const col = th.dataset.col;
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
""")

    # Plotly charts JS
    w("</script>")
    w("<script>")
    w(f"const chartData = {scatter_json};")
    w(f"const barData = {bar_json};")
    w("""
(function() {
  const darkBg = '#0f172a';
  const panelBg = '#1e293b';
  const gridColor = '#334155';
  const textColor = '#e2e8f0';
  const mutedText = '#94a3b8';
  const colors = ['#3b82f6','#10b981','#a855f7','#f59e0b','#ec4899','#06b6d4','#ef4444','#84cc16','#f97316','#14b8a6'];

  // ── 1. Precision-Recall Scatter with F2 iso-lines ──
  const scatterTraces = [];

  // F2 iso-lines
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

  // Scanner points
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

  // Add F2 iso-line annotations
  const annotations = f2Vals.map(f2v => {
    const f2 = f2v / 100;
    // Find a good position for label near right edge
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

  Plotly.newPlot('pr-scatter', scatterTraces, {
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
})();
""")
    w("</script>")
    w("</body></html>")

    return "\n".join(lines)


def _build_tooltip_html(repo: str, scanner: str, cell: dict) -> str:
    """Build tooltip div for a cell."""
    short_repo = repo.replace("realvuln-", "").replace("Reavuln-", "").replace("RealVuln-", "")
    short_scanner = scanner.replace("kolega.dev-", "")
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
        "--prompt-eval",
        nargs="+",
        default=[],
        metavar="EXPERIMENT_ID",
        help="Include prompt_eval experiments (e.g. baseline-sonnet baseline-haiku)",
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

    # Inject prompt_eval experiments
    if args.prompt_eval:
        pe_scanners = inject_prompt_eval(grid, args.prompt_eval)
        scanners = scanners + pe_scanners
        # Add any repos that only exist in prompt_eval to the repo list
        for repo in grid:
            if repo not in repos:
                repos.append(repo)
        repos.sort()
        print(f"Added {len(pe_scanners)} prompt_eval experiments: {', '.join(pe_scanners)}")

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
    html = build_html(grid, scanners, aggregates, repos)
    report = build_json_report(grid, scanners, aggregates)

    # Write
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
    print(f"HTML dashboard: {output_path}")

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
