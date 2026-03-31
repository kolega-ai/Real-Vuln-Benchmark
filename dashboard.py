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
import fnmatch
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from parsers import get_parser
from scorer.matcher import load_ground_truth, match_findings
from scorer.metrics import compute_scorecard

BASELINE_SCANNERS = {"semgrep", "snyk", "sonarqube"}

# Display-friendly names for scanner slugs
SCANNER_DISPLAY_NAMES: dict[str, str] = {
    "our-scanner-manual-opt-opus-4.6": "our-scanner manual opt opus 4.6",
}


def display_name(scanner: str) -> str:
    """Return display name for a scanner slug."""
    return SCANNER_DISPLAY_NAMES.get(scanner, scanner)


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
    """Find JSON result files for a scanner.

    Excludes .metrics.json files (operational metrics from LLM benchmark runs).
    """
    if not scanner_dir.is_dir():
        return []
    return sorted(
        f for f in scanner_dir.glob("*.json")
        if not f.name.endswith(".metrics.json")
    )


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
                run_dicts: list[dict] = []
                for rf in result_files:
                    findings = parser.parse(str(rf))
                    results = match_findings(findings, ground_truth)
                    card = compute_scorecard(
                        repo_id, scanner, timestamp, results, cwe_families
                    )
                    run_dicts.append(card.to_dict())

                if len(run_dicts) == 1:
                    cell = run_dicts[0]
                    cell["_run_f2_scores"] = [cell["f2_score"]]
                    cell["_num_runs"] = 1
                else:
                    # Average core metrics across runs
                    cell = dict(run_dicts[0])  # copy structure
                    for key in ("tp", "fp", "fn", "tn"):
                        cell[key] = round(statistics.mean(
                            [rd[key] for rd in run_dicts]
                        ))
                    for key in ("precision", "recall", "f1", "f2", "f3",
                                "tpr", "fpr", "youden_j"):
                        cell[key] = round(statistics.mean(
                            [rd[key] for rd in run_dicts]
                        ), 4)
                    cell["f2_score"] = round(statistics.mean(
                        [rd["f2_score"] for rd in run_dicts]
                    ), 1)
                    cell["f3_score"] = round(statistics.mean(
                        [rd["f3_score"] for rd in run_dicts]
                    ), 1)
                    # Keep per_family / per_severity from first run
                    cell["per_family"] = run_dicts[0].get("per_family", {})
                    cell["per_severity"] = run_dicts[0].get("per_severity", {})
                    cell["_run_f2_scores"] = [rd["f2_score"] for rd in run_dicts]
                    cell["_num_runs"] = len(run_dicts)

                grid[repo][scanner] = cell
            except Exception as e:
                print(f"Warning: Failed to score {repo}/{scanner}: {e}", file=sys.stderr)
                grid[repo][scanner] = None

    return grid


# ---------------------------------------------------------------------------
# Aggregates
# ---------------------------------------------------------------------------

def _safe_div(n: float, d: float) -> float:
    return n / d if d > 0 else 0.0


def load_repo_loc(gt_dir: Path) -> dict[str, int]:
    """Load LOC counts from ground-truth files."""
    loc_map: dict[str, int] = {}
    for d in gt_dir.iterdir():
        gt_path = d / "ground-truth.json"
        if gt_path.exists():
            with open(gt_path) as f:
                gt = json.load(f)
            if "loc" in gt:
                loc_map[d.name] = gt["loc"]
    return loc_map


def compute_scanner_costs(
    scan_dir: Path, scanners: list[str], repo_loc: dict[str, int],
) -> dict[str, dict]:
    """Collect cost data from .metrics.json files per scanner.

    Returns {scanner: {"total_cost", "successful_runs", "cost_per_run",
                        "total_loc_scanned", "cost_per_100_loc"}}.
    """
    from collections import defaultdict
    costs: dict[str, dict] = defaultdict(
        lambda: {"total_cost": 0.0, "successful_runs": 0, "repos_scanned": set()}
    )

    for repo_dir in scan_dir.iterdir():
        if not repo_dir.is_dir():
            continue
        for scanner_dir in repo_dir.iterdir():
            if not scanner_dir.is_dir() or scanner_dir.name not in scanners:
                continue
            for mf in scanner_dir.glob("run-*.metrics.json"):
                try:
                    with open(mf) as f:
                        d = json.load(f)
                    cost = d.get("cost_usd", 0)
                    costs[scanner_dir.name]["total_cost"] += cost
                    if d.get("exit_status") == "success":
                        costs[scanner_dir.name]["successful_runs"] += 1
                        costs[scanner_dir.name]["repos_scanned"].add(repo_dir.name)
                except (json.JSONDecodeError, OSError):
                    pass

    result = {}
    for scanner in scanners:
        c = costs.get(scanner, {"total_cost": 0.0, "successful_runs": 0, "repos_scanned": set()})
        runs = c["successful_runs"]
        total_loc = sum(repo_loc.get(r, 0) for r in c["repos_scanned"])
        # Cost per 100 LOC: total cost / (total LOC / 100)
        cost_per_100_loc = round(c["total_cost"] / (total_loc / 100), 4) if total_loc > 0 else 0
        result[scanner] = {
            "total_cost": round(c["total_cost"], 4),
            "successful_runs": runs,
            "cost_per_run": round(c["total_cost"] / runs, 4) if runs > 0 else 0,
            "total_loc_scanned": total_loc,
            "cost_per_100_loc": cost_per_100_loc,
        }
    return result


def compute_scanner_metadata(
    scan_dir: Path, scanners: list[str],
) -> dict[str, dict]:
    """Collect operational metadata from .metrics.json files per scanner.

    Returns {scanner: {model, prompt_version, prompt_label, avg tokens,
                        avg latency, exit_status_counts, json_repair_rate, ...}}.
    """
    from collections import defaultdict
    raw: dict[str, dict] = defaultdict(lambda: {
        "model": "", "prompt_version": "", "prompt_label": "",
        "input_tokens": [], "output_tokens": [], "total_tokens": [],
        "wall_clock_seconds": [], "json_repairs": 0, "total_runs": 0,
        "exit_status_counts": defaultdict(int),
    })

    for repo_dir in scan_dir.iterdir():
        if not repo_dir.is_dir():
            continue
        for scanner_dir in repo_dir.iterdir():
            if not scanner_dir.is_dir() or scanner_dir.name not in scanners:
                continue
            for mf in scanner_dir.glob("run-*.metrics.json"):
                try:
                    with open(mf) as f:
                        d = json.load(f)
                    s = raw[scanner_dir.name]
                    if not s["model"]:
                        s["model"] = d.get("model", "")
                        s["prompt_version"] = d.get("prompt_version", "")
                        s["prompt_label"] = d.get("prompt_label", "")
                    s["input_tokens"].append(d.get("input_tokens", 0))
                    s["output_tokens"].append(d.get("output_tokens", 0))
                    s["total_tokens"].append(d.get("total_tokens", 0))
                    s["wall_clock_seconds"].append(d.get("wall_clock_seconds", 0))
                    if d.get("llm_json_repair", False):
                        s["json_repairs"] += 1
                    s["total_runs"] += 1
                    status = d.get("exit_status", "unknown")
                    s["exit_status_counts"][status] += 1
                except (json.JSONDecodeError, OSError):
                    pass

    result = {}
    for scanner in scanners:
        s = raw.get(scanner)
        if not s or s["total_runs"] == 0:
            result[scanner] = {"has_metrics": False}
            continue
        n = s["total_runs"]
        result[scanner] = {
            "has_metrics": True,
            "model": s["model"],
            "prompt_version": s["prompt_version"],
            "prompt_label": s["prompt_label"],
            "avg_input_tokens": int(round(statistics.mean(s["input_tokens"]))),
            "avg_output_tokens": int(round(statistics.mean(s["output_tokens"]))),
            "avg_total_tokens": int(round(statistics.mean(s["total_tokens"]))),
            "avg_wall_clock_seconds": round(statistics.mean(s["wall_clock_seconds"]), 1),
            "json_repair_rate": round(s["json_repairs"] / n, 3),
            "exit_status_counts": dict(s["exit_status_counts"]),
            "total_runs": n,
        }
    return result


def compute_aggregates(
    grid: dict[str, dict[str, dict | None]],
    scanners: list[str],
    gt_dir: Path | None = None,
) -> dict[str, dict]:
    """Compute micro-avg and macro-avg per scanner in both optimistic and strict modes.

    Optimistic: only score repos where the scanner produced results.
    Strict: failed repos count as 0 TP / all vulns FN (penalizes timeouts/failures).

    Returns {scanner: {"micro": {...}, "macro": {...}, "repos_scored": int,
                        "strict_micro": {...}, "strict_repos_total": int}}.
    """
    # Pre-load vuln counts per repo for strict mode
    repo_vuln_counts: dict[str, int] = {}
    repo_trap_counts: dict[str, int] = {}
    if gt_dir:
        for repo in grid:
            gt_path = gt_dir / repo / "ground-truth.json"
            if gt_path.exists():
                with open(gt_path) as f:
                    gt = json.load(f)
                findings = gt.get("findings", [])
                repo_vuln_counts[repo] = sum(1 for f in findings if f.get("is_vulnerable", True))
                repo_trap_counts[repo] = sum(1 for f in findings if not f.get("is_vulnerable", True))

    agg: dict[str, dict] = {}

    for scanner in scanners:
        # Optimistic mode
        total_tp = total_fp = total_fn = total_tn = 0
        f2_scores: list[float] = []
        max_num_runs = 1
        # Strict mode
        strict_tp = strict_fp = strict_fn = strict_tn = 0

        for repo in grid:
            cell = grid[repo].get(scanner)
            if cell is not None:
                # Scored successfully — both modes use real results
                total_tp += cell["tp"]
                total_fp += cell["fp"]
                total_fn += cell["fn"]
                total_tn += cell["tn"]
                f2_scores.append(cell["f2_score"])
                max_num_runs = max(max_num_runs, cell.get("_num_runs", 1))
                strict_tp += cell["tp"]
                strict_fp += cell["fp"]
                strict_fn += cell["fn"]
                strict_tn += cell["tn"]
            else:
                # Failed — strict mode counts all vulns as missed
                strict_fn += repo_vuln_counts.get(repo, 0)
                strict_tn += repo_trap_counts.get(repo, 0)

        micro_prec = _safe_div(total_tp, total_tp + total_fp)
        micro_rec = _safe_div(total_tp, total_tp + total_fn)
        micro_f2 = _safe_div(
            5.0 * micro_prec * micro_rec, 4.0 * micro_prec + micro_rec
        )
        micro_f3 = _safe_div(
            10.0 * micro_prec * micro_rec, 9.0 * micro_prec + micro_rec
        )

        strict_prec = _safe_div(strict_tp, strict_tp + strict_fp)
        strict_rec = _safe_div(strict_tp, strict_tp + strict_fn)
        strict_f2 = _safe_div(
            5.0 * strict_prec * strict_rec, 4.0 * strict_prec + strict_rec
        )
        strict_f3 = _safe_div(
            10.0 * strict_prec * strict_rec, 9.0 * strict_prec + strict_rec
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
                "f3_score": round(micro_f3 * 100, 1),
            },
            "strict_micro": {
                "tp": strict_tp,
                "fp": strict_fp,
                "fn": strict_fn,
                "tn": strict_tn,
                "precision": round(strict_prec, 4),
                "recall": round(strict_rec, 4),
                "f2_score": round(strict_f2 * 100, 1),
                "f3_score": round(strict_f3 * 100, 1),
            },
            "macro": {
                "f2_score": round(
                    sum(f2_scores) / len(f2_scores), 1
                ) if f2_scores else 0.0,
            },
            "repos_scored": len(f2_scores),
            "repos_total": len(grid),
            "f2_stddev": round(statistics.stdev(f2_scores), 1) if len(f2_scores) >= 2 else 0.0,
            "num_runs": max_num_runs,
        }

    return agg


def compute_cwe_coverage(
    grid: dict[str, dict[str, dict | None]],
    scanners: list[str],
    cwe_families: dict,
) -> list[dict]:
    """Compute per-CWE-family detection stats across all scanners.

    Returns list of dicts sorted by avg_recall descending.
    """
    families_config = cwe_families.get("families", cwe_families)
    family_stats: dict[str, dict] = {}

    for scanner in scanners:
        for repo in grid:
            cell = grid[repo].get(scanner)
            if cell is None:
                continue
            for fam_slug, fam_info in cell.get("per_family", {}).items():
                if fam_slug not in family_stats:
                    label = fam_slug.replace("_", " ").title()
                    if fam_slug in families_config:
                        fam_conf = families_config[fam_slug]
                        if isinstance(fam_conf, dict):
                            label = fam_conf.get("label", label)
                    family_stats[fam_slug] = {
                        "family": fam_slug,
                        "label": label,
                        "scanner_tp": {},
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


# ---------------------------------------------------------------------------
# Color mapping
# ---------------------------------------------------------------------------

def f2_color(score: float | None) -> str:
    """Map F2 score to a background color."""
    if score is None:
        return "#262626"
    if score >= 80:
        return "#16a34a"
    if score >= 60:
        return "#65a30d"
    if score >= 40:
        return "#a16207"
    if score >= 20:
        return "#c2410c"
    return "#b91c1c"


def f2_text_color(score: float | None) -> str:
    """Text color for readability on the background."""
    if score is None:
        return "#666666"
    return "#fff"


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


# ---------------------------------------------------------------------------
# CSS — Kolega Comply Design System
# ---------------------------------------------------------------------------

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
.header-links { display: flex; gap: 16px; margin-top: 10px; }
.header-links a {
  display: inline-flex; align-items: center; gap: 6px;
  font-size: 13px; color: var(--text-tertiary); text-decoration: none;
  padding: 4px 12px; border: 1px solid var(--border-secondary); border-radius: 8px;
  transition: all 0.2s;
}
.header-links a:hover { color: var(--accent-lime); border-color: var(--accent-lime); }
.header-links a svg { width: 16px; height: 16px; fill: currentColor; }
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

/* Finding breakdown chart */

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
  border-radius: 16px; overflow-x: auto; margin-bottom: 32px;
}
.heatmap-table { border-collapse: collapse; width: 100%; font-size: 12px; white-space: nowrap; }
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
  position: sticky; left: 0; background: var(--bg-secondary); z-index: 1;
  border-right: 1px solid var(--border-secondary);
  max-width: 260px; overflow: hidden; text-overflow: ellipsis;
}
.heatmap-table tbody tr:hover td:first-child { background: var(--hover-bg); }
.hm-cell {
  display: inline-block; min-width: 44px; padding: 3px 8px;
  border-radius: 6px; font-size: 11px;
}
.hm-great { background: #16a34a; color: #fff; }
.hm-good { background: #65a30d; color: #fff; }
.hm-ok { background: #a16207; color: #fff; }
.hm-poor { background: #c2410c; color: #fff; }
.hm-bad { background: #b91c1c; color: #fff; }
.hm-none { background: var(--bg-tertiary); color: var(--text-muted); }

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

/* Instant inline tooltips (no native title delay) */
.itip {
  position: relative; cursor: help;
}
.itip::after {
  content: attr(data-tip);
  position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%);
  background: var(--bg-secondary); border: 1px solid var(--border-primary);
  border-radius: 8px; padding: 6px 10px; font-size: 11px; font-weight: 400;
  color: var(--text-secondary); white-space: nowrap; pointer-events: none;
  box-shadow: 0 4px 12px rgba(0,0,0,0.4);
  opacity: 0; visibility: hidden; transition: opacity 0.1s;
  z-index: 200;
}
.itip:hover::after { opacity: 1; visibility: visible; }

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

/* Aggregate rows */
.agg-row td { border-top: 2px solid var(--border-primary); }
.agg-row td:first-child { font-weight: 700; color: var(--text-primary); }

/* Footer */
.page-footer {
  text-align: center; padding: 32px 0; margin-top: 16px;
  border-top: 1px solid var(--border-secondary); font-size: 12px; color: var(--text-muted);
}
.page-footer a { color: var(--text-tertiary); }
.page-footer a:hover { color: var(--accent-lime); }
"""


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
    if (score === null || score === undefined || isNaN(score)) return '#262626';
    if (metric === 'precision') {
      if (score >= 60) return '#16a34a';
      if (score >= 40) return '#65a30d';
      if (score >= 25) return '#a16207';
      if (score >= 10) return '#c2410c';
      return '#b91c1c';
    }
    if (score >= 80) return '#16a34a';
    if (score >= 60) return '#65a30d';
    if (score >= 40) return '#a16207';
    if (score >= 20) return '#c2410c';
    return '#b91c1c';
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
      const inner = td.querySelector('.hm-cell');
      if (!inner) return;
      if (val === '' || val === undefined) {
        inner.style.background = '#262626';
        inner.style.color = '#666666';
        inner.className = 'hm-cell';
        inner.innerHTML = '&mdash;';
      } else {
        const num = parseFloat(val);
        inner.style.background = metricColor(num, currentMetric);
        inner.style.color = '#fff';
        inner.className = 'hm-cell';
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


# ---------------------------------------------------------------------------
# HTML Dashboard — Main Page
# ---------------------------------------------------------------------------

def _build_tooltip_html(repo: str, scanner: str, cell: dict) -> str:
    """Build tooltip div for a cell."""
    short_repo = repo.replace("realvuln-", "").replace("Reavuln-", "").replace("RealVuln-", "")
    lines = f'<div class="tt-title">{short_repo} / {scanner}</div>'
    lines += '<div class="tt-sep"></div>'
    lines += f'<div class="tt-row"><span class="tt-label">F2 Score</span><span class="tt-val">{cell["f2_score"]:.1f}</span></div>'
    lines += f'<div class="tt-row"><span class="tt-label">F3 Score</span><span class="tt-val">{cell["f3_score"]:.1f}</span></div>'
    lines += f'<div class="tt-row"><span class="tt-label">Recall</span><span class="tt-val">{cell["recall"]:.1%}</span></div>'
    lines += f'<div class="tt-row"><span class="tt-label">Precision</span><span class="tt-val">{cell["precision"]:.1%}</span></div>'
    lines += '<div class="tt-sep"></div>'
    lines += f'<div class="tt-row"><span class="tt-label">TP</span><span class="tt-val" style="color:#22c55e">{cell["tp"]}</span></div>'
    lines += f'<div class="tt-row"><span class="tt-label">FP</span><span class="tt-val" style="color:#ef4444">{cell["fp"]}</span></div>'
    lines += f'<div class="tt-row"><span class="tt-label">FN</span><span class="tt-val" style="color:#f97316">{cell["fn"]}</span></div>'
    return f'<div class="tooltip">{lines}</div>'


def build_html(
    grid: dict[str, dict[str, dict | None]],
    scanners: list[str],
    aggregates: dict[str, dict],
    repos: list[str],
    detail_dir: str = "scanners",
    gt_total_vulns: int = 0,
    gt_total_traps: int = 0,
    gt_total_repos: int = 0,
    gt_total_loc: int = 0,
    cwe_families: dict | None = None,
    manifest: dict | None = None,
) -> str:
    """Build standalone HTML index dashboard."""
    total_scanners = len(scanners)

    # Build chart data sorted by strict F3 (primary metric)
    chart_data = []
    for scanner in scanners:
        sa = aggregates.get(scanner, {})
        micro = sa.get("micro", {})
        strict = sa.get("strict_micro", {})
        cost_info = sa.get("cost", {})
        cost_per_run = cost_info.get("cost_per_run", 0)
        chart_data.append({
            "slug": scanner,
            "label": display_name(scanner),
            # Primary display uses strict scores
            "f2": strict.get("f2_score", 0),
            "f3": strict.get("f3_score", 0),
            "recall": round(strict.get("recall", 0) * 100, 1),
            "precision": round(strict.get("precision", 0) * 100, 1),
            "tp": strict.get("tp", 0),
            "fp": strict.get("fp", 0),
            "fn": strict.get("fn", 0),
            "repos": sa.get("repos_scored", 0),
            "repos_total": sa.get("repos_total", 0),
            # Optimistic (micro) variants for toggle
            "optimistic_f2": micro.get("f2_score", 0),
            "optimistic_f3": micro.get("f3_score", 0),
            "optimistic_recall": round(micro.get("recall", 0) * 100, 1),
            "optimistic_precision": round(micro.get("precision", 0) * 100, 1),
            # Strict variants for toggle
            "strict_f2": strict.get("f2_score", 0),
            "strict_f3": strict.get("f3_score", 0),
            "strict_recall": round(strict.get("recall", 0) * 100, 1),
            "strict_precision": round(strict.get("precision", 0) * 100, 1),
            "cost_per_run": cost_per_run,
            "cost_per_100_loc": cost_info.get("cost_per_100_loc", 0),
            "total_cost": cost_info.get("total_cost", 0),
            "avg_latency": sa.get("metadata", {}).get("avg_wall_clock_seconds", 0),
            "model": sa.get("metadata", {}).get("model", ""),
            "f2_stddev": sa.get("f2_stddev", 0),
            "num_runs": sa.get("num_runs", 1),
        })
    chart_data.sort(key=lambda x: x["f3"], reverse=True)

    lines: list[str] = []
    w = lines.append

    w("<!DOCTYPE html>")
    w('<html lang="en">')
    w("<head>")
    w('<meta charset="UTF-8">')
    w('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
    w("<title>RealVuln Benchmark</title>")
    w('<!-- Google tag (gtag.js) -->')
    w('<script async src="https://www.googletagmanager.com/gtag/js?id=G-KJJ3ZH24H8"></script>')
    w("<script>")
    w("  window.dataLayer = window.dataLayer || [];")
    w("  function gtag(){dataLayer.push(arguments);}")
    w("  gtag('js', new Date());")
    w("  gtag('config', 'G-KJJ3ZH24H8');")
    w("</script>")
    w(f"<style>{_common_css()}</style>")
    w("</head>")
    w("<body>")

    # ── Header ──
    w('<div class="page-header">')
    w('<h1>RealVuln Benchmark <span class="badge">Open Source</span></h1>')
    w('<div class="subtitle">Security scanner evaluation against ground-truth vulnerabilities in real-world Python code</div>')
    w('<div class="header-links">')
    w('<a href="https://github.com/kolega-ai/Real-Vuln-Benchmark" target="_blank">'
      '<svg viewBox="0 0 16 16"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>'
      'GitHub</a>')
    w('<a href="https://kolega.dev" target="_blank">kolega.dev</a>')
    w('</div>')
    w('</div>')

    # ── Hero Stats ──
    w('<div class="hero-stats">')
    w(f'<div class="stat-card" title="Total confirmed vulnerabilities across all benchmark repositories — each one is a real, documented security issue."><div class="stat-icon" style="background:rgba(239,68,68,0.1);color:#ef4444">&#9888;</div><div><div class="stat-value" style="color:#ef4444">{gt_total_vulns}</div><div class="stat-label">Vulnerabilities</div></div></div>')
    w(f'<div class="stat-card" title="Code that looks suspicious but is actually safe. Scanners that flag these get penalized — tests whether scanners can tell real vulns from false alarms."><div class="stat-icon" style="background:rgba(234,179,8,0.1);color:#eab308">&#9678;</div><div><div class="stat-value" style="color:#eab308">{gt_total_traps}</div><div class="stat-label">FP Traps</div></div></div>')
    w(f'<div class="stat-card" title="Intentionally-vulnerable Python applications used as benchmark targets — each pinned to a specific commit."><div class="stat-icon" style="background:rgba(168,85,247,0.1);color:#A076F9">&#9881;</div><div><div class="stat-value" style="color:#A076F9">{gt_total_repos}</div><div class="stat-label">Repositories</div></div></div>')
    w(f'<div class="stat-card" title="Total lines of Python code across all benchmark repositories."><div class="stat-icon" style="background:rgba(59,130,246,0.1);color:#3b82f6">&#9998;</div><div><div class="stat-value" style="color:#3b82f6">{gt_total_loc:,}</div><div class="stat-label">Python LOC</div></div></div>')
    w(f'<div class="stat-card" title="Number of security scanners evaluated — includes traditional SAST tools and LLM-based scanners."><div class="stat-icon" style="background:rgba(196,240,62,0.1);color:#C4F03E">&#9733;</div><div><div class="stat-value" style="color:#C4F03E">{total_scanners}</div><div class="stat-label">Scanners Tested</div></div></div>')
    w('</div>')

    # ── Leaderboard ──
    w('<div class="leaderboard">')
    w('<div class="section-title">Scanner Leaderboard <span class="dim">ranked by F3 Score (strict)</span></div>')
    w('<p style="color:var(--text-tertiary);font-size:13px;margin:-8px 0 16px;max-width:720px;line-height:1.5">'
      'F3 Score (0–100) measures how well a scanner finds vulnerabilities. '
      'It rewards <strong style="color:var(--text-secondary)">finding real issues (recall) 9&times; more than avoiding false alarms (precision)</strong> '
      '— because in high-risk industries, missing a real vulnerability is far worse than a false positive. '
      'Strict mode penalizes scanners that fail or time out.</p>')
    w("""<details style="margin:-4px 0 18px;max-width:720px">
<summary style="color:var(--accent-lime);font-size:13px;font-weight:500;cursor:pointer;list-style:none;display:flex;align-items:center;gap:6px">
<span style="transition:transform 0.2s;display:inline-block">&#9654;</span> How scores work
</summary>
<div style="color:var(--text-tertiary);font-size:13px;line-height:1.7;margin-top:10px;padding:14px 16px;background:var(--bg-secondary);border:1px solid var(--border-secondary);border-radius:12px">
<strong style="color:var(--text-secondary)">Recall</strong> — What percentage of real vulnerabilities did the scanner find? Higher is better. A scanner that misses nothing has 100% recall.<br><br>
<strong style="color:var(--text-secondary)">Precision</strong> — Of everything the scanner flagged, what percentage were actual vulnerabilities? Higher is better. A scanner with no false alarms has 100% precision.<br><br>
<strong style="color:var(--text-secondary)">F2 Score</strong> — Combines recall and precision with beta=2 (recall weighted 4x). Range 0–100.<br><br>
<strong style="color:var(--text-secondary)">F3 Score</strong> — Combines recall and precision with beta=3 (recall weighted 9x). Our primary metric, designed for high-risk industries where missing a vulnerability is unacceptable. Range 0–100.<br><br>
<strong style="color:var(--text-secondary)">Optimistic vs Strict</strong> — <em>Optimistic</em> only scores repos where the scanner produced results. <em>Strict</em> penalizes failed/timed-out repos by counting all their vulnerabilities as missed (FN). Toggle between them with the buttons below.
</div>
</details>
<style>details[open] summary span{transform:rotate(90deg)}</style>""")
    # Scoring mode toggle
    w('<div style="display:flex;gap:8px;margin-bottom:16px">')
    w('<button class="mode-btn active" onclick="setScoreMode(\'strict\')">Strict</button>')
    w('<button class="mode-btn" onclick="setScoreMode(\'optimistic\')">Optimistic</button>')
    w('</div>')
    w('<style>.mode-btn{background:var(--bg-secondary);color:var(--text-secondary);border:1px solid var(--border-secondary);padding:6px 16px;border-radius:8px;cursor:pointer;font-size:13px;font-family:Inter,sans-serif;transition:all 0.2s}.mode-btn.active{background:var(--accent-lime);color:#000;border-color:var(--accent-lime)}.mode-btn:hover{border-color:var(--accent-lime)}</style>')

    for rank, d in enumerate(chart_data, 1):
        row_class = "lb-row first" if rank == 1 else "lb-row"
        score_color = f2_color(d["f3"])
        strict_color = f2_color(d["strict_f3"])
        optimistic_color = f2_color(d["optimistic_f3"])
        bar_gradient = f"linear-gradient(90deg,{score_color},{score_color}88)"
        strict_bar_gradient = f"linear-gradient(90deg,{strict_color},{strict_color}88)"
        optimistic_bar_gradient = f"linear-gradient(90deg,{optimistic_color},{optimistic_color}88)"
        repos_label = f'{d["repos"]}/{d["repos_total"]}' if d["repos"] != d["repos_total"] else str(d["repos"])
        w(f'<a href="{detail_dir}/{d["slug"]}.html" class="{row_class}"'
          f' data-f2="{d["optimistic_f2"]:.1f}" data-strict-f2="{d["strict_f2"]:.1f}"'
          f' data-f3="{d["optimistic_f3"]:.1f}" data-strict-f3="{d["strict_f3"]:.1f}"'
          f' data-recall="{d["optimistic_recall"]:.1f}" data-strict-recall="{d["strict_recall"]:.1f}"'
          f' data-precision="{d["optimistic_precision"]:.1f}" data-strict-precision="{d["strict_precision"]:.1f}"'
          f' data-color="{optimistic_color}" data-strict-color="{strict_color}"'
          f' data-gradient="{optimistic_bar_gradient}" data-strict-gradient="{strict_bar_gradient}">')
        w(f'  <div class="lb-rank">{rank}</div>')
        w(f'  <div class="lb-name">{d["label"]} <span style="color:var(--text-tertiary);font-size:11px">{repos_label} repos</span></div>')
        w(f'  <div class="lb-bar-wrap"><div class="lb-bar-track"><div class="lb-bar-fill" style="width:{d["f3"]}%;background:{bar_gradient}"></div></div></div>')
        stddev_html = f'<div class="lb-stddev" style="font-size:10px;color:var(--text-muted);text-align:right;cursor:help" title="F3 standard deviation across {d["repos"]} repositories — lower means more consistent performance">stdev {d["f2_stddev"]:.1f}</div>' if d["num_runs"] > 1 and d["f2_stddev"] > 0 else ""
        if stddev_html:
            w(f'  <div style="width:80px;flex-shrink:0;text-align:right"><div class="lb-score" style="color:{score_color};width:auto">{d["f3"]:.1f}</div>{stddev_html}</div>')
        else:
            w(f'  <div class="lb-score" style="color:{score_color}">{d["f3"]:.1f}</div>')
        cost_parts = []
        if d["cost_per_run"] > 0:
            cost_parts.append(f'<span class="itip" data-tip="Average API cost to scan one repository">${d["cost_per_run"]:.2f}/repo</span>')
        if d["cost_per_100_loc"] > 0:
            est_per_100k = round(d["cost_per_100_loc"] * 1000)
            cost_parts.append(f'<span class="itip" data-tip="Estimated cost to scan 100,000 lines of code">~${est_per_100k:,}/100k LOC</span>')
        cost_str = " &middot; ".join(cost_parts)
        latency_str = f' &middot; <span class="itip" data-tip="Average scan time per repository">{d["avg_latency"]:.0f}s avg</span>' if d["avg_latency"] > 0 else ""
        extra_meta = f'{" &middot; " + cost_str if cost_str else ""}{latency_str}'
        w(f'  <div class="lb-meta"><span class="lb-meta-scores"><strong class="itip" data-tip="Percentage of real vulnerabilities found">{d["strict_recall"]:.1f}%</strong> recall &middot; <strong class="itip" data-tip="Of findings reported, percentage that were real">{d["strict_precision"]:.1f}%</strong> prec</span>'
          f'<span class="lb-meta-extra">{extra_meta}</span></div>')
        w(f'  <div class="lb-arrow">&rsaquo;</div>')
        w(f'</a>')
    w('</div>')

    # ── Plotly: Precision vs Recall Scatter ──
    scatter_json = json.dumps(chart_data)
    scanner_links = {d["label"]: f"{detail_dir}/{d['slug']}.html" for d in chart_data}

    w('<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>')
    w('<div class="section-title">Precision vs Recall <span class="dim">each dot is a scanner &middot; dashed lines are F2 iso-curves</span></div>')
    w('<div class="chart-card">')
    w('<div id="pr-scatter" style="width:100%;height:420px"></div>')
    w('</div>')

    # ── Finding Breakdown — Plotly horizontal stacked bar ──
    w('<div class="section-title">Finding Breakdown <span class="dim">TP / FP / FN per scanner</span></div>')
    w('<div class="chart-card">')
    w('<div id="fb-chart" style="width:100%;height:' + str(max(200, len(chart_data) * 60 + 80)) + 'px"></div>')
    w('</div>')
    fb_labels = json.dumps([d["label"] for d in reversed(chart_data)])
    fb_tp = json.dumps([d["tp"] for d in reversed(chart_data)])
    fb_fp = json.dumps([d["fp"] for d in reversed(chart_data)])
    fb_fn = json.dumps([d["fn"] for d in reversed(chart_data)])
    w(f"""<script>
(function() {{
  const _bg = '#171717', _grid = '#262626', _text = '#FFFFFF', _muted = '#666666';
  const labels = {fb_labels};
  const tp = {fb_tp};
  const fp = {fb_fp};
  const fn = {fb_fn};
  const traces = [
    {{y: labels, x: tp, name: 'True Positives', type: 'bar', orientation: 'h',
      marker: {{color: '#22c55e'}}, hovertemplate: '%{{y}}: %{{x}} TP<extra></extra>'}},
    {{y: labels, x: fp, name: 'False Positives', type: 'bar', orientation: 'h',
      marker: {{color: '#ef4444'}}, hovertemplate: '%{{y}}: %{{x}} FP<extra></extra>'}},
    {{y: labels, x: fn, name: 'False Negatives', type: 'bar', orientation: 'h',
      marker: {{color: '#f97316'}}, hovertemplate: '%{{y}}: %{{x}} FN<extra></extra>'}}
  ];
  Plotly.newPlot('fb-chart', traces, {{
    paper_bgcolor: _bg, plot_bgcolor: _bg, barmode: 'stack',
    xaxis: {{title: {{text: 'Count', font: {{color: _text, size: 13, family: 'Inter'}}}},
      gridcolor: _grid, zerolinecolor: _grid, tickfont: {{color: _muted, size: 11}}}},
    yaxis: {{tickfont: {{color: _text, size: 13, family: 'Space Grotesk'}}, automargin: true}},
    legend: {{font: {{color: _text, size: 12}}, orientation: 'h', y: 1.15, x: 0.5, xanchor: 'center'}},
    margin: {{l: 10, r: 30, t: 40, b: 40}},
    hoverlabel: {{bgcolor: _bg, bordercolor: _grid, font: {{color: _text, size: 12}}}}
  }}, {{responsive: true, displayModeBar: false}});
}})();
</script>""")

    # ── CWE Detection Coverage ──
    if cwe_families:
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

    # ── Per-Repository Heatmap ──
    w('<div class="section-title">Per-Repository Heatmap <span class="dim">F2 Score &middot; click headers to sort</span></div>')
    w('<div class="metric-toggle">')
    w('<button data-metric="f2">F2 Score</button>')
    w('<button class="active" data-metric="f3">F3 Score</button>')
    w('<button data-metric="recall">Recall</button>')
    w('<button data-metric="precision">Precision</button>')
    w('</div>')

    w('<div class="heatmap-wrap">')
    w('<table class="heatmap-table" id="dashboard-table">')

    # Header
    w("<thead><tr>")
    w('<th data-col="repo">Repository <span class="sort-arrow"></span></th>')
    for i, scanner in enumerate(scanners):
        w(f'<th data-col="{i}"><a href="{detail_dir}/{scanner}.html">{display_name(scanner)}</a> <span class="sort-arrow"></span></th>')
    w("</tr></thead>")

    # Body
    w("<tbody>")
    for repo in repos:
        w("<tr>")
        short_repo = repo.replace("realvuln-", "").replace("Reavuln-", "").replace("RealVuln-", "")
        w(f'<td>{short_repo}</td>')
        for scanner in scanners:
            cell = grid.get(repo, {}).get(scanner)
            if cell is None:
                w(f'<td class="cell" data-f2="" data-f3="" data-recall="" data-precision=""><span class="hm-cell hm-none">&mdash;</span></td>')
            else:
                f2_val = cell["f2_score"]
                f3_val = cell.get("f3_score", 0)
                rec_val = round(cell["recall"] * 100, 1)
                prec_val = round(cell["precision"] * 100, 1)
                hm_cls = _hm_class(f3_val)
                tooltip = _build_tooltip_html(repo, scanner, cell)
                w(f'<td class="cell" data-f2="{f2_val}" data-f3="{f3_val}" data-recall="{rec_val}" data-precision="{prec_val}"><span class="hm-cell {hm_cls}">{f3_val:.1f}</span>{tooltip}</td>')
        w("</tr>")

    # Aggregate row (strict)
    w('<tr class="agg-row">')
    w('<td>AVERAGE (strict)</td>')
    for scanner in scanners:
        sa = aggregates.get(scanner, {})
        strict = sa.get("strict_micro", {})
        micro = sa.get("micro", {})
        repos_scored = sa.get("repos_scored", 0)
        f2_agg = strict.get("f2_score", 0)
        f3_agg = strict.get("f3_score", 0)
        if repos_scored == 0:
            w('<td class="cell" data-f2="" data-f3="" data-recall="" data-precision=""><span class="hm-cell hm-none">&mdash;</span></td>')
        else:
            hm_cls = _hm_class(f3_agg)
            rec_agg = round(strict.get("recall", 0) * 100, 1)
            prec_agg = round(strict.get("precision", 0) * 100, 1)
            tooltip_lines = f'<div class="tt-title">Average (strict)</div>'
            tooltip_lines += f'<div class="tt-row"><span class="tt-label">Repos scored</span><span class="tt-val">{repos_scored} / {sa.get("repos_total", 0)}</span></div>'
            tooltip_lines += f'<div class="tt-sep"></div>'
            tooltip_lines += f'<div class="tt-row"><span class="tt-label">F3 (strict)</span><span class="tt-val">{f3_agg:.1f}</span></div>'
            tooltip_lines += f'<div class="tt-row"><span class="tt-label">F2 (strict)</span><span class="tt-val">{f2_agg:.1f}</span></div>'
            tooltip_lines += f'<div class="tt-row"><span class="tt-label">Recall</span><span class="tt-val">{strict["recall"]:.1%}</span></div>'
            tooltip_lines += f'<div class="tt-row"><span class="tt-label">Precision</span><span class="tt-val">{strict["precision"]:.1%}</span></div>'
            tooltip_lines += f'<div class="tt-sep"></div>'
            tooltip_lines += f'<div class="tt-row"><span class="tt-label">TP / FP / FN</span><span class="tt-val">{strict["tp"]} / {strict["fp"]} / {strict["fn"]}</span></div>'
            w(f'<td class="cell" data-f2="{f2_agg}" data-f3="{f3_agg}" data-recall="{rec_agg}" data-precision="{prec_agg}"><span class="hm-cell {hm_cls}">{f3_agg:.1f}</span><div class="tooltip">{tooltip_lines}</div></td>')
    w("</tr>")

    w("</tbody></table></div>")

    # ── JavaScript ──
    w("<script>")
    w(_metric_toggle_sort_js())
    w("</script>")

    w("<script>")
    w(f"const chartData = {scatter_json};")
    w(f"const scannerLinks = {json.dumps(scanner_links)};")
    w("(function() {")
    w(_plotly_theme_js())
    w("""
  // Precision-Recall Scatter with F2 iso-lines
  const scatterTraces = [];
  const f2Vals = [20, 30, 40, 50, 60, 80];
  const f2LineColors = ['#b91c1c40','#c2410c50','#a1620750','#65a30d50','#16a34a50','#16a34a30'];
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
      textfont: {color: colors[i % colors.length], size: 12, family: 'Inter, system-ui'},
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
    paper_bgcolor: panelBg, plot_bgcolor: panelBg,
    xaxis: {title: {text: 'Recall (%)', font: {color: textColor, size: 13, family: 'Inter'}},
      range: [0, 105], gridcolor: gridColor, zerolinecolor: gridColor,
      tickfont: {color: mutedText, size: 11}, dtick: 10},
    yaxis: {title: {text: 'Precision (%)', font: {color: textColor, size: 13, family: 'Inter'}},
      range: [0, null], gridcolor: gridColor, zerolinecolor: gridColor,
      tickfont: {color: mutedText, size: 11}},
    legend: {font: {color: textColor, size: 11, family: 'Inter'}, bgcolor: 'rgba(0,0,0,0)', x: 0.01, y: 0.99},
    margin: {l: 60, r: 30, t: 30, b: 50},
    annotations: annotations,
    hoverlabel: {bgcolor: panelBg, bordercolor: gridColor, font: {color: textColor, size: 12}}
  }, {responsive: true, displayModeBar: false});

  prScatter.on('plotly_click', function(data) {
    const label = data.points[0].data.name;
    if (scannerLinks[label]) window.location.href = scannerLinks[label];
  });
""")
    w("})();")
    w("</script>")

    # ── Cost Efficiency scatter (LLM scanners only) ──
    llm_data = [d for d in chart_data if d["cost_per_run"] > 0]
    if llm_data:
        w('<div class="section-title">Cost Efficiency <span class="dim">F2 Score vs Cost per Repo &middot; LLM scanners only</span></div>')
        w('<div class="chart-card">')
        w('<div id="cost-scatter" style="width:100%;height:420px"></div>')
        w('</div>')
        cost_json = json.dumps(llm_data)
        w(f"""<script>
(function() {{
  {_plotly_theme_js()}
  const cd = {cost_json};
  const links = {json.dumps({d["label"]: f"{detail_dir}/{d['slug']}.html" for d in llm_data})};
  const traces = [];
  cd.forEach((d, i) => {{
    traces.push({{
      x: [d.cost_per_run], y: [d.f2], mode: 'markers+text',
      marker: {{size: Math.max(12, Math.min(30, d.avg_latency / 3)), color: colors[i % colors.length],
        line: {{color: darkBg, width: 2}}}},
      text: [d.label], textposition: 'top center',
      textfont: {{color: colors[i % colors.length], size: 11, family: 'Inter'}},
      name: d.label,
      customdata: [[d.model, d.avg_latency, d.total_cost]],
      hovertemplate: '<b>%{{text}}</b><br>F2: %{{y:.1f}}<br>Cost/repo: $%{{x:.2f}}<br>Model: %{{customdata[0]}}<br>Avg latency: %{{customdata[1]:.0f}}s<br>Total cost: $%{{customdata[2]:.2f}}<extra></extra>'
    }});
  }});
  const el = document.getElementById('cost-scatter');
  Plotly.newPlot(el, traces, {{
    paper_bgcolor: panelBg, plot_bgcolor: panelBg,
    xaxis: {{title: {{text: 'Cost per Repo (USD)', font: {{color: textColor, size: 13, family: 'Inter'}}}},
      type: 'log', gridcolor: gridColor, zerolinecolor: gridColor,
      tickfont: {{color: mutedText, size: 11}}, tickprefix: '$'}},
    yaxis: {{title: {{text: 'F2 Score', font: {{color: textColor, size: 13, family: 'Inter'}}}},
      range: [0, null], gridcolor: gridColor, zerolinecolor: gridColor,
      tickfont: {{color: mutedText, size: 11}}}},
    legend: {{font: {{color: textColor, size: 11}}, bgcolor: 'rgba(0,0,0,0)', x: 0.01, y: 0.99}},
    margin: {{l: 60, r: 30, t: 30, b: 50}},
    hoverlabel: {{bgcolor: panelBg, bordercolor: gridColor, font: {{color: textColor, size: 12}}}}
  }}, {{responsive: true, displayModeBar: false}});
  el.on('plotly_click', function(data) {{
    const label = data.points[0].data.name;
    if (links[label]) window.location.href = links[label];
  }});
}})();
</script>""")

    # ── Score mode toggle JS ──
    w("""<script>
function setScoreMode(mode) {
  document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
  document.querySelector(`.mode-btn[onclick*="${mode}"]`).classList.add('active');
  const rows = document.querySelectorAll('.lb-row');
  const sorted = [...rows].sort((a, b) => {
    const aF3 = parseFloat(mode === 'strict' ? a.dataset.strictF3 : a.dataset.f3);
    const bF3 = parseFloat(mode === 'strict' ? b.dataset.strictF3 : b.dataset.f3);
    return bF3 - aF3;
  });
  sorted.forEach((row, i) => {
    const f3 = mode === 'strict' ? row.dataset.strictF3 : row.dataset.f3;
    const recall = mode === 'strict' ? row.dataset.strictRecall : row.dataset.recall;
    const precision = mode === 'strict' ? row.dataset.strictPrecision : row.dataset.precision;
    const color = mode === 'strict' ? row.dataset.strictColor : row.dataset.color;
    const gradient = mode === 'strict' ? row.dataset.strictGradient : row.dataset.gradient;
    row.querySelector('.lb-rank').textContent = i + 1;
    row.querySelector('.lb-score').textContent = parseFloat(f3).toFixed(1);
    row.querySelector('.lb-score').style.color = color;
    row.querySelector('.lb-bar-fill').style.width = f3 + '%';
    row.querySelector('.lb-bar-fill').style.background = gradient;
    const scoresSpan = row.querySelector('.lb-meta-scores');
    if (scoresSpan) scoresSpan.innerHTML = `<strong>${parseFloat(recall).toFixed(1)}%</strong> recall &middot; <strong>${parseFloat(precision).toFixed(1)}%</strong> prec`;
    row.classList.toggle('first', i === 0);
    row.parentNode.appendChild(row);
  });
}
// Initialize with strict mode on page load
document.addEventListener('DOMContentLoaded', () => setScoreMode('strict'));
</script>""")

    # ── Footer ──
    manifest_info = ""
    if manifest:
        bv = manifest.get("benchmark_version", "?")
        gt_hash = manifest.get("ground_truth_content_hash", "?")[:16]
        prompt_v = manifest.get("default_prompt_version", "?")[:16]
        manifest_info = (
            f' &middot; v{bv}'
            f' &middot; GT <code style="font-size:11px">{gt_hash}</code>'
            f' &middot; Prompt <code style="font-size:11px">{prompt_v}</code>'
        )
    w('<div class="page-footer">')
    w(f'RealVuln Benchmark &middot; Generated {datetime.now(timezone.utc).strftime("%Y-%m-%d")}{manifest_info}'
      f' &middot; <a href="https://github.com/kolega-ai/Real-Vuln-Benchmark">GitHub</a>'
      f' &middot; <a href="https://kolega.dev">kolega.dev</a>')
    w('</div>')

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
    scanner_metadata: dict | None = None,
) -> str:
    """Build a detail page for a single scanner."""
    sa = aggregates.get(scanner, {})
    micro = sa.get("micro", {})
    repos_scored = sa.get("repos_scored", 0)

    # Collect per-repo data
    repo_data = []
    for repo in repos:
        cell = grid.get(repo, {}).get(scanner)
        if cell is not None:
            repo_data.append((repo, cell))

    # Collect CWE families
    all_families: dict[str, str] = {}
    for _, cell in repo_data:
        for fam_slug, fam_info in cell.get("per_family", {}).items():
            if fam_slug not in all_families:
                all_families[fam_slug] = fam_info.get("label", fam_slug)
    family_slugs = sorted(all_families.keys())

    # Collect severities
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
    w('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
    w(f"<title>{display_name(scanner)} — RealVuln Scanner Detail</title>")
    w('<!-- Google tag (gtag.js) -->')
    w('<script async src="https://www.googletagmanager.com/gtag/js?id=G-KJJ3ZH24H8"></script>')
    w("<script>")
    w("  window.dataLayer = window.dataLayer || [];")
    w("  function gtag(){dataLayer.push(arguments);}")
    w("  gtag('js', new Date());")
    w("  gtag('config', 'G-KJJ3ZH24H8');")
    w("</script>")
    w(f"<style>{_common_css()}</style>")
    w("</head>")
    w("<body>")

    w('<a href="../dashboard.html" class="back-link">&larr; Back to Dashboard</a>')
    w('<div class="page-header">')
    w(f"<h1>{display_name(scanner)}</h1>")
    w(f'<div class="subtitle">Scanner detail &middot; {repos_scored} repositories scored &middot; generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</div>')
    w('</div>')

    # ── Summary cards (strict scores as default) ──
    strict = sa.get("strict_micro", micro)
    f3_val = strict.get("f3_score", 0)
    f2_val = strict.get("f2_score", 0)
    rec_val = round(strict.get("recall", 0) * 100, 1)
    prec_val = round(strict.get("precision", 0) * 100, 1)

    w('<div class="hero-stats">')
    w(f'<div class="stat-card" title="F3 Score (beta=3, strict): weights recall 9x more than precision. Primary metric for high-risk industries. Strict mode penalizes timeouts/failures."><div class="stat-icon" style="background:rgba(22,163,74,0.1);color:{f2_color(f3_val)}">F3</div><div><div class="stat-value" style="color:{f2_color(f3_val)}">{f3_val:.1f}</div><div class="stat-label">F3 Score (strict)</div></div></div>')
    w(f'<div class="stat-card" title="F2 Score (beta=2, strict): weights recall 4x more than precision."><div class="stat-icon" style="background:rgba(22,163,74,0.1);color:{f2_color(f2_val)}">F2</div><div><div class="stat-value" style="color:{f2_color(f2_val)}">{f2_val:.1f}</div><div class="stat-label">F2 Score (strict)</div></div></div>')
    w(f'<div class="stat-card" title="What percentage of real vulnerabilities did this scanner find? Strict mode counts timed-out repos as missed."><div class="stat-icon" style="background:rgba(34,197,94,0.1);color:#22c55e">&#8593;</div><div><div class="stat-value" style="color:#22c55e">{rec_val:.1f}%</div><div class="stat-label">Recall (strict)</div></div></div>')
    w(f'<div class="stat-card" title="Of everything this scanner flagged, what percentage were real vulnerabilities? 100% = no false alarms, lower = more noise."><div class="stat-icon" style="background:rgba(160,118,249,0.1);color:#A076F9">&#9670;</div><div><div class="stat-value" style="color:#A076F9">{prec_val:.1f}%</div><div class="stat-label">Precision (strict)</div></div></div>')
    w(f'<div class="stat-card" title="Number of benchmark repositories this scanner successfully scanned out of {sa.get("repos_total", 26)} total."><div class="stat-icon" style="background:rgba(196,240,62,0.1);color:#C4F03E">&#9733;</div><div><div class="stat-value" style="color:#C4F03E">{repos_scored}</div><div class="stat-label">Repos Scored</div></div></div>')
    meta = scanner_metadata or {}
    if meta.get("has_metrics"):
        cost_info = sa.get("cost", {})
        total_cost = cost_info.get("total_cost", 0)
        avg_lat = meta.get("avg_wall_clock_seconds", 0)
        model_short = meta.get("model", "").split("/")[-1]  # strip provider prefix
        w(f'<div class="stat-card" title="The LLM model used for this scanner — this is the model ID sent to the API."><div class="stat-icon" style="background:rgba(59,130,246,0.1);color:#3b82f6">&#9881;</div><div><div class="stat-value" style="color:#3b82f6;font-size:16px">{model_short}</div><div class="stat-label">Model</div></div></div>')
        w(f'<div class="stat-card" title="Total API cost across all runs and all repositories for this scanner."><div class="stat-icon" style="background:rgba(234,179,8,0.1);color:#eab308">$</div><div><div class="stat-value" style="color:#eab308">${total_cost:.2f}</div><div class="stat-label">Total Cost</div></div></div>')
        w(f'<div class="stat-card" title="Average scan time per repository, including API calls and agent reasoning."><div class="stat-icon" style="background:rgba(249,115,22,0.1);color:#f97316">&#9202;</div><div><div class="stat-value" style="color:#f97316">{avg_lat:.0f}s</div><div class="stat-label">Avg Latency</div></div></div>')
    w('</div>')

    w('<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>')

    # ── Per-repo TP/FP/FN chart ──
    w('<div class="section-title">Per-Repository Breakdown <span class="dim">TP / FP / FN</span></div>')
    w('<div class="chart-card">')
    w('<div id="repo-bars" style="width:100%;height:' + str(max(300, len(repo_data) * 28 + 80)) + 'px"></div>')
    w('</div>')

    # ── Per-repo metric table ──
    w('<div class="section-title">Per-Repository Scores <span class="dim">click headers to sort</span></div>')
    w('<div class="metric-toggle">')
    w('<button data-metric="f2">F2 Score</button>')
    w('<button class="active" data-metric="f3">F3 Score</button>')
    w('<button data-metric="recall">Recall</button>')
    w('<button data-metric="precision">Precision</button>')
    w('</div>')

    w('<div class="heatmap-wrap">')
    w('<table class="heatmap-table" id="dashboard-table">')
    w('<thead><tr>')
    w('<th data-col="repo">Repository <span class="sort-arrow"></span></th>')
    w('<th data-col="0">F2 <span class="sort-arrow"></span></th>')
    w('<th data-col="1">Recall <span class="sort-arrow"></span></th>')
    w('<th data-col="2">Precision <span class="sort-arrow"></span></th>')
    w('<th data-col="3">TP <span class="sort-arrow"></span></th>')
    w('<th data-col="4">FP <span class="sort-arrow"></span></th>')
    w('<th data-col="5">FN <span class="sort-arrow"></span></th>')
    w('</tr></thead>')
    w('<tbody>')
    for repo, cell in repo_data:
        short_repo = repo.replace("realvuln-", "").replace("Reavuln-", "").replace("RealVuln-", "")
        f2 = cell["f2_score"]
        f3 = cell.get("f3_score", 0)
        rec = round(cell["recall"] * 100, 1)
        prec = round(cell["precision"] * 100, 1)
        hm_cls = _hm_class(f2)
        w("<tr>")
        w(f'<td>{short_repo}</td>')
        w(f'<td class="cell" data-f2="{f2}" data-f3="{f3}" data-recall="{rec}" data-precision="{prec}"><span class="hm-cell {hm_cls}">{f2:.1f}</span></td>')
        w(f'<td class="cell" data-f2="{f2}" data-f3="{f3}" data-recall="{rec}" data-precision="{prec}"><span class="hm-cell" style="background:{f2_color(rec)};color:#fff">{rec:.1f}</span></td>')
        w(f'<td class="cell" data-f2="{f2}" data-f3="{f3}" data-recall="{rec}" data-precision="{prec}"><span class="hm-cell" style="background:{f2_color(prec)};color:#fff">{prec:.1f}</span></td>')
        w(f'<td style="color:#22c55e;font-weight:600">{cell["tp"]}</td>')
        w(f'<td style="color:#ef4444;font-weight:600">{cell["fp"]}</td>')
        w(f'<td style="color:#f97316;font-weight:600">{cell["fn"]}</td>')
        w("</tr>")
    w('</tbody></table></div>')

    # ── Severity breakdown ──
    sev_agg: dict[str, dict] = {}
    for _, cell in repo_data:
        for sev, sdata in cell.get("per_severity", {}).items():
            if sev not in sev_agg:
                sev_agg[sev] = {"tp": 0, "fp": 0, "fn": 0}
            sev_agg[sev]["tp"] += sdata["tp"]
            sev_agg[sev]["fp"] += sdata["fp"]
            sev_agg[sev]["fn"] += sdata["fn"]

    if all_severities:
        w('<div class="section-title">Detection by Severity</div>')
        w('<div id="severity-bars" style="width:100%;height:300px;margin-bottom:16px"></div>')

        w('<div style="display:flex;flex-wrap:wrap;margin-bottom:20px">')
        for sev in all_severities:
            if sev in sev_agg:
                sd = sev_agg[sev]
                sev_recall = sd["tp"] / (sd["tp"] + sd["fn"]) if (sd["tp"] + sd["fn"]) > 0 else 0
                sev_color = f2_color(sev_recall * 100)
                w(f'<div class="severity-card" title="Recall for {sev}-severity vulnerabilities — {sd["tp"]} found out of {sd["tp"] + sd["fn"]} total"><div class="sev-label">{sev}</div><div class="sev-recall" style="color:{sev_color}">{sev_recall:.0%}</div><div class="sev-counts" title="TP = real vulns found, FP = false alarms, FN = real vulns missed">TP {sd["tp"]} / FP {sd["fp"]} / FN {sd["fn"]}</div></div>')
        w('</div>')

    # ── LLM Operational Metrics ──
    if meta.get("has_metrics"):
        cost_info = sa.get("cost", {})
        exit_counts = meta.get("exit_status_counts", {})
        total_runs = meta.get("total_runs", 0)
        success_rate = exit_counts.get("success", 0) / total_runs * 100 if total_runs > 0 else 0
        card_style = 'background:var(--bg-secondary);border:1px solid var(--border-secondary);border-radius:12px;padding:20px'
        label_style = 'font-family:Space Grotesk,sans-serif;font-size:14px;font-weight:600;margin-bottom:12px;color:var(--text-primary)'
        row_style = 'display:flex;justify-content:space-between;padding:4px 0;font-size:13px'
        val_style = 'font-weight:600;color:var(--text-primary)'
        lbl_style = 'color:var(--text-tertiary);cursor:help'

        w('<div class="section-title">LLM Operational Metrics</div>')
        w('<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-bottom:32px">')

        # Card 1: Model & Prompt
        w(f'<div style="{card_style}">')
        w(f'<div style="{label_style}">Model &amp; Prompt</div>')
        w(f'<div style="{row_style}"><span style="{lbl_style}" title="The LLM model ID sent to the API for this scanner">Model</span><span style="{val_style}">{meta.get("model", "—")}</span></div>')
        w(f'<div style="{row_style}"><span style="{lbl_style}" title="SHA256 content hash of the rendered system prompt — changes if the prompt template, CWE families, or output schema change">Prompt Version</span><span style="{val_style}"><code style="font-size:12px">{meta.get("prompt_version", "—")}</code></span></div>')
        w(f'<div style="{row_style}"><span style="{lbl_style}" title="Human-readable label for the prompt version">Prompt Label</span><span style="{val_style}">{meta.get("prompt_label", "—")}</span></div>')
        w('</div>')

        # Card 2: Token Usage
        w(f'<div style="{card_style}">')
        w(f'<div style="{label_style}">Token Usage <span style="font-weight:400;color:var(--text-tertiary);font-size:12px">avg per run</span></div>')
        w(f'<div style="{row_style}"><span style="{lbl_style}" title="Average tokens sent to the model per repository scan (prompt + context)">Input</span><span style="{val_style}">{meta.get("avg_input_tokens", 0):,.0f}</span></div>')
        w(f'<div style="{row_style}"><span style="{lbl_style}" title="Average tokens generated by the model per repository scan (response)">Output</span><span style="{val_style}">{meta.get("avg_output_tokens", 0):,.0f}</span></div>')
        w(f'<div style="{row_style}"><span style="{lbl_style}" title="Total tokens (input + output) consumed per scan — for agentic scanners this includes multi-turn context">Total</span><span style="{val_style}">{meta.get("avg_total_tokens", 0):,.0f}</span></div>')
        w('</div>')

        # Card 3: Cost
        w(f'<div style="{card_style}">')
        w(f'<div style="{label_style}">Cost</div>')
        w(f'<div style="{row_style}"><span style="{lbl_style}" title="Total API cost across all runs and all repositories">Total</span><span style="{val_style}">${cost_info.get("total_cost", 0):.2f}</span></div>')
        w(f'<div style="{row_style}"><span style="{lbl_style}" title="Average API cost to scan one repository (total cost / number of successful runs)">Per Repo</span><span style="{val_style}">${cost_info.get("cost_per_run", 0):.2f}</span></div>')
        w(f'<div style="{row_style}"><span style="{lbl_style}" title="Cost normalized by codebase size — divide total cost by (total lines of code / 100)">Per 100 LOC</span><span style="{val_style}">${cost_info.get("cost_per_100_loc", 0):.4f}</span></div>')
        w('</div>')

        # Card 4: Reliability
        w(f'<div style="{card_style}">')
        w(f'<div style="{label_style}">Reliability</div>')
        w(f'<div style="{row_style}"><span style="{lbl_style}" title="Percentage of runs that completed successfully without timeout or error">Success Rate</span><span style="{val_style};color:{"#22c55e" if success_rate >= 90 else "#f97316"}">{success_rate:.0f}%</span></div>')
        w(f'<div style="{row_style}"><span style="{lbl_style}" title="Number of runs that hit the time limit before finishing — these repos get no score">Timeouts</span><span style="{val_style}">{exit_counts.get("timeout", 0)}</span></div>')
        w(f'<div style="{row_style}"><span style="{lbl_style}" title="Percentage of runs where the LLM output malformed JSON that needed automatic repair before scoring">JSON Repair Rate</span><span style="{val_style}">{meta.get("json_repair_rate", 0):.0%}</span></div>')
        w(f'<div style="{row_style}"><span style="{lbl_style}" title="Average scan time per repository, including API calls and agent reasoning steps">Avg Latency</span><span style="{val_style}">{meta.get("avg_wall_clock_seconds", 0):.1f}s</span></div>')
        w('</div>')

        w('</div>')  # close grid

    # ── CWE Family Heatmap ──
    if family_slugs:
        w('<div class="section-title">CWE Family Heatmap <span class="dim">recall by repository</span></div>')
        w('<div class="heatmap-wrap">')
        w('<table class="heatmap-table">')
        w('<thead><tr>')
        w('<th>Repository</th>')
        for fam_slug in family_slugs:
            label = all_families[fam_slug]
            short_label = label if len(label) <= 18 else label[:16] + ".."
            w(f'<th title="{label}" style="font-size:10px;max-width:80px;overflow:hidden;text-overflow:ellipsis">{short_label}</th>')
        w('</tr></thead>')
        w('<tbody>')
        for repo, cell in repo_data:
            short_repo = repo.replace("realvuln-", "").replace("Reavuln-", "").replace("RealVuln-", "")
            w("<tr>")
            w(f'<td>{short_repo}</td>')
            per_fam = cell.get("per_family", {})
            for fam_slug in family_slugs:
                fam_data = per_fam.get(fam_slug)
                if fam_data is None:
                    w('<td><span class="hm-cell hm-none">&mdash;</span></td>')
                else:
                    recall_pct = round(fam_data["recall"] * 100, 1)
                    hm_cls = _hm_class(recall_pct)
                    tp_fn = fam_data["tp"] + fam_data["fn"]
                    title_text = f'{all_families[fam_slug]}: {fam_data["tp"]}/{tp_fn} found'
                    w(f'<td title="{title_text}"><span class="hm-cell {hm_cls}">{recall_pct:.0f}%</span></td>')
            w("</tr>")
        w('</tbody></table></div>')

        # ── Aggregate CWE Family chart ──
        w('<div class="section-title">CWE Family Detection <span class="dim">aggregate</span></div>')
        w('<div class="chart-card">')
        w('<div id="family-bars" style="width:100%;height:' + str(max(300, len(family_slugs) * 28 + 80)) + 'px"></div>')
        w('</div>')

    # ── Plotly JS ──
    w('<script>')
    w('(function() {')
    w(_plotly_theme_js())

    # Repo breakdown bar chart
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
    {y: repoLabels, x: repoTP, type: 'bar', orientation: 'h', name: 'TP', marker: {color: '#22c55e'},
      hovertemplate: '%{y}<br>TP: %{x}<extra></extra>'},
    {y: repoLabels, x: repoFP, type: 'bar', orientation: 'h', name: 'FP', marker: {color: '#ef4444'},
      hovertemplate: '%{y}<br>FP: %{x}<extra></extra>'},
    {y: repoLabels, x: repoFN, type: 'bar', orientation: 'h', name: 'FN', marker: {color: '#f97316'},
      hovertemplate: '%{y}<br>FN: %{x}<extra></extra>'},
  ], {
    paper_bgcolor: panelBg, plot_bgcolor: panelBg, barmode: 'stack',
    xaxis: {title: {text: 'Count', font: {color: textColor, size: 13, family: 'Inter'}},
      gridcolor: gridColor, zerolinecolor: gridColor, tickfont: {color: mutedText, size: 11}},
    yaxis: {tickfont: {color: textColor, size: 11, family: 'Source Code Pro'}, automargin: true},
    legend: {font: {color: textColor, size: 11, family: 'Inter'}, bgcolor: 'rgba(0,0,0,0)', orientation: 'h', y: 1.08},
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
    {x: sevLabels, y: sevTP, type: 'bar', name: 'TP', marker: {color: '#22c55e'}},
    {x: sevLabels, y: sevFP, type: 'bar', name: 'FP', marker: {color: '#ef4444'}},
    {x: sevLabels, y: sevFN, type: 'bar', name: 'FN', marker: {color: '#f97316'}},
  ], {
    paper_bgcolor: panelBg, plot_bgcolor: panelBg, barmode: 'group', bargap: 0.3,
    xaxis: {tickfont: {color: textColor, size: 12, family: 'Inter'}},
    yaxis: {title: {text: 'Count', font: {color: textColor, size: 13, family: 'Inter'}},
      gridcolor: gridColor, zerolinecolor: gridColor, tickfont: {color: mutedText, size: 11}},
    legend: {font: {color: textColor, size: 11, family: 'Inter'}, bgcolor: 'rgba(0,0,0,0)', orientation: 'h', y: 1.1},
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
    {y: famLabels, x: famTP, type: 'bar', orientation: 'h', name: 'TP', marker: {color: '#22c55e'},
      hovertemplate: '%{y}<br>TP: %{x}<extra></extra>'},
    {y: famLabels, x: famFP, type: 'bar', orientation: 'h', name: 'FP', marker: {color: '#ef4444'},
      hovertemplate: '%{y}<br>FP: %{x}<extra></extra>'},
    {y: famLabels, x: famFN, type: 'bar', orientation: 'h', name: 'FN', marker: {color: '#f97316'},
      hovertemplate: '%{y}<br>FN: %{x}<extra></extra>'},
  ], {
    paper_bgcolor: panelBg, plot_bgcolor: panelBg, barmode: 'stack',
    xaxis: {title: {text: 'Count', font: {color: textColor, size: 13, family: 'Inter'}},
      gridcolor: gridColor, zerolinecolor: gridColor, tickfont: {color: mutedText, size: 11}},
    yaxis: {tickfont: {color: textColor, size: 11, family: 'Source Code Pro'}, automargin: true},
    legend: {font: {color: textColor, size: 11, family: 'Inter'}, bgcolor: 'rgba(0,0,0,0)', orientation: 'h', y: 1.06},
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

    # ── Footer ──
    w('<div class="page-footer">')
    w(f'RealVuln Benchmark &middot; <a href="https://github.com/kolega-ai/Real-Vuln-Benchmark">GitHub</a> &middot; <a href="https://kolega.dev">kolega.dev</a>')
    w('</div>')

    w("</body></html>")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON Report
# ---------------------------------------------------------------------------

def build_json_report(
    grid: dict[str, dict[str, dict | None]],
    scanners: list[str],
    aggregates: dict[str, dict],
    manifest: dict | None = None,
    scanner_metadata: dict | None = None,
) -> dict:
    """Build machine-readable JSON report."""
    report: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanners": scanners,
        "repos": list(grid.keys()),
        "grid": {
            repo: {
                scanner: (
                    {k: v for k, v in cell.items() if not k.startswith("_")}
                    if cell is not None else None
                )
                for scanner, cell in repo_data.items()
            }
            for repo, repo_data in grid.items()
        },
        "aggregates": aggregates,
    }
    if manifest:
        report["benchmark_version"] = manifest.get("benchmark_version")
        report["ground_truth_content_hash"] = manifest.get("ground_truth_content_hash")
        report["default_prompt_version"] = manifest.get("default_prompt_version")
    if scanner_metadata:
        report["scanner_metadata"] = scanner_metadata
    return report


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
        "--exclude-pattern",
        nargs="+",
        default=[],
        help="Glob patterns to exclude scanners (e.g. 'kolega.dev-*')",
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
        all_scanners = discover_all_scanners(scan_dir, repos)
        scanners = [s for s in all_scanners if s in BASELINE_SCANNERS]

    # Apply exclusions
    exclude = set(args.exclude_scanners)
    scanners = [s for s in scanners if s not in exclude]
    for pat in args.exclude_pattern:
        scanners = [s for s in scanners if not fnmatch.fnmatch(s, pat)]

    if not scanners:
        print("Error: No scanners to score.", file=sys.stderr)
        return 1

    print(f"Scoring {len(repos)} repos x {len(scanners)} scanners...")

    # Load CWE families
    families_path = SCRIPT_DIR / "config" / "cwe-families.json"
    with open(families_path) as f:
        cwe_families = json.load(f)

    # Compute ground truth totals
    gt_total_vulns = 0
    gt_total_traps = 0
    gt_total_repos = 0
    for repo in discover_repos(gt_dir):
        gt_path = gt_dir / repo / "ground-truth.json"
        if gt_path.exists():
            gt_data = json.load(open(gt_path))
            gt_total_vulns += sum(1 for f in gt_data["findings"] if f["is_vulnerable"])
            gt_total_traps += sum(1 for f in gt_data["findings"] if not f["is_vulnerable"])
            gt_total_repos += 1

    # Load LOC data
    repo_loc = load_repo_loc(gt_dir)
    gt_total_loc = sum(repo_loc.values())

    # Load benchmark manifest
    manifest_path = SCRIPT_DIR / "benchmark-manifest.json"
    manifest: dict = {}
    if manifest_path.exists():
        with open(manifest_path) as f:
            manifest = json.load(f)

    # Score everything
    grid = score_all(repos, scanners, gt_dir, scan_dir, cwe_families)
    aggregates = compute_aggregates(grid, scanners, gt_dir)
    scanner_costs = compute_scanner_costs(scan_dir, scanners, repo_loc)
    scanner_metadata = compute_scanner_metadata(scan_dir, scanners)

    # Merge costs and metadata into aggregates
    for scanner in scanners:
        aggregates.setdefault(scanner, {})["cost"] = scanner_costs.get(scanner, {})
        aggregates.setdefault(scanner, {})["metadata"] = scanner_metadata.get(
            scanner, {"has_metrics": False}
        )

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
    html = build_html(
        grid, scanners, aggregates, repos,
        detail_dir=detail_dir_name,
        gt_total_vulns=gt_total_vulns,
        gt_total_traps=gt_total_traps,
        gt_total_repos=gt_total_repos,
        gt_total_loc=gt_total_loc,
        cwe_families=cwe_families,
        manifest=manifest,
    )
    report = build_json_report(
        grid, scanners, aggregates,
        manifest=manifest, scanner_metadata=scanner_metadata,
    )

    # Write main dashboard
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
    print(f"HTML dashboard: {output_path}")

    # Write scanner detail pages
    scanner_detail_dir = output_path.parent / detail_dir_name
    scanner_detail_dir.mkdir(parents=True, exist_ok=True)
    for scanner in scanners:
        detail_html = build_scanner_detail_html(
            scanner, grid, repos, aggregates,
            scanner_metadata=scanner_metadata.get(scanner, {"has_metrics": False}),
        )
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
        n = sa.get("repos_scored", 0)
        print(f"  {scanner:<20} F2={micro.get('f2_score', 0):>5.1f}  repos={n}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
