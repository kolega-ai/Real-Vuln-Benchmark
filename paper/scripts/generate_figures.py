#!/usr/bin/env python3
"""Generate PDF figures for the RealVuln benchmark paper.

Reads paper/tables/data.json (produced by extract_paper_data.py) and writes
four PDF figures to paper/figures/:
  - heatmap.pdf           — 26x15 F2 score heatmap
  - cost-efficiency.pdf   — Cost vs. F2 scatter plot
  - cwe-family-recall.pdf — Grouped bar chart of recall by CWE family
  - fp-trap-rates.pdf     — FP trap fall-through rate bar chart

Usage:
    python3 paper/scripts/generate_figures.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_PATH = SCRIPT_DIR.parent / "tables" / "data.json"
FIGURES_DIR = SCRIPT_DIR.parent / "figures"


def shorten_scanner(name: str) -> str:
    """Compact display name for a scanner slug."""
    return (
        name.replace("-agentic-v1", " (A)")
        .replace("-v1", " (ST)")
        .replace("-v0.0.1", "")
        .replace("realvuln-", "")
        .replace("claude-", "C.")
        .replace("gemini-", "Gem.")
        .replace("grok-", "Grok-")
        .replace("kimi-", "Kimi-")
        .replace("glm-", "GLM-")
        .replace("minimax-", "MM-")
        .replace("qwen-", "Qwen-")
    )


def shorten_repo(name: str) -> str:
    return name.removeprefix("realvuln-")


# ---------------------------------------------------------------------------
# Figure 1 — Heatmap
# ---------------------------------------------------------------------------

def fig_heatmap(data: dict) -> None:
    heatmap = data.get("heatmap", {})
    repos = heatmap.get("repos", [])
    scanners = heatmap.get("scanners", [])
    rows = heatmap.get("rows", [])

    if not repos or not scanners or not rows:
        print("heatmap: missing data, skipping", file=sys.stderr)
        return

    # rows is a list of dicts: {"repo": str, "scores": {scanner: f2 | null}}
    matrix = np.array(
        [[float(row["scores"].get(s)) if row["scores"].get(s) is not None else np.nan for s in scanners] for row in rows],
        dtype=float,
    )

    # Sort repos by row-mean descending
    row_means = np.nanmean(matrix, axis=1)
    row_order = np.argsort(row_means)[::-1]
    matrix = matrix[row_order]
    repos_sorted = [repos[i] for i in row_order]

    # Sort scanners by leaderboard order (already sorted in data)
    leaderboard = data.get("leaderboard", [])
    lb_order = {r["scanner"]: i for i, r in enumerate(leaderboard)}
    col_order = sorted(range(len(scanners)), key=lambda j: lb_order.get(scanners[j], 999))
    matrix = matrix[:, col_order]
    scanners_sorted = [scanners[j] for j in col_order]

    row_labels = [shorten_repo(r) for r in repos_sorted]
    col_labels = [shorten_scanner(s) for s in scanners_sorted]

    cmap = plt.get_cmap("RdYlGn").copy()
    cmap.set_bad(color="#cccccc")

    n_rows, n_cols = matrix.shape
    fig, ax = plt.subplots(figsize=(max(12, n_cols * 0.9 + 3), max(8, n_rows * 0.45 + 2)))

    im = ax.imshow(matrix, cmap=cmap, vmin=0, vmax=100, aspect="auto")

    ax.set_xticks(np.arange(n_cols))
    ax.set_yticks(np.arange(n_rows))
    ax.set_xticklabels(col_labels, rotation=45, ha="right", fontsize=7)
    ax.set_yticklabels(row_labels, fontsize=7)

    for i in range(n_rows):
        for j in range(n_cols):
            val = matrix[i, j]
            if not np.isnan(val):
                color = "black" if 25 < val < 75 else "white"
                ax.text(j, i, f"{val:.0f}", ha="center", va="center", fontsize=5, color=color)

    cbar = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    cbar.set_label("F2 Score (0-100)", fontsize=9)
    ax.set_title("F2 Scores: Repos x Scanners", fontsize=11, pad=12)
    ax.set_xlabel("Scanner", fontsize=9)
    ax.set_ylabel("Repository", fontsize=9)

    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "heatmap.pdf", format="pdf", bbox_inches="tight")
    plt.close(fig)
    print("Saved heatmap.pdf")


# ---------------------------------------------------------------------------
# Figure 2 — Cost Efficiency
# ---------------------------------------------------------------------------

def fig_cost_efficiency(data: dict) -> None:
    cost_data = data.get("cost_efficiency", [])
    leaderboard = data.get("leaderboard", [])

    # SAST baselines from leaderboard
    sast_baselines = [
        (r["scanner"], r["f2_score"])
        for r in leaderboard
        if r.get("cost_total", 0) == 0 and r["scanner"] in ("semgrep", "snyk", "sonarqube")
    ]

    fig, ax = plt.subplots(figsize=(10, 6))

    xs, ys = [], []
    for row in cost_data:
        cost = row.get("cost_total") or row.get("total_cost") or 0
        f2 = row.get("f2_score")
        if f2 is None or cost == 0:
            continue
        xs.append(cost)
        ys.append(f2)
        is_single_turn = "v1" in row["scanner"] and "agentic" not in row["scanner"]
        marker = "^" if is_single_turn else "o"
        ax.scatter(cost, f2, marker=marker, s=70, zorder=3)
        ax.annotate(shorten_scanner(row["scanner"]), (cost, f2),
                    textcoords="offset points", xytext=(4, 4), fontsize=7)

    if xs:
        x_pad = (max(xs) - min(xs)) * 0.1 or 1.0
        ax.set_xlim(min(xs) - x_pad, max(xs) + x_pad * 3)

    for scanner, f2 in sast_baselines:
        ax.axhline(y=f2, linestyle="--", linewidth=0.8, alpha=0.6)
        xlim = ax.get_xlim()
        ax.text(xlim[1] * 0.98, f2 + 0.5, scanner, fontsize=7, ha="right", alpha=0.7)

    ax.set_xlabel("Total Cost (USD)", fontsize=10)
    ax.set_ylabel("Strict Micro F2 Score", fontsize=10)
    ax.set_title("Cost vs. Detection Performance", fontsize=11)
    ax.grid(True, linestyle=":", alpha=0.5)

    legend_handles = [
        Line2D([0], [0], marker="^", color="w", markerfacecolor="gray", markersize=8, label="Single-turn"),
        Line2D([0], [0], marker="o", color="w", markerfacecolor="gray", markersize=8, label="Agentic"),
    ]
    ax.legend(handles=legend_handles, fontsize=8, loc="lower right")

    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "cost-efficiency.pdf", format="pdf", bbox_inches="tight")
    plt.close(fig)
    print("Saved cost-efficiency.pdf")


# ---------------------------------------------------------------------------
# Figure 3 — CWE Family Recall
# ---------------------------------------------------------------------------

def fig_cwe_family_recall(data: dict) -> None:
    families = data.get("per_cwe_family_recall", [])
    if not families:
        print("cwe-family-recall: no data, skipping", file=sys.stderr)
        return

    # Filter to families with both LLM and SAST data
    families = [f for f in families if f.get("llm_recall") is not None and f.get("sast_recall") is not None]
    families.sort(key=lambda f: f["llm_recall"], reverse=True)

    if not families:
        print("cwe-family-recall: no families with both LLM and SAST data, skipping", file=sys.stderr)
        return

    labels = [f["label"] for f in families]
    llm_vals = [f["llm_recall"] * 100 for f in families]
    sast_vals = [f["sast_recall"] * 100 for f in families]

    n = len(labels)
    x = np.arange(n)
    width = 0.35

    fig, ax = plt.subplots(figsize=(max(10, n * 0.8 + 2), 5))
    ax.bar(x - width / 2, llm_vals, width, label="General-purpose LLM", color="steelblue", alpha=0.85)
    ax.bar(x + width / 2, sast_vals, width, label="Rule-based SAST", color="coral", alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=40, ha="right", fontsize=7)
    ax.set_ylabel("Recall (%)", fontsize=10)
    ax.set_ylim(0, 110)
    ax.set_title("CWE Family Recall: General-purpose LLM vs. Rule-based SAST", fontsize=11)
    ax.legend(fontsize=9)
    ax.grid(axis="y", linestyle=":", alpha=0.5)

    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "cwe-family-recall.pdf", format="pdf", bbox_inches="tight")
    plt.close(fig)
    print("Saved cwe-family-recall.pdf")


# ---------------------------------------------------------------------------
# Figure 4 — FP Trap Rates
# ---------------------------------------------------------------------------

def fig_fp_trap_rates(data: dict) -> None:
    fp_data = data.get("fp_trap_data", {})
    per_scanner = fp_data.get("per_scanner", [])
    if not per_scanner:
        print("fp-trap-rates: no data, skipping", file=sys.stderr)
        return

    # Sort by fall rate descending
    per_scanner.sort(key=lambda r: r.get("trap_trigger_rate", 0), reverse=True)

    category_colors = {"Rule-based SAST": "steelblue", "General-purpose LLM": "orange", "Security-specialized": "#22c55e"}

    names = [shorten_scanner(r["scanner"]) for r in per_scanner]
    rates = [r.get("trap_trigger_rate", 0) * 100 for r in per_scanner]
    colors = [category_colors.get(r.get("category", ""), "gray") for r in per_scanner]

    fig, ax = plt.subplots(figsize=(max(9, len(names) * 0.8 + 2), 5))
    ax.bar(np.arange(len(names)), rates, color=colors, alpha=0.85)
    ax.set_xticks(np.arange(len(names)))
    ax.set_xticklabels(names, rotation=40, ha="right", fontsize=7)
    ax.set_ylabel("FP Trap Fall-through Rate (%)", fontsize=10)
    ax.set_ylim(0, max(rates) * 1.15 + 1 if rates else 100)
    ax.set_title("False-Positive Trap Fall-through Rates", fontsize=11)
    ax.grid(axis="y", linestyle=":", alpha=0.5)

    cats_present = sorted(set(r.get("category", "") for r in per_scanner))
    ax.legend(
        handles=[Patch(facecolor=category_colors.get(c, "gray"), label=c, alpha=0.85) for c in cats_present],
        fontsize=9, loc="upper right",
    )

    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "fp-trap-rates.pdf", format="pdf", bbox_inches="tight")
    plt.close(fig)
    print("Saved fp-trap-rates.pdf")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    if not DATA_PATH.exists():
        print(f"Error: {DATA_PATH} not found. Run extract_paper_data.py first.", file=sys.stderr)
        return 1

    with open(DATA_PATH) as f:
        data = json.load(f)

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    fig_heatmap(data)
    fig_cost_efficiency(data)
    fig_cwe_family_recall(data)
    fig_fp_trap_rates(data)

    print("All figures generated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
