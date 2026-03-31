#!/usr/bin/env python3
"""Generate precision-recall and F3-vs-cost scatter plots for the paper."""

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent.parent
DASHBOARD = ROOT / "reports" / "dashboard.json"
FIGURES = Path(__file__).resolve().parent.parent / "figures"

CATEGORY_COLORS = {
    "Security-Specialized": "#22c55e",
    "General-purpose LLM": "#f97316",
    "Rule-Based SAST": "#3b82f6",
}

CATEGORY_MARKERS = {
    "Security-Specialized": "*",
    "General-purpose LLM": "o",
    "Rule-Based SAST": "s",
}

SAST = {"semgrep", "snyk", "sonarqube"}
SPECIALIZED = {"kolega-v0.0.1", "seclab-taskflow-agent-v1"}

# Known costs per 100k LOC
KNOWN_COSTS = {
    "kolega-v0.0.1": 25,
    "seclab-taskflow-agent-v1": 125,
}


def categorize(scanner):
    if scanner in SAST:
        return "Rule-Based SAST"
    if scanner in SPECIALIZED:
        return "Security-Specialized"
    return "General-purpose LLM"


def short_name(scanner):
    return (
        scanner
        .replace("-agentic-v1", "")
        .replace("-v0.0.1", "")
        .replace("claude-", "Claude ")
        .replace("gemini-", "Gemini ")
        .replace("grok-", "Grok ")
        .replace("kimi-", "Kimi ")
        .replace("glm-", "GLM-")
        .replace("minimax-", "Minimax ")
        .replace("qwen-", "Qwen ")
        .replace("kolega", "Kolega.Dev")
        .replace("seclab-taskflow-agent-v1", "SecLab Agent")
    )


def load_data():
    with open(DASHBOARD) as f:
        return json.load(f)


def fig_precision_recall(data):
    agg = data["aggregates"]

    fig, ax = plt.subplots(figsize=(7, 5))

    for scanner, v in agg.items():
        # Skip single-turn haiku if present
        if "v1" in scanner and "agentic" not in scanner and scanner not in SPECIALIZED and scanner not in SAST:
            continue

        sm = v.get("strict_micro", {})
        prec = sm.get("precision", 0)
        rec = sm.get("recall", 0)
        cat = categorize(scanner)
        color = CATEGORY_COLORS[cat]
        marker = CATEGORY_MARKERS[cat]
        size = 200 if cat == "Security-Specialized" else 80

        ax.scatter(rec, prec, c=color, marker=marker, s=size, zorder=5, edgecolors="white", linewidth=0.5)

        label = short_name(scanner)
        offset = (8, 5)
        if "Kolega" in label:
            offset = (10, -5)
        if "SecLab" in label:
            offset = (10, 5)
        ax.annotate(label, (rec, prec), textcoords="offset points",
                    xytext=offset, fontsize=7, color=color, fontweight="bold" if cat == "Security-Specialized" else "normal")

    # Legend
    from matplotlib.lines import Line2D
    legend = [
        Line2D([0], [0], marker="*", color="w", markerfacecolor=CATEGORY_COLORS["Security-Specialized"],
               markersize=14, label="Security-Specialized"),
        Line2D([0], [0], marker="o", color="w", markerfacecolor=CATEGORY_COLORS["General-purpose LLM"],
               markersize=8, label="General-purpose LLM"),
        Line2D([0], [0], marker="s", color="w", markerfacecolor=CATEGORY_COLORS["Rule-Based SAST"],
               markersize=8, label="Rule-Based SAST"),
    ]
    ax.legend(handles=legend, fontsize=8, loc="upper left")

    ax.set_xlabel("Recall", fontsize=11)
    ax.set_ylabel("Precision", fontsize=11)
    ax.set_xlim(0, 1.0)
    ax.set_ylim(0, 1.0)
    ax.set_title("Precision vs. Recall", fontsize=12)
    ax.grid(True, linestyle=":", alpha=0.4)

    fig.tight_layout()
    out = FIGURES / "precision-recall.pdf"
    fig.savefig(out, format="pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {out}")


def fig_f3_vs_cost(data):
    agg = data["aggregates"]

    fig, ax = plt.subplots(figsize=(7, 5))

    points = []
    for scanner, v in agg.items():
        # Skip single-turn haiku if present
        if "v1" in scanner and "agentic" not in scanner and scanner not in SPECIALIZED and scanner not in SAST:
            continue

        sm = v.get("strict_micro", {})
        f3 = sm.get("f3_score", 0)
        cat = categorize(scanner)

        # Get cost per 100k LOC
        cost_info = v.get("cost", {})
        if scanner in KNOWN_COSTS:
            cost = KNOWN_COSTS[scanner]
        elif scanner in SAST:
            cost = 0
        else:
            cost = cost_info.get("cost_per_100_loc", 0) * 1000  # convert to per 100k

        points.append((scanner, f3, cost, cat))

    for scanner, f3, cost, cat in points:
        color = CATEGORY_COLORS[cat]
        marker = CATEGORY_MARKERS[cat]
        size = 200 if cat == "Security-Specialized" else 80

        ax.scatter(cost, f3, c=color, marker=marker, s=size, zorder=5, edgecolors="white", linewidth=0.5)

        label = short_name(scanner)
        offset = (8, 3)
        if "Kolega" in label:
            offset = (10, -8)
        if "SecLab" in label:
            offset = (10, 5)
        if cost == 0:
            offset = (8, 3)
        ax.annotate(label, (cost, f3), textcoords="offset points",
                    xytext=offset, fontsize=7, color=color, fontweight="bold" if cat == "Security-Specialized" else "normal")

    # Legend
    from matplotlib.lines import Line2D
    legend = [
        Line2D([0], [0], marker="*", color="w", markerfacecolor=CATEGORY_COLORS["Security-Specialized"],
               markersize=14, label="Security-Specialized"),
        Line2D([0], [0], marker="o", color="w", markerfacecolor=CATEGORY_COLORS["General-purpose LLM"],
               markersize=8, label="General-purpose LLM"),
        Line2D([0], [0], marker="s", color="w", markerfacecolor=CATEGORY_COLORS["Rule-Based SAST"],
               markersize=8, label="Rule-Based SAST"),
    ]
    ax.legend(handles=legend, fontsize=8, loc="center right")

    ax.set_xlabel("Cost ($/100k LOC)", fontsize=11)
    ax.set_ylabel("F3 Score (strict)", fontsize=11)
    ax.set_ylim(0, 85)
    ax.set_title("Detection Performance vs. Cost", fontsize=12)
    ax.grid(True, linestyle=":", alpha=0.4)

    fig.tight_layout()
    out = FIGURES / "f3-vs-cost.pdf"
    fig.savefig(out, format="pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {out}")


def main():
    FIGURES.mkdir(parents=True, exist_ok=True)
    data = load_data()
    fig_precision_recall(data)
    fig_f3_vs_cost(data)
    print("Done.")


if __name__ == "__main__":
    main()
