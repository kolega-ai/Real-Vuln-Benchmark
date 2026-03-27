#!/usr/bin/env python3
"""Generate LLM-specific benchmark dashboard with all metrics panels.

Produces an interactive HTML dashboard with:
- F2 leaderboard with cost column
- Cost-efficiency Pareto chart (F2 vs cost)
- Reliability panel (mean +/- std, agreement rate)
- Per-CWE heatmap across models
- Tool usage comparison

Usage:
    python generate_llm_dashboard.py
    python generate_llm_dashboard.py --input results.json --output dashboard.html
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
LLM_BENCH_DIR = SCRIPT_DIR.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
except ImportError:
    print("Error: plotly required. Install with: pip install plotly", file=sys.stderr)
    sys.exit(1)


def load_results(results_path: Path) -> dict:
    """Load collected benchmark results JSON."""
    with open(results_path) as f:
        return json.load(f)


def _aggregate_model(model_data: dict) -> dict:
    """Compute aggregate metrics across all repos for a model."""
    all_f2 = []
    all_cost = []
    all_time = []
    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_tn = 0
    all_agreement = []

    for repo, repo_data in model_data.items():
        for run in repo_data.get("runs", []):
            all_f2.append(run.get("f2_score", 0))
            total_tp += run.get("tp", 0)
            total_fp += run.get("fp", 0)
            total_fn += run.get("fn", 0)
            total_tn += run.get("tn", 0)

            ops = run.get("operational_metrics", {})
            if ops.get("cost_usd"):
                all_cost.append(ops["cost_usd"])
            if ops.get("wall_clock_seconds"):
                all_time.append(ops["wall_clock_seconds"])

        rel = repo_data.get("reliability")
        if rel and rel.get("agreement_rate") is not None:
            all_agreement.append(rel["agreement_rate"])

    # Micro-averaged F2
    prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f2 = 5 * prec * recall / (4 * prec + recall) if (4 * prec + recall) > 0 else 0

    return {
        "f2_micro": round(f2 * 100, 1),
        "f2_macro": round(statistics.mean(all_f2), 1) if all_f2 else 0,
        "f2_std": round(statistics.stdev(all_f2), 1) if len(all_f2) >= 2 else 0,
        "total_cost": round(sum(all_cost), 2),
        "avg_cost_per_repo": round(statistics.mean(all_cost), 4) if all_cost else 0,
        "avg_time_per_repo": round(statistics.mean(all_time), 1) if all_time else 0,
        "total_tp": total_tp,
        "total_fp": total_fp,
        "total_fn": total_fn,
        "total_tn": total_tn,
        "precision": round(prec, 4),
        "recall": round(recall, 4),
        "repos_tested": len(model_data),
        "total_runs": sum(r.get("num_runs", 0) for r in model_data.values()),
        "agreement_rate": round(statistics.mean(all_agreement), 4) if all_agreement else None,
    }


def build_leaderboard_table(results: dict, aggregates: dict[str, dict]) -> go.Figure:
    """Build the F2 leaderboard table with cost column."""
    rows = []
    for model in results:
        agg = aggregates[model]
        rows.append({
            "Model": model,
            "F2 Score": agg["f2_micro"],
            "Precision": f"{agg['precision']:.1%}",
            "Recall": f"{agg['recall']:.1%}",
            "TP": agg["total_tp"],
            "FP": agg["total_fp"],
            "FN": agg["total_fn"],
            "Cost ($)": f"${agg['total_cost']:.2f}",
            "F2/$": round(agg["f2_micro"] / max(agg["total_cost"], 0.01), 1),
            "Repos": agg["repos_tested"],
        })

    rows.sort(key=lambda r: r["F2 Score"], reverse=True)

    cols = list(rows[0].keys()) if rows else []
    fig = go.Figure(data=[go.Table(
        header=dict(values=cols, fill_color="#1a1a2e", font=dict(color="white", size=13)),
        cells=dict(
            values=[[r[c] for r in rows] for c in cols],
            fill_color="#171717",
            font=dict(color="white", size=12),
            align="center",
        ),
    )])
    fig.update_layout(
        title="LLM Security Scanner Leaderboard (by F2 Score)",
        paper_bgcolor="#171717",
        font=dict(color="white"),
        height=100 + len(rows) * 35,
    )
    return fig


def build_cost_efficiency_chart(results: dict, aggregates: dict[str, dict]) -> go.Figure:
    """Build F2 vs Cost scatter (Pareto frontier)."""
    fig = go.Figure()

    for model in results:
        agg = aggregates[model]
        fig.add_trace(go.Scatter(
            x=[agg["total_cost"]],
            y=[agg["f2_micro"]],
            mode="markers+text",
            text=[model],
            textposition="top center",
            marker=dict(size=14),
            name=model,
        ))

    fig.update_layout(
        title="Cost-Efficiency: F2 Score vs Total Cost",
        xaxis_title="Total Cost (USD)",
        yaxis_title="F2 Score (micro-avg)",
        paper_bgcolor="#171717",
        plot_bgcolor="#171717",
        font=dict(color="white"),
        xaxis=dict(gridcolor="#333"),
        yaxis=dict(gridcolor="#333", range=[0, 100]),
        showlegend=False,
        height=500,
    )
    return fig


def build_reliability_chart(results: dict, aggregates: dict[str, dict]) -> go.Figure:
    """Build reliability comparison bar chart."""
    models = []
    f2_means = []
    f2_stds = []
    agreement_rates = []

    for model in sorted(results):
        agg = aggregates[model]
        models.append(model)
        f2_means.append(agg["f2_macro"])
        f2_stds.append(agg["f2_std"])
        agreement_rates.append((agg["agreement_rate"] or 0) * 100)

    fig = make_subplots(rows=1, cols=2, subplot_titles=("F2 Score (mean +/- std)", "Agreement Rate (%)"))

    fig.add_trace(
        go.Bar(
            x=models, y=f2_means,
            error_y=dict(type="data", array=f2_stds, visible=True),
            name="F2 Score",
            marker_color="#4ecdc4",
        ),
        row=1, col=1,
    )
    fig.add_trace(
        go.Bar(
            x=models, y=agreement_rates,
            name="Agreement Rate",
            marker_color="#ff6b6b",
        ),
        row=1, col=2,
    )

    fig.update_layout(
        title="Reliability: Consistency Across Runs",
        paper_bgcolor="#171717",
        plot_bgcolor="#171717",
        font=dict(color="white"),
        height=450,
        showlegend=False,
    )
    fig.update_xaxes(gridcolor="#333")
    fig.update_yaxes(gridcolor="#333")
    return fig


def build_cwe_heatmap(results: dict) -> go.Figure:
    """Build per-CWE-family recall heatmap across models."""
    # Collect all CWE families and models
    all_families: set[str] = set()
    model_names = sorted(results.keys())

    for model_data in results.values():
        for repo_data in model_data.values():
            for run in repo_data.get("runs", []):
                per_fam = run.get("per_family", {})
                all_families.update(per_fam.keys())

    families = sorted(all_families)
    if not families:
        return go.Figure()

    # Build recall matrix
    z = []
    labels = []
    for model in model_names:
        row = []
        for fam in families:
            total_tp = 0
            total_fn = 0
            model_data = results[model]
            for repo_data in model_data.values():
                for run in repo_data.get("runs", []):
                    fam_data = run.get("per_family", {}).get(fam, {})
                    total_tp += fam_data.get("tp", 0)
                    total_fn += fam_data.get("fn", 0)
            recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
            row.append(round(recall * 100, 1))
        z.append(row)
        labels.append(model)

    family_labels = []
    for fam in families:
        # Try to find a nice label from any run
        for model_data in results.values():
            for repo_data in model_data.values():
                for run in repo_data.get("runs", []):
                    fam_info = run.get("per_family", {}).get(fam, {})
                    if fam_info.get("label"):
                        family_labels.append(fam_info["label"])
                        break
                else:
                    continue
                break
            else:
                continue
            break
        else:
            family_labels.append(fam)

    fig = go.Figure(data=go.Heatmap(
        z=z,
        x=family_labels,
        y=labels,
        colorscale="RdYlGn",
        zmin=0,
        zmax=100,
        text=[[f"{v:.0f}%" for v in row] for row in z],
        texttemplate="%{text}",
        textfont={"size": 11},
    ))

    fig.update_layout(
        title="Per-CWE Family Recall (%) by Model",
        paper_bgcolor="#171717",
        plot_bgcolor="#171717",
        font=dict(color="white"),
        height=max(300, len(labels) * 40 + 200),
        xaxis=dict(tickangle=45),
    )
    return fig


def generate_dashboard(results: dict, output_path: Path) -> None:
    """Generate the full HTML dashboard."""
    aggregates = {model: _aggregate_model(data) for model, data in results.items()}

    leaderboard = build_leaderboard_table(results, aggregates)
    cost_chart = build_cost_efficiency_chart(results, aggregates)
    reliability = build_reliability_chart(results, aggregates)
    cwe_heatmap = build_cwe_heatmap(results)

    html_parts = [
        "<html><head>",
        "<title>LLM Security Scanner Benchmark</title>",
        '<style>body { background: #171717; color: white; font-family: system-ui; '
        'margin: 0; padding: 20px; }</style>',
        "</head><body>",
        '<h1 style="text-align: center;">LLM Security Scanner Benchmark</h1>',
        leaderboard.to_html(full_html=False, include_plotlyjs="cdn"),
        cost_chart.to_html(full_html=False, include_plotlyjs=False),
        reliability.to_html(full_html=False, include_plotlyjs=False),
        cwe_heatmap.to_html(full_html=False, include_plotlyjs=False),
        "</body></html>",
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(html_parts))
    print(f"Dashboard written to: {output_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate LLM benchmark dashboard")
    parser.add_argument(
        "--input", "-i", type=Path,
        default=PROJECT_ROOT / "reports" / "llm-benchmark-results.json",
        help="Input results JSON from collect_results.py",
    )
    parser.add_argument(
        "--output", "-o", type=Path,
        default=PROJECT_ROOT / "reports" / "llm-benchmark-dashboard.html",
        help="Output HTML dashboard path",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: Results file not found: {args.input}", file=sys.stderr)
        print("Run collect_results.py first.", file=sys.stderr)
        return 1

    results = load_results(args.input)
    generate_dashboard(results, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
