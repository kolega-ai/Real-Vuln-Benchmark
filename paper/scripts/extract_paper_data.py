#!/usr/bin/env python3
"""
Extract all numbers needed for the RealVuln paper from dashboard.json and ground-truth files.
Outputs paper/tables/data.json.
"""

import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DASHBOARD = ROOT / "reports" / "dashboard.json"
GT_DIR = ROOT / "ground-truth"
CWE_FAMILIES = ROOT / "config" / "cwe-families.json"
OUTPUT = Path(__file__).resolve().parent.parent / "tables" / "data.json"

LLM_SCANNERS = [
    "claude-haiku-4-5-agentic-v1",
    "claude-haiku-4-5-v1",
    "claude-opus-4-6-agentic-v1",
    "claude-sonnet-4-6-agentic-v1",
    "gemini-3.1-pro-agentic-v1",
    "glm-5-agentic-v1",
    "grok-3-agentic-v1",
    "grok-4.20-reasoning-agentic-v1",
    "kimi-k2.5-agentic-v1",
    "minimax-m2.7-agentic-v1",
    "qwen-3.5-397b-agentic-v1",
]

SAST_SCANNERS = ["semgrep", "snyk", "sonarqube"]
HYBRID_SCANNERS = ["kolega-v0.0.1"]


def safe_div(a, b, default=0.0):
    return a / b if b else default


def compute_derived_metrics(tp, fp, fn, tn):
    """Compute F1, TPR, FPR, and Youden's J from raw counts."""
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    tpr = recall
    fpr = safe_div(fp, fp + tn)
    youden_j = tpr - fpr
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tpr": round(tpr, 4),
        "fpr": round(fpr, 4),
        "youden_j": round(youden_j, 4),
    }


def load_dashboard():
    with open(DASHBOARD) as f:
        return json.load(f)


def load_ground_truth_stats():
    """Compute dataset statistics from ground-truth files."""
    total_vulns = 0
    total_traps = 0
    all_cwes = []
    frameworks = set()
    repo_count = 0

    for repo_dir in sorted(GT_DIR.iterdir()):
        gt_file = repo_dir / "ground-truth.json"
        if not gt_file.exists():
            continue
        repo_count += 1
        gt = json.loads(gt_file.read_text())
        fw = gt.get("framework")
        if fw:
            frameworks.add(fw)
        for f in gt.get("findings", []):
            if f.get("is_vulnerable", True):
                total_vulns += 1
                cwe = f.get("primary_cwe")
                if cwe:
                    all_cwes.append(cwe)
            else:
                total_traps += 1

    cwe_counts = defaultdict(int)
    for cwe in all_cwes:
        cwe_counts[cwe] += 1

    return {
        "repo_count": repo_count,
        "total_findings": total_vulns + total_traps,
        "vulnerable_count": total_vulns,
        "fp_trap_count": total_traps,
        "frameworks": sorted(fw for fw in frameworks if fw),
        "cwe_distribution": dict(
            sorted(cwe_counts.items(), key=lambda x: -x[1])
        ),
    }


def extract_leaderboard(dashboard):
    """Section 1: All 15 scanners ranked by strict_micro F2 score."""
    aggregates = dashboard["aggregates"]
    rows = []

    for scanner, agg in aggregates.items():
        sm = agg["strict_micro"]
        tp, fp, fn, tn = sm["tp"], sm["fp"], sm["fn"], sm["tn"]
        derived = compute_derived_metrics(tp, fp, fn, tn)

        cost = agg.get("cost", {})
        rows.append(
            {
                "scanner": scanner,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
                "precision": sm.get("precision"),
                "recall": sm.get("recall"),
                "f2_score": sm.get("f2_score"),
                "f1": derived["f1"],
                "tpr": derived["tpr"],
                "fpr": derived["fpr"],
                "youden_j": derived["youden_j"],
                "repos_scored": agg.get("repos_scored"),
                "repos_total": agg.get("repos_total"),
                "cost_total": cost.get("total_cost", 0.0),
                "cost_per_run": cost.get("cost_per_run", 0.0),
                "cost_per_100_loc": cost.get("cost_per_100_loc", 0.0),
            }
        )

    rows.sort(key=lambda r: r["f2_score"], reverse=True)
    return rows


def extract_heatmap(dashboard):
    """Section 2: 26x15 grid of per-repo per-scanner F2 scores (null for missing)."""
    grid = dashboard["grid"]
    scanners = dashboard["scanners"]
    repos = dashboard["repos"]

    heatmap = []
    for repo in repos:
        row = {"repo": repo, "scores": {}}
        repo_data = grid.get(repo, {})
        for scanner in scanners:
            cell = repo_data.get(scanner)
            if cell is not None:
                row["scores"][scanner] = cell.get("f2_score")
            else:
                row["scores"][scanner] = None
        heatmap.append(row)

    return {"repos": repos, "scanners": scanners, "rows": heatmap}


def extract_per_cwe_family_recall(dashboard):
    """Section 3: Average recall per CWE family for LLM vs SAST scanners (excluding Kolega)."""
    grid = dashboard["grid"]

    # Aggregate TP and TP+FN per family per scanner group across all repos
    # recall_per_family = sum(tp) / sum(tp + fn)
    def accumulate_family_data(scanner_list):
        family_tp = defaultdict(int)
        family_tp_fn = defaultdict(int)
        family_labels = {}

        for repo_data in grid.values():
            for scanner in scanner_list:
                cell = repo_data.get(scanner)
                if cell is None:
                    continue
                per_family = cell.get("per_family", {})
                for family_key, fdata in per_family.items():
                    tp = fdata.get("tp", 0)
                    fn = fdata.get("fn", 0)
                    family_tp[family_key] += tp
                    family_tp_fn[family_key] += tp + fn
                    if "label" in fdata:
                        family_labels[family_key] = fdata["label"]

        result = {}
        for family_key in family_tp_fn:
            denom = family_tp_fn[family_key]
            recall = safe_div(family_tp[family_key], denom)
            result[family_key] = {
                "label": family_labels.get(family_key, family_key),
                "recall": round(recall, 4),
                "total_tp": family_tp[family_key],
                "total_instances": denom,
            }
        return result

    llm_data = accumulate_family_data(LLM_SCANNERS)
    sast_data = accumulate_family_data(SAST_SCANNERS)

    # Collect all families
    all_families = sorted(set(list(llm_data.keys()) + list(sast_data.keys())))

    rows = []
    for family_key in all_families:
        llm_entry = llm_data.get(family_key, {"label": family_key, "recall": None})
        sast_entry = sast_data.get(family_key, {"label": family_key, "recall": None})
        rows.append(
            {
                "family": family_key,
                "label": llm_entry.get("label") or sast_entry.get("label", family_key),
                "llm_recall": llm_entry.get("recall"),
                "sast_recall": sast_entry.get("recall"),
            }
        )

    return rows


def extract_cost_efficiency(dashboard):
    """Section 4: For each LLM scanner, F2 score and cost metrics."""
    aggregates = dashboard["aggregates"]
    rows = []

    for scanner in LLM_SCANNERS:
        agg = aggregates.get(scanner)
        if agg is None:
            continue
        sm = agg["strict_micro"]
        cost = agg.get("cost", {})
        rows.append(
            {
                "scanner": scanner,
                "f2_score": sm.get("f2_score"),
                "total_cost": cost.get("total_cost", 0.0),
                "cost_per_run": cost.get("cost_per_run", 0.0),
                "cost_per_100_loc": cost.get("cost_per_100_loc", 0.0),
                "total_loc_scanned": cost.get("total_loc_scanned", 0),
                "successful_runs": cost.get("successful_runs", 0),
            }
        )

    rows.sort(key=lambda r: (r["f2_score"] or 0), reverse=True)
    return rows


def extract_fp_trap_data(dashboard, total_traps):
    """Section 5: FP traps triggered per scanner."""
    aggregates = dashboard["aggregates"]
    rows = []

    for scanner, agg in aggregates.items():
        sm = agg["strict_micro"]
        tn = sm["tn"]
        traps_triggered = total_traps - tn
        rows.append(
            {
                "scanner": scanner,
                "tn": tn,
                "traps_triggered": max(0, traps_triggered),
                "total_traps": total_traps,
                "trap_trigger_rate": round(
                    safe_div(max(0, traps_triggered), total_traps), 4
                ),
            }
        )

    rows.sort(key=lambda r: r["traps_triggered"])
    return {"total_traps": total_traps, "per_scanner": rows}


def extract_scanner_metadata(dashboard):
    """Section 7: Timeout rates, token counts, wall clock times per scanner."""
    scanner_meta = dashboard.get("scanner_metadata", {})
    aggregates = dashboard["aggregates"]
    rows = []

    for scanner in dashboard["scanners"]:
        meta = scanner_meta.get(scanner) or aggregates.get(scanner, {}).get(
            "metadata", {}
        )
        if not meta or not meta.get("has_metrics", False):
            rows.append(
                {
                    "scanner": scanner,
                    "has_metrics": False,
                    "timeout_rate": None,
                    "avg_input_tokens": None,
                    "avg_output_tokens": None,
                    "avg_total_tokens": None,
                    "avg_wall_clock_seconds": None,
                    "total_runs": None,
                    "model": None,
                }
            )
            continue

        exit_counts = meta.get("exit_status_counts", {})
        total_runs = meta.get("total_runs", 0)
        success_runs = exit_counts.get("success", 0)
        timeout_runs = total_runs - success_runs
        timeout_rate = safe_div(timeout_runs, total_runs)

        rows.append(
            {
                "scanner": scanner,
                "has_metrics": True,
                "model": meta.get("model"),
                "timeout_rate": round(timeout_rate, 4),
                "timeout_runs": timeout_runs,
                "success_runs": success_runs,
                "total_runs": total_runs,
                "avg_input_tokens": meta.get("avg_input_tokens"),
                "avg_output_tokens": meta.get("avg_output_tokens"),
                "avg_total_tokens": meta.get("avg_total_tokens"),
                "avg_wall_clock_seconds": meta.get("avg_wall_clock_seconds"),
                "json_repair_rate": meta.get("json_repair_rate"),
                "exit_status_counts": exit_counts,
            }
        )

    return rows


def main():
    print(f"Loading dashboard from {DASHBOARD}...")
    dashboard = load_dashboard()

    print("Loading ground truth stats...")
    gt_stats = load_ground_truth_stats()
    total_traps = gt_stats["fp_trap_count"]
    print(f"  Total FP traps (dynamic): {total_traps}")

    print("Extracting leaderboard...")
    leaderboard = extract_leaderboard(dashboard)
    print(f"  {len(leaderboard)} scanners ranked")
    # Print top 3 for verification
    for i, row in enumerate(leaderboard[:3]):
        print(f"  #{i+1}: {row['scanner']} F2={row['f2_score']}")

    print("Extracting heatmap...")
    heatmap = extract_heatmap(dashboard)
    print(f"  {len(heatmap['repos'])} repos x {len(heatmap['scanners'])} scanners")

    print("Extracting per-CWE-family recall...")
    cwe_family_recall = extract_per_cwe_family_recall(dashboard)
    print(f"  {len(cwe_family_recall)} families")

    print("Extracting cost efficiency...")
    cost_efficiency = extract_cost_efficiency(dashboard)
    print(f"  {len(cost_efficiency)} LLM scanners")

    print("Extracting FP trap data...")
    fp_trap_data = extract_fp_trap_data(dashboard, total_traps)
    print(f"  Total traps: {fp_trap_data['total_traps']}")

    print("Extracting scanner metadata...")
    scanner_metadata = extract_scanner_metadata(dashboard)
    print(f"  {len(scanner_metadata)} scanners with metadata")

    output = {
        "generated_at": dashboard.get("generated_at"),
        "benchmark_version": dashboard.get("benchmark_version"),
        "leaderboard": leaderboard,
        "heatmap": heatmap,
        "per_cwe_family_recall": cwe_family_recall,
        "cost_efficiency": cost_efficiency,
        "fp_trap_data": fp_trap_data,
        "dataset_stats": gt_stats,
        "scanner_metadata": scanner_metadata,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(output, indent=2))
    print(f"\nOutput written to {OUTPUT}")

    # Verification
    print("\n--- Verification ---")
    print("Leaderboard (top 3 and last):")
    for i, row in enumerate(leaderboard[:3]):
        print(f"  #{i+1}: {row['scanner']} strict_micro_F2={row['f2_score']}")
    print(f"  Last: {leaderboard[-1]['scanner']} strict_micro_F2={leaderboard[-1]['f2_score']}")


if __name__ == "__main__":
    main()
