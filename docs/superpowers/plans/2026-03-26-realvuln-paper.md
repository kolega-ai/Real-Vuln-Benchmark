# RealVuln Paper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Write a complete arXiv-ready research paper for the RealVuln benchmark, including all LaTeX source, figures, tables, and supporting data extraction scripts.

**Architecture:** LaTeX paper in `paper/` directory using ACM `acmart` template. A Python data extraction script (`paper/scripts/extract_paper_data.py`) reads `reports/dashboard.json` and ground truth files to generate all tables and figure data as JSON/CSV. LaTeX compiles standalone.

**Tech Stack:** LaTeX (acmart class), Python 3 (json, csv for data extraction), Plotly/matplotlib for figures exported as PDF.

**Spec:** `docs/superpowers/specs/2026-03-26-realvuln-paper-design.md`

---

## File Structure

```
paper/
├── main.tex                          # Root LaTeX file, includes all sections
├── sections/
│   ├── abstract.tex                  # Abstract
│   ├── introduction.tex              # Section 1
│   ├── related-work.tex              # Section 2
│   ├── benchmark-design.tex          # Section 3 (taxonomy, dataset, matching, scoring)
│   ├── experimental-setup.tex        # Section 4 (scanners, LLM modes, reproducibility)
│   ├── results.tex                   # Section 5 (rankings, heatmap, per-CWE, cost, FP traps)
│   ├── discussion.tex                # Section 6 (findings, limitations, threats)
│   ├── living-benchmark.tex          # Section 7 (versioning, roadmap, community)
│   ├── conclusion.tex                # Section 8
│   ├── ethics.tex                    # Section 9
│   └── data-availability.tex         # Section 10
├── references.bib                    # BibTeX references
├── figures/
│   ├── heatmap.pdf                   # 26x15 F2 heatmap (generated)
│   ├── cost-efficiency.pdf           # F2 vs cost scatter (generated)
│   ├── cwe-family-recall.pdf         # Per-CWE-family recall bar chart (generated)
│   └── fp-trap-rates.pdf             # FP trap fall-through rates (generated)
├── tables/
│   └── data.json                     # Extracted data for all tables (generated)
├── scripts/
│   ├── extract_paper_data.py         # Reads dashboard.json → tables/data.json
│   └── generate_figures.py           # Reads tables/data.json → figures/*.pdf
└── Makefile                          # Build: make data, make figures, make paper
```

---

### Task 1: Project scaffolding and LaTeX skeleton

**Files:**
- Create: `paper/main.tex`
- Create: `paper/Makefile`
- Create: `paper/sections/abstract.tex` (placeholder)
- Create: all `paper/sections/*.tex` (placeholders)
- Create: `paper/references.bib` (empty)

- [ ] **Step 1: Create paper directory structure**

```bash
mkdir -p paper/sections paper/figures paper/tables paper/scripts
```

- [ ] **Step 2: Create main.tex with acmart template**

Create `paper/main.tex`:

```latex
\documentclass[sigconf,nonacm]{acmart}

\usepackage{booktabs}
\usepackage{graphicx}
\usepackage{xcolor}
\usepackage{hyperref}
\usepackage{multirow}
\usepackage{subcaption}

\begin{document}

\title{RealVuln: An Open Benchmark for Evaluating Security Scanners on Real-World Code}

\author{[Author Names]}
\affiliation{%
  \institution{Kolega}
}
\email{[emails]}

\input{sections/abstract}

\maketitle

\input{sections/introduction}
\input{sections/related-work}
\input{sections/benchmark-design}
\input{sections/experimental-setup}
\input{sections/results}
\input{sections/discussion}
\input{sections/living-benchmark}
\input{sections/conclusion}
\input{sections/ethics}
\input{sections/data-availability}

\bibliographystyle{ACM-Reference-Format}
\bibliography{references}

\end{document}
```

- [ ] **Step 3: Create placeholder .tex files for all sections**

Each file gets a `\section{Title}` and a `% TODO` comment. This ensures `main.tex` compiles immediately.

- [ ] **Step 4: Create Makefile**

This Makefile lives at `paper/Makefile` and all commands run from inside `paper/`.

```makefile
.PHONY: paper data figures clean all

paper: sections/*.tex references.bib
	pdflatex main && bibtex main && pdflatex main && pdflatex main

data:
	python scripts/extract_paper_data.py

figures: data
	python scripts/generate_figures.py

all: data figures paper

clean:
	rm -f *.aux *.bbl *.blg *.log *.out main.pdf
```

Note: All `make` commands should be run from inside the `paper/` directory: `cd paper && make all`.

- [ ] **Step 5: Verify LaTeX compiles**

Run: `cd paper && pdflatex main.tex`
Expected: PDF generated with placeholder sections, no errors.

- [ ] **Step 6: Commit**

```bash
git add paper/
git commit -m "feat: scaffold paper directory with LaTeX skeleton"
```

---

### Task 2: Data extraction script

**Files:**
- Create: `paper/scripts/extract_paper_data.py`
- Output: `paper/tables/data.json`

This script reads `reports/dashboard.json` and `ground-truth/` to produce all numbers needed for the paper's tables and figures.

- [ ] **Step 1: Write extract_paper_data.py**

The script must extract:

1. **Leaderboard table** (Section 5.1): all 15 scanners ranked by `strict_micro.f2_score`, with TP/FP/FN/TN, precision, recall, F1, F2, repos_scored, cost.

2. **Heatmap data** (Section 5.2): 26×15 grid of per-repo per-scanner F2 scores, with null for missing/timed-out repos.

3. **Per-CWE-family recall** (Section 5.3): for each CWE family, average recall across LLM scanners vs average recall across SAST scanners.

4. **Cost-efficiency data** (Section 5.4): for each LLM scanner, (f2_score, total_cost, cost_per_run, cost_per_100_loc).

5. **FP trap data** (Section 5.5): for each scanner, count of FP traps triggered (TN count = traps correctly ignored, so traps_triggered = total_traps - TN).

6. **Dataset stats** (Section 3): total findings, vulnerable count, FP trap count, repo count, framework distribution, CWE family distribution.

7. **Scanner metadata** (Section 4): timeout/failure rates per scanner, avg tokens, avg wall clock time.

```python
#!/usr/bin/env python3
"""Extract all paper data from dashboard.json and ground truth files."""

import json
import os
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent.parent.parent  # repo root
DASHBOARD = ROOT / "reports" / "dashboard.json"
GT_DIR = ROOT / "ground-truth"
CWE_FAMILIES = ROOT / "config" / "cwe-families.json"
OUTPUT = Path(__file__).resolve().parent.parent / "tables" / "data.json"

LLM_SCANNERS = [
    "claude-haiku-4-5-agentic-v1", "claude-haiku-4-5-v1",
    "claude-opus-4-6-agentic-v1", "claude-sonnet-4-6-agentic-v1",
    "gemini-3.1-pro-agentic-v1", "glm-5-agentic-v1",
    "grok-3-agentic-v1", "grok-4.20-reasoning-agentic-v1",
    "kimi-k2.5-agentic-v1", "minimax-m2.7-agentic-v1",
    "qwen-3.5-397b-agentic-v1",
]
SAST_SCANNERS = ["semgrep", "snyk", "sonarqube"]
HYBRID_SCANNERS = ["kolega-v0.0.1"]


def load_dashboard():
    with open(DASHBOARD) as f:
        return json.load(f)


def load_ground_truth_stats():
    total_findings = 0
    vulnerable = 0
    fp_traps = 0
    frameworks = Counter()
    cwe_counts = Counter()
    for repo_dir in sorted(GT_DIR.iterdir()):
        gt_file = repo_dir / "ground-truth.json"
        if not gt_file.exists():
            continue
        with open(gt_file) as f:
            gt = json.load(f)
        fw = gt.get("framework") or "none"
        frameworks[fw] += 1
        for finding in gt.get("findings", []):
            total_findings += 1
            if finding.get("is_vulnerable", True):
                vulnerable += 1
            else:
                fp_traps += 1
            cwe_counts[finding.get("primary_cwe", "unknown")] += 1
    return {
        "total_findings": total_findings,
        "vulnerable": vulnerable,
        "fp_traps": fp_traps,
        "repo_count": len(list(GT_DIR.iterdir())),
        "frameworks": dict(frameworks.most_common()),
        "cwe_distribution": dict(cwe_counts.most_common(20)),
    }


def extract_leaderboard(dashboard):
    agg = dashboard["aggregates"]
    rows = []
    for scanner, v in agg.items():
        sm = v.get("strict_micro", {})
        m = v.get("micro", {})
        cost = v.get("cost", {})
        meta = v.get("metadata", {})
        category = (
            "Traditional SAST" if scanner in SAST_SCANNERS
            else "Hybrid" if scanner in HYBRID_SCANNERS
            else "LLM"
        )
        # Compute derived metrics from raw counts
        tp = sm.get("tp", 0)
        fp = sm.get("fp", 0)
        fn = sm.get("fn", 0)
        tn = sm.get("tn", 0)
        f1 = (2 * tp / (2 * tp + fp + fn)) if (2 * tp + fp + fn) else 0
        tpr = tp / (tp + fn) if (tp + fn) else 0
        fpr = fp / (fp + tn) if (fp + tn) else 0
        youden_j = tpr - fpr

        rows.append({
            "scanner": scanner,
            "category": category,
            "strict_micro_f2": sm.get("f2_score"),
            "micro_f2": m.get("f2_score"),
            "precision": sm.get("precision"),
            "recall": sm.get("recall"),
            "f1": round(f1, 4),
            "tpr": round(tpr, 4),
            "fpr": round(fpr, 4),
            "youden_j": round(youden_j, 4),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "repos_scored": v.get("repos_scored"),
            "repos_total": v.get("repos_total"),
            "total_cost": cost.get("total_cost"),
            "cost_per_run": cost.get("cost_per_run"),
            "cost_per_100_loc": cost.get("cost_per_100_loc"),
            "f2_stddev": v.get("f2_stddev"),
            "timeout_rate": _timeout_rate(meta),
        })
    rows.sort(key=lambda r: r["strict_micro_f2"] or 0, reverse=True)
    return rows


def _timeout_rate(meta):
    if not meta:
        return 0.0
    statuses = meta.get("exit_status_counts", {})
    total = meta.get("total_runs", 0)
    if total == 0:
        return 0.0
    success = statuses.get("success", 0)
    return round((total - success) / total, 3)


def extract_heatmap(dashboard):
    grid = dashboard["grid"]
    scanners = dashboard["scanners"]
    repos = dashboard["repos"]
    heatmap = {}
    for repo in repos:
        heatmap[repo] = {}
        for scanner in scanners:
            cell = grid.get(repo, {}).get(scanner)
            heatmap[repo][scanner] = cell.get("f2_score") if cell else None
    return heatmap


def extract_cwe_family_recall(dashboard):
    """Average per-family recall for LLM vs SAST scanners."""
    grid = dashboard["grid"]
    repos = dashboard["repos"]

    family_data = {}  # family -> {llm: [recalls], sast: [recalls]}
    for repo in repos:
        for scanner, cell in grid.get(repo, {}).items():
            if not cell or "per_family" not in cell:
                continue
            if scanner in SAST_SCANNERS:
                group = "sast"
            elif scanner in HYBRID_SCANNERS:
                continue  # exclude hybrid (Kolega) from LLM vs SAST comparison
            else:
                group = "llm"
            for family, fdata in cell["per_family"].items():
                if family not in family_data:
                    family_data[family] = {"llm": [], "sast": [], "label": fdata.get("label", family)}
                recall = fdata.get("recall")
                if recall is not None:
                    family_data[family][group].append(recall)

    result = []
    for family, data in sorted(family_data.items()):
        llm_recalls = data["llm"]
        sast_recalls = data["sast"]
        result.append({
            "family": family,
            "label": data["label"],
            "llm_avg_recall": round(sum(llm_recalls) / len(llm_recalls), 3) if llm_recalls else None,
            "sast_avg_recall": round(sum(sast_recalls) / len(sast_recalls), 3) if sast_recalls else None,
            "llm_n": len(llm_recalls),
            "sast_n": len(sast_recalls),
        })
    result.sort(key=lambda r: (r["llm_avg_recall"] or 0), reverse=True)
    return result


def extract_cost_efficiency(dashboard):
    agg = dashboard["aggregates"]
    rows = []
    for scanner in LLM_SCANNERS:
        v = agg.get(scanner, {})
        sm = v.get("strict_micro", {})
        cost = v.get("cost", {})
        rows.append({
            "scanner": scanner,
            "f2_score": sm.get("f2_score"),
            "total_cost": cost.get("total_cost"),
            "cost_per_run": cost.get("cost_per_run"),
            "cost_per_100_loc": cost.get("cost_per_100_loc"),
        })
    return rows


def extract_fp_trap_data(dashboard, dataset_stats):
    agg = dashboard["aggregates"]
    total_traps = dataset_stats["fp_traps"]  # dynamically computed from ground truth
    rows = []
    for scanner, v in agg.items():
        sm = v.get("strict_micro", {})
        tn = sm.get("tn", 0)
        traps_triggered = total_traps - tn
        category = (
            "Traditional SAST" if scanner in SAST_SCANNERS
            else "Hybrid" if scanner in HYBRID_SCANNERS
            else "LLM"
        )
        rows.append({
            "scanner": scanner,
            "category": category,
            "tn": tn,
            "traps_triggered": traps_triggered,
            "trap_fall_rate": round(traps_triggered / total_traps, 3) if total_traps else 0,
        })
    rows.sort(key=lambda r: r["trap_fall_rate"])
    return rows


def extract_scanner_metadata(dashboard):
    agg = dashboard["aggregates"]
    rows = []
    for scanner, v in agg.items():
        meta = v.get("metadata", {})
        cost = v.get("cost", {})
        rows.append({
            "scanner": scanner,
            "model": meta.get("model"),
            "prompt_version": meta.get("prompt_version"),
            "avg_input_tokens": meta.get("avg_input_tokens"),
            "avg_output_tokens": meta.get("avg_output_tokens"),
            "avg_total_tokens": meta.get("avg_total_tokens"),
            "avg_wall_clock_seconds": meta.get("avg_wall_clock_seconds"),
            "total_runs": meta.get("total_runs"),
            "success_runs": meta.get("exit_status_counts", {}).get("success"),
            "timeout_rate": _timeout_rate(meta),
        })
    return rows


def main():
    dashboard = load_dashboard()
    dataset_stats = load_ground_truth_stats()
    paper_data = {
        "generated_at": dashboard["generated_at"],
        "benchmark_version": dashboard.get("benchmark_version"),
        "ground_truth_hash": dashboard.get("ground_truth_content_hash"),
        "dataset_stats": dataset_stats,
        "leaderboard": extract_leaderboard(dashboard),
        "heatmap": extract_heatmap(dashboard),
        "cwe_family_recall": extract_cwe_family_recall(dashboard),
        "cost_efficiency": extract_cost_efficiency(dashboard),
        "fp_trap_data": extract_fp_trap_data(dashboard, dataset_stats),
        "scanner_metadata": extract_scanner_metadata(dashboard),
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(paper_data, f, indent=2)
    print(f"Paper data written to {OUTPUT}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the extraction script**

Run: `python paper/scripts/extract_paper_data.py`
Expected: `paper/tables/data.json` created with all six data sections populated.

- [ ] **Step 3: Verify output correctness**

Spot-check: Kolega should be #1 at strict_micro F2 66.5, Sonnet #2 at 53.8, SonarQube last at 7.9.

- [ ] **Step 4: Commit**

```bash
git add paper/scripts/extract_paper_data.py paper/tables/data.json
git commit -m "feat: add paper data extraction script"
```

---

### Task 3: Figure generation script

**Files:**
- Create: `paper/scripts/generate_figures.py`
- Output: `paper/figures/*.pdf`

- [ ] **Step 1: Write generate_figures.py**

Generate four figures:

1. **heatmap.pdf** — 26×15 heatmap of F2 scores. Rows = repos (sorted by avg F2), columns = scanners (sorted by aggregate F2). Color scale green (high) to red (low), gray for missing. Use matplotlib + seaborn.

2. **cost-efficiency.pdf** — Scatter plot. X-axis = total cost ($), Y-axis = strict_micro F2 score. Each point labeled with scanner name. Distinguish single-turn (triangle) vs agentic (circle). Add SAST baselines as horizontal dashed lines.

3. **cwe-family-recall.pdf** — Grouped bar chart. X-axis = CWE family, two bars per family (LLM avg recall, SAST avg recall). Sorted by LLM recall descending.

4. **fp-trap-rates.pdf** — Bar chart. X-axis = scanner, Y-axis = trap fall-through rate (%). Colored by category (SAST=blue, LLM=orange, Hybrid=green).

```python
#!/usr/bin/env python3
"""Generate paper figures from extracted data."""

import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import numpy as np

DATA = Path(__file__).resolve().parent.parent / "tables" / "data.json"
FIGURES = Path(__file__).resolve().parent.parent / "figures"


def load_data():
    with open(DATA) as f:
        return json.load(f)


def fig_heatmap(data):
    heatmap = data["heatmap"]
    leaderboard = data["leaderboard"]
    scanner_order = [r["scanner"] for r in leaderboard]
    repos = sorted(heatmap.keys())

    # Build matrix
    matrix = []
    for repo in repos:
        row = []
        for scanner in scanner_order:
            val = heatmap[repo].get(scanner)
            row.append(val if val is not None else float("nan"))
        matrix.append(row)
    matrix = np.array(matrix)

    # Sort repos by average F2 (ignoring NaN)
    avg_per_repo = np.nanmean(matrix, axis=1)
    repo_order = np.argsort(avg_per_repo)[::-1]
    matrix = matrix[repo_order]
    repos_sorted = [repos[i] for i in repo_order]

    # Short repo names (strip "realvuln-" prefix)
    repo_labels = [r.replace("realvuln-", "") for r in repos_sorted]
    scanner_labels = [s.replace("-agentic-v1", "").replace("-v1", "").replace("-v0.0.1", "") for s in scanner_order]

    fig, ax = plt.subplots(figsize=(14, 10))
    cmap = plt.cm.RdYlGn
    cmap.set_bad(color="lightgray")
    im = ax.imshow(matrix, cmap=cmap, aspect="auto", vmin=0, vmax=100)

    ax.set_xticks(range(len(scanner_labels)))
    ax.set_xticklabels(scanner_labels, rotation=45, ha="right", fontsize=7)
    ax.set_yticks(range(len(repo_labels)))
    ax.set_yticklabels(repo_labels, fontsize=7)
    ax.set_xlabel("Scanner")
    ax.set_ylabel("Repository")
    ax.set_title("F2 Score by Repository and Scanner")
    plt.colorbar(im, ax=ax, label="F2 Score (0-100)", shrink=0.8)
    plt.tight_layout()
    fig.savefig(FIGURES / "heatmap.pdf", dpi=300)
    plt.close()
    print("Generated heatmap.pdf")


def fig_cost_efficiency(data):
    cost_data = data["cost_efficiency"]
    leaderboard = data["leaderboard"]

    # SAST baselines
    sast_f2 = {r["scanner"]: r["strict_micro_f2"] for r in leaderboard if r["category"] == "Traditional SAST"}

    fig, ax = plt.subplots(figsize=(10, 6))
    for row in cost_data:
        if row["total_cost"] and row["f2_score"]:
            marker = "^" if "v1" in row["scanner"] and "agentic" not in row["scanner"] else "o"
            ax.scatter(row["total_cost"], row["f2_score"], s=80, marker=marker, zorder=5)
            label = row["scanner"].replace("-agentic-v1", "").replace("-v1", "")
            ax.annotate(label, (row["total_cost"], row["f2_score"]),
                        textcoords="offset points", xytext=(5, 5), fontsize=6)

    # SAST baselines
    for scanner, f2 in sast_f2.items():
        ax.axhline(y=f2, linestyle="--", alpha=0.5, linewidth=0.8)
        ax.text(ax.get_xlim()[1] * 0.95, f2 + 0.5, scanner, fontsize=6, ha="right", alpha=0.6)

    ax.set_xlabel("Total Cost ($)")
    ax.set_ylabel("F2 Score (strict_micro)")
    ax.set_title("Cost-Efficiency: F2 Score vs Total Evaluation Cost")
    plt.tight_layout()
    fig.savefig(FIGURES / "cost-efficiency.pdf", dpi=300)
    plt.close()
    print("Generated cost-efficiency.pdf")


def fig_cwe_family_recall(data):
    families = data["cwe_family_recall"]
    # Filter to families with both LLM and SAST data
    families = [f for f in families if f["llm_avg_recall"] is not None and f["sast_avg_recall"] is not None]

    labels = [f["label"] for f in families]
    llm_recalls = [f["llm_avg_recall"] for f in families]
    sast_recalls = [f["sast_avg_recall"] for f in families]

    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(x - width / 2, llm_recalls, width, label="LLM Scanners (avg)", color="steelblue")
    ax.bar(x + width / 2, sast_recalls, width, label="Traditional SAST (avg)", color="coral")

    ax.set_ylabel("Average Recall")
    ax.set_title("Per-CWE-Family Recall: LLM vs Traditional SAST")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=7)
    ax.legend()
    ax.set_ylim(0, 1.0)
    plt.tight_layout()
    fig.savefig(FIGURES / "cwe-family-recall.pdf", dpi=300)
    plt.close()
    print("Generated cwe-family-recall.pdf")


def fig_fp_trap_rates(data):
    fp_data = data["fp_trap_data"]
    colors = {"Traditional SAST": "steelblue", "LLM": "orange", "Hybrid": "green"}

    labels = [r["scanner"].replace("-agentic-v1", "").replace("-v1", "").replace("-v0.0.1", "") for r in fp_data]
    rates = [r["trap_fall_rate"] * 100 for r in fp_data]
    bar_colors = [colors.get(r["category"], "gray") for r in fp_data]

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.bar(range(len(labels)), rates, color=bar_colors)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=7)
    ax.set_ylabel("FP Trap Fall-Through Rate (%)")
    ax.set_title("False Positive Trap Effectiveness by Scanner")

    # Legend
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor=c, label=l) for l, c in colors.items()]
    ax.legend(handles=legend_elements)
    plt.tight_layout()
    fig.savefig(FIGURES / "fp-trap-rates.pdf", dpi=300)
    plt.close()
    print("Generated fp-trap-rates.pdf")


def main():
    FIGURES.mkdir(parents=True, exist_ok=True)
    data = load_data()
    fig_heatmap(data)
    fig_cost_efficiency(data)
    fig_cwe_family_recall(data)
    fig_fp_trap_rates(data)
    print("All figures generated.")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run figure generation**

Run: `python paper/scripts/generate_figures.py`
Expected: Four PDFs in `paper/figures/`.

- [ ] **Step 3: Visually inspect figures**

Open each PDF and verify: heatmap has correct dimensions, scatter plot has labeled points, bar charts are readable.

- [ ] **Step 4: Commit**

```bash
git add paper/scripts/generate_figures.py paper/figures/
git commit -m "feat: add paper figure generation script"
```

---

### Task 4: BibTeX references

**Files:**
- Create: `paper/references.bib`

- [ ] **Step 1: Write references.bib**

All 13 references from the spec, plus any additional works cited in the text. Each entry must have correct arXiv IDs, author names, and years.

Key entries (from spec):
- `feiglin2026sastbench` — SastBench, arXiv:2601.02941
- `owaspbenchmark` — OWASP Benchmark project
- `fluidattacks2025` — Fluid Attacks tool benchmark
- `zeropath2024` — ZeroPath blog post
- `ghost2025cast` — Ghost Security CAST report
- `delaitre2018satev` — SATE V report
- `delaitre2023satevi` — SATE VI report
- `ding2024primevul` — PrimeVul, arXiv:2403.18624
- `jimenez2024swebench` — SWE-Bench, arXiv:2310.06770
- `zhu2025cvebench` — CVE-Bench, arXiv:2503.17332
- `dubniczky2025castle` — CASTLE, arXiv:2503.09433
- `bhandari2021cvefixes` — CVEFixes, PROMISE '21
- `li2025cleanvul` — CleanVul, arXiv:2411.17274
- `wang2024reposvul` — ReposVul, arXiv:2401.13169
- `boland2012juliet` — Juliet Test Suite
- `cycode2024benchmark` — Cycode blog benchmark
- `dryrun2025sast` — DryRun Security SAST report

Each entry formatted as `@article` or `@misc` with full metadata.

- [ ] **Step 2: Verify BibTeX compiles**

Run: `cd paper && pdflatex main && bibtex main`
Expected: No undefined citation warnings.

- [ ] **Step 3: Commit**

```bash
git add paper/references.bib
git commit -m "feat: add paper bibliography"
```

---

### Task 5: Write Section 1 — Introduction

**Files:**
- Modify: `paper/sections/introduction.tex`

- [ ] **Step 1: Write the introduction**

Follow the spec (Section 1):
- Opening hook with three FP statistics (Ghost Security, Fluid Attacks, SATE)
- The four-point gap analysis
- Brief "what exists and why it falls short"
- Three contribution bullet points (use `\begin{enumerate}`)
- Closing line about open-source release

Cite: `\cite{ghost2025cast}`, `\cite{fluidattacks2025}`, `\cite{delaitre2018satev}`, `\cite{feiglin2026sastbench}`, `\cite{owaspbenchmark}`.

Target length: ~1.5 pages.

- [ ] **Step 2: Compile and check**

Run: `cd paper && pdflatex main`
Expected: Introduction renders correctly, citations show as `[?]` (resolved after bibtex).

- [ ] **Step 3: Commit**

```bash
git add paper/sections/introduction.tex
git commit -m "feat: write paper introduction"
```

---

### Task 6: Write Section 2 — Background & Related Work

**Files:**
- Modify: `paper/sections/related-work.tex`

- [ ] **Step 1: Write the related work section**

Follow the spec (Section 2):
- Comparison table (Table 1) as a `\begin{table*}` with `\begin{tabular}`. 8 columns, 8 rows. Use checkmarks (✓) and crosses (✗) with `\checkmark` and `$\times$`.
- Five narrative categories as subsections or paragraphs: synthetic benchmarks, unreleased datasets, vendor benchmarks, dataset quality research, agentic benchmarks.
- Honest self-critique paragraph at the end.

Cite all relevant references per category.

Target length: ~1.5–2 pages.

- [ ] **Step 2: Compile and check table renders**

Run: `cd paper && pdflatex main`
Expected: Table 1 renders with proper alignment, no overflow.

- [ ] **Step 3: Commit**

```bash
git add paper/sections/related-work.tex
git commit -m "feat: write related work section with comparison table"
```

---

### Task 7: Write Section 3 — Benchmark Design

**Files:**
- Modify: `paper/sections/benchmark-design.tex`

- [ ] **Step 1: Write the benchmark design section**

Four subsections per spec (Sections 3.1–3.4):

**3.1 Target Type Taxonomy** — Define Types 1–5, note v1.0 covers Type 1 only. Brief, ~0.25 pages.

**3.2 Dataset Construction** — 26 repos, 796 findings (676 + 120), pinned commits, selection criteria, authorship metadata, ground truth schema. Include a small example JSON snippet showing one GT entry. Include a table: dataset statistics (repos, findings, FP traps, frameworks, CWE families). ~1 page.

**3.3 Matching Algorithm** — Three-field matching with formal notation. File path exact match, CWE ∈ acceptable_cwes, |line - gt_line| ≤ 10. Preference ordering, one-to-one. Maybe a small algorithm pseudocode block. ~0.5 pages.

**3.4 Scoring** — F2 formula, additional metrics, per-family/severity breakdowns, multi-run aggregation, strict_micro vs micro, incomplete run handling. ~0.75 pages.

Target length: ~2.5 pages total.

- [ ] **Step 2: Compile and check**

Run: `cd paper && pdflatex main`
Expected: All subsections render, JSON snippet displays correctly in `\begin{verbatim}` or `lstlisting`.

- [ ] **Step 3: Commit**

```bash
git add paper/sections/benchmark-design.tex
git commit -m "feat: write benchmark design section"
```

---

### Task 8: Write Section 4 — Experimental Setup

**Files:**
- Modify: `paper/sections/experimental-setup.tex`

- [ ] **Step 1: Write the experimental setup section**

Three subsections per spec (Sections 4.1–4.3):

**4.1 Scanners Evaluated** — Three categories (SAST, LLM, Hybrid). Include the Scanner Classification table (Table 2) from the spec with Scanner, Category, Mode, Open Source columns. ~0.75 pages.

**4.2 LLM Evaluation Modes** — Single-turn vs agentic, prompt template description (content-hashed, shared across models), output schema, cost tracking with pricing date. Prompt sensitivity discussion. ~0.5 pages.

**4.3 Reproducibility** — Scan results committed, benchmark manifest, re-run commands. ~0.25 pages.

Target length: ~1.5 pages.

- [ ] **Step 2: Compile and check**

Run: `cd paper && pdflatex main`
Expected: Scanner classification table renders correctly.

- [ ] **Step 3: Commit**

```bash
git add paper/sections/experimental-setup.tex
git commit -m "feat: write experimental setup section"
```

---

### Task 9: Write Section 5 — Results

**Files:**
- Modify: `paper/sections/results.tex`

This is the longest section. Uses actual data from `paper/tables/data.json`.

- [ ] **Step 1: Write the results section**

Five subsections per spec (Sections 5.1–5.5):

**5.1 Aggregate Rankings** — Table 3: Leaderboard. All 15 scanners ranked by strict_micro F2. Columns: Scanner, Category, F2 (strict), F2 (micro), Prec, Recall, F1, Youden's J, TP, FP, FN, Repos, Cost. All metrics computed from raw TP/FP/FN/TN counts. Headline narrative: Kolega leads at 66.5, best LLM (Sonnet) at 53.8, best SAST (Semgrep/Snyk) at ~18, SonarQube at 7.9. Note: "11 LLM scanner configurations (10 distinct models, with Haiku evaluated in both single-turn and agentic modes)". ~1 page.

**5.2 The 26×15 Heatmap** — Reference Figure 1 (heatmap.pdf). Discuss patterns: which repos are easy/hard, which separate LLMs from SAST. Note completion rates and gray cells. ~0.5 pages.

**5.3 Per-CWE-Family Analysis** — Reference Figure 2 (cwe-family-recall.pdf). Narrative on where LLMs vs SAST excel. ~0.5 pages.

**5.4 Cost-Efficiency** — Reference Figure 3 (cost-efficiency.pdf). Kimi at $2.17 with F2 48.3 vs Gemini at $27.24 with F2 53.0. Single-turn Haiku v1 ($4.94, F2 27.0) vs agentic Haiku ($5.24, F2 39.4). ~0.5 pages.

**5.5 FP Trap Effectiveness** — Reference Figure 4 (fp-trap-rates.pdf). How many of 120 traps each scanner fell for. ~0.5 pages.

Target length: ~3 pages.

- [ ] **Step 2: Compile and check all tables and figure references**

Run: `cd paper && pdflatex main`
Expected: Tables render, figure references show as `Figure ?` (resolved when figures are included).

- [ ] **Step 3: Commit**

```bash
git add paper/sections/results.tex
git commit -m "feat: write results section with tables and figure refs"
```

---

### Task 10: Write Section 6 — Analysis & Discussion

**Files:**
- Modify: `paper/sections/discussion.tex`

- [ ] **Step 1: Write the discussion section**

Three subsections per spec (Sections 6.1–6.3):

**6.1 Key Findings** — Four discussion points: LLM vs SAST strengths, agentic vs single-turn value, model scaling, agreement analysis. ~1 page.

**6.2 Limitations** — Seven bullet points from spec (Python only, Type 1 only, vendor conflict, GT subjectivity, LLM non-determinism, scanner configuration, timeouts). ~0.5 pages.

**6.3 Threats to Validity** — Data contamination, selection bias. ~0.25 pages.

Target length: ~1.75 pages.

- [ ] **Step 2: Compile and check**

Run: `cd paper && pdflatex main`

- [ ] **Step 3: Commit**

```bash
git add paper/sections/discussion.tex
git commit -m "feat: write discussion section"
```

---

### Task 11: Write Sections 7–10 (Living Benchmark, Conclusion, Ethics, Data Availability)

**Files:**
- Modify: `paper/sections/living-benchmark.tex`
- Modify: `paper/sections/conclusion.tex`
- Modify: `paper/sections/ethics.tex`
- Modify: `paper/sections/data-availability.tex`

- [ ] **Step 1: Write Section 7 — The Living Benchmark**

Three subsections: versioning strategy, roadmap (Types 2–5, multi-language, more scanners), community contribution. ~1 page.

- [ ] **Step 2: Write Section 8 — Conclusion**

Three paragraphs: what we did, what we found (headline numbers), what comes next. Final line with URLs. ~0.5 pages.

- [ ] **Step 3: Write Section 9 — Ethics Statement**

Brief paragraph: intentionally vulnerable repos only, no zero-days, vendor relationship disclosed. ~0.25 pages.

- [ ] **Step 4: Write Section 10 — Data Availability**

Structured checklist of all published artifacts with links. ~0.25 pages.

- [ ] **Step 5: Compile and check**

Run: `cd paper && pdflatex main`

- [ ] **Step 6: Commit**

```bash
git add paper/sections/living-benchmark.tex paper/sections/conclusion.tex paper/sections/ethics.tex paper/sections/data-availability.tex
git commit -m "feat: write remaining paper sections (7-10)"
```

---

### Task 12: Write the Abstract

**Files:**
- Modify: `paper/sections/abstract.tex`

- [ ] **Step 1: Write the abstract**

~150–200 words following the spec outline:
1. Problem (1-2 sentences): SAST tools noisy, LLM scanners emerging, no open benchmark
2. Contribution (2-3 sentences): RealVuln — 26 repos, 796 findings, 120 FP traps, 15 scanners, F2-weighted
3. Key findings (1-2 sentences): headline results from the data
4. Release (1 sentence): all artifacts open-sourced
5. Living benchmark (1 sentence): versioned, community-driven

Use `\begin{abstract}...\end{abstract}`.

- [ ] **Step 2: Compile full paper**

Run: `cd paper && pdflatex main && bibtex main && pdflatex main && pdflatex main`
Expected: Complete PDF with all sections, resolved citations, no warnings.

- [ ] **Step 3: Commit**

```bash
git add paper/sections/abstract.tex
git commit -m "feat: write paper abstract"
```

---

### Task 13: Final assembly and review

**Files:**
- Modify: `paper/main.tex` (if needed for formatting fixes)
- All `paper/sections/*.tex` (final polish)

- [ ] **Step 1: Full build**

Run: `cd paper && make all`
Expected: data.json generated, figures generated, PDF compiled.

- [ ] **Step 2: Check page count**

Target: 10–12 pages. If over, identify sections to trim. If under, identify where to expand.

- [ ] **Step 3: Check all cross-references**

Verify: all `\ref{}` and `\cite{}` resolve. No `??` in output.

- [ ] **Step 4: Check all table numbers match data.json**

Spot-check: leaderboard F2 scores, TP/FP/FN counts, cost figures against `reports/dashboard.json`.

- [ ] **Step 5: Proofread for consistency**

Check: scanner names consistent throughout, "15 scanners" everywhere (not 12), "18 CWE families" (not 16), "796 findings" matches.

- [ ] **Step 6: Final commit**

```bash
git add paper/
git commit -m "feat: complete RealVuln paper v1 draft"
```
