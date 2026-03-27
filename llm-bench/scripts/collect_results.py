#!/usr/bin/env python3
"""Collect and summarize LLM benchmark results.

Reads scan-results/{repo}/{model-slug}/ directories, scores each run,
and produces a summary JSON with per-model, per-repo, and aggregate metrics.

Usage:
    python collect_results.py
    python collect_results.py --models claude-haiku-4-v1 claude-sonnet-4-v1
    python collect_results.py --repos realvuln-pygoat --output results.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
LLM_BENCH_DIR = SCRIPT_DIR.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

from parsers import get_parser
from scorer.matcher import load_ground_truth, match_findings
from scorer.metrics import compute_scorecard

from harness.reliability import compute_reliability


def load_cwe_families() -> dict:
    """Load CWE families config."""
    path = PROJECT_ROOT / "config" / "cwe-families.json"
    with open(path) as f:
        return json.load(f)


def discover_llm_scanners(scan_dir: Path) -> set[str]:
    """Find scanner slugs that look like LLM models (have run-N.json files)."""
    llm_slugs: set[str] = set()
    for repo_dir in scan_dir.iterdir():
        if not repo_dir.is_dir():
            continue
        for scanner_dir in repo_dir.iterdir():
            if not scanner_dir.is_dir():
                continue
            # LLM results have run-N.json pattern
            run_files = list(scanner_dir.glob("run-*.json"))
            # Exclude .metrics.json
            run_files = [f for f in run_files if not f.name.endswith(".metrics.json")]
            if run_files:
                llm_slugs.add(scanner_dir.name)
    return llm_slugs


def collect_results(
    scan_dir: Path,
    gt_dir: Path,
    scanner_slugs: set[str] | None = None,
    repo_filter: list[str] | None = None,
) -> dict:
    """Collect and score all LLM benchmark results.

    Returns a structured dict with per-model, per-repo results.
    """
    cwe_families = load_cwe_families()

    if scanner_slugs is None:
        scanner_slugs = discover_llm_scanners(scan_dir)

    if not scanner_slugs:
        print("No LLM scanner results found.", file=sys.stderr)
        return {}

    # Discover repos
    repos = []
    for d in sorted(gt_dir.iterdir()):
        if d.is_dir() and (d / "ground-truth.json").exists():
            if repo_filter is None or d.name in repo_filter:
                repos.append(d.name)

    results: dict[str, dict] = {}

    for slug in sorted(scanner_slugs):
        model_results: dict[str, dict] = {}

        for repo in repos:
            scanner_dir = scan_dir / repo / slug
            if not scanner_dir.is_dir():
                continue

            # Find run files (exclude .metrics.json)
            run_files = sorted([
                f for f in scanner_dir.glob("run-*.json")
                if not f.name.endswith(".metrics.json")
            ])
            if not run_files:
                continue

            gt_path = gt_dir / repo / "ground-truth.json"
            ground_truth = load_ground_truth(str(gt_path))
            parser = get_parser(slug)

            # Score each run, collecting match results for reliability
            run_scores: list[dict] = []
            all_match_results: list[list] = []
            for rf in run_files:
                findings = parser.parse(str(rf))
                match_results = match_findings(findings, ground_truth)
                all_match_results.append(match_results)
                card = compute_scorecard(
                    ground_truth["repo_id"], slug, "", match_results, cwe_families,
                )
                run_score = {
                    "file": rf.name,
                    "findings_count": len(findings),
                    **card.to_dict(),
                }

                # Load metrics if available
                metrics_path = rf.with_suffix("").with_suffix(".metrics.json")
                if metrics_path.exists():
                    with open(metrics_path) as f:
                        run_score["operational_metrics"] = json.load(f)

                run_scores.append(run_score)

            # Compute reliability if multiple runs (reuse match results)
            reliability = None
            if len(all_match_results) >= 2:
                rel = compute_reliability(
                    all_match_results, ground_truth, slug, repo, cwe_families,
                )
                reliability = rel.to_dict()

            model_results[repo] = {
                "runs": run_scores,
                "num_runs": len(run_scores),
                "reliability": reliability,
            }

        if model_results:
            results[slug] = model_results

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect LLM benchmark results")
    parser.add_argument(
        "--models", nargs="*", default=None,
        help="Scanner slugs to include (default: auto-discover)",
    )
    parser.add_argument(
        "--repos", nargs="*", default=None,
        help="Repo slugs to include (default: all)",
    )
    parser.add_argument(
        "--output", "-o", type=Path,
        default=PROJECT_ROOT / "reports" / "llm-benchmark-results.json",
        help="Output JSON path",
    )
    args = parser.parse_args()

    scan_dir = PROJECT_ROOT / "scan-results"
    gt_dir = PROJECT_ROOT / "ground-truth"

    scanner_slugs = set(args.models) if args.models else None
    results = collect_results(scan_dir, gt_dir, scanner_slugs, args.repos)

    if not results:
        print("No results to collect.", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Results written to: {args.output}")
    print(f"Models: {sorted(results.keys())}")
    for slug, repos_data in sorted(results.items()):
        print(f"  {slug}: {len(repos_data)} repos scored")

    return 0


if __name__ == "__main__":
    sys.exit(main())
