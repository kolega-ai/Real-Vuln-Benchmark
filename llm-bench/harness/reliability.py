"""Cross-run reliability analysis for LLM scanner benchmarks.

Given multiple runs of the same model on the same repo, compute:
- Agreement rate: % of findings present in ALL runs
- Flip rate: % of findings present in SOME but not ALL runs
- Per-GT-entry stability classification
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from pathlib import Path

from parsers import get_parser
from scorer.matcher import load_ground_truth, match_findings, MatchResult
from scorer.metrics import compute_scorecard


@dataclass
class FindingStability:
    """Stability classification for a single ground-truth entry across runs."""

    gt_id: str
    classification: str  # "stable_found", "stable_missed", "unstable"
    found_in_runs: int  # How many runs found it
    total_runs: int


@dataclass
class ReliabilityReport:
    """Reliability metrics across multiple runs of one model on one repo."""

    model: str
    repo: str
    num_runs: int

    # F2 statistics
    f2_scores: list[float] = field(default_factory=list)
    f2_mean: float = 0.0
    f2_std: float = 0.0

    # Agreement metrics
    agreement_rate: float = 0.0  # % findings in ALL runs
    flip_rate: float = 0.0  # % findings in SOME but not ALL runs

    # Per-GT-entry stability
    stable_found: list[str] = field(default_factory=list)
    stable_missed: list[str] = field(default_factory=list)
    unstable: list[str] = field(default_factory=list)

    # Full stability details
    finding_stability: list[FindingStability] = field(default_factory=list)

    def to_dict(self) -> dict:
        """JSON-serializable dict."""
        return {
            "model": self.model,
            "repo": self.repo,
            "num_runs": self.num_runs,
            "f2_scores": [round(s, 1) for s in self.f2_scores],
            "f2_mean": round(self.f2_mean, 1),
            "f2_std": round(self.f2_std, 1),
            "agreement_rate": round(self.agreement_rate, 4),
            "flip_rate": round(self.flip_rate, 4),
            "stable_found_count": len(self.stable_found),
            "stable_missed_count": len(self.stable_missed),
            "unstable_count": len(self.unstable),
            "stable_found": self.stable_found,
            "stable_missed": self.stable_missed,
            "unstable": self.unstable,
        }


def compute_reliability(
    run_results: list[list[MatchResult]],
    ground_truth: dict,
    model: str,
    repo: str,
    cwe_families: dict,
) -> ReliabilityReport:
    """Compute reliability metrics across multiple runs.

    Args:
        run_results: List of match results for each run.
        ground_truth: Ground truth dict (with findings).
        model: Model slug.
        repo: Repo slug.
        cwe_families: CWE families dict for scorecard computation.

    Returns:
        ReliabilityReport with all reliability metrics.
    """
    num_runs = len(run_results)
    report = ReliabilityReport(model=model, repo=repo, num_runs=num_runs)

    if num_runs == 0:
        return report

    # Compute F2 scores for each run
    for i, results in enumerate(run_results):
        card = compute_scorecard(
            ground_truth["repo_id"],
            model,
            f"run-{i + 1}",
            results,
            cwe_families,
        )
        report.f2_scores.append(card.f2_score)

    report.f2_mean = statistics.mean(report.f2_scores) if report.f2_scores else 0.0
    report.f2_std = statistics.stdev(report.f2_scores) if len(report.f2_scores) >= 2 else 0.0

    # Analyze per-GT-entry stability
    gt_entries = ground_truth["findings"]
    vuln_entries = [e for e in gt_entries if e["is_vulnerable"]]

    if not vuln_entries:
        return report

    # Pre-compute TP id sets per run (avoid rebuilding per GT entry)
    tp_ids_per_run = [
        {r.ground_truth_id for r in results if r.classification == "TP"}
        for results in run_results
    ]

    # For each GT entry, count how many runs found it (TP match)
    for gt_entry in vuln_entries:
        gt_id: str = gt_entry["id"]
        found_count = sum(1 for tp_ids in tp_ids_per_run if gt_id in tp_ids)

        if found_count == num_runs:
            classification = "stable_found"
            report.stable_found.append(gt_id)
        elif found_count == 0:
            classification = "stable_missed"
            report.stable_missed.append(gt_id)
        else:
            classification = "unstable"
            report.unstable.append(gt_id)

        report.finding_stability.append(
            FindingStability(
                gt_id=gt_id,
                classification=classification,
                found_in_runs=found_count,
                total_runs=num_runs,
            )
        )

    total_vuln = len(vuln_entries)
    report.agreement_rate = len(report.stable_found) / total_vuln if total_vuln > 0 else 0.0
    report.flip_rate = len(report.unstable) / total_vuln if total_vuln > 0 else 0.0

    return report


def compute_reliability_from_files(
    result_files: list[Path],
    gt_path: Path,
    scanner_slug: str,
    model: str,
    cwe_families: dict,
) -> ReliabilityReport:
    """Convenience: compute reliability from result file paths.

    Args:
        result_files: Paths to Semgrep-format result JSON files (one per run).
        gt_path: Path to ground-truth JSON.
        scanner_slug: Scanner slug for parser lookup.
        model: Model slug for the report.
        cwe_families: CWE families dict.

    Returns:
        ReliabilityReport.
    """
    ground_truth = load_ground_truth(str(gt_path))
    repo = ground_truth["repo_id"]
    parser = get_parser(scanner_slug)

    run_results: list[list[MatchResult]] = []
    for rf in result_files:
        findings = parser.parse(str(rf))
        results = match_findings(findings, ground_truth)
        run_results.append(results)

    return compute_reliability(run_results, ground_truth, model, repo, cwe_families)
