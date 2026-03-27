#!/usr/bin/env python3
"""RealVuln Benchmark Scorer CLI."""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

# Allow imports from the realvuln package root
sys.path.insert(0, str(SCRIPT_DIR))

from parsers import get_parser
from scorer.matcher import load_ground_truth, match_findings
from scorer.metrics import compute_scorecard, ScoreCard


def discover_scanners(scan_dir: Path) -> list[str]:
    """List scanner slugs by discovering subdirectories."""
    if not scan_dir.is_dir():
        return []
    return sorted(d.name for d in scan_dir.iterdir() if d.is_dir())


def discover_result_files(scanner_dir: Path) -> list[Path]:
    """Find all JSON result files for a scanner.

    Excludes .metrics.json files (operational metrics from LLM benchmark runs).
    """
    if not scanner_dir.is_dir():
        return []
    return sorted(
        f for f in scanner_dir.glob("*.json")
        if not f.name.endswith(".metrics.json")
    )


def print_summary_table(
    repo_id: str, commit_sha: str, scorecards: list[ScoreCard]
) -> None:
    """Print the main comparison table to stdout."""
    print()
    print(f"RealVuln Scorecard — {repo_id} @ {commit_sha[:12]}")
    print()
    header = (
        f"{'Scanner':<20} {'F2 Score':>8}  "
        f"{'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}  "
        f"{'Prec':>6} {'Recall':>6} {'F1':>6} {'F2':>6}"
    )
    print(header)
    print("=" * len(header))

    for card in scorecards:
        print(
            f"{card.scanner:<20} {card.f2_score:>7.1f}   "
            f"{card.tp:>4} {card.fp:>4} {card.fn:>4} {card.tn:>4}  "
            f"{card.precision:>6.3f} {card.recall:>6.3f} {card.f1:>6.3f} {card.f2:>6.3f}"
        )

    print()


def print_family_table(card: ScoreCard) -> None:
    """Print per-CWE-family breakdown for a single scanner."""
    if not card.per_family:
        return
    print(f"Per CWE Family ({card.scanner}):")
    header = f"{'Family':<35} {'TP':>4} {'FP':>4} {'FN':>4}  {'Recall':>6}"
    print(header)
    print("-" * len(header))
    for slug in sorted(card.per_family.keys()):
        fs = card.per_family[slug]
        print(
            f"{fs.label:<35} {fs.tp:>4} {fs.fp:>4} {fs.fn:>4}  {fs.recall:>6.3f}"
        )
    print()


def print_multirun_summary(scanner: str, run_cards: list[ScoreCard]) -> None:
    """Print mean ± stddev for multi-run scanner."""
    n = len(run_cards)
    if n < 2:
        return

    precisions = [c.precision for c in run_cards]
    recalls = [c.recall for c in run_cards]
    f1s = [c.f1 for c in run_cards]
    f2s = [c.f2 for c in run_cards]
    f2_scores = [c.f2_score for c in run_cards]

    print(f"Multi-run summary ({scanner}, {n} runs):")
    print(
        f"  F2 Score:   {statistics.mean(f2_scores):.1f} "
        f"± {statistics.stdev(f2_scores):.1f}"
    )
    print(
        f"  Precision:  {statistics.mean(precisions):.3f} "
        f"± {statistics.stdev(precisions):.3f}"
    )
    print(
        f"  Recall:     {statistics.mean(recalls):.3f} "
        f"± {statistics.stdev(recalls):.3f}"
    )
    print(
        f"  F1:         {statistics.mean(f1s):.3f} "
        f"± {statistics.stdev(f1s):.3f}"
    )
    print(
        f"  F2:         {statistics.mean(f2s):.3f} "
        f"± {statistics.stdev(f2s):.3f}"
    )
    print()


def build_markdown(
    repo_id: str,
    commit_sha: str,
    timestamp: str,
    ground_truth: dict,
    scorecards: dict[str, ScoreCard],
    multirun: dict[str, list[ScoreCard]],
) -> str:
    """Build a human-readable markdown scorecard."""
    gt_meta = ground_truth
    gt_findings = gt_meta["findings"]
    vuln_count = sum(1 for f in gt_findings if f["is_vulnerable"])
    fp_trap_count = sum(1 for f in gt_findings if not f["is_vulnerable"])

    lines: list[str] = []
    w = lines.append

    # Header
    w(f"# RealVuln Scorecard — {repo_id}")
    w("")
    w(f"**Commit:** `{commit_sha[:12]}`  ")
    w(f"**Generated:** {timestamp}  ")
    w(f"**Ground Truth:** {vuln_count} vulnerabilities, {fp_trap_count} false-positive traps  ")
    repo_url = gt_meta.get("repo_url", "")
    if repo_url:
        w(f"**Repository:** {repo_url}  ")
    w(f"**Type:** {gt_meta.get('type', '?')} | **Language:** {gt_meta.get('language', '?')} | **Authorship:** {gt_meta.get('authorship', '?')}")
    w("")

    # Glossary
    w("---")
    w("")
    w("## How to Read This Report")
    w("")
    w("### Classification")
    w("")
    w("Every scanner finding and ground truth entry is classified into one of four categories:")
    w("")
    w("| Classification | What it means |")
    w("|----------------|---------------|")
    w("| **True Positive (TP)** | Scanner correctly found a real vulnerability |")
    w("| **False Positive (FP)** | Scanner flagged something that isn't vulnerable (noise) |")
    w("| **False Negative (FN)** | Scanner missed a real vulnerability |")
    w("| **True Negative (TN)** | Scanner correctly ignored a false-positive trap (code that looks suspicious but is safe) |")
    w("")
    w("### Metrics")
    w("")
    w("| Metric | Formula | What it tells you |")
    w("|--------|---------|-------------------|")
    w("| **F2 Score** | F2 x 100 | **Primary metric.** Recall-weighted score on a 0\u2013100 scale. Higher is better. See below. |")
    w("| **Precision** | TP / (TP + FP) | Of everything the scanner flagged, what fraction was actually vulnerable? High precision = low noise. |")
    w("| **Recall** | TP / (TP + FN) | Of all real vulnerabilities, what fraction did the scanner find? High recall = few missed vulns. |")
    w("| **F1** | 2 x (Prec x Recall) / (Prec + Recall) | Harmonic mean of precision and recall. Weights both equally. |")
    w("| **F2** | 5 x (Prec x Recall) / (4 x Prec + Recall) | F-beta with beta=2. Weights recall **4x more** than precision. Range 0\u20131. |")
    w("")
    w("### Why F2 Score?")
    w("")
    w("F2 Score is our primary metric because in security scanning, **missing a real vulnerability (false negative) is far more dangerous than a false alarm**. A false positive costs a developer 30 seconds to dismiss; a missed vulnerability can lead to a breach.")
    w("")
    w("The F2 score uses beta=2, which weights recall 4x more than precision. This means a scanner that finds most real vulnerabilities but has some noise will score higher than a quiet scanner that misses critical issues.")
    w("")
    w("| F2 Score | Rating |")
    w("|----------|--------|")
    w("| 80\u2013100 | Excellent \u2014 catches nearly everything, manageable noise |")
    w("| 60\u201379 | Good \u2014 solid coverage, some gaps |")
    w("| 40\u201359 | Fair \u2014 missing significant vulns or too noisy |")
    w("| 20\u201339 | Poor \u2014 major gaps in detection |")
    w("| 0\u201319 | Failing \u2014 barely finding anything |")
    w("")

    # Headline figures per scanner
    w("---")
    w("")
    w("## Headline Results")
    w("")

    for slug, card in scorecards.items():
        w(f"### {slug}")
        w("")
        w(f"| Metric | Value |")
        w(f"|--------|-------|")
        w(f"| **F2 Score** | **{card.f2_score:.1f} / 100** |")
        w(f"| Precision | {card.precision:.1%} |")
        w(f"| Recall | {card.recall:.1%} |")
        w(f"| F1 | {card.f1:.3f} |")
        w(f"| F2 | {card.f2:.3f} |")
        w(f"| TP / FP / FN / TN | {card.tp} / {card.fp} / {card.fn} / {card.tn} |")
        w("")

        # Multi-run stats
        if slug in multirun and len(multirun[slug]) >= 2:
            rc = multirun[slug]
            w(f"*Multi-run ({len(rc)} runs):*")
            w("")
            w(f"| Metric | Mean | Stddev |")
            w(f"|--------|------|--------|")
            for metric_name, vals in [
                ("F2 Score", [c.f2_score for c in rc]),
                ("Precision", [c.precision for c in rc]),
                ("Recall", [c.recall for c in rc]),
                ("F1", [c.f1 for c in rc]),
                ("F2", [c.f2 for c in rc]),
            ]:
                w(f"| {metric_name} | {statistics.mean(vals):.3f} | {statistics.stdev(vals):.3f} |")
            w("")

    # Comparison table (if multiple scanners)
    if len(scorecards) > 1:
        w("---")
        w("")
        w("## Scanner Comparison")
        w("")
        w("| Scanner | F2 Score | TP | FP | FN | TN | Prec | Recall | F1 | F2 |")
        w("|---------|--------:|---:|---:|---:|---:|-----:|-------:|---:|---:|")
        for slug, card in scorecards.items():
            w(
                f"| {slug} | **{card.f2_score:.1f}** | {card.tp} | {card.fp} | {card.fn} | {card.tn} "
                f"| {card.precision:.3f} | {card.recall:.3f} | {card.f1:.3f} "
                f"| {card.f2:.3f} |"
            )
        w("")

    # Per-family breakdown
    w("---")
    w("")
    w("## Per CWE Family Breakdown")
    w("")

    for slug, card in scorecards.items():
        if not card.per_family:
            continue
        if len(scorecards) > 1:
            w(f"### {slug}")
            w("")
        w("| Family | TP | FP | FN | Precision | Recall |")
        w("|--------|---:|---:|---:|----------:|-------:|")
        for fam_slug in sorted(card.per_family.keys()):
            fs = card.per_family[fam_slug]
            w(
                f"| {fs.label} | {fs.tp} | {fs.fp} | {fs.fn} "
                f"| {fs.precision:.3f} | {fs.recall:.3f} |"
            )
        w("")

    # Per-severity breakdown
    w("---")
    w("")
    w("## Per Severity Breakdown")
    w("")

    for slug, card in scorecards.items():
        if not card.per_severity:
            continue
        if len(scorecards) > 1:
            w(f"### {slug}")
            w("")
        w("| Severity | TP | FP | FN | Recall |")
        w("|----------|---:|---:|---:|-------:|")
        sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
        for sev in sev_order:
            if sev in card.per_severity:
                ss = card.per_severity[sev]
                w(f"| {sev.title()} | {ss.tp} | {ss.fp} | {ss.fn} | {ss.recall:.3f} |")
        w("")

    # Detailed findings
    w("---")
    w("")
    w("## Detailed Results")
    w("")

    for slug, card in scorecards.items():
        if not card.details:
            continue
        if len(scorecards) > 1:
            w(f"### {slug}")
            w("")

        # Group by classification
        for cls_label, cls_code, emoji in [
            ("True Positives", "TP", "\u2705"),
            ("False Positives", "FP", "\u274c"),
            ("False Negatives (Missed)", "FN", "\u26a0\ufe0f"),
            ("True Negatives", "TN", "\u26aa"),
        ]:
            items = [d for d in card.details if d.classification == cls_code]
            if not items:
                continue
            w(f"**{cls_label} ({len(items)}):**")
            w("")
            for d in items:
                gt_id = d.ground_truth_id or "—"
                if d.scanner_finding:
                    f = d.scanner_finding
                    line_str = f"L{f.line}" if f.line else ""
                    w(f"- {emoji} `{f.cwe}` on `{f.file}`{':' + line_str if line_str else ''} → matched **{gt_id}**")
                elif d.ground_truth_entry:
                    gt = d.ground_truth_entry
                    loc = gt.get("location", {})
                    line_str = f"L{loc.get('start_line', '?')}"
                    w(f"- {emoji} `{gt.get('primary_cwe', '?')}` on `{gt.get('file', '?')}`:{line_str} — **{gt_id}** ({gt.get('vulnerability_class', '?')})")
            w("")

    return "\n".join(lines)



def build_report(
    repo_id: str,
    commit_sha: str,
    timestamp: str,
    scorecards: dict[str, ScoreCard],
    multirun: dict[str, list[ScoreCard]],
) -> dict:
    """Build the JSON report structure."""
    report = {
        "schema_version": "1.0",
        "repo_id": repo_id,
        "commit_sha": commit_sha,
        "generated_at": timestamp,
        "scanners": {},
    }

    for slug, card in scorecards.items():
        scanner_data = card.to_dict()

        # Add multi-run stats if available
        if slug in multirun and len(multirun[slug]) >= 2:
            run_cards = multirun[slug]
            precisions = [c.precision for c in run_cards]
            recalls = [c.recall for c in run_cards]
            f1s = [c.f1 for c in run_cards]
            f2s = [c.f2 for c in run_cards]
            f2_scores = [c.f2_score for c in run_cards]
            scanner_data["runs"] = len(run_cards)
            scanner_data["mean_f2_score"] = round(statistics.mean(f2_scores), 1)
            scanner_data["stddev_f2_score"] = round(statistics.stdev(f2_scores), 1)
            scanner_data["mean_precision"] = round(statistics.mean(precisions), 4)
            scanner_data["stddev_precision"] = round(statistics.stdev(precisions), 4)
            scanner_data["mean_recall"] = round(statistics.mean(recalls), 4)
            scanner_data["stddev_recall"] = round(statistics.stdev(recalls), 4)
            scanner_data["mean_f1"] = round(statistics.mean(f1s), 4)
            scanner_data["stddev_f1"] = round(statistics.stdev(f1s), 4)
            scanner_data["mean_f2"] = round(statistics.mean(f2s), 4)
            scanner_data["stddev_f2"] = round(statistics.stdev(f2s), 4)

        report["scanners"][slug] = scanner_data

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="RealVuln Benchmark Scorer")
    parser.add_argument(
        "--repo", required=True, help="Target repo slug (e.g. juice-shop)"
    )
    parser.add_argument(
        "--scanner",
        action="append",
        dest="scanners",
        help="Scanner slug (repeatable)",
    )
    parser.add_argument(
        "--all-scanners",
        action="store_true",
        help="Score all scanners found in scan-results/{repo}/",
    )
    parser.add_argument(
        "--runs",
        action="store_true",
        help="Score each result file independently and report mean ± stddev",
    )
    parser.add_argument(
        "--gt-dir",
        type=str,
        default=None,
        help="Override ground truth directory (default: ground-truth/)",
    )
    args = parser.parse_args()

    # Load ground truth
    gt_base = Path(args.gt_dir) if args.gt_dir else SCRIPT_DIR / "ground-truth"
    gt_path = gt_base / args.repo / "ground-truth.json"
    if not gt_path.exists():
        print(f"Error: Ground truth not found: {gt_path}", file=sys.stderr)
        return 1
    ground_truth = load_ground_truth(str(gt_path))
    repo_id = ground_truth["repo_id"]
    commit_sha = ground_truth.get("commit_sha", "unknown")

    # Load CWE families
    families_path = SCRIPT_DIR / "config" / "cwe-families.json"
    if not families_path.exists():
        print(f"Error: CWE families not found: {families_path}", file=sys.stderr)
        return 1
    with open(families_path) as f:
        cwe_families = json.load(f)

    # Discover scanners
    scan_dir = SCRIPT_DIR / "scan-results" / args.repo
    if args.all_scanners:
        scanner_slugs = discover_scanners(scan_dir)
    elif args.scanners:
        scanner_slugs = args.scanners
    else:
        print("Error: specify --scanner or --all-scanners", file=sys.stderr)
        return 1

    if not scanner_slugs:
        print(f"Error: No scanners found in {scan_dir}", file=sys.stderr)
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()
    all_scorecards: dict[str, ScoreCard] = {}
    multirun_cards: dict[str, list[ScoreCard]] = {}
    for slug in scanner_slugs:
        scanner_dir = scan_dir / slug
        result_files = discover_result_files(scanner_dir)
        if not result_files:
            print(f"Warning: No result files for {slug} in {scanner_dir}")
            continue

        try:
            p = get_parser(slug)
        except ValueError as e:
            print(f"Warning: {e}")
            continue

        if args.runs and len(result_files) > 1:
            # Multi-run mode: score each file independently
            run_cards: list[ScoreCard] = []
            run_entries: list[tuple[str, ScoreCard]] = []
            for rf in result_files:
                findings = p.parse(str(rf))
                results = match_findings(findings, ground_truth)
                card = compute_scorecard(
                    repo_id, slug, timestamp, results, cwe_families
                )
                run_cards.append(card)
                run_entries.append((rf.stem, card))

            multirun_cards[slug] = run_cards

            # Use the mean as the "representative" scorecard (summary only, no details)
            avg_card = ScoreCard(
                repo_id=repo_id,
                scanner=slug,
                timestamp=timestamp,
                tp=round(statistics.mean([c.tp for c in run_cards])),
                fp=round(statistics.mean([c.fp for c in run_cards])),
                fn=round(statistics.mean([c.fn for c in run_cards])),
                tn=round(statistics.mean([c.tn for c in run_cards])),
            )
            avg_card.precision = statistics.mean([c.precision for c in run_cards])
            avg_card.recall = statistics.mean([c.recall for c in run_cards])
            avg_card.f1 = statistics.mean([c.f1 for c in run_cards])
            avg_card.f2 = statistics.mean([c.f2 for c in run_cards])
            avg_card.f2_score = round(statistics.mean([c.f2_score for c in run_cards]), 1)
            avg_card.tpr = statistics.mean([c.tpr for c in run_cards])
            avg_card.fpr = statistics.mean([c.fpr for c in run_cards])
            avg_card.youden_j = statistics.mean([c.youden_j for c in run_cards])
            avg_card.per_family = run_cards[0].per_family
            avg_card.per_severity = run_cards[0].per_severity
            all_scorecards[slug] = avg_card
        else:
            # Single run: use first (or only) file
            rf = result_files[0]
            findings = p.parse(str(rf))
            results = match_findings(findings, ground_truth)
            card = compute_scorecard(
                repo_id, slug, timestamp, results, cwe_families
            )
            all_scorecards[slug] = card

    if not all_scorecards:
        print("Error: No results to score.", file=sys.stderr)
        return 1

    # Print results
    print_summary_table(repo_id, commit_sha, list(all_scorecards.values()))

    # Print per-family breakdown for each scanner
    for card in all_scorecards.values():
        print_family_table(card)

    # Print multi-run summaries
    for slug, run_cards in multirun_cards.items():
        print_multirun_summary(slug, run_cards)

    # Write JSON report
    report_dir = SCRIPT_DIR / "reports" / args.repo
    report_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    report_path = report_dir / f"scorecard-{date_str}.json"

    report = build_report(repo_id, commit_sha, timestamp, all_scorecards, multirun_cards)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    # Write markdown report
    md_path = report_dir / f"scorecard-{date_str}.md"
    md_content = build_markdown(
        repo_id, commit_sha, timestamp, ground_truth, all_scorecards, multirun_cards
    )
    md_path.write_text(md_content)

    print(f"Report written to: {report_path}")
    print(f"Markdown written to: {md_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
