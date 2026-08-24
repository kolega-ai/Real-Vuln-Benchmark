#!/usr/bin/env python3
"""Smoke test — verify the scoring pipeline works with known reference data.

Scores semgrep results on realvuln-pygoat and checks against expected values.
Use this to validate your setup after installation.

Usage:
    python3 smoke_test.py
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import json

from scorer.matcher import load_ground_truth, match_findings
from scorer.metrics import compute_scorecard
from parsers import get_parser

# Reference values: semgrep on realvuln-pygoat. Deterministic for a given ground
# truth, but NOT constant across releases — a GT enhancement campaign that adds
# vulnerabilities to pygoat moves every number here. These were last regenerated
# for benchmark 2.0.0 (pygoat: 78 vulns / 10 traps).
#
# If this test fails, suspect these constants before suspecting the scorer: the
# usual cause is ground truth having moved without them being updated. Confirm
# with `python3 validate_gt.py` and `python3 score.py --repo realvuln-pygoat
# --scanner semgrep`, then update the values below in the same commit as the GT
# change.
EXPECTED = {
    "repo": "realvuln-pygoat",
    "scanner": "semgrep",
    "gt_version": "2.0.0",
    "tp": 25,
    "fp": 108,
    "fn": 53,
    "tn": 9,
    "f2": 28.1,
}


def run_smoke_test() -> bool:
    repo = EXPECTED["repo"]
    scanner = EXPECTED["scanner"]

    # Check files exist
    gt_path = PROJECT_ROOT / "ground-truth" / repo / "ground-truth.json"
    results_dir = PROJECT_ROOT / "scan-results" / repo / scanner
    results_file = results_dir / "results.json"

    if not gt_path.exists():
        print(f"FAIL: Ground truth not found: {gt_path}")
        return False
    if not results_file.exists():
        print(f"FAIL: Scan results not found: {results_file}")
        return False

    # Load and score
    gt = load_ground_truth(str(gt_path))
    parser = get_parser(scanner)
    findings = parser.parse(str(results_file))
    matches = match_findings(findings, gt)

    families_path = PROJECT_ROOT / "config" / "cwe-families.json"
    with open(families_path) as f:
        cwe_families = json.load(f)

    card = compute_scorecard(repo, scanner, "", matches, cwe_families)

    # Check values
    passed = True

    def check(name: str, actual: int | float, expected: int | float, tolerance: float = 0):
        nonlocal passed
        if abs(actual - expected) > tolerance:
            print(f"  FAIL: {name} = {actual}, expected {expected}")
            passed = False
        else:
            print(f"  OK:   {name} = {actual}")

    print(f"Smoke test: {scanner} on {repo}\n")

    check("TP", card.tp, EXPECTED["tp"])
    check("FP", card.fp, EXPECTED["fp"])
    check("FN", card.fn, EXPECTED["fn"])
    check("TN", card.tn, EXPECTED["tn"])
    check("F2", round(card.f2_score, 1), EXPECTED["f2"], tolerance=0.1)

    if passed:
        print("\nAll checks passed.")
    else:
        print(
            "\nSome checks failed. The most likely cause is that the reference "
            "values above are stale — a ground-truth change moves them — rather "
            "than a broken scoring pipeline. See the note on EXPECTED."
        )

    return passed


def main() -> int:
    return 0 if run_smoke_test() else 1


if __name__ == "__main__":
    sys.exit(main())
