"""Ground truth loader and finding matcher."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from parsers.base import NormalisedFinding, normalise_path

DEFAULT_LINE_TOLERANCE = 10


@dataclass
class MatchResult:
    """Classification of a single finding or ground truth entry."""

    classification: str  # "TP" | "FP" | "FN" | "TN"
    ground_truth_id: Optional[str]  # GT finding ID, if matched
    scanner_finding: Optional[NormalisedFinding]  # None for FN/TN
    ground_truth_entry: Optional[dict]  # The GT entry; None for unmatched FPs


def load_ground_truth(gt_path: str) -> dict:
    """Load ground truth JSON and normalise file paths."""
    with open(gt_path) as f:
        gt = json.load(f)

    if "findings" not in gt:
        raise ValueError(f"Ground truth missing 'findings' key: {gt_path}")
    if "repo_id" not in gt:
        raise ValueError(f"Ground truth missing 'repo_id' key: {gt_path}")

    for entry in gt["findings"]:
        entry["file"] = normalise_path(entry["file"])

    return gt


def _gt_line_range(gt_entry: dict) -> tuple[Optional[int], Optional[int]]:
    """Extract (start_line, end_line) from a GT entry's location."""
    loc = gt_entry.get("location", {})
    return loc.get("start_line"), loc.get("end_line")


def _line_within_tolerance(
    finding_line: Optional[int],
    gt_start: Optional[int],
    gt_end: Optional[int] = None,
) -> bool:
    """Check if finding line is within the GT range ± tolerance.

    If the GT has both start_line and end_line, the finding matches if it
    falls within [start_line - tol, end_line + tol]. If only start_line is
    present, falls back to ±tol from start_line. If either side is None,
    we don't penalise.
    """
    if finding_line is None or gt_start is None:
        return True  # Can't compare — don't penalise
    tol = DEFAULT_LINE_TOLERANCE
    low = gt_start - tol
    high = (gt_end if gt_end is not None else gt_start) + tol
    return low <= finding_line <= high


def match_findings(
    findings: list[NormalisedFinding],
    ground_truth: dict,
) -> list[MatchResult]:
    """Match scanner findings against ground truth (file + cwe + line mode).

    Algorithm:
    1. For each finding, find GT entries where:
       - file matches
       - cwe in acceptable_cwes
       - line within [start_line-10, end_line+10] (or ±10 of start_line if no end_line)
    2. When multiple GT entries match, prefer is_vulnerable=true
       (scanner gets credit for real vuln, not penalised by co-located trap).
    3. Classify: match + is_vulnerable=true -> TP;
       match + is_vulnerable=false -> FP. No match -> FP.
    4. Unmatched GT: is_vulnerable=true -> FN; is_vulnerable=false -> TN.
    """
    gt_entries = ground_truth["findings"]
    results: list[MatchResult] = []
    matched_gt_ids: set[str] = set()

    for finding in findings:
        # Collect all candidate GT matches — try primary location first,
        # then alternative locations (for scanners that report attack chains)
        locations_to_try = [(finding.file, finding.line)]
        if finding.alternative_locations:
            locations_to_try.extend(finding.alternative_locations)

        candidates: list[dict] = []
        for try_file, try_line in locations_to_try:
            for gt_entry in gt_entries:
                if gt_entry["id"] in matched_gt_ids:
                    continue
                gt_start, gt_end = _gt_line_range(gt_entry)
                if (
                    try_file == gt_entry["file"]
                    and finding.cwe in gt_entry["acceptable_cwes"]
                    and _line_within_tolerance(try_line, gt_start, gt_end)
                ):
                    candidates.append(gt_entry)

        if candidates:
            # Prefer is_vulnerable=true so scanner gets credit for real vuln
            candidates.sort(key=lambda g: (not g["is_vulnerable"],))

            if finding.alternative_locations:
                # For findings with alternative locations (attack-chain scanners),
                # one audit report may describe multiple distinct vulnerabilities.
                # Match ALL candidates so each real vuln found counts as a TP.
                # Count 0 FPs since the finding matched at least one GT entry.
                for candidate in candidates:
                    classification = "TP" if candidate["is_vulnerable"] else "FP"
                    results.append(
                        MatchResult(
                            classification=classification,
                            ground_truth_id=candidate["id"],
                            scanner_finding=finding,
                            ground_truth_entry=candidate,
                        )
                    )
                    matched_gt_ids.add(candidate["id"])
            else:
                # Standard single-location finding: match one GT entry
                best = candidates[0]
                classification = "TP" if best["is_vulnerable"] else "FP"
                results.append(
                    MatchResult(
                        classification=classification,
                        ground_truth_id=best["id"],
                        scanner_finding=finding,
                        ground_truth_entry=best,
                    )
                )
                matched_gt_ids.add(best["id"])
        else:
            results.append(
                MatchResult(
                    classification="FP",
                    ground_truth_id=None,
                    scanner_finding=finding,
                    ground_truth_entry=None,
                )
            )

    # Unmatched ground truth entries
    for gt_entry in gt_entries:
        if gt_entry["id"] not in matched_gt_ids:
            classification = "FN" if gt_entry["is_vulnerable"] else "TN"
            results.append(
                MatchResult(
                    classification=classification,
                    ground_truth_id=gt_entry["id"],
                    scanner_finding=None,
                    ground_truth_entry=gt_entry,
                )
            )

    return results
