"""Ground truth loader and finding matcher."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from parsers.base import NormalisedFinding, normalise_path

DEFAULT_LINE_TOLERANCE = 10

# Values of a GT entry's optional ``scoring`` field. Entries without the field
# are scored (the default); ``non_scoring`` entries are reviewed locations whose
# status cannot be settled from the source alone. They are excluded from
# scoring in both directions: reporting one is not a false positive, missing one
# is not a false negative. See README "Non-scoring entries".
SCORING_SCORED = "scored"
SCORING_NON_SCORING = "non_scoring"
VALID_SCORING = frozenset({SCORING_SCORED, SCORING_NON_SCORING})


@dataclass
class MatchResult:
    """Classification of a single finding or ground truth entry.

    ``NS`` (non-scoring) results come in two shapes:
    - a scanner finding withheld because it landed on a non-scoring entry
      (``scanner_finding`` set, ``ground_truth_entry`` = the entry hit);
    - a non-scoring GT entry itself (``scanner_finding`` None), emitted so the
      report can list every entry and its ``non_scoring_reason``.
    Neither contributes to any metric.
    """

    classification: str  # "TP" | "FP" | "FN" | "TN" | "NS"
    ground_truth_id: Optional[str]  # GT finding ID, if matched
    scanner_finding: Optional[NormalisedFinding]  # None for FN/TN/NS-entry
    ground_truth_entry: Optional[dict]  # The GT entry; None for unmatched FPs


def is_non_scoring(gt_entry: dict) -> bool:
    """True if the GT entry is excluded from scoring in both directions.

    Raises on an out-of-vocabulary ``scoring`` value rather than defaulting to
    scored: a typo that silently scores is the worse failure direction.
    """
    scoring = gt_entry.get("scoring", SCORING_SCORED)
    if scoring not in VALID_SCORING:
        raise ValueError(
            f"Ground truth entry {gt_entry.get('id')!r} has invalid scoring "
            f"{scoring!r} (expected one of {sorted(VALID_SCORING)})"
        )
    return scoring == SCORING_NON_SCORING


def load_ground_truth(gt_path: str) -> dict:
    """Load ground truth JSON and normalise file paths."""
    with open(gt_path) as f:
        gt = json.load(f)

    if "findings" not in gt:
        raise ValueError(f"Ground truth missing 'findings' key: {gt_path}")
    if "repo_id" not in gt:
        raise ValueError(f"Ground truth missing 'repo_id' key: {gt_path}")

    for entry in gt["findings"]:
        try:
            is_non_scoring(entry)  # validate the scoring vocabulary up front
        except ValueError as exc:
            raise ValueError(f"{exc}: {gt_path}") from None
        entry["file"] = normalise_path(entry["file"])
        for loc in entry.get("acceptable_locations", []):
            if "file" in loc:
                loc["file"] = normalise_path(loc["file"])

    return gt


def _gt_line_range(gt_entry: dict) -> tuple[Optional[int], Optional[int]]:
    """Extract (start_line, end_line) from a GT entry's location."""
    loc = gt_entry.get("location", {})
    return loc.get("start_line"), loc.get("end_line")


def _location_line_range(location: dict) -> tuple[Optional[int], Optional[int]]:
    """Extract (start_line, end_line) from a GT location object."""
    return location.get("start_line"), location.get("end_line")


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


def _finding_within_gt_locations(finding: NormalisedFinding, gt_entry: dict) -> bool:
    """File + line check against the primary and any acceptable locations."""
    gt_start, gt_end = _gt_line_range(gt_entry)
    if (
        finding.file == gt_entry["file"]
        and _line_within_tolerance(finding.line, gt_start, gt_end)
    ):
        return True

    for loc in gt_entry.get("acceptable_locations", []):
        loc_start, loc_end = _location_line_range(loc)
        if (
            finding.file == loc.get("file")
            and _line_within_tolerance(finding.line, loc_start, loc_end)
        ):
            return True

    return False


def _finding_matches_gt(finding: NormalisedFinding, gt_entry: dict) -> bool:
    """Check public GT matching semantics for primary and acceptable locations."""
    if finding.cwe not in gt_entry["acceptable_cwes"]:
        return False
    return _finding_within_gt_locations(finding, gt_entry)


def _first_non_scoring_hit(
    finding: NormalisedFinding, non_scoring_entries: list[dict]
) -> Optional[dict]:
    """Return the non-scoring entry whose region contains the finding, if any.

    Deliberately location-only (no CWE gate): the entry records that the
    location's status is unsettled, so any report on it — whatever CWE the
    scanner chose — is equally unsettled and must not be charged as an FP.

    Without the CWE gate, the "no line → don't penalise" leniency in
    ``_line_within_tolerance`` would let a file-level finding be withheld by
    any non-scoring entry in the same file. A finding must therefore carry a
    line to be withheld. Ties (overlapping entries) resolve to the lowest id so
    the audit trail is deterministic.
    """
    if finding.line is None:
        return None
    hits = [e for e in non_scoring_entries if _finding_within_gt_locations(finding, e)]
    return min(hits, key=lambda e: e["id"]) if hits else None


def match_findings(
    findings: list[NormalisedFinding],
    ground_truth: dict,
) -> list[MatchResult]:
    """Match scanner findings against ground truth (file + cwe + line mode).

    Algorithm:
    1. Partition GT into scored entries and non-scoring entries. Non-scoring
       entries take NO part in matching: a label-blind assignment could let
       one win a finding away from a co-located vulnerable entry and silently
       turn a TP into a FN.
    2. For each finding, find scored GT entries where:
       - file matches
       - cwe in acceptable_cwes
       - line within [start_line-10, end_line+10] (or ±10 of start_line if no end_line)
       If the primary location does not match, public acceptable_locations
       are checked with the same file + line semantics; CWE still matches
       against the parent GT entry's acceptable_cwes.
    3. When multiple scored entries match, prefer is_vulnerable=true
       (scanner gets credit for real vuln, not penalised by co-located trap).
    4. Classify: match + is_vulnerable=true -> TP;
       match + is_vulnerable=false -> FP.
    5. A finding that matched nothing scored is checked against non-scoring
       entries on file + line only (a finding with no line is never withheld).
       A hit -> NS (withheld, not an FP). Otherwise -> FP. Many findings may
       hit the same non-scoring entry.
    6. Unmatched scored GT: is_vulnerable=true -> FN; is_vulnerable=false -> TN.
       Every non-scoring GT entry -> NS.
    """
    gt_entries = ground_truth["findings"]
    scored_entries = [e for e in gt_entries if not is_non_scoring(e)]
    non_scoring_entries = [e for e in gt_entries if is_non_scoring(e)]

    results: list[MatchResult] = []
    matched_gt_ids: set[str] = set()

    for finding in findings:
        candidates = [
            gt_entry
            for gt_entry in scored_entries
            if gt_entry["id"] not in matched_gt_ids
            and _finding_matches_gt(finding, gt_entry)
        ]

        if candidates:
            # Prefer is_vulnerable=true so scanner gets credit for real vuln
            candidates.sort(key=lambda g: (not g["is_vulnerable"],))
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
            continue

        ns_hit = _first_non_scoring_hit(finding, non_scoring_entries)
        if ns_hit is not None:
            results.append(
                MatchResult(
                    classification="NS",
                    ground_truth_id=ns_hit["id"],
                    scanner_finding=finding,
                    ground_truth_entry=ns_hit,
                )
            )
            continue

        results.append(
            MatchResult(
                classification="FP",
                ground_truth_id=None,
                scanner_finding=finding,
                ground_truth_entry=None,
            )
        )

    # Unmatched scored ground truth entries
    for gt_entry in scored_entries:
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

    # Non-scoring entries are listed for auditability; never counted.
    for gt_entry in non_scoring_entries:
        results.append(
            MatchResult(
                classification="NS",
                ground_truth_id=gt_entry["id"],
                scanner_finding=None,
                ground_truth_entry=gt_entry,
            )
        )

    return results
