"""Metrics computation and scorecard generation."""
from __future__ import annotations

from dataclasses import dataclass, field

from scorer.matcher import MatchResult


@dataclass
class FamilyScore:
    """Score breakdown for a single CWE family."""

    family: str
    label: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0


@dataclass
class SeverityScore:
    """Score breakdown for a single severity level."""

    severity: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    recall: float = 0.0


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator > 0 else 0.0


# CVSS-weighted metrics. A GT entry contributes its CVSS v3.1 base score
# (0-10) instead of 1, so a missed 9.8 costs ~10x a missed 1.0. Unmatched
# scanner findings have no GT entry to take a score from, so they are weighted
# by the scanner's own reported severity (mid-band of the CVSS severity
# ranges); a finding without severity falls back to the repo's mean GT weight.
# Trap entries (is_vulnerable=false) are deliberately scored 0.0 in GT, so an
# FP on a trap is also weighted by scanner severity, never by the trap's score.
SCANNER_SEVERITY_WEIGHT = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 2.0,
    "info": 0.5,
}


def cvss_base_score(gt_entry: dict | None) -> float | None:
    if not gt_entry:
        return None
    cvss = gt_entry.get("cvss")
    if not isinstance(cvss, dict):
        return None
    score = cvss.get("base_score")
    if isinstance(score, bool) or not isinstance(score, (int, float, str)):
        return None
    try:
        return float(score)
    except ValueError:
        return None


@dataclass
class ScoreCard:
    """Complete scoring results for one scanner on one repo."""

    repo_id: str
    scanner: str
    timestamp: str

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    # Non-scoring: excluded from every metric below, reported for transparency.
    ns: int = 0  # scanner findings withheld (landed on a non-scoring entry)
    ns_gt: int = 0  # non-scoring GT entries in this repo
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    f2: float = 0.0  # F-beta with beta=2, recall-weighted
    f2_score: float = 0.0  # F2 × 100, 0-100 scale
    f3: float = 0.0  # F-beta with beta=3, recall-weighted (9:1)
    f3_score: float = 0.0  # F3 × 100, 0-100 scale
    tpr: float = 0.0  # TP / (TP + FN) — same as recall
    fpr: float = 0.0  # FP / (FP + TN)
    youden_j: float = 0.0  # TPR - FPR

    # CVSS-weighted variants. Weights are CVSS v3.1 base scores (0-10), so
    # these are sums of scores rather than counts. cvss_coverage is the share
    # of scored GT entries in this repo that carry a cvss block; when it is 0
    # every weight is 1.0 and the weighted numbers equal the unweighted ones.
    cvss_coverage: float = 0.0
    cvss_tp_weight: float = 0.0
    cvss_fp_weight: float = 0.0
    cvss_fn_weight: float = 0.0
    cvss_precision: float = 0.0
    cvss_recall: float = 0.0
    cvss_f3: float = 0.0
    cvss_f3_score: float = 0.0

    per_family: dict[str, FamilyScore] = field(default_factory=dict)
    per_severity: dict[str, SeverityScore] = field(default_factory=dict)
    details: list[MatchResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        """JSON-serializable dict (excludes raw details)."""
        return {
            "scanner": self.scanner,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "ns": self.ns,
            "ns_gt": self.ns_gt,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "f2": round(self.f2, 4),
            "f2_score": self.f2_score,
            "f3": round(self.f3, 4),
            "f3_score": self.f3_score,
            "tpr": round(self.tpr, 4),
            "fpr": round(self.fpr, 4),
            "youden_j": round(self.youden_j, 4),
            "cvss_coverage": round(self.cvss_coverage, 4),
            "cvss_tp_weight": round(self.cvss_tp_weight, 1),
            "cvss_fp_weight": round(self.cvss_fp_weight, 1),
            "cvss_fn_weight": round(self.cvss_fn_weight, 1),
            "cvss_precision": round(self.cvss_precision, 4),
            "cvss_recall": round(self.cvss_recall, 4),
            "cvss_f3": round(self.cvss_f3, 4),
            "cvss_f3_score": self.cvss_f3_score,
            "per_family": {
                k: {
                    "label": v.label,
                    "tp": v.tp,
                    "fp": v.fp,
                    "fn": v.fn,
                    "precision": round(v.precision, 4),
                    "recall": round(v.recall, 4),
                }
                for k, v in sorted(self.per_family.items())
            },
            "per_severity": {
                k: {
                    "tp": v.tp,
                    "fp": v.fp,
                    "fn": v.fn,
                    "recall": round(v.recall, 4),
                }
                for k, v in sorted(self.per_severity.items())
            },
            "details": [
                {
                    "classification": d.classification,
                    "ground_truth_id": d.ground_truth_id,
                    "file": d.scanner_finding.file if d.scanner_finding else None,
                    "cwe": d.scanner_finding.cwe
                    if d.scanner_finding
                    else (
                        d.ground_truth_entry.get("primary_cwe")
                        if d.ground_truth_entry
                        else None
                    ),
                }
                for d in self.details
            ],
        }


def _build_cwe_to_families(cwe_families: dict) -> dict[str, list[tuple[str, str]]]:
    """Build reverse lookup: CWE string -> [(family_slug, label), ...]."""
    mapping: dict[str, list[tuple[str, str]]] = {}
    for slug, info in cwe_families.get("families", {}).items():
        label = info["label"]
        for cwe in info["cwes"]:
            mapping.setdefault(cwe, []).append((slug, label))
    return mapping


def _apply_cvss_weights(card: ScoreCard, match_results: list[MatchResult]) -> None:
    scored = [r for r in match_results if r.classification in ("TP", "FP", "FN", "TN")]
    gt_backed = [r for r in scored if r.ground_truth_entry is not None]
    known = [
        s for s in (cvss_base_score(r.ground_truth_entry) for r in gt_backed)
        if s is not None
    ]
    card.cvss_coverage = _safe_div(len(known), len(gt_backed))

    if not known:
        card.cvss_tp_weight = float(card.tp)
        card.cvss_fp_weight = float(card.fp)
        card.cvss_fn_weight = float(card.fn)
        card.cvss_precision = card.precision
        card.cvss_recall = card.recall
        card.cvss_f3 = card.f3
        card.cvss_f3_score = card.f3_score
        return

    mean_weight = sum(known) / len(known)

    def gt_weight(r: MatchResult) -> float:
        score = cvss_base_score(r.ground_truth_entry)
        return mean_weight if score is None else score

    def scanner_weight(r: MatchResult) -> float:
        severity = (r.scanner_finding.severity or "").lower() if r.scanner_finding else ""
        return SCANNER_SEVERITY_WEIGHT.get(severity, mean_weight)

    for r in scored:
        if r.classification == "TP":
            card.cvss_tp_weight += gt_weight(r)
        elif r.classification == "FN":
            card.cvss_fn_weight += gt_weight(r)
        elif r.classification == "FP":
            card.cvss_fp_weight += scanner_weight(r)

    card.cvss_precision = _safe_div(
        card.cvss_tp_weight, card.cvss_tp_weight + card.cvss_fp_weight
    )
    card.cvss_recall = _safe_div(
        card.cvss_tp_weight, card.cvss_tp_weight + card.cvss_fn_weight
    )
    card.cvss_f3 = _safe_div(
        10.0 * card.cvss_precision * card.cvss_recall,
        9.0 * card.cvss_precision + card.cvss_recall,
    )
    card.cvss_f3_score = round(card.cvss_f3 * 100, 1)


def compute_scorecard(
    repo_id: str,
    scanner: str,
    timestamp: str,
    match_results: list[MatchResult],
    cwe_families: dict,
) -> ScoreCard:
    """Compute aggregate and per-family/severity metrics from match results."""
    card = ScoreCard(
        repo_id=repo_id,
        scanner=scanner,
        timestamp=timestamp,
        details=match_results,
    )

    # Aggregate counts
    for r in match_results:
        if r.classification == "TP":
            card.tp += 1
        elif r.classification == "FP":
            card.fp += 1
        elif r.classification == "FN":
            card.fn += 1
        elif r.classification == "TN":
            card.tn += 1
        elif r.classification == "NS":
            if r.scanner_finding is not None:
                card.ns += 1
            else:
                card.ns_gt += 1

    card.precision = _safe_div(card.tp, card.tp + card.fp)
    card.recall = _safe_div(card.tp, card.tp + card.fn)
    card.f1 = _safe_div(
        2.0 * card.precision * card.recall, card.precision + card.recall
    )
    card.f2 = _safe_div(
        5.0 * card.precision * card.recall, 4.0 * card.precision + card.recall
    )
    card.f2_score = round(card.f2 * 100, 1)
    card.f3 = _safe_div(
        10.0 * card.precision * card.recall, 9.0 * card.precision + card.recall
    )
    card.f3_score = round(card.f3 * 100, 1)
    card.tpr = card.recall  # Same metric, different name
    card.fpr = _safe_div(card.fp, card.fp + card.tn)
    card.youden_j = card.tpr - card.fpr

    _apply_cvss_weights(card, match_results)

    # Breakdowns only see scored results; NS entries would otherwise create
    # empty family/severity buckets.
    scored_results = [r for r in match_results if r.classification != "NS"]

    # Per-family breakdown (bucket GT entries by primary_cwe)
    cwe_to_families = _build_cwe_to_families(cwe_families)
    family_scores: dict[str, FamilyScore] = {}

    for r in scored_results:
        gt = r.ground_truth_entry
        if gt is None:
            continue
        primary_cwe = gt.get("primary_cwe", "")
        families = cwe_to_families.get(primary_cwe, [])
        if not families:
            families = [("other", "Other")]

        # Assign to the first matching family
        fam_slug, fam_label = families[0]
        if fam_slug not in family_scores:
            family_scores[fam_slug] = FamilyScore(family=fam_slug, label=fam_label)
        fs = family_scores[fam_slug]

        if r.classification == "TP":
            fs.tp += 1
        elif r.classification == "FP":
            fs.fp += 1
        elif r.classification == "FN":
            fs.fn += 1

    for fs in family_scores.values():
        fs.precision = _safe_div(fs.tp, fs.tp + fs.fp)
        fs.recall = _safe_div(fs.tp, fs.tp + fs.fn)

    card.per_family = family_scores

    # Per-severity breakdown (use GT entry severity)
    severity_scores: dict[str, SeverityScore] = {}

    for r in scored_results:
        gt = r.ground_truth_entry
        if gt is None:
            continue
        sev = gt.get("severity", "unknown") or "unknown"
        if sev not in severity_scores:
            severity_scores[sev] = SeverityScore(severity=sev)
        ss = severity_scores[sev]

        if r.classification == "TP":
            ss.tp += 1
        elif r.classification == "FP":
            ss.fp += 1
        elif r.classification == "FN":
            ss.fn += 1

    for ss in severity_scores.values():
        ss.recall = _safe_div(ss.tp, ss.tp + ss.fn)

    card.per_severity = severity_scores

    return card
