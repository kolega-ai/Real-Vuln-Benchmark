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

    # Per-family breakdown (bucket GT entries by primary_cwe)
    cwe_to_families = _build_cwe_to_families(cwe_families)
    family_scores: dict[str, FamilyScore] = {}

    for r in match_results:
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

    for r in match_results:
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
