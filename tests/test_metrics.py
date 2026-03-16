"""Tests for metrics computation."""
from __future__ import annotations

from parsers.base import NormalisedFinding
from scorer.matcher import MatchResult
from scorer.metrics import (
    ScoreCard,
    compute_scorecard,
    _safe_div,
)


def _make_result(
    cls: str,
    gt_id: str | None = None,
    cwe: str = "CWE-89",
    severity: str = "high",
) -> MatchResult:
    finding = NormalisedFinding(
        file="app.py", cwe=cwe, line=42,
        function=None, severity=severity, rule_id="test",
        message="test", scanner="test",
    ) if cls in ("TP", "FP") else None

    gt_entry = {
        "id": gt_id or f"gt-{cls}",
        "is_vulnerable": cls in ("TP", "FN"),
        "primary_cwe": cwe,
        "severity": severity,
    } if cls in ("TP", "FP", "FN", "TN") else None

    return MatchResult(
        classification=cls,
        ground_truth_id=gt_id,
        scanner_finding=finding,
        ground_truth_entry=gt_entry,
    )


CWE_FAMILIES = {
    "families": {
        "injection": {
            "label": "SQL Injection",
            "cwes": ["CWE-89", "CWE-564"],
        },
        "xss": {
            "label": "Cross-Site Scripting",
            "cwes": ["CWE-79"],
        },
    }
}


class TestSafeDiv:
    def test_normal(self):
        assert _safe_div(3, 4) == 0.75

    def test_zero_denominator(self):
        assert _safe_div(3, 0) == 0.0

    def test_zero_numerator(self):
        assert _safe_div(0, 4) == 0.0


class TestComputeScorecard:
    def test_perfect_scanner(self):
        """All TPs, no FPs, no FNs."""
        results = [
            _make_result("TP", gt_id="gt-001"),
            _make_result("TP", gt_id="gt-002"),
            _make_result("TN", gt_id="gt-fp-001"),
        ]
        card = compute_scorecard("test", "scanner", "2024-01-01", results, CWE_FAMILIES)
        assert card.tp == 2
        assert card.fp == 0
        assert card.fn == 0
        assert card.tn == 1
        assert card.precision == 1.0
        assert card.recall == 1.0
        assert card.f1 == 1.0
        assert card.f2 == 1.0
        assert card.f2_score == 100.0

    def test_no_findings(self):
        """Scanner found nothing -> all FN."""
        results = [
            _make_result("FN", gt_id="gt-001"),
            _make_result("FN", gt_id="gt-002"),
        ]
        card = compute_scorecard("test", "scanner", "2024-01-01", results, CWE_FAMILIES)
        assert card.tp == 0
        assert card.fn == 2
        assert card.precision == 0.0
        assert card.recall == 0.0
        assert card.f2_score == 0.0

    def test_all_false_positives(self):
        """Scanner flags only wrong things."""
        results = [
            _make_result("FP"),
            _make_result("FP"),
            _make_result("FN", gt_id="gt-001"),
        ]
        card = compute_scorecard("test", "scanner", "2024-01-01", results, CWE_FAMILIES)
        assert card.tp == 0
        assert card.fp == 2
        assert card.fn == 1
        assert card.precision == 0.0
        assert card.recall == 0.0

    def test_f2_weights_recall(self):
        """F2 should favor recall over precision.

        Scanner A: 8 TP, 4 FP, 2 FN -> high recall
        Scanner B: 4 TP, 0 FP, 6 FN -> high precision
        F2 should rank A higher.
        """
        results_a = (
            [_make_result("TP", gt_id=f"gt-{i}") for i in range(8)]
            + [_make_result("FP") for _ in range(4)]
            + [_make_result("FN", gt_id=f"fn-{i}") for i in range(2)]
        )
        results_b = (
            [_make_result("TP", gt_id=f"gt-{i}") for i in range(4)]
            + [_make_result("FN", gt_id=f"fn-{i}") for i in range(6)]
        )
        card_a = compute_scorecard("test", "A", "t", results_a, CWE_FAMILIES)
        card_b = compute_scorecard("test", "B", "t", results_b, CWE_FAMILIES)
        assert card_a.f2 > card_b.f2

    def test_f2_formula(self):
        """Verify F2 = 5*P*R / (4*P + R)."""
        results = [
            _make_result("TP", gt_id="gt-001"),
            _make_result("FP"),
            _make_result("FN", gt_id="gt-002"),
        ]
        card = compute_scorecard("test", "scanner", "t", results, CWE_FAMILIES)
        p = 1 / 2  # 1 TP / (1 TP + 1 FP)
        r = 1 / 2  # 1 TP / (1 TP + 1 FN)
        expected_f2 = 5 * p * r / (4 * p + r)
        assert abs(card.f2 - expected_f2) < 1e-6
        assert card.f2_score == round(expected_f2 * 100, 1)

    def test_per_family_breakdown(self):
        results = [
            _make_result("TP", gt_id="gt-001", cwe="CWE-89"),
            _make_result("FN", gt_id="gt-002", cwe="CWE-79"),
        ]
        card = compute_scorecard("test", "scanner", "t", results, CWE_FAMILIES)
        assert "injection" in card.per_family
        assert card.per_family["injection"].tp == 1
        assert "xss" in card.per_family
        assert card.per_family["xss"].fn == 1

    def test_per_severity_breakdown(self):
        results = [
            _make_result("TP", gt_id="gt-001", severity="high"),
            _make_result("FN", gt_id="gt-002", severity="low"),
        ]
        card = compute_scorecard("test", "scanner", "t", results, CWE_FAMILIES)
        assert card.per_severity["high"].tp == 1
        assert card.per_severity["low"].fn == 1

    def test_youden_j(self):
        """Youden's J = TPR - FPR."""
        results = [
            _make_result("TP", gt_id="gt-001"),
            _make_result("FP"),
            _make_result("TN", gt_id="gt-fp-001"),
        ]
        card = compute_scorecard("test", "scanner", "t", results, CWE_FAMILIES)
        # TPR = 1/1 = 1.0, FPR = 1/(1+1) = 0.5
        assert card.tpr == 1.0
        assert card.fpr == 0.5
        assert card.youden_j == 0.5

    def test_scorecard_to_dict(self):
        card = ScoreCard(repo_id="test", scanner="s", timestamp="t", tp=3, fp=1, fn=2, tn=1)
        d = card.to_dict()
        assert d["scanner"] == "s"
        assert d["tp"] == 3
        assert isinstance(d["per_family"], dict)
        assert isinstance(d["details"], list)
