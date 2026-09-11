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


def _ns_result(withheld: bool, gt_id: str = "ns-001", cwe: str = "CWE-89") -> MatchResult:
    """NS result: withheld scanner finding (withheld=True) or bare NS GT entry."""
    finding = NormalisedFinding(
        file="app.py", cwe=cwe, line=42,
        function=None, severity="high", rule_id="test",
        message="test", scanner="test",
    ) if withheld else None
    return MatchResult(
        classification="NS",
        ground_truth_id=gt_id,
        scanner_finding=finding,
        ground_truth_entry={
            "id": gt_id,
            "is_vulnerable": True,
            "scoring": "non_scoring",
            "non_scoring_reason": "Reviewed: cannot be settled from the source alone.",
            "primary_cwe": cwe,
            "severity": "high",
        },
    )


class TestNonScoringMetrics:
    def test_ns_counted_separately_and_excluded_from_metrics(self):
        results = [
            _make_result("TP", "gt-1"),
            _make_result("FP"),
            _make_result("FN", "gt-2"),
            _ns_result(withheld=True),
            _ns_result(withheld=True),
            _ns_result(withheld=False),
        ]
        card = compute_scorecard("repo", "scanner", "ts", results, CWE_FAMILIES)
        assert (card.tp, card.fp, card.fn, card.tn) == (1, 1, 1, 0)
        assert card.ns == 2
        assert card.ns_gt == 1
        assert card.precision == 0.5
        assert card.recall == 0.5

    def test_ns_absent_from_family_and_severity_breakdowns(self):
        results = [_ns_result(withheld=True), _ns_result(withheld=False)]
        card = compute_scorecard("repo", "scanner", "ts", results, CWE_FAMILIES)
        assert card.per_family == {}
        assert card.per_severity == {}

    def test_ns_in_to_dict(self):
        card = compute_scorecard("repo", "scanner", "ts", [_ns_result(withheld=True)], CWE_FAMILIES)
        d = card.to_dict()
        assert d["ns"] == 1 and d["ns_gt"] == 0
        assert d["details"][0]["classification"] == "NS"

    def test_ns_does_not_move_headline_scores(self):
        base = [_make_result("TP", "gt-1"), _make_result("FP"), _make_result("FN", "gt-2"), _make_result("TN", "gt-3")]
        with_ns = base + [_ns_result(withheld=True), _ns_result(withheld=False)]
        a = compute_scorecard("repo", "s", "ts", base, CWE_FAMILIES)
        b = compute_scorecard("repo", "s", "ts", with_ns, CWE_FAMILIES)
        assert (a.f2_score, a.f3_score, a.fpr, a.youden_j) == (b.f2_score, b.f3_score, b.fpr, b.youden_j)


def _cvss_result(cls: str, gt_id: str, base_score: float | None, scanner_sev: str = "high") -> MatchResult:
    r = _make_result(cls, gt_id=gt_id, severity=scanner_sev)
    if r.ground_truth_entry is not None and base_score is not None:
        r.ground_truth_entry["cvss"] = {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": base_score,
            "severity": "HIGH",
        }
    return r


class TestCvssWeightedF3:
    def test_no_cvss_falls_back_to_unweighted(self):
        results = [_make_result("TP", gt_id="a"), _make_result("FN", gt_id="b")]
        card = compute_scorecard("r", "s", "t", results, CWE_FAMILIES)
        assert card.cvss_coverage == 0.0
        assert card.cvss_f3 == card.f3
        assert card.cvss_tp_weight == 1.0 and card.cvss_fn_weight == 1.0

    def test_missing_critical_costs_more_than_missing_low(self):
        # Same counts (1 TP, 1 FN); only which one was missed differs.
        miss_low = [_cvss_result("TP", "crit", 9.8), _cvss_result("FN", "low", 2.0)]
        miss_crit = [_cvss_result("TP", "low", 2.0), _cvss_result("FN", "crit", 9.8)]
        low = compute_scorecard("r", "s", "t", miss_low, CWE_FAMILIES)
        crit = compute_scorecard("r", "s", "t", miss_crit, CWE_FAMILIES)
        assert low.f3 == crit.f3  # unweighted cannot tell them apart
        assert low.cvss_recall == 9.8 / (9.8 + 2.0)
        assert crit.cvss_recall == 2.0 / (2.0 + 9.8)
        assert low.cvss_f3 > crit.cvss_f3

    def test_fp_weighted_by_scanner_severity_not_trap_score(self):
        results = [
            _cvss_result("TP", "a", 8.0),
            _cvss_result("FP", "trap", 0.0, scanner_sev="critical"),  # trap GT scored 0.0
            _make_result("FP", severity="low"),  # unmatched, no GT entry
        ]
        card = compute_scorecard("r", "s", "t", results, CWE_FAMILIES)
        assert card.cvss_tp_weight == 8.0
        assert card.cvss_fp_weight == 9.5 + 2.0
        assert card.cvss_precision == 8.0 / (8.0 + 11.5)

    def test_partial_coverage_uses_mean_for_unscored_gt(self):
        results = [_cvss_result("TP", "a", 6.0), _cvss_result("FN", "b", None)]
        card = compute_scorecard("r", "s", "t", results, CWE_FAMILIES)
        assert card.cvss_coverage == 0.5
        assert card.cvss_fn_weight == 6.0  # mean of known weights

    def test_to_dict_exposes_weighted_fields(self):
        card = compute_scorecard("r", "s", "t", [_cvss_result("TP", "a", 7.5)], CWE_FAMILIES)
        d = card.to_dict()
        assert d["cvss_f3_score"] == 100.0
        assert d["cvss_coverage"] == 1.0
