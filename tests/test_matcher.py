"""Tests for the finding matcher."""
from __future__ import annotations

from parsers.base import NormalisedFinding
from scorer.matcher import (
    match_findings,
    _line_within_tolerance,
)


def _make_finding(
    file: str = "app.py",
    cwe: str = "CWE-89",
    line: int | None = 42,
) -> NormalisedFinding:
    return NormalisedFinding(
        file=file, cwe=cwe, line=line,
        function=None, severity="high", rule_id="test",
        message="test", scanner="test",
    )


def _make_gt(
    findings: list[dict] | None = None,
) -> dict:
    if findings is None:
        findings = [
            {
                "id": "gt-001",
                "is_vulnerable": True,
                "vulnerability_class": "sql_injection",
                "primary_cwe": "CWE-89",
                "acceptable_cwes": ["CWE-89", "CWE-564"],
                "file": "app.py",
                "location": {"start_line": 40, "end_line": 45},
                "severity": "high",
                "evidence": {"source": "manual_review", "description": "test"},
            }
        ]
    return {"repo_id": "test", "findings": findings}


class TestLineWithinTolerance:
    def test_exact_match(self):
        assert _line_within_tolerance(40, 40, 45) is True

    def test_within_range(self):
        assert _line_within_tolerance(42, 40, 45) is True

    def test_at_lower_tolerance(self):
        assert _line_within_tolerance(30, 40, 45) is True  # 40 - 10 = 30

    def test_at_upper_tolerance(self):
        assert _line_within_tolerance(55, 40, 45) is True  # 45 + 10 = 55

    def test_beyond_lower_tolerance(self):
        assert _line_within_tolerance(29, 40, 45) is False

    def test_beyond_upper_tolerance(self):
        assert _line_within_tolerance(56, 40, 45) is False

    def test_none_finding_line(self):
        """None finding line should not penalize."""
        assert _line_within_tolerance(None, 40, 45) is True

    def test_none_gt_start(self):
        """None GT start line should not penalize."""
        assert _line_within_tolerance(42, None, None) is True

    def test_no_end_line(self):
        """When no end_line, tolerance is ±10 from start_line."""
        assert _line_within_tolerance(50, 40) is True   # 40 + 10 = 50
        assert _line_within_tolerance(51, 40) is False   # 40 + 10 = 50


class TestMatchFindings:
    def test_true_positive(self):
        """Finding matches a vulnerable GT entry -> TP."""
        findings = [_make_finding(file="app.py", cwe="CWE-89", line=42)]
        results = match_findings(findings, _make_gt())
        tp = [r for r in results if r.classification == "TP"]
        assert len(tp) == 1
        assert tp[0].ground_truth_id == "gt-001"

    def test_false_positive_no_gt(self):
        """Finding that matches nothing -> FP."""
        findings = [_make_finding(file="other.py", cwe="CWE-89", line=42)]
        results = match_findings(findings, _make_gt())
        fp = [r for r in results if r.classification == "FP"]
        assert len(fp) == 1
        assert fp[0].ground_truth_id is None

    def test_false_positive_fp_trap(self):
        """Finding matches an is_vulnerable=false GT entry -> FP."""
        gt = _make_gt([
            {
                "id": "fp-001",
                "is_vulnerable": False,
                "vulnerability_class": "sql_injection",
                "primary_cwe": "CWE-89",
                "acceptable_cwes": ["CWE-89"],
                "file": "app.py",
                "location": {"start_line": 40, "end_line": 45},
                "severity": "medium",
                "evidence": {"source": "manual_review", "description": "safe"},
            }
        ])
        findings = [_make_finding(file="app.py", cwe="CWE-89", line=42)]
        results = match_findings(findings, gt)
        fp = [r for r in results if r.classification == "FP"]
        assert len(fp) == 1
        assert fp[0].ground_truth_id == "fp-001"

    def test_false_negative(self):
        """GT entry with no matching finding -> FN."""
        results = match_findings([], _make_gt())
        fn = [r for r in results if r.classification == "FN"]
        assert len(fn) == 1
        assert fn[0].ground_truth_id == "gt-001"

    def test_true_negative(self):
        """Unmatched is_vulnerable=false GT -> TN."""
        gt = _make_gt([
            {
                "id": "fp-001",
                "is_vulnerable": False,
                "vulnerability_class": "xss",
                "primary_cwe": "CWE-79",
                "acceptable_cwes": ["CWE-79"],
                "file": "safe.py",
                "location": {"start_line": 10, "end_line": 12},
                "severity": "medium",
                "evidence": {"source": "manual_review", "description": "safe"},
            }
        ])
        results = match_findings([], gt)
        tn = [r for r in results if r.classification == "TN"]
        assert len(tn) == 1

    def test_acceptable_cwes(self):
        """Finding with alternative CWE from acceptable_cwes should match."""
        findings = [_make_finding(file="app.py", cwe="CWE-564", line=42)]
        results = match_findings(findings, _make_gt())
        tp = [r for r in results if r.classification == "TP"]
        assert len(tp) == 1

    def test_wrong_cwe_no_match(self):
        """Finding with CWE not in acceptable_cwes -> FP."""
        findings = [_make_finding(file="app.py", cwe="CWE-79", line=42)]
        results = match_findings(findings, _make_gt())
        fp = [r for r in results if r.classification == "FP"]
        fn = [r for r in results if r.classification == "FN"]
        assert len(fp) == 1
        assert len(fn) == 1

    def test_prefers_vulnerable_over_trap(self):
        """When both vulnerable and trap match, prefer the vulnerable one (TP)."""
        gt = _make_gt([
            {
                "id": "vuln-001",
                "is_vulnerable": True,
                "vulnerability_class": "sql_injection",
                "primary_cwe": "CWE-89",
                "acceptable_cwes": ["CWE-89"],
                "file": "app.py",
                "location": {"start_line": 40, "end_line": 45},
                "severity": "high",
                "evidence": {"source": "manual_review", "description": "vuln"},
            },
            {
                "id": "trap-001",
                "is_vulnerable": False,
                "vulnerability_class": "sql_injection",
                "primary_cwe": "CWE-89",
                "acceptable_cwes": ["CWE-89"],
                "file": "app.py",
                "location": {"start_line": 42, "end_line": 42},
                "severity": "high",
                "evidence": {"source": "manual_review", "description": "trap"},
            },
        ])
        findings = [_make_finding(file="app.py", cwe="CWE-89", line=42)]
        results = match_findings(findings, gt)
        tp = [r for r in results if r.classification == "TP"]
        tn = [r for r in results if r.classification == "TN"]
        assert len(tp) == 1
        assert tp[0].ground_truth_id == "vuln-001"
        assert len(tn) == 1  # trap-001 unmatched -> TN

    def test_line_out_of_tolerance(self):
        """Finding on wrong line should not match."""
        findings = [_make_finding(file="app.py", cwe="CWE-89", line=100)]
        results = match_findings(findings, _make_gt())
        fp = [r for r in results if r.classification == "FP"]
        fn = [r for r in results if r.classification == "FN"]
        assert len(fp) == 1
        assert len(fn) == 1

    def test_each_gt_matched_once(self):
        """Multiple findings matching same GT -> only first is TP, rest are FP."""
        findings = [
            _make_finding(file="app.py", cwe="CWE-89", line=40),
            _make_finding(file="app.py", cwe="CWE-89", line=42),
        ]
        results = match_findings(findings, _make_gt())
        tp = [r for r in results if r.classification == "TP"]
        fp = [r for r in results if r.classification == "FP"]
        assert len(tp) == 1
        assert len(fp) == 1
