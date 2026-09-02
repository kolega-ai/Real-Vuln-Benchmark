"""Tests for the finding matcher."""
from __future__ import annotations

import json

import pytest

from parsers.base import NormalisedFinding
from scorer.matcher import (
    is_non_scoring,
    load_ground_truth,
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

    def test_acceptable_location_true_positive(self):
        """Finding matching an alternate public location should be TP."""
        gt = _make_gt([
            {
                "id": "gt-alt-001",
                "is_vulnerable": True,
                "vulnerability_class": "xss",
                "primary_cwe": "CWE-79",
                "acceptable_cwes": ["CWE-79"],
                "file": "views/main.html",
                "location": {"start_line": 100, "end_line": 105},
                "acceptable_locations": [
                    {"file": "templates/x.html", "start_line": 20, "end_line": 22}
                ],
                "severity": "high",
                "evidence": {"source": "manual_review", "description": "test"},
            }
        ])
        findings = [_make_finding(file="templates/x.html", cwe="CWE-79", line=21)]
        results = match_findings(findings, gt)
        tp = [r for r in results if r.classification == "TP"]
        assert len(tp) == 1
        assert tp[0].ground_truth_id == "gt-alt-001"

    def test_acceptable_location_paths_are_normalized(self, tmp_path):
        """Alternate location paths are normalized by the GT loader."""
        gt_path = tmp_path / "ground-truth.json"
        gt_path.write_text(json.dumps(_make_gt([
            {
                "id": "gt-alt-002",
                "is_vulnerable": True,
                "vulnerability_class": "xss",
                "primary_cwe": "CWE-79",
                "acceptable_cwes": ["CWE-79"],
                "file": "./views/main.html",
                "location": {"start_line": 100, "end_line": 105},
                "acceptable_locations": [
                    {"file": "./templates/x.html", "start_line": 20, "end_line": 22}
                ],
                "severity": "high",
                "evidence": {"source": "manual_review", "description": "test"},
            }
        ])))

        gt = load_ground_truth(str(gt_path))
        findings = [_make_finding(file="templates/x.html", cwe="CWE-79", line=21)]
        results = match_findings(findings, gt)
        tp = [r for r in results if r.classification == "TP"]
        assert len(tp) == 1
        assert gt["findings"][0]["file"] == "views/main.html"
        assert gt["findings"][0]["acceptable_locations"][0]["file"] == "templates/x.html"

    def test_acceptable_location_still_requires_cwe_match(self):
        """Alternate location match should not bypass acceptable_cwes."""
        gt = _make_gt([
            {
                "id": "gt-alt-003",
                "is_vulnerable": True,
                "vulnerability_class": "xss",
                "primary_cwe": "CWE-79",
                "acceptable_cwes": ["CWE-79"],
                "file": "views/main.html",
                "location": {"start_line": 100, "end_line": 105},
                "acceptable_locations": [
                    {"file": "templates/x.html", "start_line": 20, "end_line": 22}
                ],
                "severity": "high",
                "evidence": {"source": "manual_review", "description": "test"},
            }
        ])
        findings = [_make_finding(file="templates/x.html", cwe="CWE-89", line=21)]
        results = match_findings(findings, gt)
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


def _ns_entry(
    id: str = "ns-001",
    file: str = "app.py",
    start: int = 40,
    end: int = 45,
    cwe: str = "CWE-89",
    reason: str = "Reviewed: cannot be settled from the source alone.",
) -> dict:
    return {
        "id": id,
        "is_vulnerable": True,
        "scoring": "non_scoring",
        "non_scoring_reason": reason,
        "vulnerability_class": "sql_injection",
        "primary_cwe": cwe,
        "acceptable_cwes": [cwe],
        "file": file,
        "location": {"start_line": start, "end_line": end},
        "severity": "high",
        "evidence": {"source": "manual_review", "description": "unsettled"},
    }


def _by_class(results, cls):
    return [r for r in results if r.classification == cls]


class TestNonScoring:
    def test_finding_on_non_scoring_entry_is_withheld(self):
        """A finding landing on a non-scoring entry is NS, not FP."""
        results = match_findings([_make_finding(line=42)], _make_gt([_ns_entry()]))
        assert _by_class(results, "FP") == []
        withheld = [r for r in _by_class(results, "NS") if r.scanner_finding]
        assert len(withheld) == 1
        assert withheld[0].ground_truth_id == "ns-001"

    def test_unmatched_non_scoring_entry_is_not_fn(self):
        """Missing a non-scoring entry is not a false negative."""
        results = match_findings([], _make_gt([_ns_entry()]))
        assert _by_class(results, "FN") == []
        assert _by_class(results, "TN") == []
        entries = [r for r in _by_class(results, "NS") if r.scanner_finding is None]
        assert [r.ground_truth_id for r in entries] == ["ns-001"]

    def test_non_scoring_never_steals_from_colocated_positive(self):
        """Scored rows are matched first; NS rows take no part in assignment."""
        gt = _make_gt()
        gt["findings"].append(_ns_entry(id="ns-001", start=42, end=42))
        results = match_findings([_make_finding(line=42)], gt)
        tp = _by_class(results, "TP")
        assert len(tp) == 1 and tp[0].ground_truth_id == "gt-001"
        assert _by_class(results, "FN") == []
        assert all(r.scanner_finding is None for r in _by_class(results, "NS"))

    def test_second_finding_on_consumed_positive_is_withheld_by_ns(self):
        """Once the positive is consumed, an extra finding falls through to NS."""
        gt = _make_gt()
        gt["findings"].append(_ns_entry(id="ns-001", start=42, end=42))
        findings = [_make_finding(line=42), _make_finding(line=43)]
        results = match_findings(findings, gt)
        assert len(_by_class(results, "TP")) == 1
        assert _by_class(results, "FP") == []
        assert len([r for r in _by_class(results, "NS") if r.scanner_finding]) == 1

    def test_withholding_is_location_only(self):
        """NS withholding ignores CWE: the location is unsettled, not the label."""
        results = match_findings(
            [_make_finding(cwe="CWE-79", line=42)], _make_gt([_ns_entry(cwe="CWE-89")])
        )
        assert _by_class(results, "FP") == []
        assert len([r for r in _by_class(results, "NS") if r.scanner_finding]) == 1

    def test_withholding_respects_line_tolerance(self):
        """A finding outside the NS region ± tolerance is still an FP."""
        results = match_findings([_make_finding(line=56)], _make_gt([_ns_entry()]))
        assert len(_by_class(results, "FP")) == 1

    def test_many_findings_may_hit_one_non_scoring_entry(self):
        """NS withholding is many-to-one; the entry is never 'consumed'."""
        findings = [_make_finding(line=l) for l in (40, 41, 42)]
        results = match_findings(findings, _make_gt([_ns_entry()]))
        assert _by_class(results, "FP") == []
        assert len([r for r in _by_class(results, "NS") if r.scanner_finding]) == 3

    def test_finding_prefers_scored_trap_over_non_scoring(self):
        """A co-located FP trap is scored (FP); NS only applies when nothing scored matched."""
        trap = {
            "id": "trap-001",
            "is_vulnerable": False,
            "vulnerability_class": "sql_injection",
            "primary_cwe": "CWE-89",
            "acceptable_cwes": ["CWE-89"],
            "file": "app.py",
            "location": {"start_line": 42, "end_line": 42},
            "severity": "medium",
            "evidence": {"source": "manual_review", "description": "safe"},
        }
        results = match_findings([_make_finding(line=42)], _make_gt([trap, _ns_entry()]))
        fp = _by_class(results, "FP")
        assert len(fp) == 1 and fp[0].ground_truth_id == "trap-001"

    def test_explicit_scored_value_behaves_as_default(self):
        gt = _make_gt()
        gt["findings"][0]["scoring"] = "scored"
        results = match_findings([_make_finding(line=42)], gt)
        assert len(_by_class(results, "TP")) == 1

    def test_loader_rejects_invalid_scoring_value(self, tmp_path):
        gt = _make_gt()
        gt["findings"][0]["scoring"] = "indeterminate"
        gt_path = tmp_path / "ground-truth.json"
        gt_path.write_text(json.dumps(gt))
        with pytest.raises(ValueError, match="invalid scoring"):
            load_ground_truth(str(gt_path))

    def test_finding_without_line_is_never_withheld(self):
        """Without a CWE gate, a line-less finding must not be exempted by any NS entry in the file."""
        results = match_findings([_make_finding(line=None)], _make_gt([_ns_entry()]))
        assert len(_by_class(results, "FP")) == 1

    def test_ns_acceptable_location_withholds(self):
        ns = _ns_entry(file="views/main.py", start=100, end=105)
        ns["acceptable_locations"] = [{"file": "app.py", "start_line": 40, "end_line": 45}]
        results = match_findings([_make_finding(line=42)], _make_gt([ns]))
        assert _by_class(results, "FP") == []
        assert len([r for r in _by_class(results, "NS") if r.scanner_finding]) == 1

    def test_is_vulnerable_ignored_on_non_scoring_entry(self):
        ns = _ns_entry()
        ns["is_vulnerable"] = False
        results = match_findings([], _make_gt([ns]))
        assert _by_class(results, "TN") == [] and _by_class(results, "FN") == []
        assert len(_by_class(results, "NS")) == 1

    def test_overlapping_ns_entries_resolve_to_lowest_id(self):
        gt = _make_gt([_ns_entry(id="ns-b"), _ns_entry(id="ns-a")])
        results = match_findings([_make_finding(line=42)], gt)
        withheld = [r for r in _by_class(results, "NS") if r.scanner_finding]
        assert withheld[0].ground_truth_id == "ns-a"

    def test_is_non_scoring_rejects_invalid_value(self):
        with pytest.raises(ValueError, match="invalid scoring"):
            is_non_scoring({"id": "x", "scoring": "indeterminate"})
