"""Tests for reliability metrics computation."""
from __future__ import annotations

import sys
from pathlib import Path

LLM_BENCH_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

from scorer.matcher import MatchResult
from harness.reliability import compute_reliability


def _make_gt():
    """Make a ground truth dict with 4 entries."""
    return {
        "repo_id": "test-repo",
        "findings": [
            {
                "id": "vuln-001",
                "is_vulnerable": True,
                "primary_cwe": "CWE-89",
                "acceptable_cwes": ["CWE-89"],
                "file": "app.py",
                "location": {"start_line": 10, "end_line": 12, "function": "foo"},
                "severity": "high",
                "expected_category": "injection",
                "evidence": {"source": "manual", "cve_id": None, "description": "test"},
                "vulnerability_class": "sql_injection",
            },
            {
                "id": "vuln-002",
                "is_vulnerable": True,
                "primary_cwe": "CWE-79",
                "acceptable_cwes": ["CWE-79"],
                "file": "views.py",
                "location": {"start_line": 20, "end_line": 22, "function": "bar"},
                "severity": "medium",
                "expected_category": "xss",
                "evidence": {"source": "manual", "cve_id": None, "description": "test"},
                "vulnerability_class": "xss",
            },
            {
                "id": "vuln-003",
                "is_vulnerable": True,
                "primary_cwe": "CWE-78",
                "acceptable_cwes": ["CWE-78"],
                "file": "cmd.py",
                "location": {"start_line": 30, "end_line": 32, "function": "baz"},
                "severity": "high",
                "expected_category": "injection",
                "evidence": {"source": "manual", "cve_id": None, "description": "test"},
                "vulnerability_class": "command_injection",
            },
            {
                "id": "fp-001",
                "is_vulnerable": False,
                "primary_cwe": "CWE-89",
                "acceptable_cwes": ["CWE-89"],
                "file": "safe.py",
                "location": {"start_line": 5, "end_line": 5, "function": "safe"},
                "severity": "high",
                "expected_category": "injection",
                "evidence": {"source": "manual", "cve_id": None, "description": "safe"},
                "vulnerability_class": "sql_injection",
            },
        ],
    }


def _make_results_all_found():
    """Match results where all vulns are found."""
    gt = _make_gt()
    return [
        MatchResult("TP", "vuln-001", None, gt["findings"][0]),
        MatchResult("TP", "vuln-002", None, gt["findings"][1]),
        MatchResult("TP", "vuln-003", None, gt["findings"][2]),
        MatchResult("TN", "fp-001", None, gt["findings"][3]),
    ]


def _make_results_partial():
    """Match results where only vuln-001 is found."""
    gt = _make_gt()
    return [
        MatchResult("TP", "vuln-001", None, gt["findings"][0]),
        MatchResult("FN", "vuln-002", None, gt["findings"][1]),
        MatchResult("FN", "vuln-003", None, gt["findings"][2]),
        MatchResult("TN", "fp-001", None, gt["findings"][3]),
    ]


class TestComputeReliability:
    def test_perfect_agreement(self):
        gt = _make_gt()
        cwe_fam = {"families": {}}
        run_results = [_make_results_all_found() for _ in range(3)]
        report = compute_reliability(run_results, gt, "test-model", "test-repo", cwe_fam)

        assert report.num_runs == 3
        assert report.agreement_rate == 1.0
        assert report.flip_rate == 0.0
        assert len(report.stable_found) == 3
        assert len(report.unstable) == 0

    def test_no_agreement(self):
        gt = _make_gt()
        cwe_fam = {"families": {}}
        # Run 1: finds all, Run 2: finds partial, Run 3: finds all
        run_results = [
            _make_results_all_found(),
            _make_results_partial(),
            _make_results_all_found(),
        ]
        report = compute_reliability(run_results, gt, "test-model", "test-repo", cwe_fam)

        assert report.num_runs == 3
        assert len(report.stable_found) == 1  # vuln-001 found in all
        assert len(report.unstable) == 2  # vuln-002, vuln-003 found in 2/3
        assert report.agreement_rate < 1.0
        assert report.flip_rate > 0.0

    def test_single_run(self):
        gt = _make_gt()
        cwe_fam = {"families": {}}
        report = compute_reliability(
            [_make_results_all_found()], gt, "test-model", "test-repo", cwe_fam,
        )
        assert report.num_runs == 1
        assert report.f2_std == 0.0

    def test_empty_runs(self):
        gt = _make_gt()
        cwe_fam = {"families": {}}
        report = compute_reliability([], gt, "test-model", "test-repo", cwe_fam)
        assert report.num_runs == 0
