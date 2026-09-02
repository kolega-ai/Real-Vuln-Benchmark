"""Tests for the ground-truth validator's non-scoring rules."""
from __future__ import annotations

import json
from pathlib import Path

import validate_gt


def _finding(**overrides) -> dict:
    base = {
        "id": "gt-001",
        "is_vulnerable": True,
        "vulnerability_class": "sql_injection",
        "primary_cwe": "CWE-89",
        "acceptable_cwes": ["CWE-89"],
        "file": "app.py",
        "location": {"start_line": 40, "end_line": 45, "function": None},
        "severity": "high",
        "expected_category": "injection",
        "evidence": {"source": "manual_review", "cve_id": None, "description": "test finding"},
    }
    base.update(overrides)
    return base


def _write_gt(tmp_path: Path, findings: list[dict]) -> Path:
    gt = {
        "schema_version": "1.0",
        "benchmark_version": "3.0.0",
        "ground_truth_version": "3.0.0",
        "repo_id": "test",
        "repo_url": "https://example.com/test",
        "commit_sha": "a" * 40,
        "type": 1,
        "language": "python",
        "framework": None,
        "authorship": "human_authored",
        "authorship_model": None,
        "authorship_confidence": "high",
        "authorship_evidence": "test",
        "findings": findings,
    }
    repo_dir = tmp_path / "ground-truth" / "test"
    repo_dir.mkdir(parents=True)
    path = repo_dir / "ground-truth.json"
    path.write_text(json.dumps(gt))
    return path


def _errors(tmp_path, monkeypatch, findings):
    monkeypatch.setattr(validate_gt, "GT_DIR", tmp_path / "ground-truth")
    return [str(e) for e in validate_gt.validate_gt(_write_gt(tmp_path, findings))]


class TestNonScoringValidation:
    def test_scored_default_passes(self, tmp_path, monkeypatch):
        assert _errors(tmp_path, monkeypatch, [_finding()]) == []

    def test_non_scoring_with_reason_passes(self, tmp_path, monkeypatch):
        f = _finding(scoring="non_scoring", non_scoring_reason="Reviewed: cannot be settled from the source alone.")
        assert _errors(tmp_path, monkeypatch, [f]) == []

    def test_non_scoring_requires_reason(self, tmp_path, monkeypatch):
        errs = _errors(tmp_path, monkeypatch, [_finding(scoring="non_scoring")])
        assert any("missing required field: non_scoring_reason" in e for e in errs)

    def test_non_scoring_reason_must_be_substantive(self, tmp_path, monkeypatch):
        errs = _errors(tmp_path, monkeypatch, [_finding(scoring="non_scoring", non_scoring_reason="unclear")])
        assert any("non_scoring_reason too short" in e for e in errs)

    def test_invalid_scoring_value_rejected(self, tmp_path, monkeypatch):
        errs = _errors(tmp_path, monkeypatch, [_finding(scoring="indeterminate")])
        assert any("invalid scoring" in e for e in errs)

    def test_reason_on_scored_finding_rejected(self, tmp_path, monkeypatch):
        errs = _errors(tmp_path, monkeypatch, [_finding(non_scoring_reason="should not be here at all")])
        assert any("non_scoring_reason present on a scored finding" in e for e in errs)

    def test_acceptable_location_requires_file_and_lines(self, tmp_path, monkeypatch):
        f = _finding(acceptable_locations=[{"file": "other.py"}])
        errs = _errors(tmp_path, monkeypatch, [f])
        assert any("acceptable_locations[0].start_line" in e for e in errs)

    def test_acceptable_location_complete_passes(self, tmp_path, monkeypatch):
        f = _finding(acceptable_locations=[{"file": "other.py", "start_line": 1, "end_line": 3}])
        assert _errors(tmp_path, monkeypatch, [f]) == []
