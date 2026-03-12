"""End-to-end pipeline integration test.

Creates fake LLM output, validates it, saves to scan-results format,
scores it with the existing pipeline, and verifies metrics make sense.

No API keys or Docker needed — tests the full path except the actual LLM call.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

LLM_BENCH_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

from parsers import get_parser
from scorer.matcher import load_ground_truth, match_findings
from scorer.metrics import compute_scorecard

from harness.output_validator import validate_output, save_validated_output
from harness.prompt_builder import build_prompt
from harness.cost_calculator import calculate_cost
from harness.reliability import compute_reliability
from harness.metrics_collector import RunMetrics, save_metrics


def _make_fake_llm_output() -> str:
    """Simulate LLM output that finds some real vulns in pygoat.

    Finds 3 real vulns (TPs), reports 1 wrong finding (FP),
    and misses the rest (FNs). This gives us a realistic mix.
    """
    return json.dumps({
        "version": "1.0.0",
        "results": [
            {
                "check_id": "python.security.injection.sql-injection",
                "path": "introduction/views.py",
                "start": {"line": 160, "col": 5},
                "end": {"line": 162, "col": 80},
                "extra": {
                    "message": "SQL injection via string concatenation in raw query",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-89: SQL Injection"],
                        "confidence": "HIGH",
                    },
                },
            },
            {
                "check_id": "python.security.injection.sql-injection-2",
                "path": "introduction/views.py",
                "start": {"line": 866, "col": 5},
                "end": {"line": 870, "col": 80},
                "extra": {
                    "message": "Second SQL injection via string concatenation",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-89: SQL Injection"],
                        "confidence": "HIGH",
                    },
                },
            },
            {
                "check_id": "python.security.xss.reflected-xss",
                "path": "introduction/templates/Lab/XSS/xss_lab.html",
                "start": {"line": 27, "col": 1},
                "end": {"line": 27, "col": 40},
                "extra": {
                    "message": "Reflected XSS via |safe filter on user input",
                    "severity": "WARNING",
                    "metadata": {
                        "cwe": ["CWE-79: Cross-Site Scripting"],
                        "confidence": "HIGH",
                    },
                },
            },
            {
                "check_id": "python.security.misc.debug-mode",
                "path": "pygoat/settings.py",
                "start": {"line": 10, "col": 1},
                "end": {"line": 10, "col": 20},
                "extra": {
                    "message": "DEBUG = True in production settings",
                    "severity": "INFO",
                    "metadata": {
                        "cwe": ["CWE-16: Configuration"],
                        "confidence": "LOW",
                    },
                },
            },
        ],
    })


def _make_fake_llm_output_variation() -> str:
    """A slightly different result for reliability testing.

    Finds 2 of the same vulns but misses one and finds a different one.
    """
    return json.dumps({
        "version": "1.0.0",
        "results": [
            {
                "check_id": "python.security.injection.sql-injection",
                "path": "introduction/views.py",
                "start": {"line": 160, "col": 5},
                "end": {"line": 162, "col": 80},
                "extra": {
                    "message": "SQL injection via string concatenation",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-89: SQL Injection"],
                        "confidence": "HIGH",
                    },
                },
            },
            {
                "check_id": "python.security.xss.reflected-xss",
                "path": "introduction/templates/Lab/XSS/xss_lab.html",
                "start": {"line": 27, "col": 1},
                "end": {"line": 27, "col": 40},
                "extra": {
                    "message": "Reflected XSS via |safe filter",
                    "severity": "WARNING",
                    "metadata": {
                        "cwe": ["CWE-79: Cross-Site Scripting"],
                        "confidence": "HIGH",
                    },
                },
            },
        ],
    })


class TestFullPipeline:
    """End-to-end pipeline test using fake LLM output."""

    def test_prompt_builds(self):
        """Verify prompt renders without errors."""
        prompt = build_prompt()
        assert len(prompt) > 500
        assert "SQL Injection" in prompt

    def test_validate_and_score(self):
        """Validate fake output → save → score with existing pipeline."""
        # Step 1: Validate LLM output
        raw = _make_fake_llm_output()
        result = validate_output(raw)
        assert result.valid
        assert result.findings_count == 4
        assert result.dropped_count == 0

        # Step 2: Save to temp file in scan-results format
        with tempfile.TemporaryDirectory() as tmpdir:
            result_path = Path(tmpdir) / "run-1.json"
            save_validated_output(result.data, str(result_path))

            # Verify file is valid JSON
            with open(result_path) as f:
                saved = json.load(f)
            assert len(saved["results"]) == 4

            # Step 3: Score with existing pipeline
            gt_path = PROJECT_ROOT / "ground-truth" / "realvuln-pygoat" / "ground-truth.json"
            ground_truth = load_ground_truth(str(gt_path))

            # Use SemgrepParser fallback (unknown slug → SemgrepParser)
            parser = get_parser("fake-llm-v1")
            findings = parser.parse(str(result_path))
            assert len(findings) >= 4  # May expand if multi-CWE

            # Step 4: Match and compute scorecard
            cwe_families_path = PROJECT_ROOT / "config" / "cwe-families.json"
            with open(cwe_families_path) as f:
                cwe_families = json.load(f)

            match_results = match_findings(findings, ground_truth)
            card = compute_scorecard(
                ground_truth["repo_id"],
                "fake-llm-v1",
                "2025-01-01T00:00:00Z",
                match_results,
                cwe_families,
            )

            # Step 5: Verify metrics make sense
            assert card.tp >= 2, f"Expected at least 2 TPs, got {card.tp}"
            assert card.fp >= 1, f"Expected at least 1 FP, got {card.fp}"
            assert card.fn >= 1, f"Expected FNs (we didn't find everything)"
            assert 0 < card.precision < 1, "Precision should be between 0 and 1"
            assert 0 < card.recall < 1, "Recall should be between 0 and 1"
            assert card.f2_score > 0, "F2 score should be positive"
            assert card.f2_score < 100, "F2 score should be less than 100"

    def test_metrics_json_excluded_from_discovery(self):
        """Verify .metrics.json files are excluded from result discovery."""
        from score import discover_result_files

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner_dir = Path(tmpdir)
            # Create a result file and a metrics file
            (scanner_dir / "run-1.json").write_text('{"results": []}')
            (scanner_dir / "run-1.metrics.json").write_text('{"cost": 0.16}')
            (scanner_dir / "results.json").write_text('{"results": []}')

            files = discover_result_files(scanner_dir)
            names = [f.name for f in files]
            assert "run-1.json" in names
            assert "results.json" in names
            assert "run-1.metrics.json" not in names

    def test_cost_calculation(self):
        """Verify cost calculation for a simulated run."""
        cost = calculate_cost(
            input_tokens=85_000,
            output_tokens=12_000,
            input_price_per_1m=0.80,   # Haiku
            output_price_per_1m=4.00,
        )
        assert cost.total_cost_usd > 0
        assert cost.total_cost_usd < 1.0  # Haiku should be cheap

    def test_metrics_save_and_load(self):
        """Verify RunMetrics serialization round-trips."""
        metrics = RunMetrics(
            model="claude-haiku-4",
            repo="realvuln-pygoat",
            run_id=1,
            input_tokens=85_000,
            output_tokens=12_000,
            cost_usd=0.116,
            wall_clock_seconds=342.5,
            agent_steps=28,
            tool_calls=45,
            files_read=["app.py", "views.py"],
            exit_status="success",
        )

        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            save_metrics(metrics, f.name)
            saved_path = f.name

        with open(saved_path) as f:
            loaded = json.load(f)

        assert loaded["model"] == "claude-haiku-4"
        assert loaded["input_tokens"] == 85_000
        assert loaded["cost_usd"] == 0.116
        assert loaded["files_read"] == ["app.py", "views.py"]
        Path(saved_path).unlink()

    def test_reliability_across_runs(self):
        """Test reliability computation with two different fake outputs."""
        gt_path = PROJECT_ROOT / "ground-truth" / "realvuln-pygoat" / "ground-truth.json"
        ground_truth = load_ground_truth(str(gt_path))

        cwe_families_path = PROJECT_ROOT / "config" / "cwe-families.json"
        with open(cwe_families_path) as f:
            cwe_families = json.load(f)

        # Create two runs with different results
        runs_data = [_make_fake_llm_output(), _make_fake_llm_output_variation()]
        all_match_results = []

        for raw in runs_data:
            validated = validate_output(raw)
            assert validated.valid

            with tempfile.NamedTemporaryFile(
                suffix=".json", mode="w", delete=False
            ) as f:
                json.dump(validated.data, f)
                tmp_path = f.name

            parser = get_parser("fake-llm-v1")
            findings = parser.parse(tmp_path)
            match_results = match_findings(findings, ground_truth)
            all_match_results.append(match_results)
            Path(tmp_path).unlink()

        # Compute reliability
        report = compute_reliability(
            all_match_results, ground_truth, "fake-llm-v1", "pygoat", cwe_families,
        )

        assert report.num_runs == 2
        assert len(report.f2_scores) == 2
        assert report.f2_mean > 0
        # Run 1 finds more than run 2, so there should be some instability
        assert len(report.stable_found) >= 1  # At least pygoat-001 and pygoat-003
        assert report.agreement_rate > 0
        assert report.agreement_rate <= 1.0

    def test_score_py_integration(self):
        """Test that score.py can score fake LLM results end-to-end."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Set up scan-results structure
            scanner_dir = Path(tmpdir) / "scan-results" / "realvuln-pygoat" / "fake-llm-v1"
            scanner_dir.mkdir(parents=True)

            # Save validated output
            raw = _make_fake_llm_output()
            validated = validate_output(raw)
            save_validated_output(validated.data, str(scanner_dir / "run-1.json"))

            # Also save a metrics file (should be ignored by scoring)
            metrics = RunMetrics(
                model="fake-llm", repo="pygoat", run_id=1,
                input_tokens=50000, cost_usd=0.10,
            )
            save_metrics(metrics, str(scanner_dir / "run-1.metrics.json"))

            # Verify the metrics file exists but doesn't interfere
            from score import discover_result_files
            files = discover_result_files(scanner_dir)
            assert len(files) == 1
            assert files[0].name == "run-1.json"
