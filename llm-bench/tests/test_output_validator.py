"""Tests for the LLM output validator."""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Add project paths
LLM_BENCH_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

from harness.output_validator import extract_json_from_text, validate_output


class TestExtractJson:
    def test_raw_json(self):
        raw = '{"version": "1.0.0", "results": []}'
        assert extract_json_from_text(raw) == raw

    def test_json_in_markdown_fence(self):
        raw = 'Here are the results:\n```json\n{"version": "1.0.0", "results": []}\n```\nDone!'
        result = extract_json_from_text(raw)
        assert result is not None
        data = json.loads(result)
        assert data["version"] == "1.0.0"

    def test_json_with_surrounding_text(self):
        raw = (
            "I found 3 vulnerabilities:\n\n"
            '{"version": "1.0.0", "results": [{"check_id": "test"}]}\n\n'
            "That's all."
        )
        result = extract_json_from_text(raw)
        assert result is not None
        data = json.loads(result)
        assert len(data["results"]) == 1

    def test_no_json(self):
        assert extract_json_from_text("No vulnerabilities found.") is None

    def test_empty_string(self):
        assert extract_json_from_text("") is None


class TestValidateOutput:
    def _make_valid_output(self, findings=None):
        if findings is None:
            findings = [
                {
                    "check_id": "python.security.injection.sql-injection",
                    "path": "app/views.py",
                    "start": {"line": 42, "col": 5},
                    "end": {"line": 42, "col": 60},
                    "extra": {
                        "message": "SQL injection via string concatenation",
                        "severity": "ERROR",
                        "metadata": {
                            "cwe": ["CWE-89: SQL Injection"],
                            "confidence": "HIGH",
                        },
                    },
                }
            ]
        return json.dumps({"version": "1.0.0", "results": findings})

    def test_valid_output(self):
        result = validate_output(self._make_valid_output())
        assert result.valid
        assert result.findings_count == 1
        assert result.dropped_count == 0

    def test_empty_results(self):
        result = validate_output('{"version": "1.0.0", "results": []}')
        assert result.valid
        assert result.findings_count == 0

    def test_missing_version_repaired(self):
        result = validate_output('{"results": []}')
        assert result.valid
        assert result.data is not None
        assert result.data["version"] == "1.0.0"

    def test_findings_key_renamed(self):
        raw = json.dumps({
            "findings": [
                {
                    "check_id": "test",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {
                        "message": "Test",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-89"], "confidence": "HIGH"},
                    },
                }
            ]
        })
        result = validate_output(raw)
        assert result.valid
        assert result.data is not None
        assert "results" in result.data
        assert result.findings_count == 1

    def test_missing_path_dropped(self):
        raw = json.dumps({
            "version": "1.0.0",
            "results": [
                {
                    "check_id": "test",
                    "start": {"line": 1, "col": 1},
                    "extra": {
                        "message": "Test",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-89"]},
                    },
                }
            ],
        })
        result = validate_output(raw)
        assert result.valid is False or result.findings_count == 0
        assert result.dropped_count == 1

    def test_missing_cwe_dropped(self):
        raw = json.dumps({
            "version": "1.0.0",
            "results": [
                {
                    "check_id": "test",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1},
                    "extra": {
                        "message": "Test",
                        "severity": "ERROR",
                        "metadata": {},
                    },
                }
            ],
        })
        result = validate_output(raw)
        assert result.dropped_count == 1

    def test_missing_end_repaired(self):
        raw = json.dumps({
            "version": "1.0.0",
            "results": [
                {
                    "check_id": "test",
                    "path": "app.py",
                    "start": {"line": 42, "col": 1},
                    "extra": {
                        "message": "Test",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-89"], "confidence": "HIGH"},
                    },
                }
            ],
        })
        result = validate_output(raw)
        assert result.valid
        assert result.repaired_count >= 1
        assert result.data is not None
        assert result.data["results"][0]["end"]["line"] == 42

    def test_cwe_string_converted_to_list(self):
        raw = json.dumps({
            "version": "1.0.0",
            "results": [
                {
                    "check_id": "test",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {
                        "message": "Test",
                        "severity": "ERROR",
                        "metadata": {"cwe": "CWE-89", "confidence": "HIGH"},
                    },
                }
            ],
        })
        result = validate_output(raw)
        assert result.valid
        assert result.data is not None
        assert isinstance(result.data["results"][0]["extra"]["metadata"]["cwe"], list)

    def test_path_normalization(self):
        raw = json.dumps({
            "version": "1.0.0",
            "results": [
                {
                    "check_id": "test",
                    "path": "./app\\views.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {
                        "message": "Test",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-89"], "confidence": "HIGH"},
                    },
                }
            ],
        })
        result = validate_output(raw)
        assert result.valid
        assert result.data is not None
        assert result.data["results"][0]["path"] == "app/views.py"

    def test_invalid_json(self):
        result = validate_output("not json at all")
        assert not result.valid
        assert result.data is None

    def test_json_in_markdown_fence(self):
        valid = self._make_valid_output()
        raw = f"Here are the findings:\n```json\n{valid}\n```"
        result = validate_output(raw)
        assert result.valid
        assert result.findings_count == 1
