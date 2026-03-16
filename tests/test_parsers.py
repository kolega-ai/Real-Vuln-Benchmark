"""Tests for the parser registry and Semgrep parser."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from parsers import get_parser, PARSER_REGISTRY
from parsers.base import normalise_path
from parsers.semgrep import SemgrepParser


class TestNormalisePath:
    def test_forward_slashes(self):
        assert normalise_path("src/app.py") == "src/app.py"

    def test_backslashes(self):
        assert normalise_path("src\\app.py") == "src/app.py"

    def test_leading_dot_slash(self):
        assert normalise_path("./src/app.py") == "src/app.py"

    def test_leading_slash(self):
        assert normalise_path("/src/app.py") == "src/app.py"

    def test_double_dot_slash(self):
        assert normalise_path("././src/app.py") == "src/app.py"

    def test_empty(self):
        assert normalise_path("") == ""


class TestParserRegistry:
    def test_known_scanners(self):
        for slug in ["semgrep", "opengrep", "sonarqube"]:
            assert slug in PARSER_REGISTRY

    def test_get_parser_known(self):
        p = get_parser("semgrep")
        assert isinstance(p, SemgrepParser)
        assert p.scanner_name == "semgrep"

    def test_get_parser_fallback(self):
        """Unknown slugs should fall back to SemgrepParser."""
        p = get_parser("totally-unknown-scanner")
        assert isinstance(p, SemgrepParser)
        assert p.scanner_name == "totally-unknown-scanner"


class TestSemgrepParser:
    def _write_semgrep_json(self, results: list[dict]) -> str:
        """Write a Semgrep JSON file and return its path."""
        data = {"results": results, "version": "1.0.0"}
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        json.dump(data, f)
        f.close()
        return f.name

    def test_basic_finding(self):
        path = self._write_semgrep_json([
            {
                "check_id": "python.lang.security.audit.sqli",
                "path": "app/routes.py",
                "start": {"line": 42, "col": 1},
                "end": {"line": 42, "col": 50},
                "extra": {
                    "severity": "ERROR",
                    "message": "SQL injection",
                    "metadata": {
                        "cwe": ["CWE-89: SQL Injection"],
                    },
                },
            }
        ])
        parser = SemgrepParser(scanner_slug="semgrep")
        findings = parser.parse(path)
        assert len(findings) == 1
        f = findings[0]
        assert f.file == "app/routes.py"
        assert f.cwe == "CWE-89"
        assert f.line == 42
        assert f.severity == "error"
        assert f.scanner == "semgrep"
        Path(path).unlink()

    def test_multiple_cwes(self):
        """A finding with multiple CWEs should produce multiple NormalisedFindings."""
        path = self._write_semgrep_json([
            {
                "check_id": "test-rule",
                "path": "app.py",
                "start": {"line": 10},
                "end": {"line": 10},
                "extra": {
                    "severity": "WARNING",
                    "message": "Issue",
                    "metadata": {
                        "cwe": ["CWE-79: XSS", "CWE-116: Encoding"],
                    },
                },
            }
        ])
        findings = SemgrepParser().parse(path)
        assert len(findings) == 2
        cwes = {f.cwe for f in findings}
        assert cwes == {"CWE-79", "CWE-116"}
        Path(path).unlink()

    def test_empty_results(self):
        path = self._write_semgrep_json([])
        findings = SemgrepParser().parse(path)
        assert findings == []
        Path(path).unlink()

    def test_finding_without_cwe_skipped(self):
        """Findings with no CWE metadata should be skipped."""
        path = self._write_semgrep_json([
            {
                "check_id": "no-cwe-rule",
                "path": "app.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "severity": "INFO",
                    "message": "No CWE",
                    "metadata": {},
                },
            }
        ])
        findings = SemgrepParser().parse(path)
        assert findings == []
        Path(path).unlink()

    def test_path_normalisation(self):
        path = self._write_semgrep_json([
            {
                "check_id": "rule",
                "path": "./src\\app.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "severity": "WARNING",
                    "message": "Test",
                    "metadata": {"cwe": "CWE-79"},
                },
            }
        ])
        findings = SemgrepParser().parse(path)
        assert len(findings) == 1
        assert findings[0].file == "src/app.py"
        Path(path).unlink()
