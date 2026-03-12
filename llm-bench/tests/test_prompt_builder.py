"""Tests for the prompt builder."""
from __future__ import annotations

import sys
from pathlib import Path

LLM_BENCH_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

from harness.prompt_builder import (
    build_output_schema_example,
    build_prompt,
    format_cwe_families,
    load_cwe_families,
)


class TestFormatCweFamilies:
    def test_formats_families(self):
        families = {
            "families": {
                "sql_injection": {
                    "cwes": ["CWE-89", "CWE-564"],
                    "label": "SQL Injection",
                },
                "xss": {
                    "cwes": ["CWE-79"],
                    "label": "Cross-Site Scripting",
                },
            }
        }
        result = format_cwe_families(families)
        assert "SQL Injection" in result
        assert "CWE-89" in result
        assert "Cross-Site Scripting" in result

    def test_empty_families(self):
        assert format_cwe_families({}) == ""
        assert format_cwe_families({"families": {}}) == ""


class TestBuildOutputSchemaExample:
    def test_produces_valid_json(self):
        import json

        example = build_output_schema_example()
        data = json.loads(example)
        assert "version" in data
        assert "results" in data
        assert len(data["results"]) == 1
        assert "CWE-89" in data["results"][0]["extra"]["metadata"]["cwe"][0]


class TestBuildPrompt:
    def test_builds_complete_prompt(self):
        families = load_cwe_families()
        prompt = build_prompt(families)

        # Should contain key sections
        assert "Security Code Auditor" in prompt
        assert "SQL Injection" in prompt
        assert "CWE-89" in prompt
        assert '"results"' in prompt
        assert "Semgrep" in prompt or "JSON" in prompt

    def test_no_unresolved_placeholders(self):
        prompt = build_prompt()
        assert "{cwe_families}" not in prompt
        assert "{output_schema_example}" not in prompt
