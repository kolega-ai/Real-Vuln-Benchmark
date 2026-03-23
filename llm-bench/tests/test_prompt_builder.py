"""Tests for the prompt builder."""
from __future__ import annotations

import sys
from pathlib import Path

LLM_BENCH_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

from harness.prompt_builder import (
    PromptInfo,
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
        prompt_info = build_prompt(families)

        # Should contain key sections
        assert "Security Code Auditor" in prompt_info.rendered
        assert "SQL Injection" in prompt_info.rendered
        assert "CWE-89" in prompt_info.rendered
        assert '"results"' in prompt_info.rendered
        assert "Semgrep" in prompt_info.rendered or "JSON" in prompt_info.rendered

    def test_no_unresolved_placeholders(self):
        prompt_info = build_prompt()
        assert "{cwe_families}" not in prompt_info.rendered
        assert "{output_schema_example}" not in prompt_info.rendered


class TestPromptInfo:
    def test_returns_prompt_info(self):
        result = build_prompt()
        assert isinstance(result, PromptInfo)
        assert len(result.rendered) > 500
        assert result.version_hash.startswith("sha256:")
        assert len(result.version_hash) == len("sha256:") + 12
        assert result.template_path
        assert result.label == ""

    def test_hash_stability(self):
        """Same input should produce the same hash."""
        info1 = build_prompt()
        info2 = build_prompt()
        assert info1.version_hash == info2.version_hash

    def test_hash_changes_with_input(self):
        """Different CWE families should produce different hashes."""
        info1 = build_prompt()
        # Build with minimal families to get a different rendered prompt
        info2 = build_prompt(cwe_families={"families": {}})
        assert info1.version_hash != info2.version_hash

    def test_label_propagation(self):
        info = build_prompt(label="v2-chain-of-thought")
        assert info.label == "v2-chain-of-thought"

    def test_version_hash_format(self):
        info = build_prompt()
        prefix, hex_part = info.version_hash.split(":", 1)
        assert prefix == "sha256"
        assert len(hex_part) == 12
        # Verify it's valid hex
        int(hex_part, 16)
