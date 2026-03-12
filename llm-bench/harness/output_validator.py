"""Validate and fix LLM output against the Semgrep-compatible schema.

LLMs sometimes produce malformed JSON or miss required fields. This module
validates the output, attempts repairs where possible, and reports what
was fixed or dropped.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from parsers.base import normalise_path

_CWE_RE = re.compile(r"CWE-\d+")


@dataclass
class ValidationResult:
    """Result of validating LLM output."""

    valid: bool
    data: dict | None  # The (possibly repaired) Semgrep-format dict
    findings_count: int = 0
    dropped_count: int = 0
    repaired_count: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def extract_json_from_text(text: str) -> str | None:
    """Extract JSON object from LLM output that may contain surrounding text.

    Handles common cases:
    - Raw JSON
    - JSON wrapped in markdown code fences (```json ... ```)
    - JSON preceded/followed by explanation text
    """
    text = text.strip()

    # Try direct parse first
    if text.startswith("{"):
        return text

    # Try extracting from markdown code fence
    fence_pattern = r"```(?:json)?\s*\n?(.*?)\n?\s*```"
    matches = re.findall(fence_pattern, text, re.DOTALL)
    for match in matches:
        match = match.strip()
        if match.startswith("{"):
            return match

    # Try finding the outermost JSON object
    brace_start = text.find("{")
    if brace_start == -1:
        return None

    # Find matching closing brace
    depth = 0
    in_string = False
    escape_next = False
    for i in range(brace_start, len(text)):
        c = text[i]
        if escape_next:
            escape_next = False
            continue
        if c == "\\":
            escape_next = True
            continue
        if c == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[brace_start : i + 1]

    return None


def _validate_finding(finding: dict, index: int) -> tuple[dict | None, list[str], list[str]]:
    """Validate and repair a single finding entry.

    Returns (repaired_finding_or_None, errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []
    repaired = dict(finding)

    # Required: path
    if not repaired.get("path"):
        errors.append(f"Finding [{index}]: missing 'path'")
        return None, errors, warnings

    # Normalize path
    repaired["path"] = normalise_path(repaired["path"])

    # Required: start with line
    start = repaired.get("start")
    if not isinstance(start, dict) or not start.get("line"):
        errors.append(f"Finding [{index}]: missing 'start.line'")
        return None, errors, warnings
    if not isinstance(start.get("line"), int) or start["line"] < 1:
        errors.append(f"Finding [{index}]: invalid 'start.line': {start.get('line')}")
        return None, errors, warnings

    # Repair: ensure start has col
    if "col" not in start:
        start["col"] = 1
        warnings.append(f"Finding [{index}]: defaulted start.col to 1")

    # Repair: ensure end exists
    end = repaired.get("end")
    if not isinstance(end, dict):
        repaired["end"] = {"line": start["line"], "col": start.get("col", 1)}
        warnings.append(f"Finding [{index}]: defaulted end to match start")
    elif not end.get("line"):
        end["line"] = start["line"]
        warnings.append(f"Finding [{index}]: defaulted end.line to start.line")
    if isinstance(repaired.get("end"), dict) and "col" not in repaired["end"]:
        repaired["end"]["col"] = 1

    # Required: extra.metadata.cwe
    extra = repaired.get("extra", {})
    if not isinstance(extra, dict):
        extra = {}
        repaired["extra"] = extra

    metadata = extra.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
        extra["metadata"] = metadata

    raw_cwe = metadata.get("cwe", [])
    if isinstance(raw_cwe, str):
        raw_cwe = [raw_cwe]
        metadata["cwe"] = raw_cwe
        warnings.append(f"Finding [{index}]: converted cwe string to list")

    if not raw_cwe:
        errors.append(f"Finding [{index}]: missing CWE")
        return None, errors, warnings

    # Validate CWE format
    valid_cwes = []
    for cwe_str in raw_cwe:
        if _CWE_RE.match(str(cwe_str)):
            valid_cwes.append(str(cwe_str))
        else:
            warnings.append(f"Finding [{index}]: invalid CWE format '{cwe_str}', dropped")
    if not valid_cwes:
        errors.append(f"Finding [{index}]: no valid CWEs after filtering")
        return None, errors, warnings
    metadata["cwe"] = valid_cwes

    # Repair: ensure severity
    severity = extra.get("severity", "WARNING")
    if severity not in ("ERROR", "WARNING", "INFO"):
        severity = "WARNING"
        warnings.append(f"Finding [{index}]: defaulted severity to WARNING")
    extra["severity"] = severity

    # Repair: ensure message
    if not extra.get("message"):
        extra["message"] = f"Potential vulnerability: {valid_cwes[0]}"
        warnings.append(f"Finding [{index}]: generated default message")

    # Repair: ensure confidence
    if "confidence" not in metadata:
        metadata["confidence"] = "MEDIUM"
        warnings.append(f"Finding [{index}]: defaulted confidence to MEDIUM")

    # Repair: ensure check_id
    if not repaired.get("check_id"):
        cwe_num = re.search(r"CWE-(\d+)", valid_cwes[0])
        repaired["check_id"] = f"llm.security.cwe-{cwe_num.group(1) if cwe_num else 'unknown'}"
        warnings.append(f"Finding [{index}]: generated default check_id")

    repaired["extra"] = extra
    return repaired, errors, warnings


def validate_output(raw_text: str) -> ValidationResult:
    """Validate and repair LLM output into Semgrep-compatible JSON.

    Args:
        raw_text: Raw text output from the LLM.

    Returns:
        ValidationResult with the validated/repaired data or errors.
    """
    json_str = extract_json_from_text(raw_text)
    if json_str is None:
        return ValidationResult(
            valid=False,
            data=None,
            errors=["Could not extract JSON from LLM output"],
        )

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        return ValidationResult(
            valid=False,
            data=None,
            errors=[f"Invalid JSON: {e}"],
        )

    if not isinstance(data, dict):
        return ValidationResult(
            valid=False,
            data=None,
            errors=["Top-level value is not an object"],
        )

    all_errors: list[str] = []
    all_warnings: list[str] = []

    # Ensure version field
    if "version" not in data:
        data["version"] = "1.0.0"
        all_warnings.append("Added missing 'version' field")

    # Get results array
    results = data.get("results")
    if results is None:
        # Try common alternatives
        for alt_key in ("findings", "vulnerabilities", "issues"):
            if alt_key in data:
                results = data.pop(alt_key)
                data["results"] = results
                all_warnings.append(f"Renamed '{alt_key}' key to 'results'")
                break

    if not isinstance(results, list):
        return ValidationResult(
            valid=False,
            data=None,
            errors=["Missing or invalid 'results' array"],
        )

    # Validate each finding
    validated_results: list[dict] = []
    dropped = 0
    repaired = 0

    for i, finding in enumerate(results):
        if not isinstance(finding, dict):
            all_errors.append(f"Finding [{i}]: not an object, dropped")
            dropped += 1
            continue

        fixed, errs, warns = _validate_finding(finding, i)
        all_errors.extend(errs)
        all_warnings.extend(warns)

        if fixed is None:
            dropped += 1
        else:
            if warns:
                repaired += 1
            validated_results.append(fixed)

    data["results"] = validated_results

    return ValidationResult(
        valid=len(validated_results) > 0 or len(results) == 0,
        data=data,
        findings_count=len(validated_results),
        dropped_count=dropped,
        repaired_count=repaired,
        errors=all_errors,
        warnings=all_warnings,
    )


def save_validated_output(data: dict, output_path: str) -> None:
    """Save validated Semgrep-format JSON to a file."""
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
