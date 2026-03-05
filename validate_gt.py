#!/usr/bin/env python3
"""Validate all ground truth files for schema correctness.

Usage:
    python -m evals.realvuln.validate_gt              # validate all
    python -m evals.realvuln.validate_gt realvuln-pygoat realvuln-vulpy  # specific repos
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

GT_DIR = Path(__file__).parent / "ground-truth"

# --- Schema constants ---

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_CATEGORIES = {"injection", "xss", "auth", "data_exposure", "session_config", "other"}
VALID_AUTHORSHIPS = {"human_authored", "llm_assisted", "llm_generated", "unknown"}
VALID_CONFIDENCE = {"high", "medium", "low"}
VALID_TYPES = {1, 2, 3, 4, 5}
VALID_EVIDENCE_SOURCES = {"manual_review", "cve_id", "walkthrough"}
CWE_PATTERN = re.compile(r"^CWE-\d+$")

TOP_LEVEL_REQUIRED = {
    "schema_version": str,
    "repo_id": str,
    "repo_url": str,
    "commit_sha": str,
    "type": int,
    "language": str,
    "framework": (str, type(None)),
    "authorship": str,
    "authorship_model": (str, type(None)),
    "authorship_confidence": str,
    "authorship_evidence": str,
    "findings": list,
}

FINDING_REQUIRED = {
    "id": str,
    "is_vulnerable": bool,
    "vulnerability_class": str,
    "primary_cwe": str,
    "acceptable_cwes": list,
    "file": str,
    "location": dict,
    "severity": str,
    "expected_category": str,
    "evidence": dict,
}

LOCATION_REQUIRED = {
    "start_line": int,
    "end_line": int,
    "function": (str, type(None)),
}

EVIDENCE_REQUIRED = {
    "source": str,
    "cve_id": (str, type(None)),
    "description": str,
}


class ValidationError:
    def __init__(self, path: str, finding_id: str | None, message: str):
        self.path = path
        self.finding_id = finding_id
        self.message = message

    def __str__(self):
        if self.finding_id:
            return f"  [{self.finding_id}] {self.message}"
        return f"  {self.message}"


def validate_types(obj: dict, schema: dict, prefix: str, errors: list, path: str, finding_id: str | None):
    """Check required fields exist and have correct types."""
    for field, expected_type in schema.items():
        if field not in obj:
            errors.append(ValidationError(path, finding_id, f"missing required field: {prefix}{field}"))
            continue
        val = obj[field]
        if isinstance(expected_type, tuple):
            if not isinstance(val, expected_type):
                errors.append(ValidationError(
                    path, finding_id,
                    f"{prefix}{field}: expected {' or '.join(t.__name__ for t in expected_type)}, got {type(val).__name__}"
                ))
        else:
            if not isinstance(val, expected_type):
                errors.append(ValidationError(
                    path, finding_id,
                    f"{prefix}{field}: expected {expected_type.__name__}, got {type(val).__name__}"
                ))


def validate_gt(gt_path: Path) -> list[ValidationError]:
    """Validate a single ground truth file. Returns list of errors."""
    errors: list[ValidationError] = []
    path_str = str(gt_path.relative_to(GT_DIR.parent.parent))

    # Parse JSON
    try:
        with open(gt_path) as f:
            gt = json.load(f)
    except json.JSONDecodeError as e:
        errors.append(ValidationError(path_str, None, f"invalid JSON: {e}"))
        return errors

    if not isinstance(gt, dict):
        errors.append(ValidationError(path_str, None, "root must be an object"))
        return errors

    # Top-level fields
    validate_types(gt, TOP_LEVEL_REQUIRED, "", errors, path_str, None)

    if gt.get("schema_version") != "1.0":
        errors.append(ValidationError(path_str, None, f"schema_version must be '1.0', got {gt.get('schema_version')!r}"))

    if "commit_sha" in gt and isinstance(gt["commit_sha"], str):
        if len(gt["commit_sha"]) != 40 or not re.match(r"^[0-9a-f]{40}$", gt["commit_sha"]):
            errors.append(ValidationError(path_str, None, f"commit_sha must be 40 hex chars, got {gt['commit_sha']!r}"))

    if gt.get("type") not in VALID_TYPES and "type" in gt:
        errors.append(ValidationError(path_str, None, f"type must be 1-5, got {gt.get('type')}"))

    if gt.get("authorship") not in VALID_AUTHORSHIPS and "authorship" in gt:
        errors.append(ValidationError(path_str, None, f"invalid authorship: {gt.get('authorship')!r}"))

    if gt.get("authorship_confidence") not in VALID_CONFIDENCE and "authorship_confidence" in gt:
        errors.append(ValidationError(path_str, None, f"invalid authorship_confidence: {gt.get('authorship_confidence')!r}"))

    # Findings
    findings = gt.get("findings", [])
    if not isinstance(findings, list):
        errors.append(ValidationError(path_str, None, "findings must be an array"))
        return errors

    if len(findings) == 0:
        errors.append(ValidationError(path_str, None, "findings array is empty"))

    seen_ids: set[str] = set()
    vuln_count = 0
    fp_count = 0

    for i, f in enumerate(findings):
        fid = f.get("id", f"findings[{i}]")

        if not isinstance(f, dict):
            errors.append(ValidationError(path_str, fid, "finding must be an object"))
            continue

        # Required fields
        validate_types(f, FINDING_REQUIRED, "", errors, path_str, fid)

        # Duplicate IDs
        if fid in seen_ids:
            errors.append(ValidationError(path_str, fid, "duplicate finding ID"))
        seen_ids.add(fid)

        # is_vulnerable counting
        if f.get("is_vulnerable") is True:
            vuln_count += 1
        elif f.get("is_vulnerable") is False:
            fp_count += 1

        # CWE format
        primary_cwe = f.get("primary_cwe", "")
        if isinstance(primary_cwe, str) and not CWE_PATTERN.match(primary_cwe):
            errors.append(ValidationError(path_str, fid, f"primary_cwe format invalid: {primary_cwe!r}"))

        acceptable = f.get("acceptable_cwes", [])
        if isinstance(acceptable, list):
            for cwe in acceptable:
                if not isinstance(cwe, str) or not CWE_PATTERN.match(cwe):
                    errors.append(ValidationError(path_str, fid, f"invalid CWE in acceptable_cwes: {cwe!r}"))
            if isinstance(primary_cwe, str) and primary_cwe and primary_cwe not in acceptable:
                errors.append(ValidationError(path_str, fid, f"primary_cwe {primary_cwe} not in acceptable_cwes"))

        # Severity
        if f.get("severity") not in VALID_SEVERITIES and "severity" in f:
            errors.append(ValidationError(path_str, fid, f"invalid severity: {f.get('severity')!r}"))

        # Expected category
        if f.get("expected_category") not in VALID_CATEGORIES and "expected_category" in f:
            errors.append(ValidationError(path_str, fid, f"invalid expected_category: {f.get('expected_category')!r}"))

        # File path
        file_path = f.get("file", "")
        if isinstance(file_path, str):
            if file_path.startswith("/") or file_path.startswith("./"):
                errors.append(ValidationError(path_str, fid, f"file should be relative, no leading / or ./: {file_path!r}"))
            if "\\" in file_path:
                errors.append(ValidationError(path_str, fid, f"file should use forward slashes: {file_path!r}"))

        # Location
        loc = f.get("location", {})
        if isinstance(loc, dict):
            validate_types(loc, LOCATION_REQUIRED, "location.", errors, path_str, fid)
            start = loc.get("start_line")
            end = loc.get("end_line")
            if isinstance(start, int) and isinstance(end, int):
                if start < 1:
                    errors.append(ValidationError(path_str, fid, f"start_line must be >= 1, got {start}"))
                if end < start:
                    errors.append(ValidationError(path_str, fid, f"end_line ({end}) < start_line ({start})"))

        # Evidence
        ev = f.get("evidence", {})
        if isinstance(ev, dict):
            validate_types(ev, EVIDENCE_REQUIRED, "evidence.", errors, path_str, fid)
            desc = ev.get("description", "")
            if isinstance(desc, str) and len(desc) < 10:
                errors.append(ValidationError(path_str, fid, "evidence.description too short (< 10 chars)"))

    # FP trap ratio check
    if vuln_count > 0 and fp_count == 0:
        errors.append(ValidationError(path_str, None, f"no false-positive traps (0/{vuln_count} vulns) — need at least 1 per 5"))
    elif vuln_count > 0 and fp_count < vuln_count / 5:
        errors.append(ValidationError(
            path_str, None,
            f"low FP trap ratio: {fp_count} traps for {vuln_count} vulns (need {vuln_count // 5}+)"
        ))

    return errors


def main():
    repos = sys.argv[1:] if len(sys.argv) > 1 else None

    if repos:
        gt_dirs = [GT_DIR / r for r in repos]
    else:
        gt_dirs = sorted(GT_DIR.iterdir())

    total_errors = 0
    total_files = 0
    total_findings = 0
    summary: list[tuple[str, int, int, int]] = []

    for d in gt_dirs:
        gt_file = d / "ground-truth.json" if d.is_dir() else d
        if not gt_file.exists():
            print(f"SKIP {d.name}: no ground-truth.json")
            continue

        total_files += 1
        errors = validate_gt(gt_file)

        # Count findings for summary
        try:
            with open(gt_file) as f:
                gt = json.load(f)
            n_findings = len(gt.get("findings", []))
            n_vulns = sum(1 for f in gt.get("findings", []) if f.get("is_vulnerable"))
            n_fps = n_findings - n_vulns
        except Exception:
            n_findings = n_vulns = n_fps = 0

        total_findings += n_findings
        total_errors += len(errors)
        summary.append((d.name, n_vulns, n_fps, len(errors)))

        if errors:
            print(f"\nFAIL {d.name} ({len(errors)} errors):")
            for e in errors:
                print(e)
        else:
            print(f"OK   {d.name} ({n_vulns} vulns, {n_fps} FP traps)")

    # Summary
    print(f"\n{'='*60}")
    print(f"Validated {total_files} ground truth files, {total_findings} total findings")
    if total_errors:
        print(f"FAILED: {total_errors} errors across {sum(1 for _, _, _, e in summary if e)} files")
    else:
        print("ALL PASSED")

    return 1 if total_errors else 0


if __name__ == "__main__":
    sys.exit(main())
