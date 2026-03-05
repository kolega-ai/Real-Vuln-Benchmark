#!/usr/bin/env python3
"""
Fetch findings from MongoDB and write them as Semgrep JSON into
scan-results/{repo}/{scanner}/ for RealVuln scoring.

Gets ALL open/needs_review findings for an application.
Line numbers come from finding_occurrences (not the redundant
fields on the findings collection).

Usage:
    python fetch_results.py <application_id> --repo realvuln-VAmPI
    python fetch_results.py <application_id> --repo realvuln-VAmPI --scanner our-scanner
    python fetch_results.py <application_id> --repo realvuln-VAmPI --run-name run-1
    python fetch_results.py <application_id> --repo realvuln-VAmPI --include-excluded
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BENCHMARK_SCRIPTS = SCRIPT_DIR.parent / "scripts" / "benchmark_scripts"

# Reuse the existing MongoDB helpers
sys.path.insert(0, str(BENCHMARK_SCRIPTS))
from lib.mongodb import fetch_findings_with_lines


def convert_to_semgrep(findings: list[dict]) -> tuple[list[dict], int]:
    """Convert finding records to Semgrep JSON format."""
    results = []
    skipped = 0

    for entry in findings:
        cwes = entry.get("cwe", [])
        if not cwes:
            skipped += 1
            continue

        results.append({
            "check_id": entry.get("check_id", "unknown"),
            "path": entry.get("file_path", "unknown"),
            "start": {
                "line": entry.get("line_start", 1),
                "col": 1,
            },
            "end": {
                "line": entry.get("line_end", 1),
                "col": 100,
            },
            "extra": {
                "message": entry.get("message", ""),
                "severity": entry.get("severity", "WARNING").upper(),
                "metadata": {
                    "cwe": cwes,
                    "finding_id": entry.get("finding_id"),
                },
            },
        })

    return results, skipped


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch findings from MongoDB into RealVuln scan-results"
    )
    parser.add_argument("application_id", help="MongoDB application ID")
    parser.add_argument(
        "--repo", required=True, help="Target repo slug (e.g. realvuln-VAmPI)"
    )
    parser.add_argument(
        "--scanner", default="our-scanner", help="Scanner slug (default: our-scanner)"
    )
    parser.add_argument(
        "--run-name", default=None,
        help="Result filename without .json (default: results)",
    )
    parser.add_argument(
        "--include-excluded", action="store_true",
        help="Include ignored/false_positive findings",
    )
    args = parser.parse_args()

    # Fetch all findings for the app, with lines from occurrences
    findings = fetch_findings_with_lines(
        args.application_id, include_excluded=args.include_excluded
    )

    # Convert to Semgrep JSON
    results, skipped = convert_to_semgrep(findings)
    if not results:
        print("Error: No findings with CWEs to convert.", file=sys.stderr)
        return 1

    # Write to scan-results/{repo}/{scanner}/
    out_dir = SCRIPT_DIR / "scan-results" / args.repo / args.scanner
    out_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{args.run_name}.json" if args.run_name else "results.json"
    out_path = out_dir / filename
    out_path.write_text(json.dumps({"results": results}, indent=2))

    print(f"Converted {len(results)} findings ({skipped} skipped, no CWE)")
    print(f"Output: {out_path}")
    print()
    print(f"Score with:  python3 score.py --repo {args.repo} --scanner {args.scanner}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
