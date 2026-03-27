#!/usr/bin/env python3
"""Backfill prompt_version and prompt_label into existing .metrics.json files.

Usage:
    python3 llm-bench/scripts/backfill_prompt_version.py --dry-run
    python3 llm-bench/scripts/backfill_prompt_version.py --label default-v1
    python3 llm-bench/scripts/backfill_prompt_version.py --force  # overwrite existing
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
LLM_BENCH_DIR = SCRIPT_DIR.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

from harness.prompt_builder import build_prompt


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill prompt version into .metrics.json files")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be updated")
    parser.add_argument("--label", type=str, default="default-v1", help="Prompt label to set (default: default-v1)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing prompt_version fields")
    args = parser.parse_args()

    prompt_info = build_prompt()

    scan_dir = PROJECT_ROOT / "scan-results"
    if not scan_dir.exists():
        print("No scan-results directory found")
        return 1

    metrics_files = sorted(scan_dir.rglob("run-*.metrics.json"))
    print(f"Found {len(metrics_files)} .metrics.json files")
    print(f"Prompt version: {prompt_info.version_hash}")
    print(f"Label: {args.label}")
    print()

    updated = 0
    skipped = 0
    errors = 0

    for mf in metrics_files:
        try:
            with open(mf) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"  ERROR: {mf}: {e}")
            errors += 1
            continue

        if data.get("prompt_version") and not args.force:
            skipped += 1
            continue

        data["prompt_version"] = prompt_info.version_hash
        data["prompt_label"] = args.label

        if args.dry_run:
            print(f"  Would update: {mf.relative_to(PROJECT_ROOT)}")
        else:
            with open(mf, "w") as f:
                json.dump(data, f, indent=2)

        updated += 1

    print(f"\nSummary: {updated} updated, {skipped} skipped (already set), {errors} errors")
    if args.dry_run:
        print("(dry run — no files were modified)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
