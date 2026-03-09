#!/usr/bin/env python3
"""
Batch-fetch findings from the production app for all realvuln repos.

Reads repo→application_id mapping from config/apps/{name}.json.

Usage:
    # List available app configs
    python batch_fetch.py --list

    # Fetch using a config file
    python batch_fetch.py our-scanner-dspy-kimi
    python batch_fetch.py our-scanner-manual-optimization

    # Include ignored/false_positive findings
    python batch_fetch.py our-scanner-dspy-kimi --include-excluded

    # Fetch a subset of repos
    python batch_fetch.py our-scanner-dspy-kimi --repos realvuln-pygoat realvuln-vulpy

    # Dry-run
    python batch_fetch.py our-scanner-dspy-kimi --dry-run

    # Override the output scanner slug
    python batch_fetch.py our-scanner-dspy-kimi --scanner my-custom-name
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
APPS_CONFIG_DIR = SCRIPT_DIR / "config" / "apps"
BENCHMARK_SCRIPTS = SCRIPT_DIR.parent / "scripts" / "benchmark_scripts"

sys.path.insert(0, str(BENCHMARK_SCRIPTS))
from lib.mongodb import fetch_findings_with_lines

# Import the converter from fetch_results
from fetch_results import convert_to_semgrep


def load_app_config(name: str) -> dict:
    """Load a config/apps/{name}.json file."""
    path = APPS_CONFIG_DIR / f"{name}.json"
    if not path.exists():
        available = [p.stem for p in APPS_CONFIG_DIR.glob("*.json")]
        print(f"Error: config not found: {path}", file=sys.stderr)
        print(f"Available: {', '.join(available)}", file=sys.stderr)
        sys.exit(1)
    return json.loads(path.read_text())


def list_configs() -> None:
    """Print all available app configs."""
    configs = sorted(APPS_CONFIG_DIR.glob("*.json"))
    if not configs:
        print("No app configs found in config/apps/")
        return
    for path in configs:
        cfg = json.loads(path.read_text())
        n_apps = len(cfg.get("apps", {}))
        scanner = cfg.get("scanner", "?")
        desc = cfg.get("description", "")
        print(f"  {path.stem:40s}  scanner={scanner:30s}  repos={n_apps:2d}  {desc}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Batch-fetch findings from production app for realvuln repos"
    )
    parser.add_argument(
        "config", nargs="?", default=None,
        help="App config name (from config/apps/*.json)",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List available app configs and exit",
    )
    parser.add_argument(
        "--scanner", default=None,
        help="Override scanner slug from config",
    )
    parser.add_argument(
        "--run-name", default=None,
        help="Result filename without .json (default: results)",
    )
    parser.add_argument(
        "--include-excluded", action="store_true",
        help="Include ignored/false_positive findings",
    )
    parser.add_argument(
        "--repos", nargs="+", default=None,
        help="Only fetch these repos (default: all in config)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be fetched without actually querying",
    )
    args = parser.parse_args()

    if args.list:
        list_configs()
        return 0

    if not args.config:
        parser.error("config name required (or use --list)")

    # Load config
    cfg = load_app_config(args.config)
    scanner = args.scanner or cfg.get("scanner", args.config)
    # Config format: {"apps": {"repo-slug": "application-id", ...}}
    mapping: dict[str, str] = cfg["apps"]

    print(f"Config: {args.config}")
    print(f"Scanner: {scanner}")
    print(f"Description: {cfg.get('description', '')}")
    print(f"Repos: {len(mapping)}")

    # Filter to requested repos
    if args.repos:
        repo_set = set(args.repos)
        mapping = {k: v for k, v in mapping.items() if k in repo_set}
        if not mapping:
            print(f"Error: none of {args.repos} found in config", file=sys.stderr)
            return 1

    if args.dry_run:
        for repo, app_id in sorted(mapping.items()):
            print(f"  {repo:50s} <- {app_id}")
        print(f"\nWould fetch {len(mapping)} repos as --scanner {scanner}")
        return 0

    total_results = 0
    total_skipped = 0

    for repo_name, app_id in sorted(mapping.items()):
        print(f"\n--- {repo_name} ---")

        findings = fetch_findings_with_lines(
            app_id, include_excluded=args.include_excluded
        )
        print(f"  {len(findings)} occurrence-level rows")

        if not findings:
            print("  SKIPPED — no findings")
            continue

        results, skipped = convert_to_semgrep(findings)

        out_dir = SCRIPT_DIR / "scan-results" / repo_name / scanner
        out_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{args.run_name}.json" if args.run_name else "results.json"
        out_path = out_dir / filename
        out_path.write_text(json.dumps({"results": results}, indent=2))

        print(f"  {len(results)} results saved ({skipped} skipped, no CWE)")
        total_results += len(results)
        total_skipped += skipped

    print(f"\n=== DONE: {total_results} results across {len(mapping)} repos "
          f"({total_skipped} skipped) ===")
    print(f"\nScore with:")
    print(f"  python dashboard.py --scanner-group all")
    return 0


if __name__ == "__main__":
    sys.exit(main())
