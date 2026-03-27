#!/usr/bin/env python3
"""Clone all benchmark repositories at their pinned commits.

Reads repo_url and commit_sha from each ground-truth.json file and clones
into repos/{slug}. Skips repos that already exist locally.

Usage:
    python3 clone_repos.py              # Clone all repos
    python3 clone_repos.py --repo realvuln-pygoat realvuln-vampi  # Specific repos
    python3 clone_repos.py --status      # Show clone status without cloning
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
GT_DIR = PROJECT_ROOT / "ground-truth"
REPOS_DIR = PROJECT_ROOT / "repos"


def discover_repos() -> list[dict]:
    """Read all ground-truth files and extract repo metadata."""
    repos = []
    for d in sorted(GT_DIR.iterdir()):
        gt_file = d / "ground-truth.json"
        if not d.is_dir() or not gt_file.exists():
            continue
        with open(gt_file) as f:
            gt = json.load(f)
        repos.append({
            "slug": d.name,
            "url": gt.get("repo_url", ""),
            "sha": gt.get("commit_sha", ""),
        })
    return repos


def clone_repo(slug: str, url: str, sha: str) -> bool:
    """Clone a repo and checkout the pinned commit. Returns True on success."""
    repo_path = REPOS_DIR / slug

    if repo_path.is_dir():
        print(f"  [{slug}] Already exists, skipping")
        return True

    if not url:
        print(f"  [{slug}] No repo_url in ground truth, skipping")
        return False

    REPOS_DIR.mkdir(exist_ok=True)

    print(f"  [{slug}] Cloning {url} ...", end=" ", flush=True)
    result = subprocess.run(
        ["git", "clone", "--depth=1", url, str(repo_path)],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        print(f"FAILED\n    {result.stderr.strip()[:200]}")
        return False

    if sha:
        subprocess.run(
            ["git", "-C", str(repo_path), "fetch", "--depth=1", "origin", sha],
            capture_output=True, text=True, timeout=60,
        )
        checkout = subprocess.run(
            ["git", "-C", str(repo_path), "checkout", sha],
            capture_output=True, text=True, timeout=30,
        )
        if checkout.returncode == 0:
            print(f"OK (pinned to {sha[:8]})")
        else:
            print(f"OK (clone succeeded, but couldn't checkout {sha[:8]} — using HEAD)")
    else:
        print("OK (no pinned commit, using HEAD)")

    return True


def print_status(repos: list[dict]) -> None:
    """Print clone status for all repos."""
    cloned = 0
    missing = 0
    for r in repos:
        repo_path = REPOS_DIR / r["slug"]
        if repo_path.is_dir():
            cloned += 1
            status = "cloned"
        else:
            missing += 1
            status = "MISSING"
        print(f"  [{status:>7}] {r['slug']}")
    print(f"\n  {cloned} cloned, {missing} missing, {len(repos)} total")


def main() -> int:
    parser = argparse.ArgumentParser(description="Clone benchmark repositories")
    parser.add_argument("--repo", nargs="+", help="Specific repo slugs to clone")
    parser.add_argument("--status", action="store_true", help="Show clone status only")
    args = parser.parse_args()

    all_repos = discover_repos()

    if args.repo:
        known = {r["slug"] for r in all_repos}
        for slug in args.repo:
            if slug not in known:
                print(f"Error: unknown repo '{slug}'", file=sys.stderr)
                print(f"Available: {sorted(known)}", file=sys.stderr)
                return 1
        repos = [r for r in all_repos if r["slug"] in args.repo]
    else:
        repos = all_repos

    if args.status:
        print_status(repos)
        return 0

    print(f"Cloning {len(repos)} repositories into {REPOS_DIR}/\n")

    ok = 0
    fail = 0
    for r in repos:
        try:
            if clone_repo(r["slug"], r["url"], r["sha"]):
                ok += 1
            else:
                fail += 1
        except subprocess.TimeoutExpired:
            print(f"TIMEOUT")
            fail += 1

    print(f"\nDone: {ok} succeeded, {fail} failed")
    return 1 if fail > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
