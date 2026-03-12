#!/usr/bin/env python3
"""Lightweight pilot runner — calls the Anthropic API directly.

Skips OpenHands/Docker. Sends each repo's file listing + file contents
to the LLM in a single long prompt, gets findings back, validates, and scores.

Usage:
    python3 llm-bench/scripts/run_pilot.py --repos realvuln-pygoat --runs 1
    python3 llm-bench/scripts/run_pilot.py --repos all --runs 1 --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
LLM_BENCH_DIR = SCRIPT_DIR.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

import yaml

from harness.cost_calculator import calculate_cost, estimate_total_cost
from harness.metrics_collector import RunMetrics, save_metrics
from harness.output_validator import validate_output, save_validated_output
from harness.prompt_builder import build_prompt, load_cwe_families


def discover_repos(gt_dir: Path) -> list[str]:
    repos = []
    for d in sorted(gt_dir.iterdir()):
        if d.is_dir() and (d / "ground-truth.json").exists():
            repos.append(d.name)
    return repos


def load_model_config(name: str) -> dict:
    with open(LLM_BENCH_DIR / "config" / "models.yaml") as f:
        data = yaml.safe_load(f)
    return data["models"][name]


def clone_or_find_repo(repo_slug: str) -> Path | None:
    """Find or clone the repo for analysis."""
    repos_dir = PROJECT_ROOT / "repos"
    repo_path = repos_dir / repo_slug
    if repo_path.is_dir():
        return repo_path

    # Try to get repo URL from ground truth
    gt_path = PROJECT_ROOT / "ground-truth" / repo_slug / "ground-truth.json"
    if not gt_path.exists():
        return None

    with open(gt_path) as f:
        gt = json.load(f)

    repo_url = gt.get("repo_url")
    commit_sha = gt.get("commit_sha")
    if not repo_url:
        return None

    repos_dir.mkdir(exist_ok=True)
    print(f"  Cloning {repo_url} ...")
    result = subprocess.run(
        ["git", "clone", "--depth=1", repo_url, str(repo_path)],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        print(f"  Clone failed: {result.stderr[:200]}")
        return None

    # Checkout specific commit if shallow clone allows
    if commit_sha:
        subprocess.run(
            ["git", "-C", str(repo_path), "fetch", "--depth=1", "origin", commit_sha],
            capture_output=True, text=True, timeout=60,
        )
        subprocess.run(
            ["git", "-C", str(repo_path), "checkout", commit_sha],
            capture_output=True, text=True, timeout=30,
        )

    return repo_path


def gather_repo_context(repo_path: Path) -> str:
    """Read all Python/HTML/JS/config files into a single string for the prompt."""
    extensions = {
        ".py", ".html", ".htm", ".js", ".json", ".yaml", ".yml",
        ".toml", ".cfg", ".ini", ".txt", ".md", ".xml",
    }
    skip_dirs = {
        ".git", "__pycache__", "node_modules", ".venv", "venv",
        "env", ".tox", ".eggs", "dist", "build", ".mypy_cache",
    }

    files: list[tuple[str, str]] = []
    total_chars = 0
    max_total = 500_000  # ~125K tokens budget for file content
    max_file = 50_000    # Skip very large individual files
    budget_exceeded = False

    for p in sorted(repo_path.rglob("*")):
        if not p.is_file():
            continue
        if any(skip in p.parts for skip in skip_dirs):
            continue
        if p.suffix.lower() not in extensions:
            continue

        rel = p.relative_to(repo_path)

        if budget_exceeded:
            files.append((str(rel), ""))
            continue

        try:
            content = p.read_text(errors="replace")
        except Exception:
            continue

        if len(content) > max_file:
            content = content[:max_file] + f"\n... (truncated, {len(content)} chars total)"

        if total_chars + len(content) > max_total:
            budget_exceeded = True
            files.append((str(rel), ""))
            continue

        files.append((str(rel), content))
        total_chars += len(content)

    parts = []
    # File tree first
    parts.append("## Repository File Listing\n")
    for rel_path, _ in files:
        parts.append(f"  {rel_path}")
    parts.append(f"\nTotal: {len(files)} files\n")

    # File contents
    parts.append("\n## File Contents\n")
    for rel_path, content in files:
        if content == "... (budget exceeded, file skipped)":
            parts.append(f"\n### {rel_path}\n(skipped — token budget reached)\n")
        else:
            parts.append(f"\n### {rel_path}\n```\n{content}\n```\n")

    return "\n".join(parts)


def call_anthropic(
    system_prompt: str,
    user_message: str,
    model_id: str,
    max_output_tokens: int = 16_000,
) -> tuple[str, int, int]:
    """Call Anthropic API and return (response_text, input_tokens, output_tokens)."""
    import anthropic

    client = anthropic.Anthropic()

    response = client.messages.create(
        model=model_id,
        max_tokens=max_output_tokens,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
    )

    text = ""
    for block in response.content:
        if hasattr(block, "text"):
            text += block.text

    return text, response.usage.input_tokens, response.usage.output_tokens


def run_one(
    model_config: dict,
    repo_slug: str,
    run_id: int,
    system_prompt: str,
    repo_context: str,
) -> dict:
    """Run one (model, repo, run) evaluation. Returns result dict."""
    model_id = model_config["model_id"]
    scanner_slug = model_config["scanner_slug"]
    pricing = model_config["pricing"]

    output_dir = PROJECT_ROOT / "scan-results" / repo_slug / scanner_slug
    result_path = output_dir / f"run-{run_id}.json"
    metrics_path = output_dir / f"run-{run_id}.metrics.json"

    if result_path.exists():
        print(f"  Skipping (already exists): {result_path}")
        return {"skipped": True}

    output_dir.mkdir(parents=True, exist_ok=True)

    user_msg = (
        f"Analyze the following Python repository for security vulnerabilities.\n\n"
        f"{repo_context}\n\n"
        f"Output ONLY the JSON findings object — no explanation before or after."
    )

    start = time.time()
    try:
        raw_output, input_tokens, output_tokens = call_anthropic(
            system_prompt, user_msg, model_id,
        )
    except Exception as e:
        elapsed = time.time() - start
        print(f"  API error: {e}")
        metrics = RunMetrics(
            model=model_id, repo=repo_slug, run_id=run_id,
            wall_clock_seconds=elapsed, exit_status="error",
            error_message=str(e),
        )
        save_metrics(metrics, str(metrics_path))
        return {"success": False, "error": str(e), "elapsed": elapsed}

    elapsed = time.time() - start

    # Validate output
    validation = validate_output(raw_output)

    if not validation.valid or validation.data is None:
        print(f"  Validation failed: {validation.errors[:3]}")
        # Save raw output for debugging
        (output_dir / f"run-{run_id}.raw.txt").write_text(raw_output)
        metrics = RunMetrics(
            model=model_id, repo=repo_slug, run_id=run_id,
            input_tokens=input_tokens, output_tokens=output_tokens,
            wall_clock_seconds=elapsed, exit_status="validation_failed",
            error_message=str(validation.errors[:3]),
        )
        cost = calculate_cost(input_tokens, output_tokens, pricing["input_per_1m"], pricing["output_per_1m"])
        metrics.cost_usd = cost.total_cost_usd
        save_metrics(metrics, str(metrics_path))
        return {
            "success": False, "error": "validation_failed",
            "input_tokens": input_tokens, "output_tokens": output_tokens,
            "cost": cost.total_cost_usd, "elapsed": elapsed,
        }

    # Save validated results
    save_validated_output(validation.data, str(result_path))

    # Calculate cost
    cost = calculate_cost(input_tokens, output_tokens, pricing["input_per_1m"], pricing["output_per_1m"])

    # Save metrics
    metrics = RunMetrics(
        model=model_id, repo=repo_slug, run_id=run_id,
        input_tokens=input_tokens, output_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
        cost_usd=cost.total_cost_usd,
        wall_clock_seconds=elapsed,
        exit_status="success",
    )
    save_metrics(metrics, str(metrics_path))

    return {
        "success": True,
        "findings": validation.findings_count,
        "dropped": validation.dropped_count,
        "repaired": validation.repaired_count,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost": cost.total_cost_usd,
        "elapsed": elapsed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Pilot LLM benchmark runner (direct API)")
    parser.add_argument("--model", default="claude-haiku-4", help="Model key from models.yaml")
    parser.add_argument("--repos", nargs="+", required=True, help="Repo slugs or 'all'")
    parser.add_argument("--runs", type=int, default=1, help="Runs per repo")
    parser.add_argument("--dry-run", action="store_true", help="Show cost estimate only")
    args = parser.parse_args()

    # Load config
    model_config = load_model_config(args.model)
    pricing = model_config["pricing"]

    gt_dir = PROJECT_ROOT / "ground-truth"
    if args.repos == ["all"]:
        repos = discover_repos(gt_dir)
    else:
        repos = args.repos

    if args.dry_run:
        per_run, total = estimate_total_cost(
            pricing["input_per_1m"], pricing["output_per_1m"],
            len(repos), args.runs,
        )
        print(f"\n=== Dry Run: {args.model} ===")
        print(f"Model: {model_config['model_id']}")
        print(f"Pricing: ${pricing['input_per_1m']}/1M in, ${pricing['output_per_1m']}/1M out")
        print(f"Repos: {len(repos)}, Runs: {args.runs}")
        print(f"Est. cost per run: ${per_run.total_cost_usd:.2f}")
        print(f"Est. total ({len(repos) * args.runs} runs): ${total:.2f}\n")
        return 0

    # Load API key from .env
    if not os.environ.get("ANTHROPIC_API_KEY"):
        for env_path in [
            PROJECT_ROOT / ".env",
        ]:
            if env_path.exists():
                for line in env_path.read_text().splitlines():
                    if line.startswith("ANTHROPIC_API_KEY="):
                        os.environ["ANTHROPIC_API_KEY"] = line.split("=", 1)[1].strip().strip('"').strip("'")
                        print(f"Loaded API key from {env_path}")
                        break
                if os.environ.get("ANTHROPIC_API_KEY"):
                    break

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY not found. Set it or put it in .env", file=sys.stderr)
        return 1

    # Build system prompt
    cwe_families = load_cwe_families()
    system_prompt = build_prompt(cwe_families)

    cumulative_cost = 0.0
    total_runs = len(repos) * args.runs
    completed = 0

    print(f"\n=== Pilot Run: {args.model} × {len(repos)} repos × {args.runs} runs ===\n")

    for repo_slug in repos:
        print(f"[{repo_slug}]")

        # Get repo source code
        repo_path = clone_or_find_repo(repo_slug)
        if repo_path is None:
            print(f"  Skipping — repo not found and couldn't clone")
            continue

        # Gather file contents
        print(f"  Reading repo files...")
        repo_context = gather_repo_context(repo_path)
        print(f"  Context: {len(repo_context):,} chars")

        for run_id in range(1, args.runs + 1):
            completed += 1
            print(f"  Run {run_id}/{args.runs}...", end=" ", flush=True)

            result = run_one(model_config, repo_slug, run_id, system_prompt, repo_context)

            if result.get("skipped"):
                print("(skipped)")
                continue

            if result.get("success"):
                cumulative_cost += result["cost"]
                print(
                    f"OK — {result['findings']} findings, "
                    f"{result['input_tokens']:,}+{result['output_tokens']:,} tokens, "
                    f"${result['cost']:.4f}, {result['elapsed']:.1f}s"
                )
            else:
                cost = result.get("cost", 0)
                cumulative_cost += cost
                print(f"FAIL — {result.get('error', 'unknown')}, ${cost:.4f}")

            print(f"  [{completed}/{total_runs}] Cumulative: ${cumulative_cost:.4f}")

    print(f"\n=== Done ===")
    print(f"Completed: {completed}/{total_runs} runs")
    print(f"Total cost: ${cumulative_cost:.4f}")

    # Score results
    print(f"\n=== Scoring ===")
    scanner_slug = model_config["scanner_slug"]
    for repo_slug in repos:
        scanner_dir = PROJECT_ROOT / "scan-results" / repo_slug / scanner_slug
        if not scanner_dir.exists():
            continue
        result_files = [f for f in scanner_dir.glob("run-*.json") if not f.name.endswith(".metrics.json")]
        if result_files:
            print(f"  python3 score.py --repo {repo_slug} --scanner {scanner_slug}")
            proc = subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "score.py"),
                 "--repo", repo_slug, "--scanner", scanner_slug],
                capture_output=True, text=True, cwd=str(PROJECT_ROOT),
            )
            print(proc.stdout)
            if proc.stderr:
                print(proc.stderr, file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
