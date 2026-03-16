#!/usr/bin/env python3
"""Agentic LLM benchmark runner — uses OpenCode CLI.

Unlike run_pilot.py (single-turn, whole-repo-in-prompt), this runner gives
the LLM tools to explore the codebase iteratively: read files, grep, list
dirs, run bash commands. The agent decides what to look at and when to stop.

Requires: opencode CLI installed (brew install opencode).

Usage:
    # Test on one repo
    python3 llm-bench/scripts/run_agentic.py --repos realvuln-vampi --runs 1

    # 4 repos in parallel
    python3 llm-bench/scripts/run_agentic.py --repos realvuln-vampi realvuln-dsvw realvuln-dvpwa realvuln-pygoat --runs 1 --max-concurrent 4

    # All repos × 3 runs
    python3 llm-bench/scripts/run_agentic.py --repos all --runs 3 --max-concurrent 4
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
LLM_BENCH_DIR = SCRIPT_DIR.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

import yaml

from harness.cost_calculator import estimate_total_cost
from harness.metrics_collector import RunMetrics, save_metrics
from harness.output_validator import validate_output, save_validated_output
from harness.prompt_builder import build_prompt, load_cwe_families

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("run_agentic")


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
    logger.info("Cloning %s ...", repo_url)
    result = subprocess.run(
        ["git", "clone", "--depth=1", repo_url, str(repo_path)],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        logger.error("Clone failed: %s", result.stderr[:200])
        return None

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


def run_one_agentic(
    model_config: dict,
    repo_slug: str,
    run_id: int,
    system_prompt: str,
    repo_path: Path,
    timeout: int,
) -> dict:
    """Run one agentic evaluation using OpenCode CLI."""
    model_id = model_config["model_id"]
    scanner_slug = model_config["scanner_slug"]

    output_dir = PROJECT_ROOT / "scan-results" / repo_slug / scanner_slug
    result_path = output_dir / f"run-{run_id}.json"
    metrics_path = output_dir / f"run-{run_id}.metrics.json"

    if result_path.exists():
        return {"skipped": True}

    output_dir.mkdir(parents=True, exist_ok=True)

    # OpenCode model format: provider/model_id
    provider = model_config.get("provider", "anthropic")
    opencode_model = f"{provider}/{model_id}"

    task = (
        f"{system_prompt}\n\n"
        f"The repository to audit is in the current directory.\n\n"
        f"You MUST follow these steps IN ORDER:\n"
        f"1. List all Python files in this repo\n"
        f"2. Read each Python file to understand the code\n"
        f"3. Look for SQL injection, XSS, command injection, path traversal, etc.\n"
        f"4. ONLY after reading ALL files, output your findings\n\n"
        f"CRITICAL: The example JSON in the prompt above is just a FORMAT TEMPLATE.\n"
        f"Your findings must reference actual files and line numbers from THIS repo.\n"
        f"Output ONLY the JSON findings object at the end — no markdown fences."
    )

    start = time.time()

    try:
        proc = subprocess.run(
            ["opencode", "run", "--format", "json", "-m", opencode_model, task],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(repo_path),
            env={**os.environ, "NO_COLOR": "1"},
        )
        raw_json_output = proc.stdout
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        logger.error("Timeout for %s run-%d after %.0fs", repo_slug, run_id, elapsed)
        metrics = RunMetrics(
            model=model_id, repo=repo_slug, run_id=run_id,
            wall_clock_seconds=elapsed, exit_status="timeout",
            error_message=f"Timed out after {timeout}s",
        )
        save_metrics(metrics, str(metrics_path))
        return {"success": False, "error": "timeout", "elapsed": elapsed, "cost": 0}
    except Exception as e:
        elapsed = time.time() - start
        logger.error("Error for %s run-%d: %s", repo_slug, run_id, e)
        metrics = RunMetrics(
            model=model_id, repo=repo_slug, run_id=run_id,
            wall_clock_seconds=elapsed, exit_status="error",
            error_message=str(e),
        )
        save_metrics(metrics, str(metrics_path))
        return {"success": False, "error": str(e), "elapsed": elapsed, "cost": 0}

    elapsed = time.time() - start

    # Parse JSON events to extract text output and real token/cost metrics
    raw_output = ""
    total_cost = 0.0
    total_input_tokens = 0
    total_output_tokens = 0
    total_cache_read = 0
    total_cache_write = 0
    total_tokens = 0

    for line in raw_json_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Collect text output from "text" events
        if event.get("type") == "text":
            part = event.get("part", {})
            raw_output += part.get("text", "")

        # Collect cost/token data from "step_finish" events
        if event.get("type") == "step_finish":
            part = event.get("part", {})
            total_cost += part.get("cost", 0)
            tokens = part.get("tokens", {})
            total_input_tokens += tokens.get("input", 0)
            total_output_tokens += tokens.get("output", 0)
            total_tokens += tokens.get("total", 0)
            cache = tokens.get("cache", {})
            total_cache_read += cache.get("read", 0)
            total_cache_write += cache.get("write", 0)

    # Validate output — extract JSON from the agent's response
    validation = validate_output(raw_output)

    if not validation.valid or validation.data is None:
        logger.warning(
            "Validation failed for %s run-%d: %s",
            repo_slug, run_id, validation.errors[:3],
        )
        metrics = RunMetrics(
            model=model_id, repo=repo_slug, run_id=run_id,
            input_tokens=total_input_tokens, output_tokens=total_output_tokens,
            total_tokens=total_tokens,
            cost_usd=total_cost,
            wall_clock_seconds=elapsed, exit_status="validation_failed",
            error_message=str(validation.errors[:3]),
        )
        save_metrics(metrics, str(metrics_path))
        return {
            "success": False, "error": "validation_failed",
            "elapsed": elapsed, "cost": total_cost,
        }

    # Save validated results
    save_validated_output(validation.data, str(result_path))

    metrics = RunMetrics(
        model=model_id, repo=repo_slug, run_id=run_id,
        input_tokens=total_input_tokens, output_tokens=total_output_tokens,
        total_tokens=total_tokens,
        cost_usd=total_cost,
        wall_clock_seconds=elapsed,
        exit_status="success",
    )
    save_metrics(metrics, str(metrics_path))

    return {
        "success": True,
        "findings": validation.findings_count,
        "dropped": validation.dropped_count,
        "repaired": validation.repaired_count,
        "cost": total_cost,
        "elapsed": elapsed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Agentic LLM benchmark runner (OpenCode)")
    parser.add_argument("--model", default="claude-haiku-4-agentic", help="Model key from models.yaml")
    parser.add_argument("--repos", nargs="+", required=True, help="Repo slugs or 'all'")
    parser.add_argument("--runs", type=int, default=1, help="Runs per repo")
    parser.add_argument("--max-concurrent", type=int, default=1, help="Max parallel runs")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout per run in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Show cost estimate only")
    args = parser.parse_args()

    # Verify opencode is installed
    try:
        subprocess.run(["opencode", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        logger.error("opencode not found. Install with: brew install opencode")
        return 1

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
            200_000, 50_000,  # Agentic uses more tokens
        )
        print(f"\n=== Dry Run (Agentic via OpenCode): {args.model} ===")
        print(f"Model: {model_config['model_id']}")
        print(f"Repos: {len(repos)}, Runs: {args.runs}")
        print(f"Est. cost per run: ${per_run.total_cost_usd:.2f}")
        print(f"Est. total ({len(repos) * args.runs} runs): ${total:.2f}")
        print(f"Note: Agentic runs use ~2-5x more tokens than single-turn\n")
        return 0

    # Load API key
    if not os.environ.get("ANTHROPIC_API_KEY"):
        env_path = PROJECT_ROOT / ".env"
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                if line.startswith("ANTHROPIC_API_KEY="):
                    os.environ["ANTHROPIC_API_KEY"] = line.split("=", 1)[1].strip().strip('"').strip("'")
                    logger.info("Loaded API key from %s", env_path)
                    break

    if not os.environ.get("ANTHROPIC_API_KEY"):
        logger.error("ANTHROPIC_API_KEY not found. Set it or put it in .env")
        return 1

    # Build system prompt
    cwe_families = load_cwe_families()
    system_prompt = build_prompt(cwe_families)

    # Pre-clone all repos
    repo_paths: dict[str, Path] = {}
    for repo_slug in repos:
        repo_path = clone_or_find_repo(repo_slug)
        if repo_path is None:
            logger.warning("Skipping %s — repo not found", repo_slug)
            continue
        repo_paths[repo_slug] = repo_path

    # Build jobs
    jobs: list[tuple[str, int]] = []
    for repo_slug in repos:
        if repo_slug not in repo_paths:
            continue
        for run_id in range(1, args.runs + 1):
            jobs.append((repo_slug, run_id))

    total_runs = len(jobs)
    cumulative_cost = 0.0
    completed = 0

    logger.info(
        "Starting agentic run: %s × %d repos × %d runs (%d total, %d concurrent)",
        args.model, len(repo_paths), args.runs, total_runs, args.max_concurrent,
    )

    def execute_job(job: tuple[str, int]) -> tuple[str, int, dict]:
        repo_slug, run_id = job
        result = run_one_agentic(
            model_config, repo_slug, run_id, system_prompt,
            repo_paths[repo_slug], timeout=args.timeout,
        )
        return repo_slug, run_id, result

    def log_result(repo_slug: str, run_id: int, result: dict) -> None:
        nonlocal cumulative_cost, completed
        completed += 1
        if result.get("skipped"):
            logger.info("[%d/%d] %s run-%d: skipped", completed, total_runs, repo_slug, run_id)
            return
        if result.get("success"):
            cumulative_cost += result["cost"]
            logger.info(
                "[%d/%d] %s run-%d: OK — %d findings, %.1fs, $%.4f (total: $%.4f)",
                completed, total_runs, repo_slug, run_id,
                result["findings"], result["elapsed"], result["cost"], cumulative_cost,
            )
        else:
            cost = result.get("cost", 0)
            cumulative_cost += cost
            logger.info(
                "[%d/%d] %s run-%d: FAIL — %s, %.1fs",
                completed, total_runs, repo_slug, run_id,
                result.get("error", "unknown"), result.get("elapsed", 0),
            )

    if args.max_concurrent <= 1:
        for job in jobs:
            repo_slug, run_id, result = execute_job(job)
            log_result(repo_slug, run_id, result)
    else:
        logger.info("Running with %d concurrent workers", args.max_concurrent)
        with ThreadPoolExecutor(max_workers=args.max_concurrent) as executor:
            futures = {executor.submit(execute_job, job): job for job in jobs}
            for future in as_completed(futures):
                repo_slug, run_id, result = future.result()
                log_result(repo_slug, run_id, result)

    logger.info("Done — %d/%d runs, total cost: $%.4f", completed, total_runs, cumulative_cost)

    # Score results
    logger.info("Scoring results...")
    scanner_slug = model_config["scanner_slug"]
    for repo_slug in repos:
        scanner_dir = PROJECT_ROOT / "scan-results" / repo_slug / scanner_slug
        if not scanner_dir.exists():
            continue
        result_files = [f for f in scanner_dir.glob("run-*.json") if not f.name.endswith(".metrics.json")]
        if result_files:
            proc = subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "score.py"),
                 "--repo", repo_slug, "--scanner", scanner_slug],
                capture_output=True, text=True, cwd=str(PROJECT_ROOT),
            )
            if proc.stdout.strip():
                print(proc.stdout)
            if proc.stderr:
                print(proc.stderr, file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
