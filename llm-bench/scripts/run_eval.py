#!/usr/bin/env python3
"""Run LLM security scanner benchmark evaluations.

Usage:
    # Dry run - show cost estimate only
    python run_eval.py --models claude-haiku-4 --repos all --runs 3 --dry-run

    # Single test run
    python run_eval.py --models claude-haiku-4 --repos realvuln-pygoat --runs 1

    # Full benchmark
    python run_eval.py --models all --repos all --runs 3

    # With cost limit
    python run_eval.py --models all --repos all --runs 3 --max-total-cost 50
"""
from __future__ import annotations

import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Add project root to path
SCRIPT_DIR = Path(__file__).resolve().parent
LLM_BENCH_DIR = SCRIPT_DIR.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

from harness.cost_calculator import estimate_total_cost
from harness.runner import ModelConfig, RunConfig, RunResult, load_model_configs, run_single

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("run_eval")


def discover_repos(gt_dir: Path) -> list[str]:
    """Find all repos with ground truth."""
    repos = []
    for d in sorted(gt_dir.iterdir()):
        if d.is_dir() and (d / "ground-truth.json").exists():
            repos.append(d.name)
    return repos


def resolve_models(model_names: list[str], all_configs: dict[str, ModelConfig]) -> list[ModelConfig]:
    """Resolve model names (or 'all') to ModelConfig list."""
    if model_names == ["all"]:
        return list(all_configs.values())
    result = []
    for name in model_names:
        if name not in all_configs:
            logger.error("Unknown model: %s. Available: %s", name, list(all_configs.keys()))
            sys.exit(1)
        result.append(all_configs[name])
    return result


def resolve_repos(repo_names: list[str], gt_dir: Path) -> list[str]:
    """Resolve repo names (or 'all') to repo slug list."""
    all_repos = discover_repos(gt_dir)
    if repo_names == ["all"]:
        return all_repos
    for name in repo_names:
        if name not in all_repos:
            logger.error("Unknown repo: %s", name)
            sys.exit(1)
    return repo_names


def print_dry_run(
    models: list[ModelConfig],
    repos: list[str],
    runs: int,
    estimated_input: int,
    estimated_output: int,
) -> None:
    """Print cost estimates for a dry run."""
    print("\n=== Cost Estimate ===\n")

    total_all_models = 0.0
    total_runs_all = 0

    for model in models:
        per_run, total = estimate_total_cost(
            model.pricing["input_per_1m"],
            model.pricing["output_per_1m"],
            len(repos),
            runs,
            estimated_input,
            estimated_output,
        )
        num_runs = len(repos) * runs
        total_runs_all += num_runs
        total_all_models += total

        print(f"Model: {model.name}")
        print(
            f"  Pricing: ${model.pricing['input_per_1m']}/1M in, "
            f"${model.pricing['output_per_1m']}/1M out"
        )
        print(f"  Repos: {len(repos)}")
        print(f"  Runs per repo: {runs}")
        print(
            f"  Token budget: {estimated_input:,} in + {estimated_output:,} out per run"
        )
        print(f"  Estimated cost per run:  ${per_run.total_cost_usd:.2f}")
        print(f"  Estimated total ({num_runs} runs): ${total:.2f}")
        time_est = num_runs * 10  # ~10 min per run
        print(f"  Time estimate: ~{time_est // 60}h {time_est % 60}m @ 10min/run (sequential)")
        print()

    print(f"--- Grand Total ---")
    print(f"Total runs: {total_runs_all}")
    print(f"Estimated total cost: ${total_all_models:.2f}")
    print()


def run_eval(
    models: list[ModelConfig],
    repos: list[str],
    runs: int,
    timeout: int,
    max_iterations: int,
    max_output_tokens: int,
    max_total_cost: float | None,
    max_concurrent: int,
    repos_dir: Path,
    scan_results_dir: Path,
) -> dict[str, list[RunResult]]:
    """Execute all evaluation runs.

    Returns:
        Dict mapping "model/repo/run-N" keys to RunResult.
    """
    # Build run configs
    run_configs: list[RunConfig] = []
    for model in models:
        for repo in repos:
            repo_path = repos_dir / repo
            output_dir = scan_results_dir / repo / model.scanner_slug
            for run_id in range(1, runs + 1):
                # Skip if result already exists
                result_path = output_dir / f"run-{run_id}.json"
                if result_path.exists():
                    logger.info("Skipping existing: %s/%s/run-%d", model.name, repo, run_id)
                    continue
                run_configs.append(
                    RunConfig(
                        model=model,
                        repo=repo,
                        run_id=run_id,
                        repo_path=repo_path,
                        output_dir=output_dir,
                        timeout_seconds=timeout,
                        max_iterations=max_iterations,
                        max_output_tokens=max_output_tokens,
                    )
                )

    total_runs = len(run_configs)
    if total_runs == 0:
        logger.info("All runs already completed, nothing to do.")
        return {}

    logger.info("Starting %d evaluation runs...", total_runs)

    results: dict[str, list[RunResult]] = {}
    cumulative_cost = 0.0
    completed = 0

    def execute_run(rc: RunConfig) -> tuple[str, RunResult]:
        key = f"{rc.model.name}/{rc.repo}/run-{rc.run_id}"
        result = run_single(rc)
        return key, result

    # Execute runs (with optional parallelism)
    if max_concurrent <= 1:
        for rc in run_configs:
            if max_total_cost and cumulative_cost >= max_total_cost:
                logger.warning(
                    "Cost limit reached ($%.2f >= $%.2f). Stopping.",
                    cumulative_cost, max_total_cost,
                )
                break

            key, result = execute_run(rc)
            completed += 1
            results.setdefault(rc.model.name, []).append(result)

            if result.metrics:
                cumulative_cost += result.metrics.cost_usd

            status = "OK" if result.success else f"FAIL: {result.error}"
            logger.info(
                "[%d/%d] %s — %s (%.1fs, $%.4f spent, est. $%.2f total)",
                completed, total_runs, key, status,
                result.wall_clock_seconds, cumulative_cost,
                cumulative_cost * total_runs / max(completed, 1),
            )
    else:
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            future_to_rc = {executor.submit(execute_run, rc): rc for rc in run_configs}
            for future in as_completed(future_to_rc):
                rc = future_to_rc[future]
                key, result = future.result()
                completed += 1
                results.setdefault(rc.model.name, []).append(result)

                if result.metrics:
                    cumulative_cost += result.metrics.cost_usd

                status = "OK" if result.success else f"FAIL: {result.error}"
                logger.info(
                    "[%d/%d] %s — %s (%.1fs, $%.4f total)",
                    completed, total_runs, key, status,
                    result.wall_clock_seconds, cumulative_cost,
                )

                if max_total_cost and cumulative_cost >= max_total_cost:
                    logger.warning("Cost limit reached. Cancelling remaining runs.")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

    # Summary
    successes = sum(1 for v in results.values() for r in v if r.success)
    failures = completed - successes
    logger.info(
        "Completed: %d/%d runs (%d succeeded, %d failed). Total cost: $%.4f",
        completed, total_runs, successes, failures, cumulative_cost,
    )

    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run LLM security scanner benchmark evaluations"
    )
    parser.add_argument(
        "--models", nargs="+", required=True,
        help="Model names from models.yaml, or 'all'",
    )
    parser.add_argument(
        "--repos", nargs="+", required=True,
        help="Repo slugs (e.g. realvuln-pygoat), or 'all'",
    )
    parser.add_argument(
        "--runs", type=int, default=3,
        help="Number of runs per (model, repo) pair (default: 3)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print cost estimate without running anything",
    )
    parser.add_argument(
        "--timeout", type=int, default=600,
        help="Timeout per run in seconds (default: 600)",
    )
    parser.add_argument(
        "--max-iterations", type=int, default=50,
        help="Max agent steps per run (default: 50)",
    )
    parser.add_argument(
        "--max-input-tokens", type=int, default=100_000,
        help="Estimated input tokens per run for cost calc (default: 100000)",
    )
    parser.add_argument(
        "--max-output-tokens", type=int, default=20_000,
        help="Max output tokens per run (default: 20000)",
    )
    parser.add_argument(
        "--max-total-cost", type=float, default=None,
        help="Hard stop if cumulative cost exceeds this USD amount",
    )
    parser.add_argument(
        "--max-concurrent", type=int, default=1,
        help="Max concurrent OpenHands runs (default: 1)",
    )
    parser.add_argument(
        "--models-config", type=Path, default=None,
        help="Path to models.yaml (default: llm-bench/config/models.yaml)",
    )
    args = parser.parse_args()

    # Load model configs
    all_configs = load_model_configs(args.models_config)
    models = resolve_models(args.models, all_configs)
    gt_dir = PROJECT_ROOT / "ground-truth"
    repos = resolve_repos(args.repos, gt_dir)

    if args.dry_run:
        print_dry_run(
            models, repos, args.runs,
            args.max_input_tokens, args.max_output_tokens,
        )
        return 0

    run_eval(
        models=models,
        repos=repos,
        runs=args.runs,
        timeout=args.timeout,
        max_iterations=args.max_iterations,
        max_output_tokens=args.max_output_tokens,
        max_total_cost=args.max_total_cost,
        max_concurrent=args.max_concurrent,
        repos_dir=PROJECT_ROOT / "repos",
        scan_results_dir=PROJECT_ROOT / "scan-results",
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
