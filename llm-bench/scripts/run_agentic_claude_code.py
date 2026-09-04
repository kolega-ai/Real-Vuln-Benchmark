#!/usr/bin/env python3
"""Run the simple agentic-v1 benchmark prompt through Claude Code CLI.

This is intentionally not the multi-phase claude-adaptation scanner. Each job
starts one headless Claude Code session in the target repository, gives it the
same rendered generic task as ``run_agentic.py``, validates its final response,
and writes standard ``run-N.json`` and ``run-N.metrics.json`` artifacts.

Example:
    python3 llm-bench/scripts/run_agentic_claude_code.py \
      --model claude-fable-5 \
      --scanner-slug claude-fable-5-cc-agentic-v1 \
      --repos vc-claude-code-seeded-v3-fintech-lending-express
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
LLM_BENCH_DIR = SCRIPT_DIR.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

from harness.metrics_collector import RunMetrics, save_metrics
from harness.output_validator import save_validated_output, validate_output
from harness.prompt_builder import build_prompt, load_cwe_families
from run_agentic import LANGUAGES, clone_or_find_repo, discover_repos, load_benchmark_manifest


def build_agentic_task(system_prompt: str, lang_files: str) -> str:
    """Wrap the rendered benchmark prompt with repository-audit instructions.

    Mirrors run_agentic.py's task text exactly (language-aware) so a Claude Code
    run is comparable to the OpenCode-driven runs on the same corpus.
    """
    return (
        f"{system_prompt}\n\n"
        f"The repository to audit is in the current directory.\n\n"
        f"You MUST follow these steps IN ORDER:\n"
        f"1. List all {lang_files} in this repo\n"
        f"2. Read each of those files to understand the code\n"
        f"3. Look for SQL injection, XSS, command injection, path traversal, etc.\n"
        f"4. ONLY after reading ALL files, output your findings\n\n"
        f"CRITICAL: The example JSON in the prompt above is just a FORMAT TEMPLATE.\n"
        f"Your findings must reference actual files and line numbers from THIS repo.\n"
        f"Output ONLY the JSON findings object at the end — no markdown fences."
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("run_agentic_claude_code")

_LIMIT_MARKERS = (
    "usage limit",
    "session limit",
    "rate limit",
    "limit reached",
    "resets at",
    "out of usage",
)


class RateLimitHit(RuntimeError):
    """Claude Code reported a subscription/API usage limit."""


def is_rate_limit(envelope: dict, *texts: str) -> bool:
    combined = " ".join(str(text or "") for text in texts).lower()
    return envelope.get("api_error_status") == 429 or any(
        marker in combined for marker in _LIMIT_MARKERS
    )


def default_scanner_slug(model: str) -> str:
    """Return a filesystem-safe slug that distinguishes the Claude Code backend."""
    normalized = re.sub(r"[^a-z0-9]+", "-", model.lower()).strip("-")
    if not normalized.startswith("claude-"):
        normalized = f"claude-{normalized}"
    return f"{normalized}-cc-agentic-v1"


def run_claude_command(
    cmd: list[str], *, cwd: str, timeout: int
) -> subprocess.CompletedProcess:
    """Run Claude Code in its own process group and clean up on timeout."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=cwd,
        env={**os.environ, "NO_COLOR": "1"},
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = proc.communicate()
        raise subprocess.TimeoutExpired(
            cmd=exc.cmd,
            timeout=exc.timeout,
            output=stdout,
            stderr=stderr,
        ) from exc
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def envelope_usage(envelope: dict) -> dict[str, int | float]:
    """Normalize Claude Code's JSON-envelope usage fields."""
    usage = envelope.get("usage") or {}
    input_tokens = int(usage.get("input_tokens") or 0)
    output_tokens = int(usage.get("output_tokens") or 0)
    cache_read = int(usage.get("cache_read_input_tokens") or 0)
    cache_write = int(usage.get("cache_creation_input_tokens") or 0)
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cached_input_tokens": cache_read,
        "total_tokens": input_tokens + output_tokens + cache_read + cache_write,
        "cost_usd": float(envelope.get("total_cost_usd") or 0.0),
        "agent_steps": int(envelope.get("num_turns") or 0),
    }


def result_paths(repo_slug: str, scanner_slug: str, run_id: int) -> tuple[Path, Path]:
    output_dir = PROJECT_ROOT / "scan-results" / repo_slug / scanner_slug
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / f"run-{run_id}.json", output_dir / f"run-{run_id}.metrics.json"


def run_one(
    *,
    model: str,
    scanner_slug: str,
    repo_slug: str,
    repo_path: Path,
    run_id: int,
    task: str,
    timeout: int,
    max_run_cost: float | None,
    effort: str | None,
    prompt_version: str,
    prompt_label: str,
    benchmark_metadata: dict,
) -> dict:
    result_path, metrics_path = result_paths(repo_slug, scanner_slug, run_id)
    current_gt_hash = benchmark_metadata.get("ground_truth_content_hash", "")
    if result_path.exists() and metrics_path.exists():
        try:
            existing_gt_hash = json.loads(metrics_path.read_text()).get(
                "ground_truth_content_hash", ""
            )
        except (json.JSONDecodeError, OSError):
            existing_gt_hash = ""
        if current_gt_hash and existing_gt_hash == current_gt_hash:
            return {"skipped": True}
        logger.info(
            "Re-running %s run-%d because it is not stamped with current GT",
            repo_slug,
            run_id,
        )

    cmd = [
        "claude",
        "-p",
        task,
        "--output-format",
        "json",
        "--model",
        model,
        "--permission-mode",
        "bypassPermissions",
        "--no-session-persistence",
        "--disallowedTools",
        "Edit,Write,NotebookEdit",
    ]
    if max_run_cost is not None:
        cmd.extend(["--max-budget-usd", str(max_run_cost)])
    if effort is not None:
        cmd.extend(["--effort", effort])

    started = time.time()
    envelope: dict = {}
    recovered_validation = None
    try:
        proc = run_claude_command(cmd, cwd=str(repo_path), timeout=timeout)
        elapsed = time.time() - started
        try:
            envelope = json.loads(proc.stdout)
        except json.JSONDecodeError:
            envelope = {}
        limit_hit = is_rate_limit(
            envelope,
            proc.stderr,
            proc.stdout,
            str(envelope.get("result") or ""),
        )
        if limit_hit:
            candidate = validate_output(str(envelope.get("result") or ""))
            if candidate.valid and candidate.data is not None:
                recovered_validation = candidate
                logger.warning(
                    "%s run-%d: accepting complete JSON from rate-limit envelope",
                    repo_slug,
                    run_id,
                )
            else:
                raise RateLimitHit(
                    str(envelope.get("result") or proc.stderr or "Claude usage limit")
                )
        if proc.returncode != 0 and recovered_validation is None:
            message = (proc.stderr or proc.stdout).strip()[:500]
            raise RuntimeError(f"claude_error: {message}")
        if not envelope:
            raise json.JSONDecodeError("Invalid Claude JSON envelope", proc.stdout, 0)
        if envelope.get("is_error") and recovered_validation is None:
            message = str(envelope.get("result") or "Claude Code returned an error")
            raise RuntimeError(message[:500])
    except subprocess.TimeoutExpired:
        elapsed = time.time() - started
        error, status = f"Timed out after {timeout}s", "timeout"
    except RateLimitHit as exc:
        elapsed = time.time() - started
        error, status = str(exc), "rate_limited"
    except (json.JSONDecodeError, OSError, RuntimeError) as exc:
        elapsed = time.time() - started
        error, status = str(exc), "error"
    else:
        error, status = "", "success"

    usage = envelope_usage(envelope)
    common_metrics = dict(
        model=model,
        repo=repo_slug,
        run_id=run_id,
        input_tokens=usage["input_tokens"],
        cached_input_tokens=usage["cached_input_tokens"],
        output_tokens=usage["output_tokens"],
        total_tokens=usage["total_tokens"],
        cost_usd=usage["cost_usd"],
        wall_clock_seconds=elapsed,
        agent_steps=usage["agent_steps"],
        prompt_version=prompt_version,
        prompt_label=prompt_label,
        reasoning_effort=effort or "",
        benchmark_version=benchmark_metadata.get("benchmark_version", ""),
        ground_truth_version=benchmark_metadata.get("ground_truth_version", ""),
        ground_truth_content_hash=current_gt_hash,
    )
    if status != "success":
        save_metrics(
            RunMetrics(**common_metrics, exit_status=status, error_message=error),
            metrics_path,
        )
        return {
            "success": False,
            "error": error,
            "rate_limited": status == "rate_limited",
            "elapsed": elapsed,
            "cost": usage["cost_usd"],
        }

    validation = recovered_validation or validate_output(
        str(envelope.get("result") or "")
    )
    if not validation.valid or validation.data is None:
        error = str(validation.errors[:3])
        save_metrics(
            RunMetrics(
                **common_metrics,
                exit_status="validation_failed",
                error_message=error,
            ),
            metrics_path,
        )
        return {
            "success": False,
            "error": "validation_failed",
            "elapsed": elapsed,
            "cost": usage["cost_usd"],
        }

    save_validated_output(validation.data, result_path)
    save_metrics(
        RunMetrics(
            **common_metrics,
            exit_status="success",
            llm_json_repair=validation.llm_json_repair,
        ),
        metrics_path,
    )
    return {
        "success": True,
        "findings": validation.findings_count,
        "cost": usage["cost_usd"],
        "elapsed": elapsed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Simple generic agentic-v1 runner via Claude Code CLI"
    )
    parser.add_argument("--model", required=True, help="Claude alias or full model name")
    parser.add_argument(
        "--scanner-slug",
        help="Result slug (default: <model>-cc-agentic-v1)",
    )
    parser.add_argument("--repos", nargs="+", required=True, help="Repo slugs or 'all'")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--max-concurrent", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--max-total-cost", type=float, default=50.0)
    parser.add_argument(
        "--max-run-cost",
        type=float,
        default=None,
        help="Pass Claude Code a hard USD budget for each run",
    )
    parser.add_argument("--prompt-template", type=Path, default=None)
    parser.add_argument("--prompt-label", default="generic-agentic-v1")
    parser.add_argument(
        "--language", choices=sorted(LANGUAGES), default="python",
        help="Corpus language: picks the file-listing wording (default: python)",
    )
    parser.add_argument(
        "--repos-dir", type=Path, default=None,
        help="Directory of repo checkouts (default: <root>/repos)",
    )
    parser.add_argument(
        "--effort", choices=["low", "medium", "high", "xhigh", "max"], default=None,
        help="Claude Code --effort level for the session",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        version = subprocess.run(
            ["claude", "--version"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        logger.error("Claude Code CLI is not installed or unavailable on PATH")
        return 1

    scanner_slug = args.scanner_slug or default_scanner_slug(args.model)
    repos = (
        discover_repos(PROJECT_ROOT / "ground-truth")
        if args.repos == ["all"]
        else args.repos
    )
    prompt_info = build_prompt(
        load_cwe_families(),
        template_path=args.prompt_template,
        label=args.prompt_label,
    )
    task = build_agentic_task(prompt_info.rendered, LANGUAGES[args.language]["files"])
    benchmark_metadata = load_benchmark_manifest()

    if args.dry_run:
        print(f"Claude Code: {version}")
        print(f"Model: {args.model}")
        print(f"Scanner: {scanner_slug}")
        print(f"Prompt: {prompt_info.version_hash} ({prompt_info.label})")
        print(f"Repos: {len(repos)}, runs: {args.runs}")
        return 0

    repo_paths = {
        slug: path
        for slug in repos
        if (path := clone_or_find_repo(slug, args.repos_dir)) is not None
    }
    jobs = [
        (slug, run_id)
        for slug in repos
        if slug in repo_paths
        for run_id in range(1, args.runs + 1)
    ]
    cumulative_cost = 0.0
    completed = 0
    rate_limit_hit = False

    def execute(job: tuple[str, int]) -> tuple[str, int, dict]:
        slug, run_id = job
        result = run_one(
            model=args.model,
            scanner_slug=scanner_slug,
            repo_slug=slug,
            repo_path=repo_paths[slug],
            run_id=run_id,
            task=task,
            timeout=args.timeout,
            max_run_cost=args.max_run_cost,
            effort=args.effort,
            prompt_version=prompt_info.version_hash,
            prompt_label=prompt_info.label,
            benchmark_metadata=benchmark_metadata,
        )
        return slug, run_id, result

    def report(slug: str, run_id: int, result: dict) -> None:
        nonlocal cumulative_cost, completed, rate_limit_hit
        completed += 1
        if result.get("skipped"):
            logger.info("[%d/%d] %s run-%d: skipped", completed, len(jobs), slug, run_id)
            return
        cumulative_cost += float(result.get("cost") or 0)
        rate_limit_hit = rate_limit_hit or bool(result.get("rate_limited"))
        if result.get("success"):
            logger.info(
                "[%d/%d] %s run-%d: OK — %d findings, %.1fs, $%.4f",
                completed,
                len(jobs),
                slug,
                run_id,
                result["findings"],
                result["elapsed"],
                result["cost"],
            )
        else:
            logger.error(
                "[%d/%d] %s run-%d: FAIL — %s",
                completed,
                len(jobs),
                slug,
                run_id,
                result.get("error", "unknown"),
            )

    if args.max_concurrent <= 1:
        for job in jobs:
            if cumulative_cost >= args.max_total_cost:
                logger.warning("Cost limit reached; stopping")
                break
            report(*execute(job))
            if rate_limit_hit:
                logger.warning("Claude usage limit reached; stopping")
                break
    else:
        job_iter = iter(jobs)
        with ThreadPoolExecutor(max_workers=args.max_concurrent) as executor:
            active = {}
            stop_submitting = False
            for _ in range(min(args.max_concurrent, len(jobs))):
                if (job := next(job_iter, None)) is not None:
                    active[executor.submit(execute, job)] = job
            while active:
                done, _ = wait(active, return_when=FIRST_COMPLETED)
                for future in done:
                    active.pop(future)
                    report(*future.result())
                if rate_limit_hit:
                    logger.warning(
                        "Claude usage limit reached; waiting only for active jobs"
                    )
                    stop_submitting = True
                if cumulative_cost >= args.max_total_cost:
                    logger.warning("Cost limit reached; not submitting more jobs")
                    stop_submitting = True
                if not stop_submitting and (job := next(job_iter, None)) is not None:
                    active[executor.submit(execute, job)] = job

    logger.info(
        "Done — %d/%d runs, Claude-reported cost $%.4f",
        completed,
        len(jobs),
        cumulative_cost,
    )
    for slug in repos:
        scanner_dir = PROJECT_ROOT / "scan-results" / slug / scanner_slug
        if not any(scanner_dir.glob("run-[0-9]*.json")):
            continue
        proc = subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / "score.py"),
                "--repo",
                slug,
                "--scanner",
                scanner_slug,
            ],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
        )
        if proc.stdout.strip():
            print(proc.stdout)
        if proc.stderr.strip():
            print(proc.stderr, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
