#!/usr/bin/env python3
"""Run the simple agentic-v1 benchmark prompt through the Kimi CLI (kimi-code).

Each job starts one headless `kimi -p ... --output-format stream-json` session
in the target repository. The CLI itself does not print token usage on
stream-json (only role:"assistant" content deltas and a session-resume hint),
so this runner reads the real usage back out of the session's own
`agents/main/wire.jsonl` transcript after the process exits -- the same
after-the-fact-log-reading approach used for OpenCode's session store
elsewhere in this harness.

Example:
    python3 llm-bench/scripts/run_kimi_cli.py \
      --model kimi-code/k3 --scanner-slug kimi-k3-cli-agentic-v1 \
      --repos realvuln-flask-xss --language python
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

from harness.cost_calculator import calculate_cost
from harness.metrics_collector import RunMetrics, save_metrics
from harness.output_validator import save_validated_output, validate_output
from harness.prompt_builder import build_prompt, load_cwe_families
from run_agentic import LANGUAGES, clone_or_find_repo, discover_repos, load_benchmark_manifest

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("run_kimi_cli")

KIMI_SESSIONS_ROOT = Path.home() / ".kimi-code" / "sessions"


def build_task(system_prompt: str, lang_files: str) -> str:
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


def run_kimi_command(cmd: list[str], *, cwd: str, timeout: int) -> subprocess.CompletedProcess:
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        cwd=cwd, env={**os.environ, "NO_COLOR": "1"}, start_new_session=True,
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
        raise subprocess.TimeoutExpired(cmd=exc.cmd, timeout=exc.timeout, output=stdout, stderr=stderr) from exc
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def _cwd_slug(cwd: str) -> str:
    """Mirror kimi-code's own `wd_<basename>_<hash>` session-dir naming."""
    import hashlib
    base = Path(cwd).name
    h = hashlib.sha256(cwd.encode()).hexdigest()[:12]
    return f"wd_{base}_{h}"


def _find_usage(cwd: str, session_id: str) -> dict:
    """Sum usage lines from the session's wire.jsonl transcript."""
    root = KIMI_SESSIONS_ROOT / _cwd_slug(cwd) / session_id / "agents" / "main" / "wire.jsonl"
    if not root.exists():
        # cwd hashing may not match exactly across kimi-code versions; fall back
        # to searching any session dir created for this cwd around this run.
        for cand in KIMI_SESSIONS_ROOT.glob(f"*/{session_id}/agents/main/wire.jsonl"):
            root = cand
            break
    totals = {"input": 0, "output": 0, "cache_read": 0}
    if not root.exists():
        return totals
    for line in root.read_text(errors="ignore").splitlines():
        m = re.search(r'"usage":\{([^}]*)\}', line)
        if not m:
            continue
        body = m.group(1)
        for key, field in (("inputOther", "input"), ("output", "output"), ("inputCacheRead", "cache_read")):
            fm = re.search(rf'"{key}":(\d+)', body)
            if fm:
                totals[field] += int(fm.group(1))
    return totals


def run_one(
    *, model: str, scanner_slug: str, repo_slug: str, repo_path: Path, run_id: int,
    task: str, timeout: int, pricing: dict, prompt_version: str, prompt_label: str,
    benchmark_metadata: dict,
) -> dict:
    output_dir = PROJECT_ROOT / "scan-results" / repo_slug / scanner_slug
    result_path = output_dir / f"run-{run_id}.json"
    metrics_path = output_dir / f"run-{run_id}.metrics.json"
    output_dir.mkdir(parents=True, exist_ok=True)
    current_gt_hash = benchmark_metadata.get("ground_truth_content_hash", "")
    if result_path.exists() and metrics_path.exists():
        try:
            existing_gt_hash = json.loads(metrics_path.read_text()).get("ground_truth_content_hash", "")
        except (json.JSONDecodeError, OSError):
            existing_gt_hash = ""
        if current_gt_hash and existing_gt_hash == current_gt_hash:
            return {"skipped": True}

    cmd = ["kimi", "-m", model, "-p", task, "--output-format", "stream-json"]
    started = time.time()
    session_id = None
    raw_output = ""
    try:
        proc = run_kimi_command(cmd, cwd=str(repo_path), timeout=timeout)
        elapsed = time.time() - started
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("role") == "assistant" and "content" in event:
                raw_output += event["content"]
            if event.get("type") == "session.resume_hint":
                session_id = event.get("session_id")
    except subprocess.TimeoutExpired:
        elapsed = time.time() - started
        metrics = RunMetrics(
            model=model, repo=repo_slug, run_id=run_id, wall_clock_seconds=elapsed,
            exit_status="timeout", error_message=f"Timed out after {timeout}s",
            prompt_version=prompt_version, prompt_label=prompt_label,
            benchmark_version=benchmark_metadata.get("benchmark_version", ""),
            ground_truth_version=benchmark_metadata.get("ground_truth_version", ""),
            ground_truth_content_hash=current_gt_hash,
        )
        save_metrics(metrics, str(metrics_path))
        return {"success": False, "error": "timeout", "elapsed": elapsed, "cost": 0}
    except Exception as e:  # noqa: BLE001
        elapsed = time.time() - started
        metrics = RunMetrics(
            model=model, repo=repo_slug, run_id=run_id, wall_clock_seconds=elapsed,
            exit_status="error", error_message=str(e),
            prompt_version=prompt_version, prompt_label=prompt_label,
            benchmark_version=benchmark_metadata.get("benchmark_version", ""),
            ground_truth_version=benchmark_metadata.get("ground_truth_version", ""),
            ground_truth_content_hash=current_gt_hash,
        )
        save_metrics(metrics, str(metrics_path))
        return {"success": False, "error": str(e), "elapsed": elapsed, "cost": 0}

    usage = _find_usage(str(repo_path), session_id) if session_id else {"input": 0, "output": 0, "cache_read": 0}
    it, ot = usage["input"] + usage["cache_read"], usage["output"]
    cost = calculate_cost(it, ot, pricing["input_per_1m"], pricing["output_per_1m"]).total_cost_usd if it or ot else 0.0

    common = dict(
        model=model, repo=repo_slug, run_id=run_id,
        input_tokens=it, cached_input_tokens=usage["cache_read"], output_tokens=ot,
        total_tokens=it + ot, cost_usd=cost, wall_clock_seconds=elapsed,
        prompt_version=prompt_version, prompt_label=prompt_label,
        benchmark_version=benchmark_metadata.get("benchmark_version", ""),
        ground_truth_version=benchmark_metadata.get("ground_truth_version", ""),
        ground_truth_content_hash=current_gt_hash,
    )
    validation = validate_output(raw_output)
    if not validation.valid or validation.data is None:
        save_metrics(RunMetrics(**common, exit_status="validation_failed", error_message=str(validation.errors[:3])), str(metrics_path))
        return {"success": False, "error": "validation_failed", "elapsed": elapsed, "cost": cost}

    save_validated_output(validation.data, str(result_path))
    save_metrics(RunMetrics(**common, exit_status="success", llm_json_repair=validation.llm_json_repair), str(metrics_path))
    return {"success": True, "findings": validation.findings_count, "cost": cost, "elapsed": elapsed}


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple generic agentic-v1 runner via the Kimi CLI")
    parser.add_argument("--model", default="kimi-code/k3")
    parser.add_argument("--scanner-slug", default="kimi-k3-cli-agentic-v1")
    parser.add_argument("--repos", nargs="+", required=True)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--max-concurrent", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--language", choices=sorted(LANGUAGES), default="python")
    parser.add_argument("--repos-dir", type=Path, default=None)
    parser.add_argument("--prompt-template", type=Path, default=None)
    parser.add_argument("--prompt-label", default="generic-agentic-v1")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        subprocess.run(["kimi", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        logger.error("kimi CLI not found on PATH")
        return 1

    pricing = {"input_per_1m": 3.00, "output_per_1m": 15.00}  # kimi-k3, Moonshot's published API rate
    repos = discover_repos(PROJECT_ROOT / "ground-truth") if args.repos == ["all"] else args.repos
    prompt_info = build_prompt(load_cwe_families(), template_path=args.prompt_template, label=args.prompt_label)
    task = build_task(prompt_info.rendered, LANGUAGES[args.language]["files"])
    benchmark_metadata = load_benchmark_manifest()

    if args.dry_run:
        print(f"Model: {args.model}\nScanner: {args.scanner_slug}\nPrompt: {prompt_info.version_hash} ({prompt_info.label})\nRepos: {len(repos)}, runs: {args.runs}")
        return 0

    repo_paths = {s: p for s in repos if (p := clone_or_find_repo(s, args.repos_dir)) is not None}
    jobs = [(s, r) for s in repos if s in repo_paths for r in range(1, args.runs + 1)]
    completed = 0

    def execute(job):
        slug, run_id = job
        return slug, run_id, run_one(
            model=args.model, scanner_slug=args.scanner_slug, repo_slug=slug,
            repo_path=repo_paths[slug], run_id=run_id, task=task, timeout=args.timeout,
            pricing=pricing, prompt_version=prompt_info.version_hash, prompt_label=prompt_info.label,
            benchmark_metadata=benchmark_metadata,
        )

    def report(slug, run_id, result):
        nonlocal completed
        completed += 1
        if result.get("skipped"):
            logger.info("[%d/%d] %s run-%d: skipped", completed, len(jobs), slug, run_id)
            return
        if result.get("success"):
            logger.info("[%d/%d] %s run-%d: OK — %d findings, %.1fs, $%.4f", completed, len(jobs), slug, run_id, result["findings"], result["elapsed"], result["cost"])
        else:
            logger.error("[%d/%d] %s run-%d: FAIL — %s", completed, len(jobs), slug, run_id, result.get("error", "unknown"))

    with ThreadPoolExecutor(max_workers=args.max_concurrent) as ex:
        futures = {ex.submit(execute, job): job for job in jobs}
        pending = set(futures)
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for fut in done:
                slug, run_id, result = fut.result()
                report(slug, run_id, result)

    logger.info("Done — %d/%d runs", completed, len(jobs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
