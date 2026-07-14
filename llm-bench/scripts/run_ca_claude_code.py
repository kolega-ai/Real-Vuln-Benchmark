"""Run the Kolega Scan OSS claude-adaptation pipeline with Claude Code as the agent.

The claude-adaptation scanner (shipped in the public ``kolega-security-scanner``) is an
agentic port of Anthropic's "Using LLMs to secure source code" find-and-fix loop:

    threat-model -> discovery (iterate until plateau) -> adversarial verify -> variant hunt -> triage

In its agentic mode each phase is handed to a repo-navigating agent session. This runner
swaps that agent backend to a **headless Claude Code** run:

    claude -p "<phase prompt>" --output-format json --model <m> --permission-mode bypassPermissions

Claude Code is itself the repo-navigating agent (built-in Read/Grep/Glob), so the phase
prompts — which instruct the agent to read/search the code and reply with strict JSON —
map onto it directly. We monkeypatch the scanner's ``kolega_code.run_json`` seam so every
stage (surface fan-out, plateau rounds, batched verify, variant hunt, triage, wire-format
conversion) stays the untouched shipping pipeline; only the agent invocation changes.

Each ``claude -p`` call returns ``total_cost_usd`` in its JSON envelope, so we accumulate
exact per-repo, per-phase cost and emit it as ``run-1.metrics.json`` alongside the
Semgrep-format ``results.json`` — the same schema ``dashboard.py`` reads for every other
LLM scanner, so cost/tokens land on the leaderboard.

Requires the public scanner installed (``pip install kolega-security-scanner``) and the
``claude`` CLI authenticated.

Usage:
    CC_MODEL=sonnet python3 llm-bench/scripts/run_ca_claude_code.py <repo> [<repo> ...]

Writes:
    scan-results/{repo}/{slug}/results.json        (findings; scored by dashboard.py)
    scan-results/{repo}/{slug}/run-1.metrics.json  (cost + token + latency ledger)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from kolega_security_scanner.scanner.config import ScanConfig, ScanMode
from kolega_security_scanner.scanners.claude_adaptation import kolega_code
from kolega_security_scanner.scanners.claude_adaptation.config import PipelineConfig
from kolega_security_scanner.scanners.claude_adaptation.provider import (
    ClaudeAdaptationScanProvider,
)

BENCH = Path(__file__).resolve().parents[2]  # repo root (llm-bench/scripts/..)
MODEL = os.environ.get("CC_MODEL", "sonnet")
SLUG = os.environ.get("CC_SLUG", "kolega-ca-cc-sonnet")
TIMEOUT_S = int(os.environ.get("CC_TIMEOUT", "3600"))


def log(m: str) -> None:
    print(m, file=sys.stderr, flush=True)


class RateLimitHit(Exception):
    """Raised when claude -p reports the subscription usage limit is exhausted.

    Propagates out of the pipeline so the runner ABORTS the repo without writing a
    (poisoned, empty) results.json — the repo is retried on the next resume.
    """


_LIMIT_MARKERS = (
    "usage limit", "rate limit", "limit reached", "resets at", "5-hour",
    "5 hour", "weekly limit", "reached your", "upgrade to", "out of usage",
)


def _is_rate_limit(text: str) -> bool:
    t = (text or "").lower()
    return any(m in t for m in _LIMIT_MARKERS)


def _phase_label(prompt: str) -> str:
    """Attribute a call to a phase from the prompt's rubric keywords."""
    if "VARIANT HUNT" in prompt:
        return "variants"
    if "REPORTED FINDING" in prompt or "verdicts" in prompt:
        return "verify"
    if "Shostack" in prompt or "What are we building" in prompt:
        return "threat_model"
    return "discovery"


class CostLedger:
    """Thread-safe accumulator of claude -p cost/usage, bucketed by phase."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.calls: list[dict] = []

    def record(self, phase: str, envelope: dict) -> None:
        usage = envelope.get("usage", {}) or {}
        with self._lock:
            self.calls.append({
                "phase": phase,
                "cost_usd": envelope.get("total_cost_usd", 0.0) or 0.0,
                "duration_ms": envelope.get("duration_ms"),
                "num_turns": envelope.get("num_turns"),
                "input_tokens": usage.get("input_tokens"),
                "output_tokens": usage.get("output_tokens"),
                "cache_read_input_tokens": usage.get("cache_read_input_tokens"),
                "cache_creation_input_tokens": usage.get("cache_creation_input_tokens"),
                "is_error": envelope.get("is_error"),
            })

    def metrics(self, model: str, repo: str, wall_s: float) -> dict:
        """Aggregate the per-call ledger into one run-*.metrics.json record."""
        with self._lock:
            calls = list(self.calls)

        def s(k: str) -> int:
            return sum(c.get(k) or 0 for c in calls)

        total_tokens = sum(
            (c.get("input_tokens") or 0) + (c.get("output_tokens") or 0)
            + (c.get("cache_read_input_tokens") or 0)
            + (c.get("cache_creation_input_tokens") or 0)
            for c in calls
        )
        return {
            "model": f"claude-{model}", "repo": repo, "run_id": 1,
            "input_tokens": s("input_tokens"), "output_tokens": s("output_tokens"),
            "total_tokens": total_tokens,
            "cost_usd": round(sum(c["cost_usd"] for c in calls), 6),
            "wall_clock_seconds": round(wall_s, 3),
            "start_time": "", "end_time": "",
            "agent_steps": s("num_turns"), "tool_calls": 0, "tool_calls_by_type": {},
            "files_read": [], "exit_status": "success", "error_message": "",
            "llm_json_repair": False,
            "prompt_version": "kolega-claude-adaptation@agentic",
            "prompt_label": "Claude Code harness",
        }


def make_run_json(model: str, ledger: CostLedger):
    """Build a kolega_code.run_json replacement backed by `claude -p`.

    Signature matches kolega_code.run_json exactly so the pipeline calls it unchanged.
    """
    binary = shutil.which("claude")
    if binary is None:
        raise SystemExit("claude CLI not found on PATH")

    def run_json(prompt, repo_root, *, provider="claude", model=model, timeout=TIMEOUT_S):
        phase = _phase_label(prompt)
        try:
            proc = subprocess.run(
                [
                    binary, "-p", prompt,
                    "--output-format", "json",
                    "--model", model,
                    "--permission-mode", "bypassPermissions",
                ],
                cwd=str(repo_root), capture_output=True, text=True,
                timeout=timeout, check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            log(f"    [{phase}] claude -p failed: {type(exc).__name__}")
            return None
        if proc.returncode != 0:
            if _is_rate_limit(proc.stderr) or _is_rate_limit(proc.stdout):
                raise RateLimitHit(proc.stderr[:300] or proc.stdout[:300])
            log(f"    [{phase}] claude -p rc={proc.returncode}: {proc.stderr[:200]}")
            return None
        try:
            envelope = json.loads(proc.stdout)
        except json.JSONDecodeError:
            log(f"    [{phase}] non-JSON envelope from claude -p")
            return None
        if envelope.get("subtype", "").startswith("error") and _is_rate_limit(
            str(envelope.get("result", ""))
        ):
            raise RateLimitHit(str(envelope.get("result", ""))[:300])
        ledger.record(phase, envelope)
        return kolega_code._loads_loose(str(envelope.get("result", "")))

    return run_json


def main() -> None:
    os.chdir(BENCH)
    repos = sys.argv[1:]
    if not repos:
        log("usage: run_ca_claude_code.py <repo> [<repo> ...]")
        raise SystemExit(2)

    for repo in repos:
        repo_dir = BENCH / "repos" / repo
        if not repo_dir.is_dir():
            log(f"{repo}: NO SUCH REPO ({repo_dir})")
            continue
        out_dir = BENCH / "scan-results" / repo / SLUG
        out_file = out_dir / "results.json"
        if out_file.exists():
            log(f"{repo}: SKIP (exists)")
            continue
        out_dir.mkdir(parents=True, exist_ok=True)

        ledger = CostLedger()
        kolega_code.run_json = make_run_json(MODEL, ledger)  # type: ignore[assignment]

        cfg = PipelineConfig(
            agentic=True, agent_surface_concurrency=2, discovery_rounds=2,
            verifiers=1, agent_provider="claude", agent_model=MODEL,
        )
        prov = ClaudeAdaptationScanProvider(cfg)
        log(f"{repo}: scanning with claude -p (model={MODEL}, slug={SLUG}) ...")
        t0 = time.monotonic()
        try:
            res = prov.scan(ScanConfig(repo_path=repo_dir, mode=ScanMode.HYBRID), llm=None)
            findings = [f.model_dump() for f in res.findings]
            note = f"{len(findings)} findings"
        except RateLimitHit as exc:
            wall = time.monotonic() - t0
            log(f"{repo}: RATE LIMIT after {wall:.0f}s — not written, halting sweep.")
            log(f"    signal: {exc}")
            raise SystemExit(7)
        except Exception as exc:  # noqa: BLE001
            findings, note = [], f"ERROR {type(exc).__name__}: {exc}"
        wall = time.monotonic() - t0

        # A real scan makes >=2 calls (threat model + discovery). Zero successful calls
        # means every claude -p failed — do NOT write an empty, poisoned results.json.
        if not ledger.calls:
            log(f"{repo}: 0 successful calls after {wall:.0f}s — likely throttled/outage, "
                f"not written, halting sweep.")
            raise SystemExit(7)

        out_file.write_text(json.dumps({"results": findings}, indent=2))
        (out_dir / "run-1.metrics.json").write_text(
            json.dumps(ledger.metrics(MODEL, repo, wall), indent=2)
        )
        m = ledger.metrics(MODEL, repo, wall)
        log(f"{repo}: {note} | ${m['cost_usd']} | {len(ledger.calls)} calls | {wall:.0f}s")


if __name__ == "__main__":
    main()
