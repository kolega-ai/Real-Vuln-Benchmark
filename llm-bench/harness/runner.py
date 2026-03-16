"""Orchestrate a single OpenHands evaluation run for (model, repo).

This module handles:
1. Building the prompt with CWE families context
2. Configuring and launching an OpenHands agent instance
3. Extracting the LLM's output and validating it
4. Collecting operational metrics from the trajectory
5. Saving results and metrics to the scan-results directory
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

from .cost_calculator import calculate_cost
from .metrics_collector import RunMetrics, parse_trajectory, save_metrics
from .output_validator import ValidationResult, save_validated_output, validate_output
from .prompt_builder import build_prompt, load_cwe_families

logger = logging.getLogger(__name__)

LLM_BENCH_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent


@dataclass
class ModelConfig:
    """Configuration for a single LLM model."""

    name: str
    provider: str
    model_id: str
    scanner_slug: str
    pricing: dict[str, float]  # input_per_1m, output_per_1m
    max_context: int = 200_000


@dataclass
class RunConfig:
    """Configuration for a single evaluation run."""

    model: ModelConfig
    repo: str
    run_id: int
    repo_path: Path
    output_dir: Path
    timeout_seconds: int = 600
    max_iterations: int = 50
    max_output_tokens: int = 20_000


@dataclass
class RunResult:
    """Result of a single evaluation run."""

    success: bool
    result_path: Path | None = None
    metrics_path: Path | None = None
    metrics: RunMetrics | None = None
    validation: ValidationResult | None = None
    error: str = ""
    wall_clock_seconds: float = 0.0


def load_model_configs(config_path: Path | None = None) -> dict[str, ModelConfig]:
    """Load model configurations from YAML file.

    Args:
        config_path: Path to models.yaml. Uses default if None.

    Returns:
        Dict mapping model name to ModelConfig.
    """
    import yaml

    path = config_path or (LLM_BENCH_DIR / "config" / "models.yaml")
    with open(path) as f:
        data = yaml.safe_load(f)

    configs: dict[str, ModelConfig] = {}
    for name, info in data.get("models", {}).items():
        configs[name] = ModelConfig(
            name=name,
            provider=info["provider"],
            model_id=info["model_id"],
            scanner_slug=info["scanner_slug"],
            pricing=info["pricing"],
            max_context=info.get("max_context", 200_000),
        )
    return configs



def run_single(run_config: RunConfig) -> RunResult:
    """Execute a single OpenHands evaluation run.

    Args:
        run_config: Configuration for this run.

    Returns:
        RunResult with paths to output files and metrics.
    """
    start_time = time.time()
    model = run_config.model
    repo = run_config.repo
    run_id = run_config.run_id

    logger.info(
        "Starting run: model=%s repo=%s run=%d",
        model.name, repo, run_id,
    )

    # Ensure output directory exists
    output_dir = run_config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    result_path = output_dir / f"run-{run_id}.json"
    metrics_path = output_dir / f"run-{run_id}.metrics.json"

    # Build prompt
    try:
        cwe_families = load_cwe_families()
        prompt = build_prompt(cwe_families)
    except Exception as e:
        return RunResult(
            success=False,
            error=f"Failed to build prompt: {e}",
            wall_clock_seconds=time.time() - start_time,
        )

    # Run OpenHands
    try:
        trajectory_path, raw_output = _run_openhands(run_config, prompt)
    except ImportError:
        return RunResult(
            success=False,
            error="OpenHands not installed. Install with: pip install openhands-ai",
            wall_clock_seconds=time.time() - start_time,
        )
    except Exception as e:
        return RunResult(
            success=False,
            error=f"OpenHands execution failed: {e}",
            wall_clock_seconds=time.time() - start_time,
        )

    wall_clock = time.time() - start_time

    # Validate output
    validation = validate_output(raw_output)
    if not validation.valid or validation.data is None:
        logger.warning(
            "Validation failed for %s/%s/run-%d: %s",
            model.name, repo, run_id, validation.errors,
        )
        return RunResult(
            success=False,
            validation=validation,
            error=f"Output validation failed: {validation.errors}",
            wall_clock_seconds=wall_clock,
        )

    # Save validated results
    save_validated_output(validation.data, str(result_path))
    logger.info(
        "Saved %d findings to %s (dropped=%d, repaired=%d)",
        validation.findings_count, result_path,
        validation.dropped_count, validation.repaired_count,
    )

    # Collect metrics from trajectory (parse_trajectory handles missing files)
    if trajectory_path:
        metrics = parse_trajectory(trajectory_path, model.name, repo, run_id)
    else:
        metrics = RunMetrics(model=model.name, repo=repo, run_id=run_id)

    # Calculate cost
    cost = calculate_cost(
        metrics.input_tokens,
        metrics.output_tokens,
        model.pricing["input_per_1m"],
        model.pricing["output_per_1m"],
    )
    metrics.cost_usd = cost.total_cost_usd
    metrics.wall_clock_seconds = wall_clock

    if not metrics.exit_status:
        metrics.exit_status = "success"

    save_metrics(metrics, str(metrics_path))

    return RunResult(
        success=True,
        result_path=result_path,
        metrics_path=metrics_path,
        metrics=metrics,
        validation=validation,
        wall_clock_seconds=wall_clock,
    )


def _run_openhands(
    run_config: RunConfig,
    prompt: str,
) -> tuple[str | None, str]:
    """Execute OpenHands agent and return (trajectory_path, raw_output).

    This function interfaces with the OpenHands library (v1.5+). It:
    1. Creates a Docker sandbox with the repo mounted read-only
    2. Runs the CodeActAgent with the security auditor prompt
    3. The agent can explore files, grep, run commands iteratively
    4. Returns the trajectory file path and the agent's final output

    Raises:
        ImportError: If openhands is not installed.
        RuntimeError: If the agent fails to complete.
    """
    import asyncio

    try:
        from openhands.core.config import (
            OpenHandsConfig,
            SandboxConfig,
            LLMConfig,
        )
        from openhands.core.main import run_controller
        from openhands.events.action import MessageAction
    except ImportError:
        raise ImportError(
            "OpenHands not installed. Install with: pip install openhands-ai"
        )

    repo_path_str = str(run_config.repo_path.resolve())

    # Configure OpenHands
    config = OpenHandsConfig(
        default_agent="CodeActAgent",
        max_iterations=run_config.max_iterations,
        runtime="docker",
        workspace_base=repo_path_str,
        sandbox=SandboxConfig(
            base_container_image="nikolaik/python-nodejs:python3.12-nodejs22",
            timeout=run_config.timeout_seconds,
        ),
    )
    # Set LLM config
    config.set_llm_config(LLMConfig(
        model=run_config.model.model_id,
        max_output_tokens=run_config.max_output_tokens,
    ))

    # Build the task message
    task = (
        f"{prompt}\n\n"
        f"The repository to audit is at /workspace. "
        f"Explore it thoroughly and report all security vulnerabilities "
        f"in the JSON format specified above. "
        f"IMPORTANT: Do NOT modify any files. Only read and analyze."
    )

    # Run the agent (async API)
    def fake_user_response(state, encapsulate_solution=False, try_parse=None) -> str:
        """Auto-respond to keep the agent going until it produces JSON."""
        last_msg = state.get_last_agent_message()
        if last_msg and last_msg.content:
            content = last_msg.content
            if '"check_id"' in content and '"path"' in content and '"cwe"' in content.lower():
                return "/exit"
        return "Continue your analysis. When done, output ONLY the JSON findings."

    async def _run() -> tuple[str | None, str]:
        state = await run_controller(
            config=config,
            initial_user_action=MessageAction(content=task),
            headless_mode=True,
            fake_user_response_fn=fake_user_response,
        )

        # Extract output from the agent's last message
        raw_output = ""
        if state:
            last_msg = state.get_last_agent_message()
            if last_msg:
                raw_output = last_msg.content
            # Fallback: search history for JSON output
            if not raw_output and state.history:
                for event in reversed(list(state.history)):
                    content = getattr(event, "content", "")
                    if content and ('"results"' in content or '"findings"' in content):
                        raw_output = content
                        break

        trajectory_path = getattr(state, "trajectory_path", None) if state else None
        return trajectory_path, raw_output

    return asyncio.run(_run())
