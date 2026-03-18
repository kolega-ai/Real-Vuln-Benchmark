"""Parse OpenHands trajectory JSON to extract operational metrics.

OpenHands logs every agent step, tool call, and API interaction as structured
JSON events. This module extracts the metrics we need for the benchmark.
"""
from __future__ import annotations

import json
import shlex
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class RunMetrics:
    """Operational metrics for a single (model, repo, run) evaluation."""

    model: str
    repo: str
    run_id: int

    # Token usage
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0

    # Cost (USD)
    cost_usd: float = 0.0

    # Timing
    wall_clock_seconds: float = 0.0
    start_time: str = ""
    end_time: str = ""

    # Agent activity
    agent_steps: int = 0
    tool_calls: int = 0
    tool_calls_by_type: dict[str, int] = field(default_factory=dict)

    # Files examined
    files_read: list[str] = field(default_factory=list)

    # Exit status
    exit_status: str = ""  # "success", "timeout", "error", "max_iterations"
    error_message: str = ""

    # JSON repair tracking
    llm_json_repair: bool = False

    def to_dict(self) -> dict:
        """JSON-serializable dict."""
        return asdict(self)


def parse_trajectory(
    trajectory_path: str | Path,
    model: str,
    repo: str,
    run_id: int,
) -> RunMetrics:
    """Parse an OpenHands trajectory file to extract operational metrics.

    Args:
        trajectory_path: Path to the OpenHands trajectory JSON/JSONL file.
        model: Model identifier string.
        repo: Repository identifier string.
        run_id: Run number (1-indexed).

    Returns:
        RunMetrics populated from the trajectory data.
    """
    metrics = RunMetrics(model=model, repo=repo, run_id=run_id)
    trajectory_path = Path(trajectory_path)

    if not trajectory_path.exists():
        metrics.exit_status = "error"
        metrics.error_message = f"Trajectory file not found: {trajectory_path}"
        return metrics

    events = _load_events(trajectory_path)
    if not events:
        metrics.exit_status = "error"
        metrics.error_message = "No events found in trajectory"
        return metrics

    files_seen: set[str] = set()
    tool_counts: dict[str, int] = {}

    for event in events:
        _process_event(event, metrics, files_seen, tool_counts)

    metrics.files_read = sorted(files_seen)
    metrics.tool_calls_by_type = tool_counts
    metrics.total_tokens = metrics.input_tokens + metrics.output_tokens

    # Extract timestamps from first and last events
    if events:
        metrics.start_time = _get_timestamp(events[0])
        metrics.end_time = _get_timestamp(events[-1])

    return metrics


def _load_events(path: Path) -> list[dict]:
    """Load events from either JSON or JSONL format."""
    text = path.read_text().strip()
    if not text:
        return []

    # Try as JSON array first
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # OpenHands may store events under a key
            for key in ("history", "events", "trajectory"):
                if key in data and isinstance(data[key], list):
                    return data[key]
            return [data]
    except json.JSONDecodeError:
        pass

    # Try as JSONL
    events = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def _get_timestamp(event: dict) -> str:
    """Extract timestamp from an event."""
    for key in ("timestamp", "created_at", "time", "ts"):
        if key in event:
            return str(event[key])
    return ""


def _process_event(
    event: dict,
    metrics: RunMetrics,
    files_seen: set[str],
    tool_counts: dict[str, int],
) -> None:
    """Process a single trajectory event, updating metrics in-place."""
    event_type = event.get("action", event.get("type", event.get("event", "")))

    # Count agent steps (actions by the agent)
    source = event.get("source", "")
    if source == "agent" or event_type in ("action", "AgentAction"):
        metrics.agent_steps += 1

    # Count tool calls
    action = event.get("action", "")
    if action in ("read", "read_file", "open_file"):
        metrics.tool_calls += 1
        tool_counts[action] = tool_counts.get(action, 0) + 1
        # Track file paths
        args = event.get("args", {})
        file_path = args.get("path", args.get("file", ""))
        if file_path:
            files_seen.add(file_path)
    elif action in (
        "run",
        "execute",
        "execute_bash",
        "CmdRunAction",
        "bash",
    ):
        metrics.tool_calls += 1
        tool_counts["bash"] = tool_counts.get("bash", 0) + 1
        # Check if bash command reads files (cat, head, etc.)
        args = event.get("args", {})
        cmd = args.get("command", "")
        if cmd:
            _extract_files_from_bash(cmd, files_seen)
    elif action in ("search", "search_dir", "search_file", "find_file"):
        metrics.tool_calls += 1
        tool_counts[action] = tool_counts.get(action, 0) + 1
    elif action in ("list_dir", "ls"):
        metrics.tool_calls += 1
        tool_counts["list_dir"] = tool_counts.get("list_dir", 0) + 1

    # Token usage from LLM responses
    extras = event.get("extras", event.get("extra", {}))
    if isinstance(extras, dict):
        metrics.input_tokens += extras.get("input_tokens", 0)
        metrics.output_tokens += extras.get("output_tokens", 0)
        # Also check nested llm_metrics
        llm = extras.get("llm_metrics", {})
        if isinstance(llm, dict):
            metrics.input_tokens += llm.get("input_tokens", 0)
            metrics.output_tokens += llm.get("output_tokens", 0)

    # Check for exit/finish events
    if action in ("finish", "AgentFinishAction"):
        metrics.exit_status = "success"
    elif event_type == "error" or action == "error":
        metrics.exit_status = "error"
        metrics.error_message = str(
            event.get("message", event.get("args", {}).get("message", ""))
        )


def _extract_files_from_bash(cmd: str, files_seen: set[str]) -> None:
    """Heuristic: extract file paths from common bash commands."""
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return

    # Commands that take file path arguments
    read_cmds = {"cat", "head", "tail", "less", "more", "grep", "awk", "sed", "wc"}
    if parts and parts[0] in read_cmds:
        for part in parts[1:]:
            if not part.startswith("-") and ("/" in part or "." in part):
                files_seen.add(part)


def save_metrics(metrics: RunMetrics, output_path: str | Path) -> None:
    """Save run metrics to a JSON file."""
    with open(output_path, "w") as f:
        json.dump(metrics.to_dict(), f, indent=2)
