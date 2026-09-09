import importlib.util
import sys
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "run_agentic_claude_code.py"
)
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("run_agentic_claude_code", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_default_scanner_slug_marks_claude_code_backend():
    assert (
        MODULE.default_scanner_slug("claude-fable-5")
        == "claude-fable-5-cc-agentic-v1"
    )
    assert MODULE.default_scanner_slug("opus") == "claude-opus-cc-agentic-v1"


def test_envelope_usage_includes_cache_tokens_and_cost():
    usage = MODULE.envelope_usage(
        {
            "total_cost_usd": 1.25,
            "num_turns": 7,
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_read_input_tokens": 30,
                "cache_creation_input_tokens": 40,
            },
        }
    )

    assert usage == {
        "input_tokens": 10,
        "output_tokens": 20,
        "cached_input_tokens": 30,
        "total_tokens": 100,
        "cost_usd": 1.25,
        "agent_steps": 7,
    }


def test_rate_limit_detected_from_api_status_or_result():
    assert MODULE.is_rate_limit({"api_error_status": 429})
    assert MODULE.is_rate_limit({}, "You've hit your session limit")
    assert not MODULE.is_rate_limit({"api_error_status": 500}, "server error")
