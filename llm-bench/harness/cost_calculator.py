"""Calculate costs from token usage and model pricing."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CostEstimate:
    """Cost breakdown for a run or set of runs."""

    input_tokens: int
    output_tokens: int
    input_cost_usd: float
    output_cost_usd: float
    total_cost_usd: float


def calculate_cost(
    input_tokens: int,
    output_tokens: int,
    input_price_per_1m: float,
    output_price_per_1m: float,
) -> CostEstimate:
    """Calculate cost from token counts and per-1M-token pricing.

    Args:
        input_tokens: Number of input tokens used.
        output_tokens: Number of output tokens used.
        input_price_per_1m: USD price per 1M input tokens.
        output_price_per_1m: USD price per 1M output tokens.

    Returns:
        CostEstimate with breakdown.
    """
    input_cost = (input_tokens / 1_000_000) * input_price_per_1m
    output_cost = (output_tokens / 1_000_000) * output_price_per_1m

    return CostEstimate(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        input_cost_usd=round(input_cost, 6),
        output_cost_usd=round(output_cost, 6),
        total_cost_usd=round(input_cost + output_cost, 6),
    )


def calculate_cost_tiered(
    input_tokens: int,
    output_tokens: int,
    pricing: dict,
    cached_input_tokens: int = 0,
) -> CostEstimate:
    """Calculate cost for one call, honoring a `pricing["tiered"]` override.

    `pricing` is a models.yaml pricing dict: flat `input_per_1m`/`output_per_1m`,
    plus an optional `tiered` block ({threshold_tokens, long_input_per_1m,
    long_output_per_1m}) applied when THIS call's input_tokens exceeds the
    threshold. Must be called per-call (not on aggregated totals) since the
    tier is a property of a single call's context size.
    """
    tiered = pricing.get("tiered")
    if tiered and input_tokens > tiered["threshold_tokens"]:
        input_price = tiered["long_input_per_1m"]
        output_price = tiered["long_output_per_1m"]
        cached_input_price = tiered.get("long_cached_input_per_1m", input_price)
    else:
        input_price = pricing["input_per_1m"]
        output_price = pricing["output_per_1m"]
        cached_input_price = pricing.get("cached_input_per_1m", input_price)

    # OpenAI usage reports input_tokens inclusive of cached_input_tokens.
    # Charge only the uncached remainder at the regular input rate.
    cached_input_tokens = min(max(cached_input_tokens, 0), input_tokens)
    uncached_input_tokens = input_tokens - cached_input_tokens
    input_cost = (
        (uncached_input_tokens / 1_000_000) * input_price
        + (cached_input_tokens / 1_000_000) * cached_input_price
    )
    output_cost = (output_tokens / 1_000_000) * output_price
    return CostEstimate(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        input_cost_usd=round(input_cost, 6),
        output_cost_usd=round(output_cost, 6),
        total_cost_usd=round(input_cost + output_cost, 6),
    )


def estimate_run_cost(
    input_price_per_1m: float,
    output_price_per_1m: float,
    estimated_input_tokens: int = 100_000,
    estimated_output_tokens: int = 20_000,
) -> CostEstimate:
    """Estimate cost for a single run using token budget defaults."""
    return calculate_cost(
        estimated_input_tokens,
        estimated_output_tokens,
        input_price_per_1m,
        output_price_per_1m,
    )


def estimate_total_cost(
    input_price_per_1m: float,
    output_price_per_1m: float,
    num_repos: int,
    runs_per_repo: int,
    estimated_input_tokens: int = 100_000,
    estimated_output_tokens: int = 20_000,
) -> tuple[CostEstimate, float]:
    """Estimate total cost for a full benchmark run.

    Returns:
        Tuple of (per_run_estimate, total_cost_usd).
    """
    per_run = estimate_run_cost(
        input_price_per_1m,
        output_price_per_1m,
        estimated_input_tokens,
        estimated_output_tokens,
    )
    total = per_run.total_cost_usd * num_repos * runs_per_repo
    return per_run, round(total, 2)
