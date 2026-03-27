"""Tests for cost calculator."""
from __future__ import annotations

import sys
from pathlib import Path

LLM_BENCH_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

from harness.cost_calculator import calculate_cost, estimate_run_cost, estimate_total_cost


class TestCalculateCost:
    def test_basic_cost(self):
        result = calculate_cost(
            input_tokens=1_000_000,
            output_tokens=1_000_000,
            input_price_per_1m=3.00,
            output_price_per_1m=15.00,
        )
        assert result.input_cost_usd == 3.00
        assert result.output_cost_usd == 15.00
        assert result.total_cost_usd == 18.00

    def test_zero_tokens(self):
        result = calculate_cost(0, 0, 3.00, 15.00)
        assert result.total_cost_usd == 0.0

    def test_haiku_pricing(self):
        # 100K input + 20K output at Haiku prices
        result = calculate_cost(100_000, 20_000, 0.80, 4.00)
        assert abs(result.total_cost_usd - 0.16) < 0.01


class TestEstimateRunCost:
    def test_default_budget(self):
        result = estimate_run_cost(0.80, 4.00)
        # 100K in @ $0.80/1M + 20K out @ $4.00/1M
        assert abs(result.total_cost_usd - 0.16) < 0.01

    def test_custom_budget(self):
        result = estimate_run_cost(
            3.00, 15.00,
            estimated_input_tokens=50_000,
            estimated_output_tokens=10_000,
        )
        expected = (50_000 / 1_000_000) * 3.00 + (10_000 / 1_000_000) * 15.00
        assert abs(result.total_cost_usd - expected) < 0.01


class TestEstimateTotalCost:
    def test_total_estimation(self):
        per_run, total = estimate_total_cost(
            input_price_per_1m=0.80,
            output_price_per_1m=4.00,
            num_repos=27,
            runs_per_repo=3,
        )
        # 81 runs * ~$0.16 each
        assert total > 10
        assert total < 20
        assert per_run.total_cost_usd > 0
