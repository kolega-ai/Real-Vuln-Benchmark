import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dashboard import compute_scanner_costs


def test_costs_are_normalized_to_one_benchmark_run(tmp_path):
    scanner = "three-pass-scanner"
    repo_loc = {"repo-a": 100, "repo-b": 300}

    for repo, loc in repo_loc.items():
        scanner_dir = tmp_path / repo / scanner
        scanner_dir.mkdir(parents=True)
        for run in range(1, 4):
            (scanner_dir / f"run-{run}.metrics.json").write_text(
                json.dumps({"cost_usd": loc / 100, "exit_status": "success"})
            )

    cost = compute_scanner_costs(tmp_path, [scanner], repo_loc)[scanner]

    assert cost["benchmark_runs"] == 3.0
    assert cost["campaign_total_cost"] == 12.0
    assert cost["total_cost"] == 4.0
    assert cost["cost_per_run"] == 4.0
    assert cost["cost_per_repo"] == 2.0
    assert cost["cost_per_100_loc"] == 1.0
