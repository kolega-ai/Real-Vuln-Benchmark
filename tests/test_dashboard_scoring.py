"""Regression coverage for multi-run dashboard counts."""

import json

from dashboard import score_all
from scorer.matcher import GREEDY_MATCHER


def test_half_integer_run_means_preserve_positive_population(tmp_path):
    gt_dir = tmp_path / "ground-truth"
    scan_dir = tmp_path / "scan-results"
    target = gt_dir / "test"
    target.mkdir(parents=True)
    (target / "ground-truth.json").write_text(json.dumps({
        "repo_id": "test",
        "findings": [
            {
                "id": f"gt-{line}", "file": "app.py", "location": {"start_line": line},
                "is_vulnerable": True, "acceptable_cwes": ["CWE-89"],
            }
            for line in (20, 50, 80)
        ],
    }))
    runs = scan_dir / "test" / "semgrep"
    runs.mkdir(parents=True)
    for number, lines in enumerate(((20,), (20, 50)), 1):
        (runs / f"run-{number}.json").write_text(json.dumps({
            "results": [
                {
                    "path": "app.py", "start": {"line": line},
                    "extra": {"metadata": {"cwe": ["CWE-89"]}},
                }
                for line in lines
            ],
        }))

    current = score_all(["test"], ["semgrep"], gt_dir, scan_dir, {})["test"]["semgrep"]
    legacy = score_all(
        ["test"], ["semgrep"], gt_dir, scan_dir, {}, matcher_version=GREEDY_MATCHER,
    )["test"]["semgrep"]
    assert (current["tp"], current["fn"]) == (2, 1)
    assert (legacy["tp"], legacy["fn"]) == (2, 2)
