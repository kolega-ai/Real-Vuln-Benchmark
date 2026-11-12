import json
import unittest
from pathlib import Path

from private_score_overlay import apply_private_receipt


ROOT = Path(__file__).resolve().parents[1]


class PrivateScoreOverlayTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "reports/dashboard.json").read_text())
        self.receipt = json.loads((ROOT / "reports/private-score-launch.json").read_text())

    def test_official_receipt_pools_into_main_leaderboard(self):
        merged = apply_private_receipt(self.data, self.receipt)
        self.assertEqual(len(merged["repos"]), 208)
        self.assertEqual(len(merged["tab_repos"]["python"]), 71)
        self.assertEqual(len(merged["tab_repos"]["intentional"]), 79)
        row = merged["aggregates"]["kolega-devsec-max-v0.1.0"]
        self.assertEqual(row["repos_scored"], 208)
        self.assertEqual(tuple(row["strict_micro"][k] for k in ("tp", "fp", "fn")), (7559, 17817, 1503))
        self.assertEqual(row["strict_micro"]["f3_score"], 70.69)
        self.assertEqual(row["language_coverage"]["python"], [71, 71])
        self.assertEqual(self.data["aggregates"]["kolega-devsec-max-v0.1.0"]["repos_scored"], 203)

    def test_unscanned_repositories_are_strict_misses(self):
        merged = apply_private_receipt(self.data, self.receipt)
        slug = "gpt-daybreak-blue-codex-cli"
        before = self.data["aggregates"][slug]
        after = merged["aggregates"][slug]
        self.assertEqual(after["strict_micro"]["fn"], before["strict_micro"]["fn"] + 1944)
        self.assertEqual(after["micro"]["fn"], before["micro"]["fn"])

    def test_rejects_mutated_receipt(self):
        self.receipt["repo_scores"]["sentry"]["tp"] += 1
        with self.assertRaises(ValueError):
            apply_private_receipt(self.data, self.receipt)


if __name__ == "__main__":
    unittest.main()
