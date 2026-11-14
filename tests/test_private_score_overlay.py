import json
import unittest
from pathlib import Path

from private_score_overlay import apply_private_receipts
from build_site import repo_size_points


ROOT = Path(__file__).resolve().parents[1]


class PrivateScoreOverlayTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "reports/dashboard.json").read_text())
        self.receipts = json.loads((ROOT / "reports/private-score-launch.json").read_text())

    def test_official_receipt_pools_into_main_leaderboard(self):
        merged = apply_private_receipts(self.data, self.receipts)
        self.assertEqual(len(merged["repos"]), 208)
        self.assertEqual(len(merged["tab_repos"]["python"]), 71)
        self.assertEqual(len(merged["tab_repos"]["intentional"]), 79)
        row = merged["aggregates"]["kolega-devsec-max-v0.1.0"]
        self.assertEqual(row["repos_scored"], 208)
        self.assertEqual(tuple(row["strict_micro"][k] for k in ("tp", "fp", "fn")), (7559, 17817, 1503))
        self.assertEqual(row["strict_micro"]["f3_score"], 70.69)
        self.assertEqual(row["language_coverage"]["python"], [71, 71])
        self.assertEqual(self.data["aggregates"]["kolega-devsec-max-v0.1.0"]["repos_scored"], 203)
        expected = {
            "gpt-daybreak-blue-codex-cli": (4307, 3281, 4755, 48.31),
            "deepseek-v4.1-flash-agentic-v1": (3003, 3062, 6059, 34.27),
            "claude-sonnet-5-cc-agentic-v1": (2464, 2701, 6598, 28.41),
        }
        for slug, (tp, fp, fn, f3) in expected.items():
            row = merged["aggregates"][slug]
            self.assertEqual(row["repos_scored"], 208)
            self.assertEqual(tuple(row["strict_micro"][k] for k in ("tp", "fp", "fn")), (tp, fp, fn))
            self.assertEqual(row["strict_micro"]["f3_score"], f3)

    def test_unscanned_repositories_are_strict_misses(self):
        merged = apply_private_receipts(self.data, self.receipts)
        slug = "gpt-5.5-agentic-v1"
        before = self.data["aggregates"][slug]
        after = merged["aggregates"][slug]
        self.assertEqual(after["strict_micro"]["fn"], before["strict_micro"]["fn"] + 1944)
        self.assertEqual(after["micro"]["fn"], before["micro"]["fn"])

    def test_rejects_mutated_receipt(self):
        self.receipts[0]["repo_scores"]["sentry"]["tp"] += 1
        with self.assertRaises(ValueError):
            apply_private_receipts(self.data, self.receipts)

    def test_requires_every_released_receipt(self):
        with self.assertRaisesRegex(ValueError, "Exactly one receipt"):
            apply_private_receipts(self.data, self.receipts[:-1])

    def test_size_chart_uses_published_repo_aggregates(self):
        merged = apply_private_receipts(self.data, self.receipts)
        points = repo_size_points(merged, ROOT / "ground-truth", self.receipts)
        self.assertEqual(len(points), 206)  # two public repos have no recorded LOC
        sentry = next(p for p in points if p["repo"] == "sentry")
        self.assertEqual(sentry["loc"], 816371)
        self.assertEqual(sentry["scores"]["kolega-devsec-max-v0.1.0"], 0.575)
        self.assertEqual(len(sentry["scores"]), 4)
        self.assertIn("python", sentry["tabs"])


if __name__ == "__main__":
    unittest.main()
