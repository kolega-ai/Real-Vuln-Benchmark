import json
import tempfile
import unittest
from pathlib import Path

from private_score_overlay import apply_private_receipts, resolve_attached_receipts
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
        self.assertEqual(tuple(row["strict_micro"][k] for k in ("tp", "fp", "fn")), (7557, 17819, 1505))
        self.assertEqual(row["strict_micro"]["f3_score"], 70.67)
        self.assertEqual(row["language_coverage"]["python"], [71, 71])
        self.assertEqual(self.data["aggregates"]["kolega-devsec-max-v0.1.0"]["repos_scored"], 203)
        expected = {
            "gpt-daybreak-blue-codex-cli": (4289, 3299, 4773, 48.11),
            "deepseek-v4.1-flash-agentic-v1": (2996, 3069, 6066, 34.19),
            "claude-sonnet-5-cc-agentic-v1": (2462, 2703, 6600, 28.39),
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

    def test_receipt_is_optional_and_new_scanner_can_attach_one(self):
        without = apply_private_receipts(self.data, self.receipts[:-1])
        sonnet = "claude-sonnet-5-cc-agentic-v1"
        self.assertEqual(without["aggregates"][sonnet]["repos_scored"], 203)
        self.assertEqual(without["aggregates"][sonnet]["strict_micro"]["fn"],
                         self.data["aggregates"][sonnet]["strict_micro"]["fn"] + 1944)
        new = dict(self.receipts[0], scanner="gpt-5.5-agentic-v1", run_id="f" * 32)
        new.pop("repo_scores")
        with_new = apply_private_receipts(self.data, self.receipts + [new])
        row = with_new["aggregates"][new["scanner"]]
        self.assertEqual(row["repos_scored"], self.data["aggregates"][new["scanner"]]["repos_scored"] + 5)
        self.assertEqual(row["private_receipt"], new["run_id"])

    def test_submission_attachment_fetches_service_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            submissions = root / "submissions"
            submissions.mkdir()
            scanner = self.receipts[0]["scanner"]
            (submissions / f"{scanner}.json").write_text(json.dumps(
                {"scanner": scanner, "private_receipt_id": self.receipts[0]["run_id"]}))
            snapshot = root / "snapshot.json"
            snapshot.write_text(json.dumps(self.receipts))
            live = {k: v for k, v in self.receipts[0].items() if k != "repo_scores"}
            resolved = resolve_attached_receipts(submissions, snapshot, fetch=lambda _: live)
            self.assertEqual(resolved[0]["repo_scores"], self.receipts[0]["repo_scores"])
            with self.assertRaisesRegex(ValueError, "does not belong"):
                resolve_attached_receipts(submissions, snapshot,
                                          fetch=lambda _: dict(live, scanner="another-scanner"))

    def test_size_chart_uses_published_repo_aggregates(self):
        merged = apply_private_receipts(self.data, self.receipts)
        points = repo_size_points(merged, ROOT / "ground-truth", self.receipts)
        self.assertEqual(len(points), 206)  # two public repos have no recorded LOC
        sentry = next(p for p in points if p["repo"] == "sentry")
        self.assertEqual(sentry["loc"], 816371)
        self.assertEqual(sentry["scores"]["kolega-devsec-max-v0.1.0"], 0.5738)
        self.assertEqual(len(sentry["scores"]), 4)
        self.assertIn("python", sentry["tabs"])


if __name__ == "__main__":
    unittest.main()
