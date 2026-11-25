import json
import tempfile
import unittest
from pathlib import Path

from private_score_overlay import PRIVATE_RUN_COSTS, apply_private_receipts, resolve_attached_receipts
from build_site import build_scanners, build_tab_datasets, dataset_stats, repo_size_points, tab_loc


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
        self.assertEqual(tuple(row["strict_micro"][k] for k in ("tp", "fp", "fn")), (7554, 17822, 1505))
        self.assertEqual(row["strict_micro"]["f3_score"], 70.66)
        self.assertEqual(row["language_coverage"]["python"], [71, 71])
        self.assertEqual(self.data["aggregates"]["kolega-devsec-max-v0.1.0"]["repos_scored"], 203)
        expected = {
            "gpt-daybreak-blue-codex-cli": (4287, 3301, 4772, 48.10),
            "deepseek-v4.1-flash-agentic-v1": (2994, 3071, 6065, 34.18),
            "claude-sonnet-5-cc-agentic-v1": (2462, 2703, 6597, 28.40),
        }
        for slug, (tp, fp, fn, f3) in expected.items():
            row = merged["aggregates"][slug]
            self.assertEqual(row["repos_scored"], 208)
            self.assertEqual(tuple(row["strict_micro"][k] for k in ("tp", "fp", "fn")), (tp, fp, fn))
            self.assertEqual(row["strict_micro"]["f3_score"], f3)
        tracehunt = merged["aggregates"]["tracehunt-lite-preview-v0.1.0"]
        self.assertEqual(tuple(tracehunt["strict_micro"][k] for k in ("tp", "fp", "fn")),
                         (5088, 16333, 3971))
        self.assertEqual(tracehunt["strict_micro"]["f3_score"], 49.42)

    def test_corpus_loc_includes_private_repos_only_on_their_tabs(self):
        gt_dir = ROOT / "ground-truth"
        public = tab_loc(self.data, gt_dir)
        merged = apply_private_receipts(self.data, self.receipts)
        combined = tab_loc(merged, gt_dir)
        self.assertEqual(public["all"], 2_464_329)
        self.assertEqual(combined["all"], 5_155_194)
        self.assertEqual(dataset_stats(merged, [], 208)["loc"], combined["all"])
        for tab in ("all", "python", "intentional", "python:intentional"):
            self.assertEqual(combined[tab] - public[tab], 2_690_865)
        for tab in set(public) - {"all", "python", "intentional", "python:intentional"}:
            self.assertEqual(combined[tab], public[tab])

    def test_unscanned_repositories_are_strict_misses(self):
        merged = apply_private_receipts(self.data, self.receipts)
        slug = "gpt-5.5-agentic-v1"
        before = self.data["aggregates"][slug]
        after = merged["aggregates"][slug]
        self.assertEqual(after["strict_micro"]["fn"], before["strict_micro"]["fn"] + 1944)
        self.assertEqual(after["micro"]["fn"], before["micro"]["fn"])

    def test_accepted_private_run_costs_restore_combined_leaderboard_rates(self):
        self.assertAlmostEqual(sum(PRIVATE_RUN_COSTS["kolega-devsec-max-v0.1.0"].values()), 1.681)
        merged = apply_private_receipts(self.data, self.receipts)
        rows, _ = build_scanners(merged)
        by_slug = {row["slug"]: row for row in rows}
        expected = {
            "kolega-devsec-max-v0.1.0": (0.55, 0.38),
            "gpt-daybreak-blue-codex-cli": (22.13, 26.61),
            "deepseek-v4.1-flash-agentic-v1": (0.27, 0.47),
            "claude-sonnet-5-cc-agentic-v1": (5.53, 11.58),
        }
        for slug, (cost_per_100k, cost_per_100_vulns) in expected.items():
            with self.subTest(scanner=slug):
                self.assertEqual(by_slug[slug]["cost"], cost_per_100k)
                self.assertEqual(by_slug[slug]["cpv"], cost_per_100_vulns)
        self.assertFalse(by_slug["kolega-devsec-max-v0.1.0"]["est"])
        tabs, _ = build_tab_datasets(merged, rows, 208)
        kolega_python = next(row for row in tabs["python"] if row["slug"] == "kolega-devsec-max-v0.1.0")
        kolega_intentional = next(row for row in tabs["intentional"] if row["slug"] == "kolega-devsec-max-v0.1.0")
        self.assertEqual(kolega_python["cost"], 0.17)
        self.assertEqual(kolega_intentional["cost"], 0.30)
        without_sonnet = apply_private_receipts(
            self.data, [r for r in self.receipts if r["scanner"] != "claude-sonnet-5-cc-agentic-v1"])
        rows, _ = build_scanners(without_sonnet)
        self.assertIsNone(next(row for row in rows if row["slug"] == "claude-sonnet-5-cc-agentic-v1")["cost"])

    def test_rejects_mutated_receipt(self):
        self.receipts[0]["repo_scores"]["sentry"]["tp"] += 1
        with self.assertRaises(ValueError):
            apply_private_receipts(self.data, self.receipts)

    def test_receipt_is_optional_and_new_scanner_can_attach_one(self):
        without = apply_private_receipts(
            self.data, [r for r in self.receipts if r["scanner"] != "claude-sonnet-5-cc-agentic-v1"])
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
            with self.assertRaisesRegex(ValueError, "must be published"):
                resolve_attached_receipts(submissions, snapshot,
                                          fetch=lambda _: dict(live, published=False))

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
