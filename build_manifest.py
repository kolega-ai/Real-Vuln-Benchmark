#!/usr/bin/env python3
"""Regenerate benchmark-manifest.json from the ground-truth files.

Every dataset figure in the manifest is derived from ground-truth/*/ground-truth.json
so it can never drift from the corpus. Hand-maintained fields (version, release
date, prompt version, corpus description) are passed on the command line or kept
from the existing manifest.

Usage:
    python3 build_manifest.py                       # rewrite counts, keep version fields
    python3 build_manifest.py --version 3.0.0 --release-date 2026-09-03
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from compute_gt_hash import compute_gt_hash  # noqa: E402

MANIFEST = ROOT / "benchmark-manifest.json"
HASH_ALGORITHM = (
    "sha256 over sorted ground-truth/{repo}/ground-truth.json: utf-8 path + \\n + "
    "file bytes (see compute_gt_hash.py)"
)


def is_non_scoring(finding: dict) -> bool:
    return finding.get("scoring") == "non_scoring"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", help="benchmark + ground-truth version (default: keep)")
    ap.add_argument("--release-date", help="YYYY-MM-DD (default: keep)")
    ap.add_argument("--prompt-version", help="default_prompt_version (default: keep)")
    ap.add_argument("--check", action="store_true", help="exit 1 if the manifest is stale")
    args = ap.parse_args()

    old = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}

    repos: dict[str, dict] = {}
    languages: Counter = Counter()
    frameworks: Counter = Counter()
    authorship: Counter = Counter()
    authorship_models: Counter = Counter()
    severity: Counter = Counter()
    cwes: set[str] = set()
    vulns = traps = non_scoring = 0
    type_1 = 0
    loc_total = 0
    per_language: dict[str, dict] = {}

    for path in sorted(glob.glob(str(ROOT / "ground-truth/*/ground-truth.json"))):
        gt = json.loads(Path(path).read_text())
        slug = Path(path).parent.name
        lang = (gt.get("language") or "unknown").lower()
        scored = [f for f in gt["findings"] if not is_non_scoring(f)]
        ns = [f for f in gt["findings"] if is_non_scoring(f)]
        r_vulns = sum(1 for f in scored if f["is_vulnerable"])
        r_traps = len(scored) - r_vulns
        vulns += r_vulns
        traps += r_traps
        non_scoring += len(ns)
        languages[lang] += 1
        frameworks[gt.get("framework") or "none"] += 1
        authorship[gt.get("authorship") or "unknown"] += 1
        if gt.get("authorship") == "llm_generated":
            authorship_models[gt.get("authorship_model") or "unknown"] += 1
        if gt.get("type") == 1:
            type_1 += 1
        loc_total += gt.get("loc") or 0
        for f in scored:
            if f["is_vulnerable"]:
                severity[f.get("severity", "unknown")] += 1
                cwes.add(f["primary_cwe"])
        pl = per_language.setdefault(
            lang, {"repos": 0, "vulnerable_findings": 0, "false_positive_traps": 0, "non_scoring": 0, "loc": 0}
        )
        pl["repos"] += 1
        pl["vulnerable_findings"] += r_vulns
        pl["false_positive_traps"] += r_traps
        pl["non_scoring"] += len(ns)
        pl["loc"] += gt.get("loc") or 0
        repos[slug] = {
            "repo_url": gt["repo_url"],
            "commit_sha": gt["commit_sha"],
            "type": gt.get("type"),
            "language": gt.get("language"),
            "framework": gt.get("framework"),
            "authorship": gt.get("authorship"),
            "authorship_model": gt.get("authorship_model"),
            "vulnerable_findings": r_vulns,
            "false_positive_traps": r_traps,
            "non_scoring": len(ns),
            **({"source_layout": gt["source_layout"]} if gt.get("source_layout") else {}),
        }

    version = args.version or old.get("benchmark_version")
    manifest = {
        "schema_version": "3.0",
        "benchmark_version": version,
        "ground_truth_version": version,
        "ground_truth_schema_version": "1.0",
        "release_date": args.release_date or old.get("release_date"),
        "ground_truth_content_hash": compute_gt_hash(),
        "ground_truth_hash_algorithm": HASH_ALGORITHM,
        "default_prompt_version": args.prompt_version or old.get("default_prompt_version"),
        "dataset": {
            "repo_count": len(repos),
            "vulnerable_findings": vulns,
            "false_positive_traps": traps,
            "non_scoring_entries": non_scoring,
            "total_findings": vulns + traps,
            "total_entries": vulns + traps + non_scoring,
            "type_1_repos": type_1,
            "loc": loc_total,
            "languages": dict(sorted(languages.items())),
            "per_language": dict(sorted(per_language.items())),
            "frameworks": dict(sorted(frameworks.items())),
            "authorship": dict(sorted(authorship.items())),
            "human_authored_repos": authorship.get("human_authored", 0),
            "llm_generated_repos": authorship.get("llm_generated", 0),
            "distinct_primary_cwes": len(cwes),
            "severity_counts": dict(sorted(severity.items())),
        },
        "llm_generated_corpus": {
            "description": (
                "Company-style applications generated end-to-end by coding agents, then "
                "reviewed and labeled. The authorship model of each repository is recorded "
                "in its ground-truth.json."
            ),
            "authorship_models": dict(sorted(authorship_models.items())),
        },
        "non_scoring": {
            "description": (
                "Reviewed locations whose vulnerability status is highly discretionary are "
                "kept in ground truth with scoring=non_scoring and a written reason. They "
                "are excluded from every metric in both directions: reporting one is not a "
                "false positive and missing one is not a false negative."
            ),
            "entries": non_scoring,
        },
        "repos": repos,
    }

    text = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        current = MANIFEST.read_text() if MANIFEST.exists() else ""
        # release_date/version are inputs; compare everything else
        a = json.loads(current) if current else {}
        for k in ("benchmark_version", "ground_truth_version", "release_date", "default_prompt_version"):
            a.pop(k, None)
            manifest.pop(k, None)
        if a != manifest:
            print("benchmark-manifest.json is stale; run python3 build_manifest.py")
            return 1
        print("benchmark-manifest.json is up to date")
        return 0
    MANIFEST.write_text(text)
    d = manifest["dataset"]
    print(
        f"wrote benchmark-manifest.json  v{version}  {d['repo_count']} repos  "
        f"{d['vulnerable_findings']} vulns  {d['false_positive_traps']} traps  "
        f"{d['non_scoring_entries']} non-scoring  languages={d['languages']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
