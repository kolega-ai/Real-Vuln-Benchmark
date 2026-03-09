#!/usr/bin/env python3
"""Fetch scan results from MongoDB and score all repos against ground truth.

Usage:
    # From the kolega-comply root, using the backend venv (has pymongo):
    backend/.venv/bin/python -m evals.realvuln.run_baseline

    # Fetch + score (default)
    backend/.venv/bin/python -m evals.realvuln.run_baseline

    # Score only (skip fetch, use existing scan-results/)
    backend/.venv/bin/python -m evals.realvuln.run_baseline --score-only

    # Single repo
    backend/.venv/bin/python -m evals.realvuln.run_baseline --repo realvuln-pygoat
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

# Add realvuln dir to path for scorer imports
sys.path.insert(0, str(SCRIPT_DIR))

from parsers import get_parser
from scorer.matcher import load_ground_truth, match_findings
from scorer.metrics import compute_scorecard, ScoreCard

# ── Repo → Application ID mapping ──────────────────────────────────────────

REPOS = {
    "realvuln-pygoat":                                     "20552022-624c-454b-bcd3-76ae5233b82b",
    "realvuln-vulpy":                                      "79a6f1a2-80de-475a-a2ac-cfbd5c1c45f3",
    "realvuln-Vulnerable-Flask-App":                        "710a3053-1d3d-4f6d-b138-fb8cd2489732",
    "realvuln-DjanGoat":                                    "22836aa3-2ae5-4212-a430-786862ee8f62",
    "realvuln-vulnpy":                                      "575e2ebd-0c8f-4bb7-a273-1f56c34ce192",
    "realvuln-Vulnerable-API":                              "7d7e15a0-9af1-4cd6-adc4-25ccfca61b67",
    "realvuln-ThreatByte":                                  "a46896d2-8947-4a6e-98ac-a8b231576fcc",
    "realvuln-DVBLab":                                      "e621f3da-72d5-474e-8bbe-6094e2ad1eec",
    "realvuln-lets-be-bad-guys":                            "c6afd732-455f-4836-893f-1486d9bad207",
    "realvuln-DSVPWA":                                      "b82ecb22-e4b6-490e-9c5b-37215180072c",
    "realvuln-Vulnerable_Tornado_App":                      "b3420f20-64ac-4f88-9d36-42121dfa96ed",
    "realvuln-vfapi":                                       "38cd80a3-b0ee-4240-b8c7-cb0d5a290551",
    "realvuln-PythonSSTI":                                  "83b518ce-942a-4416-be34-4d0f332a176e",
    "realvuln-python-insecure-app":                         "1a96ca5c-266b-46c5-9d34-c708612cf8e8",
    "realvuln-Damn-Vulnerable-Flask-Application":           "ead07bdf-5b9e-4924-a0e1-bc4cb5b9fb8e",
    "realvuln-extremely-vulnerable-flask-app":              "c1775c6f-8779-41cf-9534-095a0eac6cb6",
    "realvuln-insecure-web":                                "5ff8eb8e-8d4a-4af1-b979-d68833ac0637",
    "realvuln-OWASP-Web-Playground-":                       "0e841a04-3632-479d-86a6-57dddc0a9445",
    "realvuln-Intentionally-Vulnerable-Python-Application": "ef56f429-cd70-493c-b2b3-f8fe8e55c5f2",
    "realvuln-python-app":                                  "ba421c0d-0240-4961-a71a-9619ecadcd8f",
    "realvuln-defdev-app":                                  "cacf0378-38d7-4f48-b06b-f3703fffef91",
    "realvuln-Flask_XSS":                                   "ddce713e-269e-4d51-ac61-1ffc5b0674c9",
    "realvuln-Vulnerable_Python_Apps":                      "2a30d4c0-bc15-4f5e-8297-a34177dc4bba",
}

SCANNER_SLUG = "our-scanner"


# ── MongoDB fetch ───────────────────────────────────────────────────────────

def get_mongo_db():
    """Connect to MongoDB using MONGODB_URI from backend/.env."""
    from pymongo import MongoClient

    env_path = SCRIPT_DIR.parent.parent / "backend" / ".env"
    if not env_path.exists():
        raise FileNotFoundError(f".env not found at: {env_path}")

    env = {}
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip().strip("'\"")
        env[k.strip()] = v

    uri = env.get("MONGODB_URI")
    if not uri:
        raise RuntimeError("MONGODB_URI not set in backend/.env")

    client = MongoClient(uri)
    db_name = uri.rstrip("/").rsplit("/", 1)[-1].split("?")[0]
    return client, client[db_name]


def fetch_findings(db, app_id: str) -> list[dict]:
    """Fetch findings + line numbers from occurrences for an application."""
    findings = list(db["findings"].find({
        "application_id": app_id,
        "status": {"$nin": ["ignored", "false_positive"]},
    }))

    if not findings:
        return []

    finding_ids = [f["id"] for f in findings]

    # Get latest occurrence per finding for line numbers
    occurrences = list(
        db["finding_occurrences"]
        .find({"finding_id": {"$in": finding_ids}})
        .sort("detected_at", -1)
    )

    latest_occ: dict[str, dict] = {}
    for occ in occurrences:
        fid = occ["finding_id"]
        if fid not in latest_occ:
            latest_occ[fid] = occ

    results = []
    for f in findings:
        occ = latest_occ.get(f["id"])
        if not occ or occ.get("line_start") is None:
            continue

        cwes = f.get("cwe", [])
        if not cwes:
            continue

        results.append({
            "check_id": f.get("check_id", "unknown"),
            "path": f.get("file_path", "unknown"),
            "start": {"line": occ["line_start"], "col": 1},
            "end": {"line": occ.get("line_end", occ["line_start"]), "col": 100},
            "extra": {
                "message": f.get("message", ""),
                "severity": f.get("severity", "WARNING").upper(),
                "metadata": {
                    "cwe": cwes,
                    "finding_id": f["id"],
                },
            },
        })

    return results


def fetch_and_save(db, repo: str, app_id: str) -> Path | None:
    """Fetch findings for a repo and save as semgrep JSON."""
    results = fetch_findings(db, app_id)
    if not results:
        return None

    out_dir = SCRIPT_DIR / "scan-results" / repo / SCANNER_SLUG
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "results.json"
    out_path.write_text(json.dumps({"results": results}, indent=2))
    return out_path


# ── Scoring ─────────────────────────────────────────────────────────────────

def score_repo(repo: str, cwe_families: dict) -> ScoreCard | None:
    """Score a single repo. Returns None if GT or results missing."""
    gt_path = SCRIPT_DIR / "ground-truth" / repo / "ground-truth.json"
    if not gt_path.exists():
        return None

    scan_dir = SCRIPT_DIR / "scan-results" / repo / SCANNER_SLUG
    result_files = sorted(scan_dir.glob("*.json")) if scan_dir.is_dir() else []
    if not result_files:
        return None

    ground_truth = load_ground_truth(str(gt_path))
    parser = get_parser(SCANNER_SLUG)
    findings = parser.parse(str(result_files[0]))
    results = match_findings(findings, ground_truth)

    timestamp = datetime.now(timezone.utc).isoformat()
    return compute_scorecard(
        ground_truth["repo_id"], SCANNER_SLUG, timestamp, results, cwe_families
    )


# ── Main ────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch + score all RealVuln repos")
    parser.add_argument("--score-only", action="store_true", help="Skip fetch, score existing results")
    parser.add_argument("--repo", action="append", dest="repos", help="Specific repo(s) to run")
    args = parser.parse_args()

    repos = {r: REPOS[r] for r in args.repos} if args.repos else REPOS

    # Load CWE families
    families_path = SCRIPT_DIR / "config" / "cwe-families.json"
    with open(families_path) as f:
        cwe_families = json.load(f)

    # Fetch phase
    if not args.score_only:
        client, db = get_mongo_db()
        print(f"Fetching results for {len(repos)} repos...")
        for repo, app_id in repos.items():
            out = fetch_and_save(db, repo, app_id)
            if out:
                n = json.loads(out.read_text())["results"]
                print(f"  {repo}: {len(n)} findings")
            else:
                print(f"  {repo}: NO findings (app_id={app_id})")
        client.close()
        print()

    # Score phase
    print(f"{'Repo':<55} {'F2':>5} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'Prec':>6} {'Recall':>6}")
    print("=" * 95)

    all_cards: list[ScoreCard] = []
    missing: list[str] = []

    for repo in repos:
        card = score_repo(repo, cwe_families)
        if card is None:
            missing.append(repo)
            print(f"  {repo:<53} — no results or no GT")
            continue

        all_cards.append(card)
        print(
            f"  {repo:<53} {card.f2_score:>5.1f} "
            f"{card.tp:>4} {card.fp:>4} {card.fn:>4} {card.tn:>4} "
            f"{card.precision:>6.3f} {card.recall:>6.3f}"
        )

    # Aggregate
    if all_cards:
        total_tp = sum(c.tp for c in all_cards)
        total_fp = sum(c.fp for c in all_cards)
        total_fn = sum(c.fn for c in all_cards)
        total_tn = sum(c.tn for c in all_cards)
        agg_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0
        agg_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0
        agg_f2 = (5 * agg_prec * agg_recall) / (4 * agg_prec + agg_recall) if (4 * agg_prec + agg_recall) else 0

        import statistics
        avg_f2 = statistics.mean([c.f2_score for c in all_cards])

        print("=" * 95)
        print(
            f"  {'MICRO-AVG (pooled)':<53} {agg_f2 * 100:>5.1f} "
            f"{total_tp:>4} {total_fp:>4} {total_fn:>4} {total_tn:>4} "
            f"{agg_prec:>6.3f} {agg_recall:>6.3f}"
        )
        print(f"  {'MACRO-AVG (mean F2 score)':<53} {avg_f2:>5.1f}")
        print()
        print(f"Scored {len(all_cards)} repos, {len(missing)} missing/skipped")

    # Save aggregate report
    if all_cards:
        report_dir = SCRIPT_DIR / "reports"
        report_dir.mkdir(exist_ok=True)
        date_str = datetime.now().strftime("%Y-%m-%d")
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanner": SCANNER_SLUG,
            "repos_scored": len(all_cards),
            "repos_missing": missing,
            "micro_avg": {
                "tp": total_tp, "fp": total_fp, "fn": total_fn, "tn": total_tn,
                "precision": round(agg_prec, 4),
                "recall": round(agg_recall, 4),
                "f2_score": round(agg_f2 * 100, 1),
            },
            "macro_avg_f2_score": round(avg_f2, 1),
            "per_repo": {
                c.repo_id: {
                    "f2_score": c.f2_score,
                    "tp": c.tp, "fp": c.fp, "fn": c.fn, "tn": c.tn,
                    "precision": round(c.precision, 4),
                    "recall": round(c.recall, 4),
                }
                for c in all_cards
            },
        }
        report_path = report_dir / f"baseline-{date_str}.json"
        report_path.write_text(json.dumps(report, indent=2))
        print(f"Report: {report_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
