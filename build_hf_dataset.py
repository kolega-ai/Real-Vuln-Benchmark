"""Build a Hugging Face dataset snapshot from ground-truth and scan-results.

Outputs to `hf-dataset/`:
  - findings.jsonl      one row per ground-truth finding (denormalized with repo metadata)
  - repos.jsonl         one row per labeled repo
  - scan_results.jsonl  one row per scanner finding across all scanners
  - cwe_families.json   copied from config/
  - README.md           existing dataset card is preserved if present

Run:  python build_hf_dataset.py
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GT_DIR = ROOT / "ground-truth"
SCAN_DIR = ROOT / "scan-results"
CONFIG_DIR = ROOT / "config"
OUT_DIR = ROOT / "hf-dataset"

REPO_META_FIELDS = (
    "repo_id", "repo_url", "commit_sha", "language", "framework",
    "loc", "type", "authorship", "authorship_model",
    "authorship_confidence", "authorship_evidence", "schema_version",
)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def flatten_finding(repo_id: str, f: dict) -> dict:
    loc = f.get("location") or {}
    ev = f.get("evidence") or {}
    return {
        "repo_id": repo_id,
        "finding_id": f.get("id"),
        "is_vulnerable": f.get("is_vulnerable"),
        "vulnerability_class": f.get("vulnerability_class"),
        "primary_cwe": f.get("primary_cwe"),
        "acceptable_cwes": f.get("acceptable_cwes", []),
        "file": f.get("file"),
        "start_line": loc.get("start_line"),
        "end_line": loc.get("end_line"),
        "function": loc.get("function"),
        "severity": f.get("severity"),
        "expected_category": f.get("expected_category"),
        "source": ev.get("source"),
        "cve_id": ev.get("cve_id"),
        "description": ev.get("description"),
        "manually_verified": ev.get("manually_verified"),
        "poc": f.get("poc"),
    }


def build_gt() -> tuple[list[dict], list[dict], dict[str, str]]:
    """Returns (repos, findings, dir_to_repo_id map for joining scan results)."""
    repos, findings = [], []
    dir_to_repo_id: dict[str, str] = {}
    for gt_path in sorted(GT_DIR.glob("*/ground-truth.json")):
        data = json.loads(gt_path.read_text())
        repo_id = data.get("repo_id") or gt_path.parent.name
        dir_to_repo_id[gt_path.parent.name] = repo_id
        repos.append({k: data.get(k) for k in REPO_META_FIELDS})
        for f in data.get("findings", []):
            findings.append(flatten_finding(repo_id, f))
    return repos, findings, dir_to_repo_id


def flatten_scan(repo_id: str, scanner: str, run: str | None, r: dict) -> dict:
    start = r.get("start") or {}
    end = r.get("end") or {}
    extra = r.get("extra") or {}
    meta = extra.get("metadata") or {}
    cwes = meta.get("cwe") or []
    return {
        "repo_id": repo_id,
        "scanner": scanner,
        "run": run,
        "check_id": r.get("check_id"),
        "file": r.get("path"),
        "start_line": start.get("line"),
        "end_line": end.get("line"),
        "severity": extra.get("severity"),
        "message": extra.get("message"),
        "cwe": cwes[0] if cwes else None,
        "all_cwes": cwes,
        "finding_id": meta.get("finding_id"),
    }


def iter_scan_files():
    """Yields (repo_dir, scanner, run_label, path). run_label is None for
    deterministic scanners with a single results.json, or 'run-N' for agentic
    scanners with multiple stochastic runs."""
    for scanner_dir in sorted(SCAN_DIR.glob("*/*")):
        if not scanner_dir.is_dir():
            continue
        results = scanner_dir / "results.json"
        if results.exists():
            yield scanner_dir.parent.name, scanner_dir.name, None, results
            continue
        for run_path in sorted(scanner_dir.glob("run-*.json")):
            if run_path.name.endswith(".metrics.json"):
                continue
            yield scanner_dir.parent.name, scanner_dir.name, run_path.stem, run_path


def build_scans(dir_to_repo_id: dict[str, str]) -> list[dict]:
    rows = []
    unknown_dirs: set[str] = set()
    for dir_name, scanner, run, path in iter_scan_files():
        repo_id = dir_to_repo_id.get(dir_name)
        if repo_id is None:
            unknown_dirs.add(dir_name)
            repo_id = dir_name.removeprefix("realvuln-")
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        for r in data.get("results", []):
            rows.append(flatten_scan(repo_id, scanner, run, r))
    if unknown_dirs:
        print(f"warning: {len(unknown_dirs)} scan dirs have no matching GT: {sorted(unknown_dirs)}")
    return rows


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)

    repos, findings, dir_to_repo_id = build_gt()
    write_jsonl(OUT_DIR / "repos.jsonl", repos)
    write_jsonl(OUT_DIR / "findings.jsonl", findings)
    print(f"repos.jsonl      {len(repos):>5} rows")
    print(f"findings.jsonl   {len(findings):>5} rows")

    scans = build_scans(dir_to_repo_id)
    write_jsonl(OUT_DIR / "scan_results.jsonl", scans)
    print(f"scan_results.jsonl {len(scans):>5} rows")

    shutil.copy(CONFIG_DIR / "cwe-families.json", OUT_DIR / "cwe_families.json")
    print("cwe_families.json copied")


if __name__ == "__main__":
    main()
