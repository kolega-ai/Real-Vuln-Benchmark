#!/usr/bin/env python3
"""Generate the HuggingFace companion dataset from ground truth and scan results.

The published dataset used to be assembled by hand, which is how it drifted:
three `repo_url` values in it pointed at repos that had 404'd, and one
disagreed with `ground-truth/`. Everything here is derived from the files in
this repo instead, so a release cannot silently diverge from the benchmark.

Emits the three JSONL files the dataset is configured around, plus a README:

    repos.jsonl         one row per target: URL, pinned SHA, framework, LOC
    findings.jsonl      one row per ground-truth entry, FP traps included
    scan_results.jsonl  one row per raw scanner finding
    README.md           dataset card with counts computed, never typed

Usage:
    python3 export_hf_dataset.py --out dist/hf-v2
    python3 export_hf_dataset.py --out dist/hf-v1 --authorship human_authored

Publishing is deliberately NOT done here — this writes a directory for review.
Upload it with, and tag the release so the exact version stays citable:

    hf upload Kolega-Dev/RealVuln-v2 dist/hf-v2 . --repo-type dataset
    hf repos tag create Kolega-Dev/RealVuln-v2 v2.0.0 --repo-type dataset
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GT_DIR = ROOT / "ground-truth"
SCAN_DIR = ROOT / "scan-results"

# Field order copied from the published dataset so existing consumers and the
# dataset viewer's inferred schema keep working across versions.
REPO_FIELDS = [
    "repo_id", "repo_url", "commit_sha", "language", "framework", "loc",
    "type", "authorship", "authorship_model", "authorship_confidence",
    "authorship_evidence", "schema_version",
]
FINDING_FIELDS = [
    "repo_id", "finding_id", "is_vulnerable", "vulnerability_class",
    "primary_cwe", "acceptable_cwes", "file", "start_line", "end_line",
    "function", "severity", "expected_category", "source", "cve_id",
    "description", "manually_verified", "poc",
]
SCAN_FIELDS = [
    "repo_id", "scanner", "run", "check_id", "file", "start_line", "end_line",
    "severity", "message", "cwe", "all_cwes", "finding_id",
]


def row(src: dict, fields: list[str], **extra) -> dict:
    """Project src onto fields in order, defaulting missing keys to None."""
    out = {f: src.get(f) for f in fields}
    out.update(extra)
    return {f: out.get(f) for f in fields}


def load_targets(authorship: str | None) -> list[tuple[str, dict]]:
    """(gt_dir_name, ground truth) per target, optionally filtered by authorship."""
    targets = []
    for path in sorted(GT_DIR.glob("*/ground-truth.json")):
        gt = json.loads(path.read_text())
        if authorship and (gt.get("authorship") or "") != authorship:
            continue
        targets.append((path.parent.name, gt))
    return targets


def published_scanners() -> set[str]:
    """Scanner slugs allowed into the dataset: exactly those on the public site.

    scan-results/ holds far more than the site publishes — internal variants and
    experiment series that are deliberately not on the leaderboard, some of them
    gitignored and never pushed anywhere (see .gitignore's scan-results entries).
    Exporting every directory found on disk would publish those, so the allowlist
    is SCANNER_META: if a scanner is not on the public dashboard, its raw output
    does not belong in a public dataset either.
    """
    from build_site import SCANNER_META

    return set(SCANNER_META)


def scan_rows(dir_name: str, repo_id: str, allowed: set[str] | None) -> list[dict]:
    """Flatten each published scanner's raw output for one target into rows.

    Reads the Semgrep-shaped `results` array directly rather than going through
    parsers/, because the dataset publishes what scanners actually emitted; the
    normalisation that scoring applies is deliberately not baked in here.
    """
    rows: list[dict] = []
    repo_scans = SCAN_DIR / dir_name
    if not repo_scans.is_dir():
        return rows
    for scanner_dir in sorted(p for p in repo_scans.iterdir() if p.is_dir()):
        if allowed is not None and scanner_dir.name not in allowed:
            continue
        for result_file in sorted(scanner_dir.glob("*.json")):
            if result_file.name.endswith(".metrics.json"):
                continue
            try:
                data = json.loads(result_file.read_text())
            except json.JSONDecodeError:
                print(f"  WARNING: skipping unreadable {result_file}")
                continue
            results = data.get("results", data if isinstance(data, list) else [])
            for r in results:
                extra = r.get("extra") or {}
                meta = extra.get("metadata") or {}
                cwe = meta.get("cwe")
                all_cwes = cwe if isinstance(cwe, list) else ([cwe] if cwe else [])
                rows.append(row(
                    {}, SCAN_FIELDS,
                    repo_id=repo_id,
                    scanner=scanner_dir.name,
                    run=result_file.stem,
                    check_id=r.get("check_id"),
                    file=r.get("path"),
                    start_line=(r.get("start") or {}).get("line"),
                    end_line=(r.get("end") or {}).get("line"),
                    severity=extra.get("severity") or meta.get("severity"),
                    message=extra.get("message"),
                    cwe=all_cwes[0] if all_cwes else None,
                    all_cwes=all_cwes,
                    finding_id=r.get("finding_id"),
                ))
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
    print(f"  wrote {path.name}  ({len(rows):,} rows)")


DATASET_CARD = """---
license: {license}
language:
  - en
  - code
task_categories:
  - text-classification
  - token-classification
tags:
  - security
  - vulnerability-detection
  - sast
  - code
  - python
  - benchmark
  - cwe
pretty_name: {pretty_name}
size_categories:
  - {size_category}
configs:
  - config_name: findings
    data_files: findings.jsonl
    default: true
  - config_name: repos
    data_files: repos.jsonl
  - config_name: scan_results
    data_files: scan_results.jsonl
---

# {pretty_name}

Ground-truth vulnerability labels for {n_repos} intentionally-vulnerable Python
repositories, plus the raw outputs of {n_scanners} security scanners (rule-based
SAST, general-purpose LLMs, and security-specialised agents).

Benchmark version **{version}**. Generated from
[kolega-ai/Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark)
by `export_hf_dataset.py`, so the metadata here always matches the benchmark's
own ground truth.

## Dataset summary

| Split | Rows | Description |
|-------|------|-------------|
| `findings` | {n_findings:,} | Human-reviewed vulnerabilities and FP traps |
| `repos` | {n_repos} | Target metadata (URL, pinned commit SHA, framework, LOC) |
| `scan_results` | {n_scans:,} | Raw scanner output across {n_scanners} scanners |

- **{n_vulns:,}** vulnerabilities + **{n_traps}** false-positive traps (`is_vulnerable: false`)
- **{n_cwes}** unique primary CWEs
- Every finding carries `primary_cwe` and an `acceptable_cwes` list for tolerant matching
{corpus_note}
## Versioning

`main` always tracks the latest {major}.x release. Every release is also a git
tag, so a citation can pin an exact, immutable version:

```python
from datasets import load_dataset

# exact version — use this in papers
findings = load_dataset("{repo_id}", "findings", split="train", revision="v{version}")

# latest {major}.x
findings = load_dataset("{repo_id}", "findings", split="train")
repos    = load_dataset("{repo_id}", "repos",    split="train")
scans    = load_dataset("{repo_id}", "scan_results", split="train")
```

Corpora are not comparable across major versions, because the official target
set changes. {sibling_note}

## Notes

The vulnerable source code is not redistributed here. Each `repos` row gives a
`repo_url` and `commit_sha` so the exact labelled revision can be cloned; all
URLs are verified reachable at their pinned SHA at release time.

Scoring uses file + CWE + line matching with a +/-10 line tolerance. Rows with
`is_vulnerable: false` are false-positive traps: a scanner flagging one is
penalised, not rewarded.
"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--authorship", help="filter targets, e.g. human_authored")
    ap.add_argument(
        "--all-scanners", action="store_true",
        help="INTERNAL USE ONLY. Include every scanner directory found on disk, "
             "not just those published on the public dashboard. This will pull in "
             "unreleased variants and gitignored experiment runs — never pass this "
             "for anything destined for the public Hub.",
    )
    ap.add_argument("--repo-id", default="Kolega-Dev/RealVuln-v2")
    ap.add_argument("--pretty-name", default="RealVuln v2")
    ap.add_argument("--license", default="apache-2.0")
    ap.add_argument("--sibling-note", default=(
        "Version 1, the corpus described in "
        "[arXiv:2604.13764](https://arxiv.org/abs/2604.13764), is at "
        "[Kolega-Dev/RealVuln](https://huggingface.co/datasets/Kolega-Dev/RealVuln)."
    ))
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    targets = load_targets(args.authorship)
    if not targets:
        raise SystemExit("no targets matched")

    allowed = None if args.all_scanners else published_scanners()
    if allowed is None:
        print("  WARNING: --all-scanners set; output may contain unpublished "
              "scanners and must not be uploaded to a public dataset")

    repos, findings, scans = [], [], []
    for dir_name, gt in targets:
        repo_id = gt.get("repo_id") or dir_name
        repos.append(row(gt, REPO_FIELDS, repo_id=repo_id))
        for f in gt["findings"]:
            findings.append(row(f, FINDING_FIELDS, repo_id=repo_id))
        scans += scan_rows(dir_name, repo_id, allowed)

    write_jsonl(out / "repos.jsonl", repos)
    write_jsonl(out / "findings.jsonl", findings)
    write_jsonl(out / "scan_results.jsonl", scans)

    version = str(targets[0][1].get("benchmark_version") or "")
    n_vulns = sum(1 for f in findings if f["is_vulnerable"])
    n_traps = len(findings) - n_vulns
    n_scanners = len({s["scanner"] for s in scans})
    corpus_note = ""
    if not args.authorship:
        human = sum(1 for r in repos if r["authorship"] == "human_authored")
        llm = sum(1 for r in repos if r["authorship"] == "llm_generated")
        corpus_note = (
            f"- Corpus split: **{human}** human-authored targets, "
            f"**{llm}** LLM-generated (vibe-coded) targets, "
            "distinguished by the `authorship` field\n"
        )

    (out / "README.md").write_text(DATASET_CARD.format(
        license=args.license,
        pretty_name=args.pretty_name,
        repo_id=args.repo_id,
        version=version,
        major=version.split(".")[0] or "2",
        size_category="n<1K" if len(findings) < 1000 else "1K<n<10K",
        n_repos=len(repos), n_findings=len(findings), n_scans=len(scans),
        n_vulns=n_vulns, n_traps=n_traps, n_scanners=n_scanners,
        n_cwes=len({f["primary_cwe"] for f in findings if f["primary_cwe"]}),
        corpus_note=corpus_note,
        sibling_note=args.sibling_note,
    ))
    print(f"  wrote README.md")
    print(f"\n  {len(repos)} targets · {len(findings):,} findings "
          f"({n_vulns:,} vulns / {n_traps} traps) · {len(scans):,} scan rows "
          f"· {n_scanners} scanners · benchmark {version}")


if __name__ == "__main__":
    main()
