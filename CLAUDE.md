# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RealVuln Benchmark evaluates security scanners (Semgrep, Snyk, SonarQube, custom LLM-based scanners) against ground-truth vulnerabilities across 27+ intentionally-vulnerable Python repos. Primary metric is **F2 score** (0-100, recall-weighted with beta=2).

## Common Commands

```bash
# Validate ground truth schemas
python validate_gt.py                                # all repos
python validate_gt.py realvuln-pygoat realvuln-dvpwa  # specific repos

# Fetch scan results from MongoDB (requires MONGODB_URI in env)
python batch_fetch.py --list                          # list configs
python batch_fetch.py <config-name>                   # fetch all repos
python batch_fetch.py <config-name> --dry-run         # preview only

# Score and generate dashboard
python dashboard.py --scanner-group all
python score.py --repo realvuln-pygoat --all-scanners
python score.py --repo realvuln-VAmPI --scanner semgrep
```

## Architecture

**Pipeline:** Scan Execution → Fetch from MongoDB → Parse & Normalize → Match against GT → Score (F2)

### Key modules

- **`parsers/`** — Normalize scanner output to `NormalisedFinding` (file, cwe, line, severity). All 50+ scanner slugs currently map to `SemgrepParser` in `PARSER_REGISTRY`.
- **`scorer/matcher.py`** — 3-field matching: file path + CWE (checks `acceptable_cwes`) + line number (±10 tolerance). GT entries with `is_vulnerable: false` are FP traps.
- **`scorer/metrics.py`** — `ScoreCard` with TP/FP/FN/TN, precision, recall, F1, F2, per-CWE-family and per-severity breakdowns.

### Entry points

| Script | Purpose |
|--------|---------|
| `batch_fetch.py` | Config-driven batch fetch from MongoDB for all repos |
| `fetch_results.py` | Single-repo fetch (used by batch_fetch) |
| `score.py` | Score one repo against one or all scanners |
| `dashboard.py` | Multi-scanner multi-repo HTML dashboard with Plotly |
| `run_baseline.py` | End-to-end: fetch + score all repos |
| `validate_gt.py` | Schema validation for ground-truth JSON |

### Data layout

- `ground-truth/{repo}/ground-truth.json` — manually labeled vulnerabilities
- `scan-results/{repo}/{scanner}/results.json` — Semgrep-format scanner output
- `config/apps/{name}.json` — repo → MongoDB application_id mapping (gitignored)
- `config/cwe-families.json` — CWE groupings for per-category metrics
- `reports/` — generated HTML/JSON dashboards and scorecards (gitignored)

## Critical Domain Concepts

**Findings vs Occurrences:** MongoDB deduplicates findings by `check_id + file_path + application_id`. One finding can have multiple occurrences at different lines. Scoring happens at the **occurrence level** — each line is a separate match attempt.

**FP Traps:** Ground truth entries with `is_vulnerable: false` test for false positives. A scanner matching these gets penalized (counted as FP).

**CWE matching:** A scanner finding matches if its CWE appears in the GT entry's `acceptable_cwes` list (not just `primary_cwe`).

**Line tolerance:** Default ±10 lines from GT `start_line`/`end_line` (`DEFAULT_LINE_TOLERANCE` in `scorer/matcher.py`).

## Adding New Scanners/Repos

**New scanner:** Add parser class in `parsers/`, register slug in `PARSER_REGISTRY` (`parsers/__init__.py`). Output must produce `NormalisedFinding` list.

**New repo:** Create `ground-truth/{repo}/ground-truth.json` following the schema, run `validate_gt.py` to verify, then add scan results to `scan-results/{repo}/{scanner}/results.json`.
