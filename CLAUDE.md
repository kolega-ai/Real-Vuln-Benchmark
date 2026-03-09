# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RealVuln Benchmark evaluates security scanners against ground-truth vulnerabilities across 27+ intentionally-vulnerable Python repos. Primary metric is **F2 score** (0-100, recall-weighted with beta=2).

## Common Commands

```bash
# Validate ground truth schemas
python validate_gt.py                                # all repos
python validate_gt.py realvuln-pygoat realvuln-dvpwa  # specific repos

# Score and generate dashboard
python dashboard.py --scanner-group all
python score.py --repo realvuln-pygoat --all-scanners
python score.py --repo realvuln-VAmPI --scanner semgrep
```

## Architecture

**Pipeline:** Parse Scanner Output → Normalize → Match against GT → Score (F2)

### Key modules

- **`parsers/`** — Normalize scanner output to `NormalisedFinding` (file, cwe, line, severity). Known scanners registered in `PARSER_REGISTRY`; unknown slugs fall back to `SemgrepParser`.
- **`scorer/matcher.py`** — 3-field matching: file path + CWE (checks `acceptable_cwes`) + line number (±10 tolerance). GT entries with `is_vulnerable: false` are FP traps.
- **`scorer/metrics.py`** — `ScoreCard` with TP/FP/FN/TN, precision, recall, F1, F2, per-CWE-family and per-severity breakdowns.

### Entry points

| Script | Purpose |
|--------|---------|
| `score.py` | Score one repo against one or all scanners |
| `dashboard.py` | Multi-scanner multi-repo HTML dashboard with Plotly |
| `validate_gt.py` | Schema validation for ground-truth JSON |

### Data layout

- `ground-truth/{repo}/ground-truth.json` — manually labeled vulnerabilities
- `scan-results/{repo}/{scanner}/results.json` — Semgrep-format scanner output
- `config/cwe-families.json` — CWE groupings for per-category metrics
- `reports/` — generated HTML/JSON dashboards and scorecards (gitignored)

## Critical Domain Concepts

**FP Traps:** Ground truth entries with `is_vulnerable: false` test for false positives. A scanner matching these gets penalized (counted as FP).

**CWE matching:** A scanner finding matches if its CWE appears in the GT entry's `acceptable_cwes` list (not just `primary_cwe`).

**Line tolerance:** Default ±10 lines from GT `start_line`/`end_line` (`DEFAULT_LINE_TOLERANCE` in `scorer/matcher.py`).

## Adding New Scanners/Repos

**New scanner:** Place Semgrep-format JSON results in `scan-results/{repo}/{scanner}/results.json`. Unknown scanner slugs automatically use `SemgrepParser`. For non-Semgrep formats, add a parser class in `parsers/` and register in `PARSER_REGISTRY`.

**New repo:** Create `ground-truth/{repo}/ground-truth.json` following the schema, run `validate_gt.py` to verify, then add scan results to `scan-results/{repo}/{scanner}/results.json`.
