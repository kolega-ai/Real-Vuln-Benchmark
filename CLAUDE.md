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
| `dashboard.py` | Computes scores → writes `reports/dashboard.json` (the data source of truth). HTML is built by `build_site.py` |
| `build_site.py` | Builds the public site into `reports/` from `dashboard.json`: generates `realvuln-data.js`, substitutes `{{...}}` dataset tokens in `site/*.html`, and copies `site/` over the deployed files |
| `validate_gt.py` | Schema validation for ground-truth JSON |

### Data layout

- `ground-truth/{repo}/ground-truth.json` — manually labeled vulnerabilities
- `scan-results/{repo}/{scanner}/results.json` — Semgrep-format scanner output
- `config/cwe-families.json` — CWE groupings for per-category metrics
- `site/` — source for the public website (HTML pages, `styles.css`, `dashboard.css`, `app.js`, `dashboard.js`); `{{TOKEN}}` placeholders are filled by `build_site.py`
- `reports/` — deploy directory served by a single Cloudflare Worker (`reports/wrangler.jsonc`, `assets.directory: "."`) at **realvuln.com**. The *latest* built site (`index.html`, `dashboard.html`, assets, `realvuln-data.js`) lives at the top level (tracked); per-repo subdirs and large JSON are gitignored. Build with `make dashboard` (rescore + build) or `make site` (build only)
- `reports/v/<version>/` — **immutable per-version snapshots** served at `realvuln.com/v/<version>/`. Written once by `release.py`, never regenerated, and tracked in git so they stay permanent (the paper cites `realvuln.com/v/1.0.0/`). `reports/versions.json` indexes them and drives the dashboard's version switcher (`site/versions.js`)

## Versioning / Releasing

The live site keeps **latest at `/`** and **every past release frozen under `/v/<version>/`**, so URLs printed in the paper never change meaning.

```bash
make dashboard               # rescore + build the new version into reports/ root
make release VERSION=2.0.0   # freeze reports/ root -> reports/v/2.0.0/, update versions.json
# review reports/, then deploy with wrangler (needs explicit user approval to push/deploy)
make versions                # rebuild reports/versions.json from existing snapshots only
```

- `release.py` refuses to overwrite an existing `reports/v/<version>/` (a frozen release is immutable; `--force` overrides).
- `build_site.py` warns if the version currently in `reports/` was never frozen — freeze it before rebuilding or it is lost.
- The brand version label comes from `benchmark_version` in `dashboard.json` via the `{{VERSION}}` token; `site/versions.js` upgrades it into a dropdown at runtime.

## Critical Domain Concepts

**FP Traps:** Ground truth entries with `is_vulnerable: false` test for false positives. A scanner matching these gets penalized (counted as FP).

**CWE matching:** A scanner finding matches if its CWE appears in the GT entry's `acceptable_cwes` list (not just `primary_cwe`).

**Line tolerance:** Default ±10 lines from GT `start_line`/`end_line` (`DEFAULT_LINE_TOLERANCE` in `scorer/matcher.py`).

## Adding New Scanners/Repos

**New scanner:** Place Semgrep-format JSON results in `scan-results/{repo}/{scanner}/results.json`. Unknown scanner slugs automatically use `SemgrepParser`. For non-Semgrep formats, add a parser class in `parsers/` and register in `PARSER_REGISTRY`.

**New repo:** Create `ground-truth/{repo}/ground-truth.json` following the schema, run `validate_gt.py` to verify, then add scan results to `scan-results/{repo}/{scanner}/results.json`.
