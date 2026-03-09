# RealVuln Benchmark

Evaluate security scanners against ground-truth vulnerabilities across 27+ intentionally-vulnerable Python repos. See [SPEC.md](SPEC.md) for the full benchmark specification.

## Quick Start

```bash
# Validate ground truth schemas
python validate_gt.py

# Score a single repo against all scanners
python score.py --repo realvuln-pygoat --all-scanners

# Generate multi-scanner dashboard
python dashboard.py --scanner-group all
```

## Adding Scan Results

Place scanner output in Semgrep JSON format at:

```
scan-results/{repo}/{scanner-slug}/results.json
```

Any scanner producing Semgrep-compatible JSON works automatically — no registration needed.

## Scoring

```bash
# Score specific scanner
python score.py --repo realvuln-VAmPI --scanner semgrep

# Score all scanners for a repo
python score.py --repo realvuln-VAmPI --all-scanners

# Multi-run mode (mean +/- stddev across result files)
python score.py --repo realvuln-pygoat --all-scanners --runs

# Multi-scanner dashboard
python dashboard.py --scanner-group all
python dashboard.py --scanners semgrep sonarqube my-scanner
```

Output:
- `reports/dashboard.html` — interactive HTML with heatmap, Plotly charts
- `reports/dashboard.json` — machine-readable scores
- `reports/{repo}/scorecard-{date}.json` — per-repo JSON scorecard
- `reports/{repo}/scorecard-{date}.md` — per-repo markdown scorecard

## Directory Structure

```
├── config/
│   └── cwe-families.json                   # CWE groupings for per-category metrics
├── ground-truth/{repo}/ground-truth.json   # Labelled vulnerabilities
├── scan-results/{repo}/{scanner}/results.json  # Scanner outputs (Semgrep JSON)
├── parsers/                                # Normalise scanner output
├── scorer/                                 # Matching + metrics (F2, precision, recall)
├── score.py                                # Score one repo
├── dashboard.py                            # Multi-scanner dashboard
├── validate_gt.py                          # Ground truth schema validator
└── reports/                                # Generated HTML/JSON (gitignored)
```

## Scoring Method

- **Matching**: file path + CWE + line number (±10 tolerance)
- **Primary metric**: F2 score (0-100, recall-weighted with beta=2): `5*P*R / (4*P + R) * 100`
- Ground truth entries marked `is_vulnerable: false` are FP traps — matching them counts as FP
- CWE matching uses `acceptable_cwes` list, not just `primary_cwe`
- CWE families group related CWEs for per-category breakdown

## Adding a New Scanner

1. Place results in `scan-results/{repo}/{scanner-slug}/results.json` (Semgrep JSON format)
2. Run `python score.py --repo {repo} --scanner {scanner-slug}`

If your scanner uses a different output format, add a parser class in `parsers/` and register it in `PARSER_REGISTRY` (`parsers/__init__.py`).

## Adding a New Repo

1. Create `ground-truth/{repo}/ground-truth.json` following the schema in [SPEC.md](SPEC.md)
2. Run `python validate_gt.py {repo}` to verify
3. Add scan results to `scan-results/{repo}/{scanner}/results.json`
