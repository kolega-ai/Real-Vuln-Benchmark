# RealVuln Benchmark

Evaluate security scanners against ground-truth vulnerabilities across 27+ intentionally-vulnerable Python repos.

## Quick Start

```bash
cd evals/realvuln
source ../../backend/.env

# List available scanner configs
python batch_fetch.py --list

# Fetch + score a scanner experiment
python batch_fetch.py our-scanner-dspy-kimi
python dashboard.py --scanner-group all
```

## App Configs

Each scanner experiment has a config in `config/apps/{name}.json` mapping repos to application IDs:

```json
{
  "scanner": "our-scanner-dspy-kimi",
  "description": "DSPy MIPROv2 optimised kimi-k2.5 prompts, chunked multi-pass",
  "apps": {
    "realvuln-pygoat": "02639283-4435-4636-a057-6bfe9f2b260d",
    "realvuln-vulpy": "601b57bf-61a6-4dce-94dc-fc8d9b8e8923"
  }
}
```

Available configs:
- **our-scanner-manual-optimization** — manually optimised prompts, Claude Opus 4.6, chunked multi-pass (6 categories per chunk)
- **our-scanner-dspy-kimi** — DSPy MIPROv2 optimised kimi-k2.5 prompts

## Scoring Pipeline

### 1. Run scans via the app

Scan each realvuln repo through the production app.

### 2. Create an app config

Add a new `config/apps/{name}.json` with the repo → application_id mapping.

### 3. Fetch findings from MongoDB

**All repos (batch) — recommended:**
```bash
python batch_fetch.py <config-name>

# Include findings marked ignored/false_positive by AI assessment
python batch_fetch.py <config-name> --include-excluded

# Fetch a subset
python batch_fetch.py <config-name> --repos realvuln-pygoat realvuln-vulpy

# Override scanner slug
python batch_fetch.py <config-name> --scanner custom-name

# Preview without querying
python batch_fetch.py <config-name> --dry-run
```

**Single repo:**
```bash
python fetch_results.py <application_id> \
    --repo realvuln-VAmPI \
    --scanner our-scanner-dspy-kimi
```

The fetch pipeline:
1. Queries `findings` collection by `application_id`
2. Joins with `finding_occurrences` to get line numbers
3. Emits **one result per occurrence** (not per finding — a single finding can have multiple occurrences at different lines)
4. Filters out findings marked as ignored/false_positive (unless `--include-excluded`)
5. Skips findings with no CWE (can't match against ground truth)
6. Writes Semgrep-compatible JSON to `scan-results/{repo}/{scanner}/results.json`

### 4. Score + generate dashboard

```bash
# Score all scanners found in scan-results/
python dashboard.py --scanner-group all

# Include prompt_eval experiments
python dashboard.py --scanner-group all \
    --prompt-eval baseline-sonnet baseline-haiku-all dspy-kimi-k2.5-all

# Score specific scanners only
python dashboard.py --scanners our-scanner our-scanner-dspy-kimi semgrep

# Score a single repo + scanner
python score.py --repo realvuln-VAmPI --scanner our-scanner-dspy-kimi
python score.py --repo realvuln-VAmPI --all-scanners
```

Output:
- `reports/dashboard.html` — interactive HTML with heatmap, Plotly charts
- `reports/dashboard.json` — machine-readable scores

## Directory Structure

```
evals/realvuln/
├── config/
│   ├── apps/                               # App configs (repo → application_id)
│   │   ├── our-scanner-manual-optimization.json
│   │   └── our-scanner-dspy-kimi.json
│   └── cwe-families.json                   # CWE groupings
├── ground-truth/{repo}/ground-truth.json   # Labelled vulnerabilities
├── scan-results/{repo}/{scanner}/results.json  # Scanner outputs (Semgrep JSON)
├── parsers/                                # Normalise scanner output
├── scorer/                                 # Matching + metrics (F2, precision, recall)
├── fetch_results.py                        # Fetch single app from MongoDB
├── batch_fetch.py                          # Fetch all realvuln apps (config-driven)
├── score.py                                # Score one repo
├── dashboard.py                            # Multi-scanner dashboard
└── reports/                                # Generated HTML/JSON
```

## Scoring Method

- **Matching**: file path + CWE + line number (±10 tolerance)
- **Primary metric**: micro-F2 (recall-weighted, beta=2): `5*P*R / (4*P + R)`
- Ground truth entries marked `is_vulnerable: false` are traps — matching them counts as FP
- CWE families group related CWEs for per-category breakdown

## Key: Findings vs Occurrences

The app deduplicates findings by `check_id + file_path + application_id` (fingerprint). A single **finding** can have multiple **occurrences** at different line numbers across scans.

Scoring must happen at the **occurrence level** — `fetch_results.py` and `batch_fetch.py` handle this correctly by joining findings with occurrences.
