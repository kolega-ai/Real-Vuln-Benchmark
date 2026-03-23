# RealVuln Benchmark

An open benchmark for evaluating security scanners against ground-truth vulnerabilities in real-world code. Primary metric is **F2 Score** (0–100, recall-weighted).

Application security scanners routinely fail to catch basic vulnerabilities — missing authentication, broken access control, IDOR — in real-world code. Existing benchmarks use synthetic test cases (OWASP Benchmark), vendor-controlled methodology (DryRun, ZeroPath, Cycode/Bearer), or lack scoring tooling (NIST Juliet, CVEFixes). RealVuln provides machine-readable ground truth with CWE mappings, an automated scoring engine, and is designed for community contribution.

## Current State

### Dataset

**26 Python repos · 796 findings · 676 vulnerabilities · 120 FP traps**

All targets are **Type 1 (intentionally vulnerable apps)** with `human_authored` authorship.

> **Language coverage:** Python only (Flask, Django, FastAPI, aiohttp, Tornado). JavaScript/TypeScript, Go, and Java are planned — see [Roadmap](#roadmap).

| Repo | Language | Framework | Vulns | FP Traps |
|------|----------|-----------|------:|--------:|
| realvuln-damn-vulnerable-flask-application | python | flask | 15 | 4 |
| realvuln-damn-vulnerable-graphql-application | python | flask | 35 | 4 |
| realvuln-djangoat | python | django | 50 | 6 |
| realvuln-dsvpwa | python | — | 32 | 6 |
| realvuln-dsvw | python | — | 27 | 4 |
| realvuln-dvblab | python | flask | 22 | 4 |
| realvuln-dvpwa | python | aiohttp | 22 | 4 |
| realvuln-extremely-vulnerable-flask-app | python | flask | 28 | 4 |
| realvuln-flask-xss | python | flask | 28 | 5 |
| realvuln-insecure-web | python | flask | 9 | 2 |
| realvuln-intentionally-vulnerable-python-application | python | flask | 7 | 2 |
| realvuln-lets-be-bad-guys | python | django | 24 | 4 |
| realvuln-owasp-web-playground | python | flask | 29 | 6 |
| realvuln-pygoat | python | django | 70 | 10 |
| realvuln-python-app | python | flask | 20 | 4 |
| realvuln-python-insecure-app | python | fastapi | 8 | 2 |
| realvuln-pythonssti | python | fastapi | 2 | 1 |
| realvuln-threatbyte | python | flask | 24 | 5 |
| realvuln-vampi | python | flask | 13 | 4 |
| realvuln-vfapi | python | fastapi | 9 | 2 |
| realvuln-vulnerable-api | python | flask | 14 | 3 |
| realvuln-vulnerable-flask-app | python | flask | 20 | 4 |
| realvuln-vulnerable-python-apps | python | flask | 22 | 5 |
| realvuln-vulnerable-tornado-app | python | tornado | 14 | 3 |
| realvuln-vulnpy | python | — | 78 | 16 |
| realvuln-vulpy | python | flask | 54 | 6 |

### What Works Today

- **Scoring engine** — F2, precision, recall, per-CWE-family and per-severity breakdowns
- **Finding matching** — file path + CWE + line tolerance (±10 lines)
- **FP traps** — `is_vulnerable: false` entries for measuring false positive rates
- **Real scanner results** — Semgrep, Snyk, SonarQube, Kolega, and 13+ LLM-based scanners (Claude, GPT-4o, Gemini, Grok, Kimi, etc.)
- **LLM benchmark harness** — 3 runner modes: single-turn API, agentic (tools), and Docker sandbox
- **Container isolation** — agentic evaluations run in sandboxed environments with network disabled and repos mounted read-only, preventing data leakage between runs
- **Cost controls** — `--dry-run` for cost estimation, `--max-total-cost` hard limit, per-model pricing tracked in real-time
- **Prompt versioning** — content-hashed prompts (`sha256:...`) stamped into every run's metrics for reproducibility
- **Interactive dashboard** — multi-scanner HTML dashboard with Plotly heatmaps (`dashboard.py`)
- **CLI tools** — `realvuln-score`, `realvuln-dashboard`, `realvuln-validate`, `realvuln-clone`, `realvuln-smoke-test`
- **Multi-run mode** — mean ± stddev scoring for non-deterministic scanners
- **Reproducibility manifest** — `benchmark-manifest.json` locks GT version, prompt version, and all repo commit SHAs

### Not Yet Implemented

- Multi-language support (Python only — JavaScript/TypeScript, Go, and Java are planned)
- Target types beyond Type 1 (no CVE-based, library, or benchmark roll-up targets)

---

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Clone all 26 benchmark repos at pinned commits
python3 clone_repos.py

# Verify your setup
python3 smoke_test.py

# Validate ground truth schemas
python3 validate_gt.py

# Score a single repo against all scanners
python3 score.py --repo realvuln-pygoat --all-scanners

# Generate multi-scanner dashboard
python3 dashboard.py --scanner-group all
```

Run `make help` to see all available commands.

---

## Directory Structure

```
├── config/
│   └── cwe-families.json                        # CWE groupings for per-category metrics
├── ground-truth/{repo}/ground-truth.json        # Labelled vulnerabilities
├── scan-results/{repo}/{scanner}/results.json   # Scanner outputs (Semgrep JSON)
├── parsers/                                     # Normalise scanner output to NormalisedFinding
├── scorer/
│   ├── matcher.py                               # Finding matching (file + CWE + line tolerance)
│   └── metrics.py                               # ScoreCard with F2, precision, recall, breakdowns
├── llm-bench/                                   # LLM security scanner benchmark harness
│   ├── config/                                  #   Model configs, eval defaults
│   ├── harness/                                 #   Runner, prompt builder, validator, metrics
│   ├── prompts/                                 #   System prompt template + output schema
│   ├── scripts/                                 #   run_pilot.py, run_agentic.py, run_eval.py
│   └── docker/                                  #   Sandbox Dockerfile + docker-compose
├── score.py                                     # Score one repo (CLI + JSON + Markdown output)
├── dashboard.py                                 # Multi-scanner multi-repo HTML dashboard (Plotly)
├── validate_gt.py                               # Ground truth schema validator
├── clone_repos.py                               # Clone all benchmark repos at pinned commits
├── smoke_test.py                                # Verify scoring pipeline with known baseline
├── benchmark-manifest.json                      # Reproducibility manifest (GT hash, repo SHAs)
├── Makefile                                     # Common commands (make test, lint, dashboard, etc.)
└── reports/                                     # Generated outputs
    ├── dashboard.html                           # Interactive cross-scanner comparison
    └── dashboard.json                           # Machine-readable scores
```

### Entry Points

| Script | Purpose |
|--------|---------|
| `score.py` | Score one repo against one or all scanners. Outputs CLI table, per-repo JSON + Markdown scorecard. Supports `--runs` for multi-run mean ± stddev. |
| `dashboard.py` | Score all repos × all scanners. Outputs interactive HTML dashboard with heatmaps and Plotly charts. |
| `validate_gt.py` | Schema validation for ground-truth JSON files. |
| `clone_repos.py` | Clone all 26 benchmark repos at their pinned commit SHAs. |
| `smoke_test.py` | Verify the scoring pipeline against known reference values. |

For the LLM benchmark harness, see [`llm-bench/README.md`](llm-bench/README.md).

---

## Ground Truth Schema

Each target repo has a ground truth manifest pinned to a specific commit SHA.

```json
{
  "schema_version": "1.0",
  "repo_id": "juice-shop",
  "repo_url": "https://github.com/juice-shop/juice-shop",
  "commit_sha": "abc123...",
  "type": 1,
  "language": "javascript",
  "framework": "express",
  "authorship": "human_authored",
  "authorship_model": null,
  "authorship_confidence": "high",
  "authorship_evidence": "pre-LLM project, established 2014",
  "findings": [
    {
      "id": "juice-shop-001",
      "is_vulnerable": true,
      "vulnerability_class": "sql_injection",
      "primary_cwe": "CWE-89",
      "acceptable_cwes": ["CWE-89", "CWE-564", "CWE-943"],
      "file": "routes/login.ts",
      "location": { "start_line": 42, "end_line": 48, "function": "loginUser" },
      "severity": "high",
      "evidence": {
        "source": "juice-shop-pwning-guide",
        "cve_id": null,
        "description": "SQL injection via unsanitized email parameter"
      }
    },
    {
      "id": "juice-shop-fp-001",
      "is_vulnerable": false,
      "vulnerability_class": "xss",
      "primary_cwe": "CWE-79",
      "acceptable_cwes": ["CWE-79"],
      "file": "lib/utils.ts",
      "location": { "start_line": 88, "end_line": 90, "function": "sanitizeHtml" },
      "severity": "medium",
      "evidence": {
        "source": "manual_review",
        "description": "Uses DOMPurify — not vulnerable despite suspicious pattern"
      }
    }
  ]
}
```

Key design decisions:

- **`is_vulnerable: false` entries** are false-positive traps — code that looks suspicious but is safe. Critical for measuring FP rates.
- **`acceptable_cwes`** handles CWE ambiguity. Missing auth could be CWE-306, CWE-862, CWE-287, or CWE-284. Any acceptable CWE on the correct file earns credit.
- **Pinned commit SHAs** prevent ground truth drift as repos get patched.
- A **global CWE family mapping** (`config/cwe-families.json`) groups related CWEs so scoring handles scanner-specific CWE choices gracefully.

### Quality Gates

Every ground truth submission requires: evidence source (CVE ID, walkthrough URL, or manual review with reviewer identity), at least one `is_vulnerable: false` entry per five `true` entries, and a verified-cloneable pinned commit.

---

## Matching & Scoring

### Finding Matching

Scanner findings are matched against ground truth using a single fixed matching mode: **file + CWE + line tolerance**. A scanner finding matches a ground truth entry when all three criteria are met:

1. **File path** — normalised paths must match exactly
2. **CWE** — the scanner's CWE must appear in the GT entry's `acceptable_cwes` list
3. **Line proximity** — the scanner's reported line must fall within `[start_line - 10, end_line + 10]` (or `±10` of `start_line` if no `end_line`). If either side lacks line information, the check is skipped (no penalty).

When multiple GT entries match a single finding, `is_vulnerable: true` entries are preferred so the scanner gets credit for real vulnerabilities rather than being penalised by a co-located FP trap.

Each GT entry can only be matched once. Once a GT entry is claimed by a finding, subsequent findings cannot match it — additional unmatched findings are scored as FP.

### Finding Classification

| Category | Definition |
|----------|------------|
| **True Positive (TP)** | Matches an `is_vulnerable: true` ground truth entry |
| **False Positive (FP)** | Matches an `is_vulnerable: false` ground truth entry, or flagged something with no ground truth entry |
| **False Negative (FN)** | `is_vulnerable: true` entry the scanner missed |
| **True Negative (TN)** | `is_vulnerable: false` entry the scanner correctly ignored |

Unmatched scanner findings (no ground truth entry) are scored as false positives. If a scanner flags something that isn't in ground truth, the burden is on the scanner to be right — not on the benchmark to assume it might be.

### Metrics

**Primary metric: F2 Score** (0–100 scale). F-beta with beta=2 weights recall 4x more than precision — missing a real vulnerability is far worse than a false alarm.

Full metrics computed per scorer run:

| Metric | Formula |
|--------|---------|
| Precision | TP / (TP + FP) |
| Recall (= TPR) | TP / (TP + FN) |
| F1 | 2 × (Prec × Recall) / (Prec + Recall) |
| F2 | 5 × (Prec × Recall) / (4 × Prec + Recall) |
| F2 Score | F2 × 100 |
| FPR | FP / (FP + TN) |

Breakdowns: **per-CWE-family** (TP/FP/FN/precision/recall) and **per-severity** (TP/FP/FN/recall), both derived from ground truth entry metadata.

For non-deterministic scanners (e.g. AI agents), the scorer supports **multi-run mode** (`--runs`): each result file is scored independently, and mean ± stddev are reported for all metrics.

---

## Scanner Integration

```
Scanner Output (native format)
  ↓
Parser (per-scanner)          ← What contributors add
  ↓
Normalised Finding Format     ← Uniform internal representation
  ↓
Scoring Engine                ← Unchanged regardless of scanner
  ↓
Scorecard (JSON + HTML)
```

### Adding a New Scanner

1. Place results in `scan-results/{repo}/{scanner-slug}/results.json` (Semgrep JSON format)
2. Run `python score.py --repo {repo} --scanner {scanner-slug}`

Any scanner producing Semgrep-compatible JSON works automatically — unknown scanner slugs fall back to `SemgrepParser`. For non-Semgrep formats, add a parser class in `parsers/` and register it in `PARSER_REGISTRY` (`parsers/__init__.py`).

### Adding a New Repo

1. Create `ground-truth/{repo}/ground-truth.json` following the schema above
2. Run `python validate_gt.py {repo}` to verify
3. Add scan results to `scan-results/{repo}/{scanner}/results.json`

---

## Roadmap

The following describes planned capabilities that are not yet implemented.

### Additional Target Types

Targets will be classified on two independent axes.

**Axis 1: Code Realism (Type)** — Currently only Type 1 exists.

| Type | Description | Examples | Ground Truth Source |
|------|-------------|----------|---------------------|
| **1 — Intentionally Vulnerable Apps** | Deliberately insecure apps with documented vulns (current) | DVWA, Juice Shop, WebGoat | Published walkthroughs, solution guides, manual expert review |
| **2 — Previously-Vulnerable Platforms** | Production apps pinned to pre-patch commits with disclosed CVEs | WordPress plugins, GitLab, Django | NVD/CVE → fix commit diff → file + CWE extraction → expert verification |
| **3 — Previously-Vulnerable Libraries** | Libraries pinned to vulnerable versions | Known-vulnerable npm/PyPI packages | Same CVE/NVD approach as Type 2 |
| **4 — Benchmark Roll-ups** | Existing benchmarks integrated as unified, scoreable targets | OWASP Benchmark, NIST Juliet | Direct import or adapter mapping |
| **5 — Academic Reproduction** | Published scanner evaluations encoded as reproducible configs | Cycode/Bearer (2023), DryRun (2025) | Methodology extracted from papers, encoded as config |

**Axis 2: Code Authorship** — Currently all targets are `human_authored`.

| Value | Definition |
|-------|------------|
| `human_authored` | Pre-LLM era or confirmed no LLM use |
| `llm_assisted` | Written by humans with LLM help |
| `llm_generated` | Primarily or entirely LLM-generated |
| `unknown` | Post-2023, no authorship disclosure |

These axes are orthogonal. LLM-generated does not mean synthetic.

### Reproducibility

_"Run version X against commit Y and you should get statistically similar results."_

**Implemented:**
- `benchmark-manifest.json` locks ground-truth content hash, prompt version, and all repo commit SHAs
- Content-hashed prompts (`sha256:...`) stamped into every `.metrics.json` file
- Multi-run mode: run N times per target, report mean ± stddev for all metrics
- All raw outputs from all runs are published in `scan-results/`

**Planned:**
- Scanner version strings (semver) stamped into every result file
- Exact commands used to run each scanner logged alongside results

### Research Question: Scanner Performance vs Code Authorship

**Hypothesis:** LLM-based scanners may perform disproportionately well on LLM-generated code compared to human-authored code.

**Method:** Run every scanner against matched pairs — same vulnerability class, same Type, `human_authored` vs `llm_generated`. Compare performance deltas across scanners.

**If confirmed:** _"If your codebase is primarily LLM-generated, AI-native scanners provide measurably better detection. If legacy human-written code, traditional SAST still holds up."_

This would be a publishable contribution independent of who wins the benchmark. No existing benchmark tracks authorship, and as codebases shift toward LLM-generated code, the industry needs data on whether scanner performance generalises.

### Other Planned Work

- Multi-language support (JavaScript/TypeScript, Go, Java)
- Additional scanner integrations (Bandit, CodeQL, AI-native scanners)

---

## Attribution

This benchmark uses intentionally-vulnerable applications created by the open-source security community. We are grateful to the original authors:

| Repository | Original Source |
|------------|----------------|
| Damn Vulnerable Flask Application | [akamai-threat-research](https://github.com/akamai-threat-research/Damn-Vulnerable-Flask-Application) |
| Damn Vulnerable GraphQL Application | [dolevf](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) |
| DjanGoat | [Contrast-Security-OSS](https://github.com/Contrast-Security-OSS/DjanGoat) |
| DSVPWA | [sgabe](https://github.com/sgabe/DSVPWA) |
| DSVW | [stamparm](https://github.com/stamparm/DSVW) |
| DVBLab | [mamgad](https://github.com/mamgad/DVBLab) |
| dvpwa | [anxolerd](https://github.com/anxolerd/dvpwa) |
| Extremely Vulnerable Flask App | [manuelz120](https://github.com/manuelz120/extremely-vulnerable-flask-app) |
| Flask_XSS | [terrabitz](https://github.com/terrabitz/Flask_XSS) |
| insecure-web | [brenesrm](https://github.com/brenesrm/insecure-web) |
| lets-be-bad-guys | [mpirnat](https://github.com/mpirnat/lets-be-bad-guys) |
| OWASP Web Playground | [kolega-ai-dev](https://github.com/kolega-ai-dev/realvuln-OWASP-Web-Playground) |
| pygoat | [adeyosemanputra](https://github.com/adeyosemanputra/pygoat) |
| owasp-bay-area | [RiieCco](https://github.com/RiieCco/owasp-bay-area) |
| PythonSSTI | [TheWation](https://github.com/TheWation/PythonSSTI) |
| ThreatByte | [anotherik](https://github.com/anotherik/ThreatByte) |
| VAmPI | [erev0s](https://github.com/erev0s/VAmPI) |
| vfapi | [naryal2580](https://github.com/naryal2580/vfapi) |
| Vulnerable-Flask-App | [we45](https://github.com/we45/Vulnerable-Flask-App) |
| vulnpy | [Contrast-Security-OSS](https://github.com/Contrast-Security-OSS/vulnpy) |
| vulpy | [fportantier](https://github.com/fportantier/vulpy) |

Some repositories are forked under the [kolega-ai](https://github.com/kolega-ai) org to ensure pinned commits remain available. All original licenses are preserved.
