# RealVuln Benchmark

**[Live Dashboard →](https://realvuln.com/dashboard.html)**

An open benchmark for evaluating security scanners against ground-truth vulnerabilities in real-world code. Primary metric is **F3 Score** (0–100, recall-weighted 9:1).

## Problem & Purpose

Application security scanners routinely fail to catch basic vulnerabilities — missing authentication, broken access control, IDOR — in real-world code. No credible, open benchmark exists to measure this:

- **OWASP Benchmark** uses synthetic single-file test cases. Scanners can be tuned to ace it without improving real-world detection.
- **Vendor self-benchmarks** (DryRun, ZeroPath, Cycode/Bearer) use small samples, vendor-controlled methodology, and no reusable infrastructure.
- **Academic benchmarks** (NIST Juliet, NIST SARD, CVEFixes, VulBench) lack scoring tooling, have inconsistent labelling, or target ML evaluation rather than scanner comparison.
- **Academic papers** produce one-off results locked in PDFs that nobody reproduces.

**RealVuln** is an open, extensible benchmark that uses real-world code, provides machine-readable ground truth with CWE mappings, includes an automated scoring engine, and is designed for community contribution. We launch as **RealVuln Beta** — publishing the framework, initial ground truth, and our results as an invitation for the security community to contribute, validate, and extend.

Full story: [Why We Built Our Own Security Benchmark](https://kolega.ai/blog/why-we-built-our-own-security-benchmark)

---

## Current State

### Dataset

**Benchmark version: `3.0.0`**

**140 repos · 66 Python + 74 TypeScript/JavaScript · 4,138 vulnerabilities · 280 FP traps · 176 non-scoring entries**

All targets are **Type 1 (intentionally vulnerable apps)**. RealVuln 3.0.0 adds
a TypeScript/JavaScript corpus (24 community apps + 50 LLM-generated apps) to
the Python benchmark set, and introduces **non-scoring** ground-truth entries:
reviewed locations whose status is too discretionary to grade, excluded from
every metric in both directions. Scores against 2.x and 3.x are not directly
comparable because the official repo set changed; the Python subset is
unchanged, so per-language Python scores remain comparable.

> **Language coverage:** Python (Flask, Django, FastAPI, aiohttp, Tornado) and
> TypeScript/JavaScript (Express, Next.js, NestJS + Angular, Remix, Fastify + Vue,
> React, Koa). Java is the next planned language. The leaderboard shows an
> overall score plus one tab per language; scanners that only cover one language
> are flagged as *language-limited* on the overall tab.

| Corpus | Repos | Vulns | FP Traps | Non-scoring | Authorship |
|---|---:|---:|---:|---:|---|
| Python — community intentionally vulnerable apps | 26 | 703 | 121 | 0 | `human_authored` |
| Python — LLM-generated seeded apps | 40 | 1,199 | 159 | 0 | `llm_generated` |
| TS/JS — community intentionally vulnerable apps | 24 | 535 | 0 | 114 | mixed (see GT) |
| TS/JS — LLM-generated seeded apps | 50 | 1,701 | 0 | 62 | `llm_generated` |
| **Total** | **140** | **4,138** | **280** | **176** |  |

The TS/JS corpus ships without false-positive traps in this release; trap
labelling for TS/JS is on the roadmap.

#### LLM-Generated Seeded Corpus

Company-style applications generated end-to-end by coding agents, then seeded
with reviewed ground-truth vulnerabilities. Each generated repo is a pinned,
single-snapshot public repository under `kolega-ai-dev`, recorded by commit SHA
in `benchmark-manifest.json`.

| Language | Authorship Model | Repos | Vulns | FP Traps | Non-scoring |
|---|---|---:|---:|---:|---:|
| Python | Claude Opus 4.7 | 10 | 308 | 40 | 0 |
| Python | GPT-5.5 | 10 | 339 | 39 | 0 |
| Python | GPT-5.5 x-high | 10 | 263 | 40 | 0 |
| Python | Kimi K2.6 | 10 | 289 | 40 | 0 |
| TS/JS | Claude Opus 4.7 | 10 | 399 | 0 | 0 |
| TS/JS | GPT-5.5 x-high | 10 | 421 | 0 | 5 |
| TS/JS | Kimi K2.6 | 10 | 392 | 0 | 34 |
| TS/JS | DeepSeek V4 Pro | 10 | 255 | 0 | 0 |
| TS/JS | DeepSeek V4 Flash | 10 | 234 | 0 | 23 |
| **Total** |  | **90** | **2,900** | **159** | **62** |

#### Community Corpus — Python

| Repo | Language | Framework | Vulns | FP Traps |
|------|----------|-----------|------:|--------:|
| realvuln-damn-vulnerable-flask-application | python | flask | 15 | 4 |
| realvuln-damn-vulnerable-graphql-application | python | flask | 36 | 4 |
| realvuln-djangoat | python | django | 52 | 6 |
| realvuln-dsvpwa | python | — | 32 | 6 |
| realvuln-dsvw | python | — | 27 | 4 |
| realvuln-dvblab | python | flask | 22 | 4 |
| realvuln-dvpwa | python | aiohttp | 23 | 4 |
| realvuln-extremely-vulnerable-flask-app | python | flask | 32 | 4 |
| realvuln-flask-xss | python | flask | 30 | 5 |
| realvuln-insecure-web | python | flask | 9 | 2 |
| realvuln-intentionally-vulnerable-python-application | python | flask | 7 | 2 |
| realvuln-lets-be-bad-guys | python | django | 24 | 4 |
| realvuln-owasp-web-playground | python | flask | 28 | 6 |
| realvuln-pygoat | python | django | 78 | 10 |
| realvuln-python-app | python | flask | 21 | 4 |
| realvuln-python-insecure-app | python | fastapi | 8 | 2 |
| realvuln-pythonssti | python | fastapi | 2 | 1 |
| realvuln-threatbyte | python | flask | 26 | 5 |
| realvuln-vampi | python | flask | 15 | 4 |
| realvuln-vfapi | python | fastapi | 9 | 2 |
| realvuln-vulnerable-api | python | flask | 14 | 3 |
| realvuln-vulnerable-flask-app | python | flask | 21 | 4 |
| realvuln-vulnerable-python-apps | python | flask | 22 | 5 |
| realvuln-vulnerable-tornado-app | python | tornado | 14 | 3 |
| realvuln-vulnpy | python | — | 80 | 16 |
| realvuln-vulpy | python | flask | 57 | 6 |

#### Community Corpus — TypeScript/JavaScript

| Repo | Language | Framework | Vulns | Non-scoring |
|------|----------|-----------|------:|------------:|
| realvuln-dvna | javascript | express | 17 | 0 |
| realvuln-dvws-node | javascript | express | 77 | 0 |
| realvuln-ivna | javascript | express | 19 | 0 |
| realvuln-juice-shop | typescript | express | 81 | 64 |
| realvuln-juice-shop-goof | typescript | express | 51 | 37 |
| realvuln-nextjs-vulnerable-app | javascript | nextjs | 1 | 0 |
| realvuln-ninjasworkout | javascript | express | 22 | 0 |
| realvuln-node-api-goat | javascript | express | 7 | 0 |
| realvuln-nodegoat | javascript | express | 28 | 0 |
| realvuln-nodejs-goof | javascript | express | 17 | 0 |
| realvuln-oss-oopssec-store | typescript | nextjs | 40 | 6 |
| realvuln-react-security | javascript | react | 7 | 0 |
| realvuln-react-test-bench | javascript | react | 1 | 0 |
| realvuln-reactvulna | javascript | react | 1 | 0 |
| realvuln-simply-vulnerable-react | javascript | react | 1 | 0 |
| realvuln-vuln-node-express | javascript | express | 5 | 4 |
| realvuln-vuln-node-express-swagger | javascript | express | 49 | 3 |
| realvuln-vulnerable-app-angular | javascript | express | 8 | 0 |
| realvuln-vulnerable-node | javascript | express | 21 | 0 |
| realvuln-vulnerable-nodejs | javascript | express | 19 | 0 |
| realvuln-vulnerable-react-fatih | javascript | react | 7 | 0 |
| realvuln-vulnerable-rest-api-owasp-2023 | javascript | express | 15 | 0 |
| realvuln-vulnnodeapp | javascript | express | 29 | 0 |
| realvuln-xvna | javascript | express | 12 | 0 |

> `realvuln-xvna` ships its source as `xvna.zip`; ground-truth paths are
> relative to the extracted `xvna/` directory (see `source_layout` in its
> ground-truth.json). Extract the archive before scanning.

The full official repo list, pinned commit SHAs, authorship metadata, and GT
content hash are in `benchmark-manifest.json`.

### What Works Today

- **Scoring engine** — F2, precision, recall, per-CWE-family and per-severity breakdowns
- **Finding matching** — file path + CWE + line tolerance (±10 lines)
- **FP traps** — `is_vulnerable: false` entries for measuring false positive rates
- **Non-scoring entries** — `scoring: "non_scoring"` rows excluded from every metric in both directions (`ns` column in every score)
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

- Java, Go and other languages (Python and TypeScript/JavaScript are covered today)
- False-positive traps for the TypeScript/JavaScript corpus
- Target types beyond Type 1 (no CVE-based, library, or benchmark roll-up targets)

---

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Clone all 140 benchmark repos at pinned commits
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
| `clone_repos.py` | Clone all 140 benchmark repos at their pinned commit SHAs. |
| `smoke_test.py` | Verify the scoring pipeline against known reference values. |

For the LLM benchmark harness, see [`llm-bench/README.md`](llm-bench/README.md).

---

## Ground Truth Schema

Each target repo has a ground truth manifest pinned to a specific commit SHA.

```json
{
  "schema_version": "1.0",
  "benchmark_version": "2.0.0",
  "ground_truth_version": "2.0.0",
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

- **`benchmark_version` and `ground_truth_version`** make each GT file self-identifying. RealVuln v2.0.0 scores should not be compared directly with v1.x scores.
- **`is_vulnerable: false` entries** are false-positive traps — code that looks suspicious but is safe. Critical for measuring FP rates.
- **`scoring: "non_scoring"` entries** (optional field; default `"scored"`) are reviewed locations whose status cannot be settled from the source alone. Each carries a `non_scoring_reason`. See [Non-scoring entries](#non-scoring-entries).
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
| **Non-Scoring (NS)** | A `scoring: "non_scoring"` entry, or a finding that landed on one. Excluded from every metric |

Unmatched scanner findings (no ground truth entry) are scored as false positives. If a scanner flags something that isn't in ground truth, the burden is on the scanner to be right — not on the benchmark to assume it might be.

### Non-scoring entries

Some reviewed locations are **highly discretionary**: whether they are a vulnerability depends on intent or deployment context that the source alone does not settle — for example an unauthenticated endpoint that the code itself documents as deliberately public, or one instance of a pattern that ground truth already credits through a whole-file entry. Labelling such a location vulnerable would penalise scanners for our uncertainty; labelling it safe would reward them for it. Neither is defensible, so the entry is kept in ground truth and marked `scoring: "non_scoring"` with a `non_scoring_reason` explaining why.

Non-scoring entries are excluded from scoring **in both directions**:

- **Reporting one is not a false positive.** A finding that matched no scored entry but lands inside a non-scoring entry's file and line range (±10) is withheld from the FP count. This check is on location only — the CWE the scanner chose is irrelevant, because it is the location's status that is unsettled. Any number of findings may be withheld by the same entry.
- **Missing one is not a false negative.** Non-scoring entries never appear in the FN or TN counts.

Non-scoring entries take **no part in matching**. Scored entries are matched first, so a non-scoring entry can never claim a finding away from a co-located vulnerable entry and turn a TP into a FN. Only findings left over after scored matching are checked against non-scoring entries.

The scorer reports the number of withheld findings (`ns`) and non-scoring entries (`ns_gt`) alongside the confusion matrix so the exclusion is visible, and the markdown scorecard lists each with its `non_scoring_reason` so every exclusion can be audited individually. Published dataset totals (vulnerabilities, traps) never include non-scoring entries.

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

---

## Companion Datasets

Ground truth, target metadata and raw scanner output are mirrored to HuggingFace,
generated from this repo by `export_hf_dataset.py` so they cannot drift from it.
Only scanners published on the public dashboard are included.

| Dataset | Corpus | Findings | Licence |
|---|---|---|---|
| [Kolega-Dev/RealVuln-v2](https://huggingface.co/datasets/Kolega-Dev/RealVuln-v2) | 66 targets | 2,182 | Apache-2.0 |
| [Kolega-Dev/RealVuln](https://huggingface.co/datasets/Kolega-Dev/RealVuln) | 26 targets (v1, the paper's corpus) | 796 | MIT |

`main` tracks the latest release of that major version; every release is also a
git tag, so a citation can pin an exact corpus:

```python
load_dataset("Kolega-Dev/RealVuln-v2", "findings", revision="v2.0.0")
load_dataset("Kolega-Dev/RealVuln",    "findings", revision="v1.0.0")  # paper
```

Scores are not comparable across major versions, because the official target set
changes. v1 stays under the MIT terms it was published with; v2 onward follows
this repository's Apache-2.0 licence.

## Further Reading

- Blog post: [Why We Built Our Own Security Benchmark](https://kolega.ai/blog/why-we-built-our-own-security-benchmark)
