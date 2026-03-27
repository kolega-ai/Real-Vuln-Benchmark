# RealVuln Paper — Design Spec

**Title:** RealVuln: An Open Benchmark for Evaluating Security Scanners on Real-World Code

**Target:** arXiv preprint (priority claim), then iterate toward venue submission

**Approach:** Living benchmark (hybrid) — benchmark contribution + LLM vs SAST comparison + open-source release

**Audience:** Security practitioners evaluating scanners; researchers building on the dataset

**Author affiliation:** Kolega (vendor of one evaluated scanner — disclosed, mitigated by full open-source release)

---

## Abstract (outline)

RealVuln is the first fully open-source benchmark for evaluating security scanners on real-world code. [Problem: SAST tools noisy, LLM scanners emerging, no open benchmark to compare them.] [Contribution: 26 repos, 796 hand-labeled findings including 120 FP traps, F2-weighted scoring, 15 scanners evaluated.] [Key findings: headline result from data — TBD.] [Release: all code, data, results, and tooling published at GitHub URL.] [Living benchmark: versioned, community-driven, roadmap to multi-language and production CVE targets.]

---

## Paper Structure

### 1. Introduction

**Opening hook — the false positive problem:**
- Ghost Security CAST: 99.5% FP rate for command injection in Python/Flask, 91% noise across 2,166 findings
- Fluid Attacks: best automated tool found only 22.7% of vulns, average F2 of 1.9%
- SATE V/VI: 70-92% false positives depending on language

**The gap:** LLM-powered scanners promise semantic understanding over pattern matching, but no open benchmark exists to verify these claims. Existing benchmarks fail on one or more of:
1. Using real-world code (not synthetic Juliet/OWASP templates)
2. Explicitly measuring false positive rates (not just detection)
3. Comparing LLM and traditional scanners on equal footing
4. Publishing all artifacts for reproducibility

**What exists and why it falls short (brief, expanded in Section 2):**
- OWASP Benchmark: synthetic Java test cases
- SastBench: closest to our work, but dataset not released, focused on triage agents not scanners
- Vendor benchmarks (ZeroPath, Cycode, DryRun): not reproducible, self-serving

**Three contributions:**
1. **RealVuln**, the first fully open-source SAST benchmark: 26 real-world Python repos, 796 hand-labeled findings (including 120 FP traps), F2-weighted scoring
2. **The first large-scale comparison** of 15 scanners (3 traditional SAST + 11 LLM-based + 1 proprietary) on identical ground truth
3. **A living benchmark** with versioned scoring, a public dashboard, and a clear path for community contribution

**Close:** "We release all code, data, results, and tooling at [GitHub URL]."

---

### 2. Background & Related Work

**Comparison table** (key differentiator — shows RealVuln fills the intersection):

| Benchmark | Real Code | Open Data | Open Scoring | FP Testing | Multi-Scanner | LLM Scanners | Multi-Language |
|-----------|-----------|-----------|-------------|------------|--------------|-------------|---------------|
| OWASP Benchmark | No | Yes | Yes | Yes (Youden's J) | Yes | No | Java only |
| Juliet Test Suite | No | Yes | No | No | No | No | C/C++, Java |
| SastBench | Yes | **No** | No | Yes (SAST proxy) | No | No (triage only) | Yes |
| ZeroPath/XBOW | No (toy apps) | Partial | No | Yes (patched variants) | Yes | Yes | Python, PHP |
| Fluid Attacks | Yes (1 NodeJS app) | No | No | Yes | Yes (36 tools) | No | JS/TS only |
| CASTLE | No (micro) | Yes | Yes | No | Yes (13+10) | Yes | Multi |
| Cycode/DryRun | Yes | No | No | No | Yes | No | Multi |
| **RealVuln** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes (15)** | **Yes (11)** | Python (v1) |

**Narrative categories:**
- **Synthetic benchmarks** (OWASP, Juliet): don't reflect real code complexity, easy for pattern-matchers
- **Unreleased datasets** (SastBench): great methodology but can't be verified or built upon
- **Vendor benchmarks** (ZeroPath, Fluid Attacks, Cycode): useful data points but not reproducible, inherent conflicts of interest
- **Dataset quality research** (PrimeVul, CleanVul): shows existing vuln datasets have massive label noise — motivates hand-labeled ground truth
- **Agentic benchmarks** (SWE-Bench, CVE-Bench): design influence on our evaluation harness

**Honest self-critique:** Python-only (v1), Type 1 only (intentionally vulnerable), and we are a vendor — mitigated by open-sourcing everything.

---

### 3. Benchmark Design

#### 3.1 Target Type Taxonomy

RealVuln defines five target types for benchmark repos:
- **Type 1**: Intentionally vulnerable applications (e.g., PyGoat, DVPWA) — current scope
- **Type 2**: Previously-vulnerable production applications with CVE-linked commits — planned
- **Type 3**: Previously-vulnerable libraries — planned
- **Type 4**: Benchmark roll-ups (OWASP, Juliet re-scored with RealVuln metrics) — planned
- **Type 5**: Academic reproduction studies — planned

v1.0 covers Type 1 only. This taxonomy is defined here so the roadmap (Section 7) references are clear.

#### 3.2 Dataset Construction

- **26 intentionally-vulnerable Python repos (Type 1)** spanning Flask, Django, FastAPI, aiohttp, Tornado
- **796 hand-labeled findings**: 676 real vulnerabilities + 120 FP traps (`is_vulnerable: false`)
- All repos pinned to specific commit SHAs via `benchmark-manifest.json`
- **Selection criteria**: real GitHub projects with meaningful code structure (not single-file toys), diverse CWE families, multiple frameworks
- **Authorship metadata**: all `human_authored`, pre-LLM era — relevant for data contamination discussion
- **Ground truth schema**: `primary_cwe`, `acceptable_cwes` (CWE ambiguity tolerance), `location` with start/end lines, `severity`, `evidence` with source tracing (manual_review, cve_id, walkthrough)
- **FP traps explained with example**: code that looks suspicious but is safe (e.g., parameterized query flagged as SQLi). Scanner flags it = false positive, counted against them.

#### 3.3 Matching Algorithm

- **Three-field matching**: file path (exact) + CWE (must appear in `acceptable_cwes`) + line (±10 tolerance from `start_line`/`end_line`)
- **Why acceptable_cwes**: same vulnerability can reasonably be classified as different CWEs (e.g., missing auth = CWE-306, CWE-862, CWE-287). No penalty for reasonable disagreement.
- **Why ±10 lines**: scanners may point to sink, source, or call site — all valid
- **Preference ordering**: when a finding matches both a real vuln and an FP trap, prefer the real vuln (benefit of the doubt)
- **One-to-one matching**: each GT entry consumed at most once

#### 3.4 Scoring

- **Primary metric: F2 score (0-100)** — beta=2 weights recall 4x over precision. Missing a real vulnerability is worse than a false alarm. Same rationale as SastBench and Fluid Attacks.
- **Additional metrics**: Precision, Recall, F1, TPR, FPR, Youden's J
- **Per-CWE-family breakdown**: 18 families (SQL injection, XSS, command injection, etc.) via `cwe-families.json`
- **Per-severity breakdown**: critical/high/medium/low
- **Multi-run support**: non-deterministic scanners (LLMs) scored across multiple runs, report mean +/- stddev. Aggregation: each run scored independently per-repo, then micro-averaged across repos.
- **Scoring modes**: `micro` (standard micro-average across all repos with results) and `strict_micro` (treats repos with no results — due to timeouts or validation failures — as all-FN). Paper reports both; `strict_micro` is the conservative primary metric.
- **Incomplete runs**: LLM scanners may timeout or produce invalid output. Timeout/failure rates reported per scanner. Repos with no valid output score 0 recall under `strict_micro`.
- **Reproducibility**: `benchmark-manifest.json` locks ground truth content hash, repo commit SHAs, prompt versions (content-hashed)

---

### 4. Experimental Setup

#### 4.1 Scanners Evaluated

**Traditional SAST (3):**
- Semgrep (open-source, rule-based) — `semgrep --config auto`, default rules
- Snyk (commercial, pattern + dataflow) — `snyk code test`
- SonarQube (community edition) — default Python profile

**LLM-based (11):**
- Claude family: Haiku 4.5 (single-turn + agentic), Sonnet 4.6 (agentic), Opus 4.6 (agentic)
- Gemini 3.1 Pro (agentic)
- Grok 3 (agentic), Grok 4.20 Reasoning (agentic)
- Kimi K2.5 (agentic)
- GLM-5 (agentic)
- Minimax M2.7 (agentic)
- Qwen 3.5 397B (agentic)

**Kolega v0.0.1** — LLM-augmented hybrid scanner (results published, internals proprietary)

All scanners run on identical pinned commits.

#### 4.1.1 Scanner Classification

| Scanner | Category | Mode | Open Source |
|---------|----------|------|-------------|
| Semgrep | Traditional SAST | Rule-based | Yes |
| Snyk | Traditional SAST | Pattern + dataflow | No (free tier) |
| SonarQube | Traditional SAST | Pattern-based | Yes (community) |
| Claude Haiku 4.5 | LLM | Single-turn + Agentic | No |
| Claude Sonnet 4.6 | LLM | Agentic | No |
| Claude Opus 4.6 | LLM | Agentic | No |
| Gemini 3.1 Pro | LLM | Agentic | No |
| Grok 3 | LLM | Agentic | No |
| Grok 4.20 Reasoning | LLM | Agentic | No |
| Kimi K2.5 | LLM | Agentic | No |
| GLM-5 | LLM | Agentic | No |
| Minimax M2.7 | LLM | Agentic | No |
| Qwen 3.5 397B | LLM | Agentic | No |
| Kolega v0.0.1 | Hybrid (LLM-augmented) | Proprietary | No |

#### 4.2 LLM Evaluation Modes

- **Single-turn (pilot)**: entire repo context in one API call — cheapest, baseline
- **Agentic**: LLM has tools (file read, grep, bash) and iterates via tool loop — more realistic, more expensive
- Prompt template and output schema described (JSON with CWE, file, line, severity)
- Cost tracking: per-model token pricing (pricing date specified), total cost per repo
- **Prompt sensitivity**: all LLM scanners share a single prompt template (content-hashed). Paper discusses whether results are sensitive to prompt design and notes that per-model prompt tuning was intentionally avoided to ensure fair comparison. The shared prompt is published for reproducibility.

#### 4.3 Reproducibility

- All scan results committed to the repo
- `benchmark-manifest.json` for version locking
- Anyone can re-run scoring: `python score.py --repo X --all-scanners`
- Dashboard regenerated: `python dashboard.py --scanner-group all`

---

### 5. Results

#### 5.1 Aggregate Rankings
- Full leaderboard table: all 15 scanners ranked by F2 score, with TP/FP/FN/TN, precision, recall, F1, F2
- Actual numbers pulled from `dashboard.json`
- Headline: which scanner wins overall, gap between best LLM and best traditional SAST

#### 5.2 The 26x15 Heatmap
- Full grid visualization — F2 score per repo per scanner
- Cells where scanner timed out or produced invalid output are marked distinctly (grayed out / hatched) — not treated as zero
- Patterns: which repos are easy/hard for everyone, which repos separate LLMs from SAST
- Variance: some scanners consistent, others spiky
- Completion rate per scanner shown alongside (percentage of repos with valid results)

#### 5.3 Per-CWE-Family Analysis
- Table: recall per CWE family per scanner type (LLM avg vs SAST avg)
- Expected: SAST excels at pattern-matchable vulns (SQLi, XSS, hardcoded creds), LLMs may do better on semantic vulns (broken access control, SSRF, business logic)
- Which families does everyone fail on? Which are solved?

#### 5.4 Cost-Efficiency Analysis (LLM-specific)
- Scatter plot: F2 score vs cost per repo
- Single-turn vs agentic: does the extra cost of tool use pay off?
- Best F2-per-dollar model

#### 5.5 FP Trap Effectiveness
- How many of the 120 FP traps did each scanner fall for?
- Traditional SAST vs LLM FP rates
- Validates the benchmark design: traps differentiate scanners

---

### 6. Analysis & Discussion

#### 6.1 Key Findings
- Where LLMs beat traditional SAST and vice versa — implications for practitioners
- Agentic vs single-turn: is the extra cost worth it?
- Model scaling: do bigger/more expensive models reliably score higher?
- Agreement analysis: when multiple scanners agree, how reliable is the signal?

#### 6.2 Limitations
- **Python only (v1)**: results may not generalize to other languages — planned for v2
- **Type 1 repos only**: intentionally vulnerable apps have higher vulnerability density than production code
- **Vendor conflict**: Kolega is evaluated. Mitigated by open-sourcing everything.
- **Ground truth subjectivity**: hand-labeling is inherently subjective. Evidence published, community challenges invited.
- **LLM non-determinism**: single runs may not capture true performance. Multi-run stats where available but not for every model due to cost.
- **Scanner configuration**: default/recommended settings. Tuned configurations could perform differently.
- **Timeouts and failures**: some LLM scanners had significant timeout/validation failure rates (e.g., Opus 4.6: ~36%, Minimax: ~31%). This affects their effective coverage and is reflected in `strict_micro` scores.

#### 6.3 Threats to Validity
- **Data contamination**: repos are public, LLMs may have seen them in training. Mitigated by FP traps (memorization doesn't help avoid them) and planned post-cutoff repos in v2.
- **Selection bias**: 26 repos is substantial but not exhaustive. Roadmap addresses this.

---

### 7. The Living Benchmark

#### 7.1 Versioning Strategy
- Benchmark versions tied to manifest: ground truth content hash + repo commit SHAs + prompt versions
- Scores always reported against a specific version — old results remain valid
- Dashboard shows current version with historical comparison

#### 7.2 Roadmap
- **Multi-language**: JavaScript/TypeScript, Go, Java repos
- **Type 2 targets**: previously-vulnerable production apps with CVE-linked commits
- **Type 3 targets**: previously-vulnerable libraries
- **Type 4 roll-ups**: incorporate OWASP Benchmark and Juliet as sub-benchmarks
- **More scanners**: community-submitted results
- **Agentic evaluation sandbox**: expand OpenHands Docker harness

#### 7.3 Community Contribution
- **Adding a repo**: create ground truth JSON, run `validate_gt.py`, submit PR
- **Adding a scanner**: drop Semgrep-format results in `scan-results/{repo}/{scanner}/`, or write a parser
- **Challenging ground truth**: open an issue, provide evidence, review and update
- **Leaderboard**: live dashboard at GitHub Pages, updated on merge

---

### 8. Conclusion

Three paragraphs:
1. **What we did**: first fully open-source SAST benchmark on real-world code — 26 repos, 796 findings, 120 FP traps, 15 scanners
2. **What we found**: [headline result from data — filled in when paper is written from actual numbers]
3. **What comes next**: living benchmark, community contributions, v2 multi-language + production CVE targets

Final line: GitHub URL + dashboard URL.

---

### 9. Ethics Statement

Brief paragraph covering:
- All evaluated repos are **intentionally vulnerable** applications designed for security education — no responsible disclosure concerns
- No zero-day or novel vulnerability information is published
- Scanner weaknesses are published to advance the field, not to enable attacks
- We disclose our vendor relationship (Kolega) transparently

---

### 10. Data Availability

Structured artifact checklist:
- **Benchmark code**: GitHub (MIT license) — scoring pipeline, parsers, dashboard generator
- **Ground truth**: GitHub — 26 repos × hand-labeled JSON
- **Scan results**: GitHub — all 15 scanners' raw output
- **LLM evaluation harness**: GitHub — prompts, runners, cost tracker
- **Live dashboard**: GitHub Pages — interactive results explorer
- **Benchmark manifest**: GitHub — version-locked reproducibility file
- **Paper**: arXiv — preprint with supplementary reference to all above

---

## Open-Source Release Plan

### Published (everything)
- Ground truth JSONs (all 26 repos)
- Scan results (all 15 scanners including Kolega v0.0.1)
- Scoring pipeline (score.py, dashboard.py, validate_gt.py)
- Parsers and matcher code
- LLM evaluation harness (llm-bench/) — prompts, runners, cost tracking
- Dashboard (HTML + JSON)
- Benchmark manifest
- CWE family mappings

### Not published
- Kolega scanner methodology/internals (proprietary)

### Artifacts
- **GitHub repo**: primary artifact, linked from paper
- **Live dashboard**: GitHub Pages deployment, linked from paper
- **arXiv**: paper PDF with supplementary materials reference

---

## Key References

- SastBench (Feiglin & Dar, 2026) — arXiv:2601.02941 — closest prior work, unreleased dataset
- OWASP Benchmark — synthetic Java, Youden's J scoring
- Fluid Attacks — 36 tools, avg F2 of 1.9%, pentester found 99%
- ZeroPath — forked XBOW, added FP testing, removed hints
- Ghost Security CAST — 99.5% FP rate stats
- SATE V/VI (NIST) — 70-92% FP rates
- PrimeVul (Ding et al., 2024) — label noise in vuln datasets
- SWE-Bench (Jimenez et al., 2024) — agentic benchmark design influence
- CVE-Bench (Zhu et al., 2025) — data contamination / knowledge cutoff
- CASTLE (Dubniczky et al., 2025) — micro-benchmarks, 25 CWEs
- CVEFixes (Bhandari et al., 2021) — CVE mining methodology
- CleanVul (Li et al., 2025) — LLM-based dataset cleaning
- ReposVul (Wang et al., 2024) — repo-level context

---

## Paper Parameters

- **Length**: ~10-12 pages (arXiv, no page limit but targeting venue-ready length)
- **Format**: LaTeX, likely ACM or IEEE template for future submission
- **Figures**: comparison table (Section 2), heatmap (Section 5.2), per-CWE table (Section 5.3), cost scatter plot (Section 5.4)
- **Supplementary**: full 26x15 grid available online via dashboard
