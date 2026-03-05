# RealVuln Benchmark — Unified Specification

## 1. Problem & Purpose

Application security scanners routinely fail to catch basic vulnerabilities — missing authentication, broken access control, IDOR — in real-world code. No credible, open benchmark exists to measure this:

- **OWASP Benchmark** uses synthetic single-file test cases. Scanners can be tuned to ace it without improving real-world detection.
- **Vendor self-benchmarks** (DryRun, ZeroPath, Cycode/Bearer) use small samples, vendor-controlled methodology, and no reusable infrastructure.
- **Academic benchmarks** (NIST Juliet, NIST SARD, CVEFixes, VulBench) lack scoring tooling, have inconsistent labelling, or target ML evaluation rather than scanner comparison.
- **Academic papers** produce one-off results locked in PDFs that nobody reproduces.

**RealVuln** is an open, extensible benchmark that uses real-world code, provides machine-readable ground truth with CWE mappings, includes an automated scoring engine, and is designed for community contribution. We launch as **RealVuln Beta** — publishing the framework, initial ground truth, and our results as an invitation for the security community to contribute, validate, and extend.

---

## 2. Target Classification

Targets are classified on two independent axes.

### Axis 1: Code Realism (Type)

| Type                                    | Description                                                     | Examples                                              | Ground Truth Source                                                     |
| --------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------- | ----------------------------------------------------------------------- |
| **1 — Intentionally Vulnerable Apps**   | Deliberately insecure apps with documented vulns                | DVWA, Juice Shop, WebGoat, OpenClaw                   | Published walkthroughs, solution guides, manual expert review           |
| **2 — Previously-Vulnerable Platforms** | Production apps pinned to pre-patch commits with disclosed CVEs | WordPress plugins, GitLab, Django, Discourse          | NVD/CVE → fix commit diff → file + CWE extraction → expert verification |
| **3 — Previously-Vulnerable Libraries** | Libraries pinned to vulnerable versions                         | Known-vulnerable npm/PyPI packages                    | Same CVE/NVD approach as Type 2                                         |
| **4 — Benchmark Roll-ups**              | Existing benchmarks integrated as unified, scoreable targets    | OWASP Benchmark, NIST Juliet, XBOW/ZeroPath           | Direct import or adapter mapping                                        |
| **5 — Academic Reproduction**           | Published scanner evaluations encoded as reproducible configs   | Cycode/Bearer (2023), DryRun (2025), SastBench (2026) | Methodology extracted from papers, encoded as config                    |

### Axis 2: Code Authorship

Every target carries authorship metadata, independent of Type:

| Value            | Definition                          |
| ---------------- | ----------------------------------- |
| `human_authored` | Pre-LLM era or confirmed no LLM use |
| `llm_assisted`   | Written by humans with LLM help     |
| `llm_generated`  | Primarily or entirely LLM-generated |
| `unknown`        | Post-2023, no authorship disclosure |

These axes are orthogonal. OpenClaw is both `llm_generated` and Type 1 (intentionally vulnerable app) — LLM-generated does not mean synthetic.

---

## 3. Ground Truth Schema

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
      "location": {
        "start_line": 88,
        "end_line": 90,
        "function": "sanitizeHtml"
      },
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
- A **global CWE family mapping** (`cwe-families.json`) groups related CWEs so scoring handles scanner-specific CWE choices gracefully.

### Quality Gates

Every ground truth submission requires: evidence source (CVE ID, walkthrough URL, or manual review with reviewer identity), at least one `is_vulnerable: false` entry per five `true` entries, a verified-cloneable pinned commit, and peer review before merge.

---

## 4. Matching & Scoring

### Finding Matching

Scanner findings are matched against ground truth at configurable granularity:

| Mode                 | Match Criteria                              | Use Case                                                             |
| -------------------- | ------------------------------------------- | -------------------------------------------------------------------- |
| `file+cwe` (default) | Same file + CWE in acceptable set           | Fair cross-tool comparison                                           |
| `function+cwe`       | Same file + function name + CWE             | Tighter, requires function-level reporting                           |
| `line+cwe`           | Same file + line within ±10 tolerance + CWE | Strictest; accommodates scanners pointing at source vs sink vs route |

Multiple scanner findings for the same CWE in the same file are deduplicated to prevent inflated TP counts.

### Finding Classification

| Category                | Definition                                                                                            |
| ----------------------- | ----------------------------------------------------------------------------------------------------- |
| **True Positive (TP)**  | Matches an `is_vulnerable: true` ground truth entry                                                   |
| **False Positive (FP)** | Matches an `is_vulnerable: false` ground truth entry, or flagged something with no ground truth entry |
| **False Negative (FN)** | `is_vulnerable: true` entry the scanner missed                                                        |
| **True Negative (TN)**  | `is_vulnerable: false` entry the scanner correctly ignored                                            |

Unmatched scanner findings (no ground truth entry) are scored as false positives. If a scanner flags something that isn't in ground truth, the burden is on the scanner to be right — not on the benchmark to assume it might be.

### Metrics

Recall, F1, per-CWE-family breakdown, Youden's J (for OWASP Benchmark compatibility), per-Type breakdown, and optional breakdown by authorship axis.

---

## 5. Scanner Integration

### Architecture

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

### Parser Roadmap

| Format                 | Scanners                                       | Priority    |
| ---------------------- | ---------------------------------------------- | ----------- |
| Semgrep JSON           | Semgrep, Opengrep                              | v1 (launch) |
| Custom JSON            | Our AI scanner                                 | v1 (launch) |
| OWASP Benchmark format | Type 4 compatibility                           | v1 (launch) |
| SARIF                  | CodeQL, Checkmarx, Snyk, most commercial tools | v1.1        |
| SonarQube API JSON     | SonarQube, SonarCloud                          | v1.1        |

### Licensing Constraints

As a competitor building a SAST tool, licensing governs which tools we can benchmark:

| Tool                               | Status            | Notes                                                                                             |
| ---------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------- |
| Joern                              | ✅ Safe           | Apache 2.0                                                                                        |
| Opengrep                           | ✅ Safe           | LGPL 2.1                                                                                          |
| CodeQL                             | ✅ Safe           | Academic research + open-source analysis explicitly permitted                                     |
| Semgrep CE                         | ⚠️ Partial        | Engine (LGPL) fine; **maintained rules blocked** for competitors. Use Opengrep or write own rules |
| SonarQube                          | 🔴 Blocked        | SSALv1 blocks competing products                                                                  |
| Qwiet AI                           | 🔴 Blocked        | ToS prohibits competitive use                                                                     |
| Veracode, Checkmarx, Fortify, Snyk | 🔴 Likely blocked | Proprietary EULAs, need written permission                                                        |

**Mitigations:** Contact vendors for academic benchmarking permission. Cite publicly available OWASP scores where they exist. Disclose all exclusions in the paper. Primary publication at an academic venue for strongest licensing position.

---

## 6. Reproducibility

### The Contract

_"Run version X against commit Y and you should get statistically similar results."_

### What We Publish

- Scanner version strings (semver) stamped into every result file
- Pinned commit SHAs for every target repo
- Exact commands used to run each scanner
- All raw scan outputs
- Supported languages and scanner capabilities

### What Stays Proprietary

Prompts, orchestration logic, agent workflow, model architecture details beyond backbone identification, internal retrieval/fine-tuning data. This is the same standard as Checkmarx, SonarCloud, and Snyk.

### Handling Non-Determinism

AI agents are non-deterministic. Rather than hiding this, we surface stability as a measurable property:

- Run the agent **N times (5–10)** per benchmark target
- Report **mean and variance** for each metric
- Publish **all raw outputs** from all runs
- Reproduction standard: another party runs N times and checks **distributional consistency**

### Metadata Manifest (per run)

Every published result includes: scanner version, model backbone version (e.g. `claude-sonnet-4-20250514`), timestamp, target repo commit SHA, and config hash (proves config is frozen without revealing contents).

### Agent Versioning

- Semver on every release
- Frozen config manifest per version (model ID, prompt hashes, orchestration commit SHA)
- Immutable archived artifacts (tagged git release or pinned Docker image)
- If an external model is deprecated: _"Results produced with model X at version Y. If unavailable, raw outputs provided for verification."_

---

## 7. Research Question: Scanner Performance vs Code Authorship

**Hypothesis:** LLM-based scanners may perform disproportionately well on LLM-generated code compared to human-authored code.

**Method:** Run every scanner against matched pairs — same vulnerability class, same Type, `human_authored` vs `llm_generated`. Compare performance deltas across scanners.

**If confirmed:** _"If your codebase is primarily LLM-generated, AI-native scanners provide measurably better detection. If legacy human-written code, traditional SAST still holds up."_

This is a publishable contribution independent of who wins the benchmark. No existing benchmark tracks authorship, and as codebases shift toward LLM-generated code, the industry needs data on whether scanner performance generalises.

---

## 8. Launch Strategy

### Beta Framing

_"RealVuln Beta — we're publishing the framework, initial ground truth, and our results. We actively invite security researchers, tool vendors, and practitioners to contribute ground truth, validate existing entries, and run their own tools."_

### Credibility Measures

- Publish benchmark framework and ground truth **before** results (or prove via git history that ground truth was committed before scans)
- Include at least one metric where we don't win
- External security researcher independently validates ≥20% of ground truth
- Disclose affiliation and conflict of interest in the paper
- Open GitHub repo with issues, PRs, `CONTRIBUTING.md`, and clear templates from day one

### Progression

Beta → **v1.0** (after external validation and community contributions) → ongoing versioned releases.

### Publication

Primary publication at an academic venue (arXiv minimum, ideally SCORED, SecDev, ISSTA, or similar). Company blog links to the paper afterward.

---

## 9. Repository Structure

```
realvuln/
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── ground-truth/
│   ├── type-1-intentional/
│   ├── type-2-cve-platforms/
│   ├── type-3-cve-libraries/
│   ├── type-4-benchmark-rollups/
│   └── type-5-academic/
├── cwe-families.json
├── matching-config.json
├── parsers/
│   ├── semgrep.py
│   ├── sarif.py
│   └── ...
├── scorer/
│   ├── engine.py
│   └── reporter.py
├── results/
│   ├── semgrep/
│   ├── codeql/
│   └── realvuln-ai/
└── docs/
    ├── adding-a-repo.md
    ├── adding-a-parser.md
    └── schema-reference.md
```

---

## 10. What We Ship

1. **The framework** — open-source CLI tool. Ingest scanner output, score against ground truth, generate scorecards.
2. **The ground truth dataset** — curated, versioned, machine-readable manifests for all targets.
3. **Our results** — our AI scanner vs Joern, Opengrep, CodeQL, and any licensed commercial tools. All raw outputs published, with N-run variance data for non-deterministic scanners.
4. **Reproducibility package** — pinned commits, scanner versions, commands, metadata manifests, and all raw outputs from all runs.
5. **Contribution framework** — `CONTRIBUTING.md`, schema docs, parser interface spec, and ground truth templates.
