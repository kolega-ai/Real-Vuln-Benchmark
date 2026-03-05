# RealVuln Scorer — Build Spec v0.1

## Goal

Build the minimum scoring infrastructure to run one repo end-to-end, structured so adding the next repo or scanner is a 10-minute job, not a refactor.

---

## Directory Layout

```
realvuln/
├── score.py                          # CLI entry point
├── config/
│   └── cwe-families.json             # CWE grouping data
├── ground-truth/
│   └── juice-shop/
│       └── ground-truth.json         # One file per target repo
├── scan-results/
│   └── juice-shop/
│       ├── semgrep/
│       │   └── results.json          # Raw scanner output, untouched
│       ├── opengrep/
│       │   └── results.json
│       └── our-scanner/
│           ├── run-1.json            # Multiple runs for non-deterministic
│           ├── run-2.json
│           └── run-3.json
├── parsers/
│   ├── __init__.py
│   ├── base.py                       # Abstract parser interface
│   └── semgrep.py                    # Covers Semgrep, Opengrep, and our scanner
├── scorer/
│   ├── __init__.py
│   ├── matcher.py                    # Matching logic
│   └── metrics.py                    # Metric computation
├── reports/
│   └── juice-shop/
│       └── scorecard-2025-02-19.json # Generated output
└── schemas/
    ├── ground-truth.schema.json      # JSON Schema for validation
    └── normalised-finding.schema.json
```

**Key conventions:**

- `ground-truth/` and `scan-results/` mirror each other by repo slug
- Scanner subdirectories under `scan-results/{repo}/` use the scanner's slug
- Reports land in `reports/{repo}/` with timestamped filenames
- Adding a new repo = create two directories + one ground truth file
- Adding a new scanner = one new parser file + one new subdirectory per repo

---

## Component 1: CWE Families Mapping

**File:** `config/cwe-families.json`

Maps individual CWEs to family groups so the scorer can treat related CWEs as equivalent.

```json
{
  "schema_version": "1.0",
  "families": {
    "sql_injection": {
      "cwes": ["CWE-89", "CWE-564", "CWE-943"],
      "label": "SQL Injection"
    },
    "xss": {
      "cwes": ["CWE-79", "CWE-80", "CWE-87"],
      "label": "Cross-Site Scripting"
    },
    "missing_auth": {
      "cwes": ["CWE-306", "CWE-862", "CWE-287", "CWE-284"],
      "label": "Missing Authentication / Authorization"
    },
    "broken_access_control": {
      "cwes": ["CWE-639", "CWE-284", "CWE-285", "CWE-862", "CWE-863"],
      "label": "Broken Access Control / IDOR"
    },
    "path_traversal": {
      "cwes": ["CWE-22", "CWE-23", "CWE-36"],
      "label": "Path Traversal"
    },
    "command_injection": {
      "cwes": ["CWE-78", "CWE-77"],
      "label": "Command / OS Injection"
    },
    "open_redirect": {
      "cwes": ["CWE-601"],
      "label": "Open Redirect"
    },
    "ssrf": {
      "cwes": ["CWE-918"],
      "label": "Server-Side Request Forgery"
    },
    "insecure_deserialization": {
      "cwes": ["CWE-502"],
      "label": "Insecure Deserialization"
    },
    "sensitive_data_exposure": {
      "cwes": ["CWE-200", "CWE-209", "CWE-532"],
      "label": "Sensitive Data Exposure"
    },
    "hardcoded_credentials": {
      "cwes": ["CWE-798", "CWE-259"],
      "label": "Hardcoded Credentials"
    },
    "nosql_injection": {
      "cwes": ["CWE-943"],
      "label": "NoSQL Injection"
    },
    "xxe": {
      "cwes": ["CWE-611"],
      "label": "XML External Entities"
    },
    "security_misconfiguration": {
      "cwes": ["CWE-16", "CWE-1004", "CWE-614"],
      "label": "Security Misconfiguration"
    }
  }
}
```

**Note:** A CWE can appear in multiple families. That's fine — `acceptable_cwes` in ground truth is the authority for matching. The families file is used for _reporting breakdowns_, not matching.

---

## Component 2: Normalised Finding Format

Every parser emits a list of these. This is the internal contract between parsers and the scorer.

```python
@dataclass
class NormalisedFinding:
    file: str            # Relative path from repo root, forward slashes
    cwe: str             # "CWE-89" format
    line: int | None     # Start line, if available
    function: str | None # Function name, if available
    severity: str | None # "critical" | "high" | "medium" | "low" | "info"
    rule_id: str | None  # Scanner's own rule identifier
    message: str | None  # Scanner's description
    scanner: str         # Scanner slug, e.g. "semgrep"
```

**Path normalisation rules (critical for matching):**

- Strip any leading `./` or `/`
- Forward slashes only
- Relative to repo root
- Case-sensitive (Linux filesystem semantics)

---

## Component 3: Parser Interface

**File:** `parsers/base.py`

```python
from abc import ABC, abstractmethod

class BaseParser(ABC):
    """
    All parsers implement this interface.
    Adding a scanner = subclass this + register in PARSER_REGISTRY.
    """

    scanner_name: str  # Slug used in directory names and reports

    @abstractmethod
    def parse(self, file_path: str) -> list[NormalisedFinding]:
        """
        Read a scanner output file, return normalised findings.
        Must handle the scanner's native format entirely.
        """
        ...
```

**File:** `parsers/__init__.py`

```python
# Registry — add new parsers here
PARSER_REGISTRY: dict[str, type[BaseParser]] = {
    "semgrep": SemgrepParser,
    "sarif": SarifParser,
    "realvuln-ai": RealVulnAIParser,
}

def get_parser(scanner_slug: str) -> BaseParser:
    cls = PARSER_REGISTRY.get(scanner_slug)
    if not cls:
        raise ValueError(
            f"No parser for '{scanner_slug}'. "
            f"Available: {list(PARSER_REGISTRY.keys())}"
        )
    return cls()
```

### Parser to Build

**`parsers/semgrep.py`** — Reads Semgrep/Opengrep JSON output. Our own scanner also conforms to this format, so this single parser covers all scanners we're benchmarking.

- Input: Semgrep `--json` output
- Key fields to extract: `results[].path`, `results[].extra.metadata.cwe[]`, `results[].start.line`, `results[].extra.severity`, `results[].check_id`, `results[].extra.message`
- Gotcha: Semgrep CWEs are in metadata and may be arrays or strings. Some rules have no CWE. Skip findings with no CWE.
- Gotcha: CWE format varies — sometimes `"CWE-89"`, sometimes `"CWE-89: Improper Neutralization of..."`. Parse to `"CWE-89"` form.

---

## Component 4: Matcher

**File:** `scorer/matcher.py`

Takes a list of `NormalisedFinding` and a loaded ground truth dict. Returns classified results.

### Matching Algorithm (file+cwe mode only for v0.1)

```
Input:
  - findings: list[NormalisedFinding]
  - ground_truth: list[GroundTruthEntry]  (the "findings" array from GT file)

Output:
  - matched_results: list[MatchResult]

Algorithm:

1. DEDUPLICATE scanner findings:
   Group by (file, cwe). Keep one per group (prefer highest severity).

2. BUILD lookup from ground truth:
   For each GT entry, build key = (file, frozenset(acceptable_cwes))

3. For each deduplicated scanner finding:
   a. Look for GT entries where finding.file == gt.file
      AND finding.cwe IN gt.acceptable_cwes
   b. If match found:
      - If gt.is_vulnerable == true  → TP
      - If gt.is_vulnerable == false → FP (known false-positive trap)
      - Mark GT entry as "matched" (prevent double-counting)
   c. If NO match found → FP (unmatched scanner finding)

4. For each GT entry NOT matched:
   - If gt.is_vulnerable == true  → FN
   - If gt.is_vulnerable == false → TN

5. Return all classifications
```

### Output Data Structure

```python
@dataclass
class MatchResult:
    classification: str           # "TP" | "FP" | "FN" | "TN"
    ground_truth_id: str | None   # GT finding ID, if matched
    scanner_finding: NormalisedFinding | None  # None for FN/TN
    ground_truth_entry: dict      # The GT entry
```

### Edge Cases to Handle

- **Multiple GT entries on the same file with different CWEs:** Scanner finding should match the _most specific_ one. If a scanner reports CWE-89 on `login.ts` and GT has both a CWE-89 and a CWE-79 entry on `login.ts`, it should match the CWE-89 entry only.
- **Scanner reports a CWE not in any GT acceptable set for that file:** FP.
- **Scanner reports on a file with no GT entries at all:** FP.
- **GT entry with multiple acceptable CWEs matches multiple scanner findings:** Only count one TP. The rest are discarded (not FPs).

---

## Component 5: Metrics Calculator

**File:** `scorer/metrics.py`

Takes the list of `MatchResult` and computes:

```python
@dataclass
class ScoreCard:
    repo_id: str
    scanner: str
    timestamp: str

    # Aggregate
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float    # TP / (TP + FP), handle div-by-zero
    recall: float       # TP / (TP + FN)
    f1: float           # 2 * (P * R) / (P + R)

    # Per CWE family breakdown
    per_family: dict[str, FamilyScore]

    # Per severity breakdown
    per_severity: dict[str, SeverityScore]

    # Detail — every match result for inspection
    details: list[MatchResult]

@dataclass
class FamilyScore:
    family: str
    label: str
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float

@dataclass
class SeverityScore:
    severity: str
    tp: int
    fp: int
    fn: int
    recall: float
```

For the per-family breakdown, use the CWE families mapping to bucket each GT entry by family (based on its `primary_cwe`).

---

## Component 6: CLI Entry Point

**File:** `score.py`

Minimal CLI. No framework needed — just `argparse`.

```
Usage:
  python score.py --repo juice-shop --scanner semgrep
  python score.py --repo juice-shop --scanner semgrep --scanner codeql --scanner realvuln-ai
  python score.py --repo juice-shop --all-scanners
  python score.py --repo juice-shop --scanner realvuln-ai --runs   # Average N runs
```

**Behaviour:**

1. Load ground truth from `ground-truth/{repo}/ground-truth.json`
2. Load CWE families from `config/cwe-families.json`
3. For each scanner:
   a. Discover result files in `scan-results/{repo}/{scanner}/`
   b. Parse with appropriate parser
   c. Run matcher
   d. Compute metrics
4. If `--runs` flag and multiple result files exist, score each independently, then report mean ± stddev for each metric
5. Write scorecard JSON to `reports/{repo}/`
6. Print summary table to stdout

### Stdout Output (example)

```
RealVuln Scorecard — juice-shop @ abc123

Scanner        | TP | FP | FN | TN | Precision | Recall |   F1
---------------|----|----|----|----|-----------|--------|------
semgrep        | 12 |  8 |  9 |  3 |     0.600 |  0.571 | 0.585
codeql         | 15 |  5 |  6 |  4 |     0.750 |  0.714 | 0.732
realvuln-ai    | 18 |  3 |  3 |  4 |     0.857 |  0.857 | 0.857

Per CWE Family (realvuln-ai):
Family                  | TP | FP | FN | Recall
------------------------|----|----|----|---------
SQL Injection           |  3 |  0 |  0 |  1.000
XSS                     |  4 |  1 |  1 |  0.800
Missing Auth            |  2 |  0 |  2 |  0.500
...
```

---

## Component 7: Report Output

**File:** Written to `reports/{repo}/scorecard-{date}.json`

```json
{
  "schema_version": "1.0",
  "repo_id": "juice-shop",
  "commit_sha": "abc123...",
  "generated_at": "2025-02-19T14:30:00Z",
  "scanners": {
    "semgrep": {
      "version": "1.56.0",
      "tp": 12, "fp": 8, "fn": 9, "tn": 3,
      "precision": 0.600, "recall": 0.571, "f1": 0.585,
      "per_family": { ... },
      "details": [ ... ]
    }
  }
}
```

For multi-run scanners, add:

```json
{
  "realvuln-ai": {
    "runs": 5,
    "mean_precision": 0.843,
    "stddev_precision": 0.021,
    "mean_recall": 0.851,
    "stddev_recall": 0.015,
    "mean_f1": 0.847,
    "stddev_f1": 0.012,
    "per_run": [ ... ]
  }
}
```

---

## Build Order

This is the order you should build things to get to a working scorer fastest:

| Step | What                                                                            | Effort | Output                     |
| ---- | ------------------------------------------------------------------------------- | ------ | -------------------------- |
| 1    | Define `NormalisedFinding` dataclass + path normalisation util                  | 30 min | `parsers/base.py`          |
| 2    | Write the Semgrep parser (covers all scanners since we conform to their format) | 1 hr   | `parsers/semgrep.py`       |
| 3    | Write the ground truth loader (just `json.load` + basic validation)             | 30 min | In `scorer/matcher.py`     |
| 4    | Write the matcher                                                               | 2-3 hr | `scorer/matcher.py`        |
| 5    | Write the metrics calculator                                                    | 1 hr   | `scorer/metrics.py`        |
| 6    | Wire it together with a minimal CLI                                             | 1 hr   | `score.py`                 |
| 7    | **Run it end-to-end on one repo + one scanner**                                 | —      | First scorecard            |
| 8    | Add CWE families file + per-family breakdown                                    | 1 hr   | `config/cwe-families.json` |
| 9    | Add multi-run averaging                                                         | 1 hr   | Update scorer              |
| 10   | Pretty stdout tables + JSON report output                                       | 1 hr   | Update CLI                 |

Steps 1–7 get you a working system. Steps 8–10 extend it. Total estimate: ~1 day of focused work to get through step 7, another couple hours for the rest.

---

## What's Deliberately Out of Scope

- `function+cwe` and `line+cwe` matching modes (add later as flags)
- JSON Schema validation of ground truth files (add when accepting contributions)
- HTML report generation
- Docker packaging
- CI/CD integration
- Any UI beyond stdout
- Authorship axis tracking (metadata is in ground truth but scoring doesn't filter by it yet)
