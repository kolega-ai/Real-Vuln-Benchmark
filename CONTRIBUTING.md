# Contributing to RealVuln

We welcome contributions from security researchers, tool vendors, and practitioners. This document explains how to contribute ground truth, scanner results, and parsers.

## Ways to Contribute

1. **Add a new target repo** with ground truth labels
2. **Add scan results** for an existing repo
3. **Add a parser** for a new scanner output format
4. **Validate or correct** existing ground truth entries
5. **Report issues** with scoring, matching, or tooling

## Adding a New Target Repo

### 1. Choose a repo

Pick a repo that fits one of the [target types](README.md#target-classification). Intentionally vulnerable apps (Type 1) and previously-vulnerable platforms with CVEs (Type 2) are highest priority.

### 2. Create ground truth

Create `ground-truth/{repo-slug}/ground-truth.json` following the schema:

```json
{
  "schema_version": "1.0",
  "repo_id": "short-name",
  "repo_url": "https://github.com/...",
  "commit_sha": "<40-char hex SHA>",
  "type": 1,
  "language": "python",
  "framework": "flask",
  "authorship": "human_authored",
  "authorship_model": null,
  "authorship_confidence": "high",
  "authorship_evidence": "Pre-LLM project, established 2018",
  "findings": [...]
}
```

### 3. Label findings

Each finding entry requires:

```json
{
  "id": "repo-slug-001",
  "is_vulnerable": true,
  "vulnerability_class": "sql_injection",
  "primary_cwe": "CWE-89",
  "acceptable_cwes": ["CWE-89", "CWE-564"],
  "file": "path/to/file.py",
  "location": { "start_line": 42, "end_line": 48, "function": "login" },
  "severity": "high",
  "expected_category": "injection",
  "evidence": {
    "source": "manual_review",
    "cve_id": null,
    "description": "SQL injection via unsanitized user input in login query"
  }
}
```

### 4. Include false-positive traps

Add entries with `"is_vulnerable": false` for code that *looks* suspicious but is actually safe. Aim for at least 1 trap per 5 vulnerabilities. These are critical for measuring false positive rates.

### 5. Naming convention

Use `realvuln-{repo-name}` as the directory name, all lowercase with hyphens.

### 6. Validate

```bash
python validate_gt.py realvuln-your-repo
```

Fix all errors before submitting.

## Adding Scan Results

Place scanner output in `scan-results/{repo-slug}/{scanner-slug}/results.json`.

The default format is Semgrep JSON (`--json` output). If your scanner outputs a different format, you'll need to add a parser (see below).

For multi-run experiments (to measure variance), use multiple files: `results-r1.json`, `results-r2.json`, etc.

## Adding a Parser

If your scanner doesn't output Semgrep-compatible JSON:

1. Create `parsers/{format_name}.py` with a class extending `BaseParser`
2. Implement the `parse()` method returning `list[NormalisedFinding]`
3. Register the scanner slug in `PARSER_REGISTRY` in `parsers/__init__.py`

```python
from parsers.base import BaseParser, NormalisedFinding

class MyParser(BaseParser):
    scanner_name: str = "my-scanner"

    def __init__(self, scanner_slug: str = "my-scanner"):
        self.scanner_name = scanner_slug

    def parse(self, file_path: str) -> list[NormalisedFinding]:
        # Read file_path, return normalised findings
        ...
```

## Development Setup

```bash
# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check .

# Type check
mypy parsers/ scorer/

# Validate ground truth
python validate_gt.py
```

## Pull Request Checklist

- [ ] `python validate_gt.py` passes (if ground truth changed)
- [ ] `pytest` passes
- [ ] `ruff check .` passes
- [ ] Ground truth entries include evidence sources
- [ ] False-positive traps included (1 per 5 vulns minimum)
- [ ] Commit SHA is pinned and repo is cloneable at that commit

## Code of Conduct

Be respectful and constructive. We're building a shared resource for the security community.
