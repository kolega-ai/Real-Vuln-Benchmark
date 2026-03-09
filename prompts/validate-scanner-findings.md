# Validate Scanner Findings Against Ground Truth

You are orchestrating the validation of scanner findings for the RealVuln benchmark. Your job is to take scan results, check each finding against existing ground truth, and produce a suggestions file for human review.

## What You Do

1. Read the scan results file
2. Read the existing ground truth for the target repo
3. For each scanner finding, launch the **vuln-validator** subagent to validate it
4. Collect all LEGITIMATE (non-duplicate) findings into a suggestions file

## Process

### Step 1: Load Data

Read these two files:
- **Scan results**: `evals/realvuln/scan-results/<REPO>/<SCANNER>/results.json`
- **Existing ground truth**: `evals/realvuln/ground-truth/<REPO>/ground-truth.json`

### Step 2: Validate Each Finding

For each finding in the scan results, launch the `vuln-validator` agent with this prompt:

> Validate this scanner finding against the ground truth for `<REPO>`.
>
> **Ground truth file**: `evals/realvuln/ground-truth/<REPO>/ground-truth.json`
> **Source code**: `/Users/faizanraza/Documents/kolega/analysis_repos/<REPO>/`
>
> **Finding to validate**:
> ```json
> <paste the individual finding JSON here>
> ```
>
> Is this LEGITIMATE, FALSE POSITIVE, or DUPLICATE?

### Step 3: Collect Results

Track the verdict for each finding:
- **DUPLICATE**: Skip — already in ground truth.
- **FALSE POSITIVE**: Skip — not a real vulnerability.
- **LEGITIMATE**: Convert to ground truth format and add to suggestions.

### Step 4: Build the Suggestions File

For all LEGITIMATE findings, create a file at:

```
evals/realvuln/ground-truth/<REPO>/<SCANNER>_suggestions.json
```

The file must use the **exact same schema** as `ground-truth.json`, including all top-level fields (`schema_version`, `repo_id`, `repo_url`, `commit_sha`, `type`, `language`, `framework`, `authorship`, etc.). Copy these from the existing ground truth file.

The `findings` array should contain only the new validated entries. Use the ground truth finding format:

```json
{
  "id": "<repo_slug>-suggestion-001",
  "is_vulnerable": true,
  "vulnerability_class": "sql_injection",
  "primary_cwe": "CWE-89",
  "acceptable_cwes": ["CWE-89", "CWE-564", "CWE-943"],
  "file": "path/to/file.py",
  "location": {
    "start_line": 42,
    "end_line": 48,
    "function": "functionName"
  },
  "severity": "high",
  "expected_category": "injection",
  "evidence": {
    "source": "<SCANNER>",
    "cve_id": null,
    "description": "Description of why this is a real vulnerability, based on the validator's data flow analysis"
  }
}
```

Key details:
- **IDs**: Use `<repo_slug>-suggestion-NNN` numbering (sequential starting at 001)
- **`evidence.source`**: Set to the scanner name (e.g. `"snyk"`, `"our-scanner"`, `"vibeship"`)
- **`evidence.description`**: Use the vuln-validator's reasoning, not just the scanner's message
- **Severity**: Use the classification from `evals/realvuln/prompts/prompt.md` (critical/high/medium/low), mapped from the validator's assessment
- **`expected_category`**: Map to one of: `injection`, `xss`, `auth`, `data_exposure`, `session_config`, `other`

### Step 5: Summary

After writing the suggestions file, output a summary:

```
Scan: <SCANNER> on <REPO>
Total findings in scan: X
Duplicates (already in GT): X
False positives: X
New legitimate findings: X
Suggestions written to: evals/realvuln/ground-truth/<REPO>/<SCANNER>_suggestions.json
```

## Important Rules

- Do NOT modify `ground-truth.json` directly. Only write to `<SCANNER>_suggestions.json`.
- Do NOT skip the vuln-validator step. Every finding must be validated against actual source code.
- If the scan results file has many findings (>20), you may batch them — but every finding must still be validated.
- The suggestions file is for human review. Quality matters — don't add junk.

---

## Run Parameters

Fill in the target repo and scanner below, then use this prompt.

**Repo**: `<REPO>`
**Scanner**: `<SCANNER>`
**Scan results path**: `evals/realvuln/scan-results/<REPO>/<SCANNER>/results.json`
