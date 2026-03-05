---
name: gt-validator
description: >
  Validates RealVuln ground truth files for completeness by cross-referencing against
  the actual source code, the repo's official documentation (README, wikis, guides),
  CVE/NVD databases, and broader web sources (security blogs, writeups, advisories).
  Produces a gap analysis report and offers to patch the ground truth with any missing
  vulnerabilities. Use this skill whenever the user asks to validate, verify, audit, or
  check a ground truth file, or when they want to find missing vulnerabilities in a
  ground truth, or when they mention "ground truth completeness" or "GT validation".
---

# Ground Truth Validator

You are validating whether a RealVuln ground truth file is complete — that it captures
every real vulnerability that's publicly known or discoverable in the target repository.

## Project layout

The RealVuln project is organized like this:

```
realvuln/
├── ground-truth/<RepoDir>/ground-truth.json   ← the file you're validating
├── gt-generation-prompt.md                    ← schema reference for the GT format
repos/<RepoDir>/                               ← local clone of the actual repo (sibling to realvuln/)
```

The `<RepoDir>` folder name is shared between `ground-truth/` and `repos/`. Note that
`repos/` lives at the project root (sibling of `realvuln/`), not inside it. The ground
truth JSON contains a `repo_url` field pointing to the upstream GitHub repo.

## Workflow

### Step 1: Load and understand the ground truth

Read the ground truth JSON. Extract:
- The list of documented vulnerabilities (`is_vulnerable: true`) — note each one's
  `vulnerability_class`, `primary_cwe`, `file`, `location`, and `evidence.description`
- The false-positive traps (`is_vulnerable: false`)
- The `repo_url` for web searches
- The `repo_id` and `language` for context

Summarize what the ground truth currently covers (how many vulns, what types, which files).

### Step 2: Examine the actual source code

Read the source code from the `repos/<RepoDir>/` directory at the project root. The goal isn't a full audit — it's to
spot any obvious vulnerabilities that the ground truth might have missed. Focus on:

- Dangerous function calls (e.g., `eval`, `exec`, `system`, `shell=True`,
  raw SQL concatenation, unsafe DOM writes, unsafe deserialization)
- Request parameter handling without sanitization
- Files not mentioned in the ground truth at all (a whole file with vulns could be missing)

Keep a list of anything suspicious that isn't in the ground truth.

### Step 3: Search official documentation

Fetch the repo's GitHub page and README. Many intentionally-vulnerable apps
(DSVW, Juice Shop, DVWA, WebGoat) document their vulnerabilities in their README,
wiki, or companion guides. Look for:

- Explicit vulnerability lists ("this app contains the following vulnerabilities...")
- Challenge descriptions that imply specific vuln types
- Official walkthroughs or "pwning guides"

Cross-reference every vulnerability mentioned in the docs against the ground truth.

### Step 4: Search CVE databases and the web

Search for known CVEs and security writeups:

1. **CVE/NVD search**: Search for `<repo_name> CVE` or `<repo_name> vulnerability`
   on NVD/CVE databases
2. **Security blogs**: Search for `<repo_name> vulnerability writeup`,
   `<repo_name> security`, `<repo_name> exploit`
3. **GitHub issues/advisories**: Check if the repo has security advisories or
   issues tagged as security bugs

For each external source that mentions a vulnerability, check whether it's
already captured in the ground truth.

### Step 5: Produce the gap analysis report

Write a markdown report to `realvuln/reports/<RepoDir>/gt-validation-report.md`
with these sections:

```markdown
# Ground Truth Validation Report: <repo_id>

**Date**: <today>
**Ground Truth**: <path to GT file>
**Repo**: <repo_url>

## Summary

- Vulnerabilities in GT: <count>
- False-positive traps in GT: <count>
- Potential gaps found: <count>
- Sources checked: repo code, README/docs, CVE/NVD, web searches

## Coverage by Vulnerability Class

| Class | In GT | Found in Sources | Status |
|-------|-------|-----------------|--------|
| sql_injection | 3 | 3 | Covered |
| xss | 2 | 3 | GAP — 1 missing |
| ... | ... | ... | ... |

## Confirmed Gaps

For each missing vulnerability, include:
- **Source**: where it was found (README line, CVE ID, blog URL, code inspection)
- **Vulnerability class**: what type
- **Location**: file and approximate line if known
- **Evidence**: why this is a real vulnerability
- **Suggested GT entry**: a draft JSON entry matching the GT schema

## Potential Gaps (Lower Confidence)

Vulnerabilities found in code review that may or may not warrant a GT entry.
Include reasoning for why they might be intentional omissions.

## Existing GT Entries Validated

For each GT entry, note whether external sources confirm it. This builds
confidence in the ground truth's accuracy — not just completeness.

## Sources Consulted

List every source checked with URLs where applicable.
```

### Step 6: Offer to update the ground truth

After presenting the report, ask the user if they want to add any of the
confirmed gaps to the ground truth. For each gap they approve:

- Generate a properly formatted finding entry following the GT schema
- Use the next available ID (e.g., if the last vuln is `dsvw-019`, the next is `dsvw-020`)
- Read `gt-generation-prompt.md` if you need to double-check the schema
- Add it to the ground truth JSON and save

## Important notes

- The ground truth is the source of truth for scoring scanners, so accuracy matters
  more than speed. Double-check line numbers against the actual code.
- For Type 1 repos (intentionally vulnerable apps), the README is usually the
  single best source of what vulns should be present.
- Don't flag missing "vulnerability classes" that the GT deliberately excludes
  (e.g., dependency vulns, missing headers). The GT schema docs say what to
  include and what to skip.
- When searching the web, be transparent about what you found and where.
  Include URLs so the user can verify.
- False-positive traps don't need external validation — they're authored by the
  GT creator. But do flag if the ratio is below 1 trap per 5 vulns.
