# RealVuln Ground Truth Generation Prompt

You are a security researcher building ground truth for the **RealVuln Benchmark** — an open benchmark that measures how well application security scanners detect real vulnerabilities in real code.

Your task: analyze the target repository and produce a `ground-truth.json` file that catalogues **every single exploitable vulnerability** in the codebase **and** includes false-positive traps (code that looks suspicious but is actually safe).

**Completeness is paramount.** A missing vulnerability is just as harmful to benchmark accuracy as a wrong line number. You must be exhaustive — find every vulnerability, not just the obvious ones.

---

## Key Context: These Are Intentionally Vulnerable Applications

Most targets in this benchmark are **deliberately vulnerable apps** (DVWA, Juice Shop, WebGoat, DSVW, etc.) created specifically to teach security concepts. This gives you a major advantage:

1. **Writeups and walkthroughs exist.** These apps have extensive documentation, blog posts, CTF writeups, and official vulnerability lists published online. Use your knowledge of these resources to ensure you don't miss any known vulnerabilities.
2. **Vulnerabilities are planted on purpose.** The developers intentionally introduced security flaws across many categories (injection, XSS, auth bypass, etc.). Assume there are vulnerabilities hiding in every major feature area — if you haven't found one in a section of the app, look harder.
3. **The vulnerability count is typically high.** These apps often contain dozens to hundreds of intentional vulnerabilities. If you've only found a handful, you are almost certainly missing many. Push yourself to be thorough.
4. **Check every route, every handler, every form.** Intentionally vulnerable apps embed flaws throughout their codebase. Don't stop after finding the first vulnerability in a file — there may be several more.

**Your goal is 100% recall.** It is far better to document a borderline vulnerability (and note the ambiguity in the evidence description) than to miss a real one.

---

## What You Are Producing

A single JSON file that will be used to **score** security scanners. When a scanner runs against this repo, its findings get matched against your ground truth to compute:

- **True Positives** — scanner found a real vulnerability you documented
- **False Positives** — scanner flagged something that isn't actually vulnerable
- **False Negatives** — scanner missed a real vulnerability you documented
- **True Negatives** — scanner correctly ignored a false-positive trap you planted

**Your ground truth directly determines these scores.** Every missed vulnerability or sloppy line number degrades the benchmark's accuracy.

---

## Output Schema

```json
{
  "schema_version": "1.0",
  "repo_id": "<slug>",
  "repo_url": "<github url>",
  "commit_sha": "<full 40-char SHA you are analyzing>",
  "type": <1-5>,
  "language": "<primary language>",
  "framework": "<framework or null>",
  "authorship": "<human_authored | llm_assisted | llm_generated | unknown>",
  "authorship_model": "<model name or null>",
  "authorship_confidence": "<high | medium | low>",
  "authorship_evidence": "<brief justification>",
  "findings": [
    // ... entries documented below
  ]
}
```

### Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | Always `"1.0"` |
| `repo_id` | string | Short slug, e.g. `"juice-shop"`, `"dsvw"`. Lowercase, hyphens. |
| `repo_url` | string | GitHub URL of the repository |
| `commit_sha` | string | **Full 40-character** commit SHA you are analyzing. The ground truth is pinned to this exact commit. |
| `type` | integer | Target classification (see below) |
| `language` | string | Primary language: `"python"`, `"javascript"`, `"java"`, `"go"`, etc. |
| `framework` | string or null | Framework if applicable: `"express"`, `"django"`, `"spring"`, etc. |
| `authorship` | string | One of: `"human_authored"`, `"llm_assisted"`, `"llm_generated"`, `"unknown"` |
| `authorship_model` | string or null | If LLM-assisted/generated, which model. Null otherwise. |
| `authorship_confidence` | string | `"high"`, `"medium"`, or `"low"` |
| `authorship_evidence` | string | Brief justification for the authorship classification |

### Type Values

| Type | Description | Examples |
|------|-------------|----------|
| 1 | Intentionally vulnerable apps | DVWA, Juice Shop, WebGoat, DSVW |
| 2 | Previously-vulnerable platforms (pinned to pre-patch commit) | WordPress plugins, GitLab, Django |
| 3 | Previously-vulnerable libraries | Known-vulnerable npm/PyPI packages |
| 4 | Benchmark roll-ups | OWASP Benchmark, NIST Juliet |
| 5 | Academic reproduction | Published scanner evaluations |

---

## Finding Entry Schema

Each entry in the `findings` array:

```json
{
  "id": "<repo_slug>-001",
  "is_vulnerable": true,
  "vulnerability_class": "sql_injection",
  "primary_cwe": "CWE-89",
  "acceptable_cwes": ["CWE-89", "CWE-564", "CWE-943"],
  "file": "routes/login.ts",
  "location": {
    "start_line": 42,
    "end_line": 48,
    "function": "loginUser"
  },
  "severity": "high",
  "expected_category": "injection",
  "evidence": {
    "source": "manual_review",
    "cve_id": null,
    "description": "SQL injection via unsanitized email parameter in login query"
  }
}
```

### Finding Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique ID. Format: `<repo_slug>-NNN` for vulnerabilities, `<repo_slug>-fp-NNN` for false-positive traps. Sequential numbering. |
| `is_vulnerable` | boolean | Yes | `true` = real vulnerability. `false` = false-positive trap (looks suspicious but is safe). |
| `vulnerability_class` | string | Yes | Snake_case slug: `sql_injection`, `reflected_xss`, `stored_xss`, `command_injection`, `path_traversal`, `ssrf`, `xxe`, `open_redirect`, `insecure_deserialization`, `hardcoded_credentials`, `sensitive_data_exposure`, etc. |
| `primary_cwe` | string | Yes | The most accurate CWE. Format: `"CWE-89"`. |
| `acceptable_cwes` | string[] | Yes | All CWE IDs a scanner could reasonably report for this vulnerability and still get credit. Include the primary_cwe plus close relatives. |
| `file` | string | Yes | Relative path from repo root. Forward slashes. No leading `./` or `/`. |
| `location.start_line` | integer | Yes | **Exact** line number where the vulnerable code begins. |
| `location.end_line` | integer | Yes | Line number where the vulnerable code ends. Same as start_line for single-line vulns. |
| `location.function` | string or null | Yes | Function/method name containing the vulnerability. Null if at module/class level. |
| `severity` | string | Yes | `"critical"`, `"high"`, `"medium"`, or `"low"` |
| `expected_category` | string | Yes | High-level category for reporting breakdowns. One of: `"injection"`, `"xss"`, `"auth"`, `"data_exposure"`, `"session_config"`, `"other"`. See Expected Category table below. |
| `evidence.source` | string | Yes | `"manual_review"`, `"cve_id"`, `"walkthrough"`, or other source identifier |
| `evidence.cve_id` | string or null | Yes | CVE ID if this vulnerability has one, null otherwise |
| `evidence.description` | string | Yes | Clear, specific description of **why** this code is (or is not) vulnerable |

---

## Critical Rules

### 1. Line Numbers Must Be Exact

The scorer matches scanner findings to ground truth using **file + CWE + line number** with a **±10 line tolerance**. If your line numbers are wrong by more than 10 lines, correct scanner findings will be scored as false positives.

**How to get line numbers right:**
- Point to the **sink** — the line where tainted data reaches a dangerous function (e.g., the `cursor.execute()` call, not where the parameter is first read from the request)
- If the vulnerability spans multiple lines, set `start_line` to the first relevant line and `end_line` to the last
- For single-expression vulnerabilities, `start_line` and `end_line` should be the same
- **Double-check every line number.** Count from line 1. Off-by-one errors are the most common mistake.

### 2. Include False-Positive Traps

False-positive traps (`is_vulnerable: false`) are **mandatory**. They measure a scanner's ability to distinguish real vulnerabilities from safe code that merely looks suspicious.

**Quality gate: at least 1 false-positive trap per 5 vulnerabilities.**

Good false-positive traps:
- Parameterized SQL queries (looks like SQL injection but uses `?` placeholders)
- User input that is properly sanitized/escaped before being used in HTML
- `subprocess` calls that use a list (not `shell=True`) with validated input
- Hardcoded strings that look like credentials but are defaults/examples/test data with no real auth behind them
- XML parsing with entity resolution explicitly disabled

**The `evidence.description` for FP traps must explain WHY the code is safe** — what sanitization, validation, or safe API prevents exploitation.

### 3. CWE Mapping

**`primary_cwe`**: The single most accurate CWE. Use the most specific CWE that applies.

**`acceptable_cwes`**: All CWEs a scanner could reasonably report and still get credit. This handles the fact that different scanners classify the same vulnerability differently.

Examples:
- SQL injection: primary `CWE-89`, acceptable `["CWE-89", "CWE-564", "CWE-943"]`
- Reflected XSS: primary `CWE-79`, acceptable `["CWE-79", "CWE-80"]`
- Command injection: primary `CWE-78`, acceptable `["CWE-78", "CWE-77", "CWE-88"]`
- Path traversal: primary `CWE-22`, acceptable `["CWE-22", "CWE-23", "CWE-36", "CWE-73"]`
- SSRF: primary `CWE-918`, acceptable `["CWE-918", "CWE-441"]`
- XXE: primary `CWE-611`, acceptable `["CWE-611", "CWE-776", "CWE-827"]`
- Open redirect: primary `CWE-601`, acceptable `["CWE-601"]`
- Insecure deserialization: primary `CWE-502`, acceptable `["CWE-502", "CWE-94"]`
- Hardcoded credentials: primary `CWE-798`, acceptable `["CWE-798", "CWE-259", "CWE-321"]`
- Missing auth: primary `CWE-862`, acceptable `["CWE-306", "CWE-862", "CWE-287", "CWE-284"]`
- IDOR: primary `CWE-639`, acceptable `["CWE-639", "CWE-284", "CWE-285", "CWE-862"]`

### 4. Severity Guidelines

| Severity | Criteria |
|----------|----------|
| **Critical** | RCE, authentication bypass, full database compromise. Directly exploitable with no preconditions. |
| **High** | Data exfiltration, privilege escalation, significant data modification. May require authenticated access. |
| **Medium** | Information disclosure, open redirect, stored/reflected XSS, DoS. Requires user interaction or specific conditions. |
| **Low** | Information leakage (verbose errors, version disclosure), missing security headers, weak crypto in non-sensitive context. |

### 5. Expected Category

Each finding must include an `expected_category` — a high-level grouping used for reporting breakdowns. Choose the single best fit:

| Category | Use For |
|----------|---------|
| `injection` | SQL injection, command injection, XPath injection, code injection, path traversal, SSRF, XXE, template injection, deserialization, RFI, HTTP header injection |
| `xss` | Reflected XSS, stored XSS, DOM-based XSS |
| `auth` | Missing authentication, missing authorization, IDOR/BOLA, broken access control, privilege escalation, rate limiting on auth endpoints |
| `data_exposure` | Sensitive data exposure, hardcoded credentials, plaintext password storage, information disclosure, debug info leakage |
| `session_config` | CSRF, insecure cookies, session fixation, security misconfigurations (debug mode, disabled protections, weak headers), CORS issues |
| `other` | Anything that doesn't clearly fit the above: DoS, mass assignment, weak PRNG, prompt injection, client-side trust issues, log injection |

When in doubt, prefer the more specific category. For example, a hardcoded JWT secret is `data_exposure` (credentials), not `session_config`.

### 6. What to Document

**DO document:**
- Injection flaws (SQL, command, XPath, LDAP, template, code injection)
- Cross-site scripting (reflected, stored, DOM-based)
- Broken authentication and session management
- Insecure deserialization
- Path traversal / arbitrary file read
- SSRF
- XXE
- Open redirects
- Hardcoded credentials and secrets
- Sensitive data exposure (stack traces, debug info, etc.)
- Missing access control / IDOR
- Security misconfigurations with concrete impact

**DO NOT document:**
- Missing HTTP security headers with no concrete exploit (unless the repo is specifically about headers)
- Theoretical vulnerabilities that require an unrealistic attack chain
- Dependencies with known CVEs (this benchmark tests SAST, not SCA)
- Code quality issues that aren't security vulnerabilities

### 7. Naming Conventions

- Finding IDs: `<repo_slug>-001`, `<repo_slug>-002`, ..., `<repo_slug>-fp-001`, `<repo_slug>-fp-002`, ...
- Vulnerability classes: snake_case, e.g. `sql_injection`, `reflected_xss`, `stored_xss`, `dom_xss`, `command_injection`, `path_traversal`, `ssrf`, `xxe`, `xpath_injection`, `open_redirect`, `insecure_deserialization`, `hardcoded_credentials`, `sensitive_data_exposure`, `remote_file_inclusion`, `http_header_injection`, `denial_of_service`
- Files: relative paths from repo root, forward slashes, no leading `./` or `/`

---

## CWE Families Reference

These families are used for reporting breakdowns. Your `primary_cwe` should ideally fall into one of these families:

| Family Slug | Label | CWEs |
|-------------|-------|------|
| sql_injection | SQL Injection | CWE-89, CWE-564, CWE-943 |
| xss | Cross-Site Scripting | CWE-79, CWE-80, CWE-87 |
| missing_auth | Missing Authentication / Authorization | CWE-306, CWE-862, CWE-287, CWE-284 |
| broken_access_control | Broken Access Control / IDOR | CWE-639, CWE-284, CWE-285, CWE-862, CWE-863 |
| path_traversal | Path Traversal | CWE-22, CWE-23, CWE-36 |
| command_injection | Command / OS Injection | CWE-78, CWE-77 |
| open_redirect | Open Redirect | CWE-601 |
| ssrf | Server-Side Request Forgery | CWE-918 |
| insecure_deserialization | Insecure Deserialization | CWE-502 |
| sensitive_data_exposure | Sensitive Data Exposure | CWE-200, CWE-209, CWE-532 |
| hardcoded_credentials | Hardcoded Credentials | CWE-798, CWE-259 |
| nosql_injection | NoSQL Injection | CWE-943 |
| xxe | XML External Entities | CWE-611 |
| security_misconfiguration | Security Misconfiguration | CWE-16, CWE-1004, CWE-614 |
| xpath_injection | XPath Injection | CWE-643, CWE-91 |
| code_injection | Code Injection / RFI | CWE-94, CWE-95, CWE-98 |
| denial_of_service | Denial of Service | CWE-400, CWE-770, CWE-789 |
| http_header_injection | HTTP Header Injection | CWE-113, CWE-644 |

If a vulnerability's CWE doesn't fit any family, that's fine — use the correct CWE anyway. The scorer handles unmapped CWEs gracefully.

---

## Example: Abbreviated Ground Truth

Here's a condensed example showing the key patterns (one vulnerability, one false-positive trap):

```json
{
  "schema_version": "1.0",
  "repo_id": "example-app",
  "repo_url": "https://github.com/example/example-app",
  "commit_sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "type": 1,
  "language": "python",
  "framework": "flask",
  "authorship": "human_authored",
  "authorship_model": null,
  "authorship_confidence": "high",
  "authorship_evidence": "Project created in 2018, pre-LLM era, single author with consistent commit history",
  "findings": [
    {
      "id": "example-app-001",
      "is_vulnerable": true,
      "vulnerability_class": "sql_injection",
      "primary_cwe": "CWE-89",
      "acceptable_cwes": ["CWE-89", "CWE-564", "CWE-943"],
      "file": "app/routes/users.py",
      "location": {
        "start_line": 45,
        "end_line": 45,
        "function": "get_user"
      },
      "severity": "high",
      "expected_category": "injection",
      "evidence": {
        "source": "manual_review",
        "cve_id": null,
        "description": "User ID from request args is concatenated directly into SQL query: cursor.execute('SELECT * FROM users WHERE id=' + request.args['id'])"
      }
    },
    {
      "id": "example-app-fp-001",
      "is_vulnerable": false,
      "vulnerability_class": "sql_injection",
      "primary_cwe": "CWE-89",
      "acceptable_cwes": ["CWE-89", "CWE-943"],
      "file": "app/routes/users.py",
      "location": {
        "start_line": 62,
        "end_line": 62,
        "function": "search_users"
      },
      "severity": "high",
      "expected_category": "injection",
      "evidence": {
        "source": "manual_review",
        "cve_id": null,
        "description": "Uses parameterized query with ? placeholder: cursor.execute('SELECT * FROM users WHERE name LIKE ?', ('%' + query + '%',)) — not vulnerable"
      }
    }
  ]
}
```

---

## Your Process

1. **Get the commit SHA.** Identify the exact commit you are analyzing. All line numbers must be correct for this commit.
2. **Research known vulnerabilities.** Since these are intentionally vulnerable apps, recall what you know about their documented vulnerabilities, official challenge lists, and community writeups. Use this as a checklist to ensure completeness.
3. **Read every source file.** Understand the application's architecture, routing, data flow, and security-relevant code paths. Do not skip any files — vulnerabilities can be anywhere.
4. **Identify ALL vulnerabilities — be exhaustive.**
   - For each vulnerability, trace the data flow from source (user input) to sink (dangerous function). Document the exact file and line of the sink.
   - Go through every route handler, every form processor, every database query, every file operation, every template render, every redirect, every deserialization call.
   - Cross-reference against your knowledge of known vulnerabilities for this app. If a known vulnerability isn't in your list, find it in the code.
   - Check for less obvious categories too: IDOR, missing auth on sensitive endpoints, insecure session handling, debug modes left on, information disclosure, weak crypto.
5. **Identify false-positive traps.** Find code that looks like a vulnerability but is actually safe due to sanitization, parameterization, or safe API usage. Aim for at least 1 trap per 5 vulnerabilities.
6. **Self-audit for completeness.** Before finalizing, ask yourself: "Have I covered every OWASP Top 10 category? Have I checked every endpoint? Are there any known challenges or levels in this app I haven't accounted for?" If the answer is no, go back and find what you missed.
7. **Verify line numbers.** Go back and confirm every `start_line` and `end_line` is correct. This is the single most important quality check.
8. **Write the JSON.** Follow the schema exactly. Validate it is well-formed JSON before outputting.

---

## Output

Output the complete `ground-truth.json` file contents. The file should be saved at:

```
evals/realvuln/ground-truth/<REPO_DIR>/ground-truth.json
```

Where `<REPO_DIR>` is the directory name for this target (e.g. `RealVuln-DSVW`, `realvuln-pygoat`).
