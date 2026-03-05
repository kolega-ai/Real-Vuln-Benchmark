# DVGA Scan Feedback — v2 (Rescan with Feedback)

## Score Progression

| Metric | Opus R1 | Opus R2 | Opus R3 | Rescan v1 | **Rescan v2** |
|--------|---------|---------|---------|-----------|---------------|
| **F2 Score** | 22.0 | 42.0 | 29.0 | **64.6** | **61.0** |
| TP | 5 | 10 | 7 | 23 | 20 |
| FP | 15 | 24 | 16 | 31 | 20 |
| FN | 14 | 9 | 12 | 8 | 11 |
| Precision | 25.0% | 29.4% | 30.4% | 42.6% | 50.0% |
| Recall | 26.3% | 52.6% | 36.8% | 74.2% | 64.5% |

**GT: 31 vulnerabilities, 4 FP traps.**

v2 improved precision (50% vs 43%) and reduced FP count (20 vs 31), but regressed on recall (64.5% vs 74.2%) — a net F2 drop of 3.6 points.

---

## What v2 Improved

1. **Unbundled IDORs** → gained dvga-014 (DeletePaste IDOR, CWE-862). v1 only found EditPaste (dvga-013) and used up its one CWE-639 match. v2 reported each mutation separately with distinct CWEs.
2. **Found /start_over route** → gained dvga-023 (CWE-306, views.py L431). v1 missed all HTTP routes.
3. **Lower FP count** (20 vs 31) — 11 fewer false positives. Reduced noise in templates and tests.
4. **Triggered fewer FP traps** — TN=3 in v2 vs TN=4 in v1 (dvga-fp-003 audit.html XSS was incorrectly flagged).

---

## What v2 Regressed On

### 5 TPs Lost (v1→v2 regressions)

| GT ID | Vuln | v1 Finding | v2 Status | Root Cause |
|-------|------|-----------|-----------|------------|
| dvga-012 | `deleteAllPastes` missing auth | CWE-862, views.py:L385 | **Gone** | Crowded out by easy-mode middleware findings |
| dvga-021 | `resolve_users` info exposure | CWE-200, views.py:L370 | **Gone** | Crowded out; scanner focused on model-level exposure instead |
| dvga-026 | Truncated UUID (weak IDs) | CWE-330, helpers.py:L14 | **Gone** | Scanner reported CWE-209 at helpers.py:L28 instead (wrong vuln) |
| dvga-027 | GraphiQL cookie bypass | CWE-807, middleware.py:L122 | **Gone** | Scanner reported CWE-284 at L72 instead (wrong line, wrong finding) |
| dvga-028 | Broken command allow-list | CWE-16, security.py:L37 | **CWE mismatch** | v2 reported CWE-78 at same location; GT expects CWE-16/693/183 |

**Key pattern**: The scanner spent attention budget on 5 "easy mode bypass" findings (CWE-200/94/862/284/16 on middleware.py) that are all FPs, displacing real findings like dvga-012, 021, 026, 027.

### Persistent FNs (missed in both v1 and v2)

| GT ID | Vuln | Why Missed |
|-------|------|-----------|
| dvga-004 | `systemDiagnostics` cmd injection (views.py:L345) | Scanner found ImportPaste cmd injection (dvga-002) but didn't trace other callers of `run_cmd` |
| dvga-005 | `systemDebug` cmd injection (views.py:L352) | Same — each resolver calling `run_cmd` is a distinct vuln |
| dvga-008 | Stored XSS in paste gallery (paste.html:L132) | Scanner found WebSocket XSS (dvga-009 at L65) but missed the `get_pastes()` AJAX function doing the same |
| dvga-019 | Log injection via operationName (models.py:L58) | Scanner found CWE-117 at views.py:L105 (call site) instead of models.py (sink). Wrong file = FN |
| dvga-022 | Unauthenticated `/audit` (views.py:L426) | One CWE-306 finding at L431 matched dvga-023 (/start_over), consuming the match. Need separate findings per route |
| dvga-024 | Unauthenticated `/difficulty/<level>` (views.py:L441) | Not reported at all. This is the most critical — it disables ALL security middleware |

---

## FP Analysis (20 False Positives)

### By Category

| Category | Count | Findings |
|----------|-------|----------|
| **Easy-mode bypass spam** | 5 | CWE-200 middleware.py:L107, CWE-94 L14, CWE-862 L43, CWE-284 L72, CWE-16 L88 |
| **Wrong file (def not caller)** | 4 | CWE-78 helpers.py:L8, CWE-22 views.py:L185, CWE-400 security.py:L8, CWE-117 views.py:L105 |
| **Duplicates / nearby** | 3 | CWE-798 setup.py:L49, CWE-312 views.py:L234, CWE-209 views.py:L516 |
| **Speculative / low-quality** | 4 | CWE-915 models.py:L16, CWE-306 view_override.py:L157, CWE-209 config.py:L11, CWE-209 helpers.py:L28 |
| **Excluded by GT design** | 2 | CWE-307 views.py:L233 (rate limiting), CWE-770 views.py:L508 (batch enabled) |
| **FP trap triggered** | 1 | CWE-79 audit.html:L32 (Jinja2 auto-escapes) |
| **CWE mismatch** | 1 | CWE-78 security.py:L37 (should be CWE-16) |

---

## Prompt Additions for Next Scan

### 1. STOP reporting "easy mode bypass" as separate findings

**Problem**: 5 of 20 FPs (25%) are findings like "DepthProtectionMiddleware is bypassed in easy mode". These are not vulnerabilities — the easy/hard mode toggle is the application's design. The real vulns are the *consequences* (e.g., the actual DoS via circular types, the actual denylist bypass via batch queries).

**Prompt addition**:
> Do NOT report "middleware is disabled in easy mode" or "protection is bypassed in easy mode" as separate findings. These mode checks are application configuration, not vulnerabilities. Instead, report the actual vulnerability that the disabled middleware would have prevented (e.g., report the deep recursion DoS, not the fact that depth protection is off).

### 2. Report at the VULNERABLE CALL SITE, not the function definition

**Problem**: 4 FPs report the helper/utility function definition instead of where user-controlled input enters it. E.g., CWE-78 on `helpers.py:L8` (where `run_cmd` is defined) instead of `views.py:L211` (where user input reaches it via ImportPaste). The function definition alone is not vulnerable — it's only vulnerable when reached with unsanitized input.

**Prompt addition**:
> When reporting a vulnerability involving a helper/utility function (e.g., `run_cmd`, `save_file`, `simulate_load`), report the finding at the **call site** where user-controlled input enters the function, not at the function definition. If the same helper is called from multiple resolvers with user input, report EACH call site as a separate finding.

### 3. Report EACH distinct vulnerable endpoint/resolver separately

**Problem**: The scanner bundles nearby vulnerabilities. E.g., one CWE-306 finding at L431 consumed the match for dvga-023 (/start_over), leaving dvga-022 (/audit at L426) and dvga-024 (/difficulty at L441) as FNs. Similarly, only one cmd injection (ImportPaste) was reported, missing systemDiagnostics and systemDebug.

**Prompt addition**:
> Each GraphQL resolver or HTTP route that has the same vulnerability must be reported as a SEPARATE finding with its own line number. Do not combine multiple endpoints into one finding. Specifically for this codebase:
> - `/audit`, `/start_over`, and `/difficulty/<level>` are THREE separate unauthenticated routes
> - `systemDiagnostics`, `systemDebug`, and `ImportPaste.mutate` are THREE separate command injection sinks
> - The `get_pastes()` AJAX handler (paste.html ~L132) and the WebSocket `subscribeToPastes` handler (paste.html ~L65) are TWO separate stored XSS vectors

### 4. Use precise CWEs for misconfiguration vs injection

**Problem**: dvga-028 (broken command allow-list due to missing comma) was reported as CWE-78 (OS command injection). But this is a misconfiguration (CWE-16) or broken protection mechanism (CWE-693), not an injection flaw. The scanner correctly identified the bug but used the wrong CWE.

**Prompt addition**:
> When a security control (allowlist, denylist, middleware) is misconfigured or broken, use CWE-16 (Configuration) or CWE-693 (Protection Mechanism Failure), not the CWE of the attack it fails to prevent. A broken allowlist is CWE-16, not CWE-78. A bypassable denylist is CWE-693 or CWE-862, not CWE-78.

### 5. Log injection: report at the SINK (where data is written), not the call site

**Problem**: Scanner found the right issue (log injection via operationName, CWE-117) but reported it at `views.py:L105` (where `create_audit_entry` is called) instead of `models.py:L58` (where the unsanitized data is actually written to the database). This caused a file mismatch → FN.

**Prompt addition**:
> For log injection / audit trail tampering vulnerabilities, report the finding at the **sink** where unsanitized data is persisted (e.g., the database write in the logging function), not at every call site that invokes the logging function.

### 6. Don't flag template rendering when Jinja2 auto-escaping is active

**Problem**: Scanner flagged CWE-79 on audit.html:L32, but Flask/Jinja2 auto-escapes all `{{ }}` expressions in `.html` templates by default. This is a known-safe pattern.

**Prompt addition**:
> In Flask/Jinja2 templates, `{{ variable }}` expressions are auto-escaped by default. Do NOT flag these as XSS unless the template uses `| safe`, `{% autoescape false %}`, or `Markup()`. Only flag XSS in JavaScript template literals (`${var}`) or when auto-escaping is explicitly disabled.

### 7. Don't report rate limiting or batch-enabled as standalone findings

**Problem**: CWE-307 (missing rate limiting on login) and CWE-770 (batch queries enabled) are architectural concerns, not specific vulnerabilities in the GT.

**Prompt addition**:
> Do NOT report missing rate limiting (CWE-307) or "batch queries enabled" (CWE-770) as standalone findings. These are defense-in-depth measures, not vulnerabilities. Only report batch query support when it enables a specific bypass (e.g., batch queries bypass the denylist — report that as the finding).

---

## Summary of Expected Impact

If all prompt additions are applied:

| Change | FP Removed | TP Gained |
|--------|-----------|-----------|
| Stop easy-mode spam | -5 FP | +2-4 TP (attention freed for real findings) |
| Report at call site | -4 FP | +1 TP (dvga-019 log injection at correct file) |
| Separate endpoints | — | +3 TP (dvga-004, 005, 022 or 024) |
| Precise CWEs | -1 FP | +1 TP (dvga-028 as CWE-16) |
| Log injection at sink | — | +1 TP (dvga-019) |
| Jinja2 awareness | -1 FP | — |
| No rate-limiting/batch | -2 FP | — |
| **Total** | **-13 FP** | **+5-8 TP** |

**Projected scores**: TP≈25-28, FP≈7-10, FN≈3-6 → **F2≈78-88**
