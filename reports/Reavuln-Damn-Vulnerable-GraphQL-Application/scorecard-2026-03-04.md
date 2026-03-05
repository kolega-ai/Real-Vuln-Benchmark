# RealVuln Scorecard — dvga

**Commit:** `a961308c02d1`  
**Generated:** 2026-03-04T05:53:43.131782+00:00  
**Ground Truth:** 31 vulnerabilities, 4 false-positive traps  
**Repository:** https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application  
**Type:** 1 | **Language:** python | **Authorship:** human_authored

---

## How to Read This Report

### Classification

Every scanner finding and ground truth entry is classified into one of four categories:

| Classification | What it means |
|----------------|---------------|
| **True Positive (TP)** | Scanner correctly found a real vulnerability |
| **False Positive (FP)** | Scanner flagged something that isn't vulnerable (noise) |
| **False Negative (FN)** | Scanner missed a real vulnerability |
| **True Negative (TN)** | Scanner correctly ignored a false-positive trap (code that looks suspicious but is safe) |

### Metrics

| Metric | Formula | What it tells you |
|--------|---------|-------------------|
| **F2 Score** | F2 x 100 | **Primary metric.** Recall-weighted score on a 0–100 scale. Higher is better. See below. |
| **Precision** | TP / (TP + FP) | Of everything the scanner flagged, what fraction was actually vulnerable? High precision = low noise. |
| **Recall** | TP / (TP + FN) | Of all real vulnerabilities, what fraction did the scanner find? High recall = few missed vulns. |
| **F1** | 2 x (Prec x Recall) / (Prec + Recall) | Harmonic mean of precision and recall. Weights both equally. |
| **F2** | 5 x (Prec x Recall) / (4 x Prec + Recall) | F-beta with beta=2. Weights recall **4x more** than precision. Range 0–1. |

### Why F2 Score?

F2 Score is our primary metric because in security scanning, **missing a real vulnerability (false negative) is far more dangerous than a false alarm**. A false positive costs a developer 30 seconds to dismiss; a missed vulnerability can lead to a breach.

The F2 score uses beta=2, which weights recall 4x more than precision. This means a scanner that finds most real vulnerabilities but has some noise will score higher than a quiet scanner that misses critical issues.

| F2 Score | Rating |
|----------|--------|
| 80–100 | Excellent — catches nearly everything, manageable noise |
| 60–79 | Good — solid coverage, some gaps |
| 40–59 | Fair — missing significant vulns or too noisy |
| 20–39 | Poor — major gaps in detection |
| 0–19 | Failing — barely finding anything |

---

## Headline Results

### kolega.dev-snapshot-r1

| Metric | Value |
|--------|-------|
| **F2 Score** | **41.1 / 100** |
| Precision | 38.2% |
| Recall | 41.9% |
| F1 | 0.400 |
| F2 | 0.411 |
| TP / FP / FN / TN | 13 / 21 / 18 / 3 |

### kolega.dev-snapshot-r2

| Metric | Value |
|--------|-------|
| **F2 Score** | **36.5 / 100** |
| Precision | 24.1% |
| Recall | 41.9% |
| F1 | 0.306 |
| F2 | 0.365 |
| TP / FP / FN / TN | 13 / 41 / 18 / 3 |

### kolega.dev-snapshot-r3

| Metric | Value |
|--------|-------|
| **F2 Score** | **42.9 / 100** |
| Precision | 29.4% |
| Recall | 48.4% |
| F1 | 0.366 |
| F2 | 0.429 |
| TP / FP / FN / TN | 15 / 36 / 16 / 3 |

---

## Scanner Comparison

| Scanner | F2 Score | TP | FP | FN | TN | Prec | Recall | F1 | F2 |
|---------|--------:|---:|---:|---:|---:|-----:|-------:|---:|---:|
| kolega.dev-snapshot-r1 | **41.1** | 13 | 21 | 18 | 3 | 0.382 | 0.419 | 0.400 | 0.411 |
| kolega.dev-snapshot-r2 | **36.5** | 13 | 41 | 18 | 3 | 0.241 | 0.419 | 0.306 | 0.365 |
| kolega.dev-snapshot-r3 | **42.9** | 15 | 36 | 16 | 3 | 0.294 | 0.484 | 0.366 | 0.429 |

---

## Per CWE Family Breakdown

### kolega.dev-snapshot-r1

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 1 | 0 | 1 | 1.000 | 0.500 |
| Command / OS Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Denial of Service | 0 | 0 | 1 | 0.000 | 0.000 |
| Hardcoded Credentials | 1 | 0 | 0 | 1.000 | 1.000 |
| Missing Authentication / Authorization | 0 | 0 | 5 | 0.000 | 0.000 |
| Other | 3 | 0 | 6 | 1.000 | 0.333 |
| Path Traversal | 1 | 0 | 0 | 1.000 | 1.000 |
| Security Misconfiguration | 0 | 0 | 1 | 0.000 | 0.000 |
| Sensitive Data Exposure | 3 | 0 | 1 | 1.000 | 0.750 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Server-Side Request Forgery | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 1 | 1 | 1 | 0.500 | 0.500 |

### kolega.dev-snapshot-r2

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 0 | 0 | 2 | 0.000 | 0.000 |
| Command / OS Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Denial of Service | 0 | 0 | 1 | 0.000 | 0.000 |
| Hardcoded Credentials | 1 | 0 | 0 | 1.000 | 1.000 |
| Missing Authentication / Authorization | 2 | 0 | 3 | 1.000 | 0.400 |
| Other | 3 | 0 | 6 | 1.000 | 0.333 |
| Path Traversal | 1 | 0 | 0 | 1.000 | 1.000 |
| Security Misconfiguration | 0 | 0 | 1 | 0.000 | 0.000 |
| Sensitive Data Exposure | 2 | 0 | 2 | 1.000 | 0.500 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Server-Side Request Forgery | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 1 | 1 | 1 | 0.500 | 0.500 |

### kolega.dev-snapshot-r3

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 0 | 0 | 2 | 0.000 | 0.000 |
| Command / OS Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Denial of Service | 0 | 0 | 1 | 0.000 | 0.000 |
| Hardcoded Credentials | 1 | 0 | 0 | 1.000 | 1.000 |
| Missing Authentication / Authorization | 2 | 0 | 3 | 1.000 | 0.400 |
| Other | 3 | 0 | 6 | 1.000 | 0.333 |
| Path Traversal | 1 | 0 | 0 | 1.000 | 1.000 |
| Security Misconfiguration | 1 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 3 | 0 | 1 | 1.000 | 0.750 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Server-Side Request Forgery | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 1 | 1 | 1 | 0.500 | 0.500 |

---

## Per Severity Breakdown

### kolega.dev-snapshot-r1

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 2 | 0 | 2 | 0.500 |
| High | 7 | 0 | 5 | 0.583 |
| Medium | 4 | 1 | 11 | 0.267 |

### kolega.dev-snapshot-r2

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 2 | 0 | 2 | 0.500 |
| High | 8 | 0 | 4 | 0.667 |
| Medium | 3 | 1 | 12 | 0.200 |

### kolega.dev-snapshot-r3

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 3 | 0.250 |
| High | 7 | 0 | 5 | 0.583 |
| Medium | 7 | 1 | 8 | 0.467 |

---

## Detailed Results

### kolega.dev-snapshot-r1

**True Positives (13):**

- ✅ `CWE-798` on `app.py`:L14 → matched **dvga-006**
- ✅ `CWE-347` on `core/helpers.py`:L21 → matched **dvga-007**
- ✅ `CWE-22` on `core/helpers.py`:L25 → matched **dvga-010**
- ✅ `CWE-312` on `core/models.py`:L14 → matched **dvga-020**
- ✅ `CWE-862` on `core/views.py`:L140 → matched **dvga-013**
- ✅ `CWE-918` on `core/views.py`:L209 → matched **dvga-003**
- ✅ `CWE-78` on `core/views.py`:L211 → matched **dvga-002**
- ✅ `CWE-89` on `core/views.py`:L320 → matched **dvga-001**
- ✅ `CWE-312` on `setup.py`:L63 → matched **dvga-015**
- ✅ `CWE-79` on `templates/paste.html`:L65 → matched **dvga-009**
- ✅ `CWE-209` on `core/view_override.py`:L47 → matched **dvga-011**
- ✅ `CWE-200` on `core/views.py`:L370 → matched **dvga-021**
- ✅ `CWE-209` on `core/security.py`:L48 → matched **dvga-025**

**False Positives (21):**

- ❌ `CWE-321` on `app.py`:L15 → matched **—**
- ❌ `CWE-78` on `core/helpers.py`:L8 → matched **—**
- ❌ `CWE-306` on `core/views.py`:L118 → matched **—**
- ❌ `CWE-16` on `core/middleware.py`:L14 → matched **—**
- ❌ `CWE-863` on `core/middleware.py`:L15 → matched **—**
- ❌ `CWE-78` on `core/security.py`:L37 → matched **—**
- ❌ `CWE-307` on `core/views.py`:L233 → matched **—**
- ❌ `CWE-312` on `core/views.py`:L234 → matched **—**
- ❌ `CWE-352` on `core/views.py`:L508 → matched **—**
- ❌ `CWE-798` on `setup.py`:L49 → matched **—**
- ❌ `CWE-306` on `templates/audit.html`:L1 → matched **—**
- ❌ `CWE-79` on `templates/audit.html`:L32 → matched **dvga-fp-003**
- ❌ `CWE-200` on `templates/audit.html`:L32 → matched **—**
- ❌ `CWE-400` on `app.py`:L26 → matched **—**
- ❌ `CWE-209` on `core/helpers.py`:L28 → matched **—**
- ❌ `CWE-770` on `core/security.py`:L8 → matched **—**
- ❌ `CWE-770` on `core/views.py`:L185 → matched **—**
- ❌ `CWE-79` on `templates/index.html`:L15 → matched **—**
- ❌ `CWE-319` on `templates/paste.html`:L46 → matched **—**
- ❌ `CWE-312` on `tests/test_auth.py`:L33 → matched **—**
- ❌ `CWE-798` on `tests/test_auth.py`:L46 → matched **—**

**False Negatives (Missed) (18):**

- ⚠️ `CWE-78` on `core/views.py`:L345 — **dvga-004** (command_injection)
- ⚠️ `CWE-78` on `core/views.py`:L352 — **dvga-005** (command_injection)
- ⚠️ `CWE-79` on `templates/paste.html`:L132 — **dvga-008** (stored_xss)
- ⚠️ `CWE-862` on `core/views.py`:L385 — **dvga-012** (missing_authorization)
- ⚠️ `CWE-639` on `core/views.py`:L164 — **dvga-014** (idor)
- ⚠️ `CWE-200` on `core/views.py`:L61 — **dvga-016** (sensitive_data_exposure)
- ⚠️ `CWE-400` on `core/views.py`:L333 — **dvga-017** (denial_of_service)
- ⚠️ `CWE-674` on `core/views.py`:L67 — **dvga-018** (denial_of_service)
- ⚠️ `CWE-117` on `core/models.py`:L58 — **dvga-019** (log_injection)
- ⚠️ `CWE-306` on `core/views.py`:L426 — **dvga-022** (missing_authorization)
- ⚠️ `CWE-306` on `core/views.py`:L431 — **dvga-023** (missing_authorization)
- ⚠️ `CWE-306` on `core/views.py`:L441 — **dvga-024** (missing_authorization)
- ⚠️ `CWE-330` on `core/helpers.py`:L14 — **dvga-026** (sensitive_data_exposure)
- ⚠️ `CWE-807` on `core/middleware.py`:L122 — **dvga-027** (broken_access_control)
- ⚠️ `CWE-16` on `core/security.py`:L37 — **dvga-028** (security_misconfiguration)
- ⚠️ `CWE-693` on `core/middleware.py`:L87 — **dvga-029** (security_misconfiguration)
- ⚠️ `CWE-862` on `core/security.py`:L57 — **dvga-030** (security_misconfiguration)
- ⚠️ `CWE-312` on `core/models.py`:L25 — **dvga-031** (sensitive_data_exposure)

**True Negatives (3):**

- ⚪ `CWE-89` on `core/views.py`:L234 — **dvga-fp-001** (sql_injection)
- ⚪ `CWE-89` on `core/views.py`:L303 — **dvga-fp-002** (sql_injection)
- ⚪ `CWE-78` on `core/views.py`:L367 — **dvga-fp-004** (command_injection)

### kolega.dev-snapshot-r2

**True Positives (13):**

- ✅ `CWE-798` on `app.py`:L14 → matched **dvga-006**
- ✅ `CWE-347` on `core/helpers.py`:L21 → matched **dvga-007**
- ✅ `CWE-22` on `core/helpers.py`:L23 → matched **dvga-010**
- ✅ `CWE-916` on `core/models.py`:L14 → matched **dvga-020**
- ✅ `CWE-918` on `core/views.py`:L210 → matched **dvga-003**
- ✅ `CWE-89` on `core/views.py`:L319 → matched **dvga-001**
- ✅ `CWE-78` on `core/views.py`:L349 → matched **dvga-004**
- ✅ `CWE-862` on `core/views.py`:L385 → matched **dvga-012**
- ✅ `CWE-312` on `setup.py`:L63 → matched **dvga-015**
- ✅ `CWE-200` on `core/views.py`:L370 → matched **dvga-021**
- ✅ `CWE-79` on `templates/paste.html`:L65 → matched **dvga-009**
- ✅ `CWE-209` on `core/security.py`:L48 → matched **dvga-025**
- ✅ `CWE-693` on `core/security.py`:L57 → matched **dvga-030**

**False Positives (41):**

- ❌ `CWE-862` on `templates/audit.html`:L1 → matched **—**
- ❌ `CWE-321` on `app.py`:L15 → matched **—**
- ❌ `CWE-78` on `core/helpers.py`:L8 → matched **—**
- ❌ `CWE-862` on `core/middleware.py`:L15 → matched **—**
- ❌ `CWE-306` on `core/views.py`:L118 → matched **—**
- ❌ `CWE-22` on `core/views.py`:L185 → matched **—**
- ❌ `CWE-287` on `core/views.py`:L61 → matched **—**
- ❌ `CWE-798` on `setup.py`:L49 → matched **—**
- ❌ `CWE-862` on `tests/test_auth.py`:L34 → matched **—**
- ❌ `CWE-306` on `tests/test_queries.py`:L229 → matched **—**
- ❌ `CWE-863` on `core/middleware.py`:L14 → matched **—**
- ❌ `CWE-78` on `core/security.py`:L33 → matched **—**
- ❌ `CWE-209` on `core/view_override.py`:L21 → matched **—**
- ❌ `CWE-916` on `core/views.py`:L233 → matched **—**
- ❌ `CWE-312` on `core/views.py`:L234 → matched **—**
- ❌ `CWE-639` on `core/views.py`:L324 → matched **—**
- ❌ `CWE-863` on `core/views.py`:L468 → matched **—**
- ❌ `CWE-307` on `core/views.py`:L98 → matched **—**
- ❌ `CWE-79` on `templates/audit.html`:L32 → matched **dvga-fp-003**
- ❌ `CWE-306` on `tests/test_batching.py`:L20 → matched **—**
- ❌ `CWE-306` on `tests/test_mode.py`:L5 → matched **—**
- ❌ `CWE-306` on `tests/test_rollback.py`:L5 → matched **—**
- ❌ `CWE-312` on `app.py`:L10 → matched **—**
- ❌ `CWE-352` on `app.py`:L9 → matched **—**
- ❌ `CWE-489` on `config.py`:L11 → matched **—**
- ❌ `CWE-209` on `core/helpers.py`:L28 → matched **—**
- ❌ `CWE-16` on `core/middleware.py`:L116 → matched **—**
- ❌ `CWE-693` on `core/middleware.py`:L34 → matched **—**
- ❌ `CWE-1004` on `core/views.py`:L395 → matched **—**
- ❌ `CWE-352` on `core/views.py`:L431 → matched **—**
- ❌ `CWE-770` on `core/views.py`:L508 → matched **—**
- ❌ `CWE-79` on `templates/index.html`:L15 → matched **—**
- ❌ `CWE-352` on `templates/partials/pastes/create_paste.html`:L1 → matched **—**
- ❌ `CWE-352` on `templates/partials/pastes/import_paste.html`:L1 → matched **—**
- ❌ `CWE-352` on `templates/partials/pastes/upload_paste.html`:L1 → matched **—**
- ❌ `CWE-312` on `templates/partials/solutions/solution_11.html`:L25 → matched **—**
- ❌ `CWE-319` on `templates/paste.html`:L46 → matched **—**
- ❌ `CWE-312` on `tests/test_auth.py`:L46 → matched **—**
- ❌ `CWE-770` on `tests/test_batching.py`:L5 → matched **—**
- ❌ `CWE-209` on `tests/test_vulnerabilities.py`:L173 → matched **—**
- ❌ `CWE-200` on `core/middleware.py`:L105 → matched **—**

**False Negatives (Missed) (18):**

- ⚠️ `CWE-78` on `core/views.py`:L211 — **dvga-002** (command_injection)
- ⚠️ `CWE-78` on `core/views.py`:L352 — **dvga-005** (command_injection)
- ⚠️ `CWE-79` on `templates/paste.html`:L132 — **dvga-008** (stored_xss)
- ⚠️ `CWE-209` on `core/view_override.py`:L52 — **dvga-011** (sensitive_data_exposure)
- ⚠️ `CWE-639` on `core/views.py`:L140 — **dvga-013** (idor)
- ⚠️ `CWE-639` on `core/views.py`:L164 — **dvga-014** (idor)
- ⚠️ `CWE-200` on `core/views.py`:L61 — **dvga-016** (sensitive_data_exposure)
- ⚠️ `CWE-400` on `core/views.py`:L333 — **dvga-017** (denial_of_service)
- ⚠️ `CWE-674` on `core/views.py`:L67 — **dvga-018** (denial_of_service)
- ⚠️ `CWE-117` on `core/models.py`:L58 — **dvga-019** (log_injection)
- ⚠️ `CWE-306` on `core/views.py`:L426 — **dvga-022** (missing_authorization)
- ⚠️ `CWE-306` on `core/views.py`:L431 — **dvga-023** (missing_authorization)
- ⚠️ `CWE-306` on `core/views.py`:L441 — **dvga-024** (missing_authorization)
- ⚠️ `CWE-330` on `core/helpers.py`:L14 — **dvga-026** (sensitive_data_exposure)
- ⚠️ `CWE-807` on `core/middleware.py`:L122 — **dvga-027** (broken_access_control)
- ⚠️ `CWE-16` on `core/security.py`:L37 — **dvga-028** (security_misconfiguration)
- ⚠️ `CWE-693` on `core/middleware.py`:L87 — **dvga-029** (security_misconfiguration)
- ⚠️ `CWE-312` on `core/models.py`:L25 — **dvga-031** (sensitive_data_exposure)

**True Negatives (3):**

- ⚪ `CWE-89` on `core/views.py`:L234 — **dvga-fp-001** (sql_injection)
- ⚪ `CWE-89` on `core/views.py`:L303 — **dvga-fp-002** (sql_injection)
- ⚪ `CWE-78` on `core/views.py`:L367 — **dvga-fp-004** (command_injection)

### kolega.dev-snapshot-r3

**True Positives (15):**

- ✅ `CWE-798` on `app.py`:L14 → matched **dvga-006**
- ✅ `CWE-22` on `core/helpers.py`:L23 → matched **dvga-010**
- ✅ `CWE-918` on `core/views.py`:L209 → matched **dvga-003**
- ✅ `CWE-78` on `core/views.py`:L211 → matched **dvga-002**
- ✅ `CWE-89` on `core/views.py`:L320 → matched **dvga-001**
- ✅ `CWE-200` on `core/views.py`:L370 → matched **dvga-021**
- ✅ `CWE-862` on `core/views.py`:L385 → matched **dvga-012**
- ✅ `CWE-312` on `setup.py`:L63 → matched **dvga-015**
- ✅ `CWE-79` on `templates/paste.html`:L65 → matched **dvga-009**
- ✅ `CWE-78` on `core/middleware.py`:L87 → matched **dvga-029**
- ✅ `CWE-16` on `core/security.py`:L41 → matched **dvga-028**
- ✅ `CWE-862` on `core/security.py`:L57 → matched **dvga-030**
- ✅ `CWE-209` on `core/view_override.py`:L48 → matched **dvga-011**
- ✅ `CWE-312` on `core/models.py`:L25 → matched **dvga-031**
- ✅ `CWE-209` on `core/security.py`:L48 → matched **dvga-025**

**False Positives (36):**

- ❌ `CWE-321` on `app.py`:L15 → matched **—**
- ❌ `CWE-94` on `core/helpers.py`:L20 → matched **—**
- ❌ `CWE-78` on `core/helpers.py`:L8 → matched **—**
- ❌ `CWE-693` on `core/middleware.py`:L14 → matched **—**
- ❌ `CWE-862` on `core/middleware.py`:L15 → matched **—**
- ❌ `CWE-862` on `core/models.py`:L120 → matched **—**
- ❌ `CWE-22` on `core/models.py`:L14 → matched **—**
- ❌ `CWE-78` on `core/security.py`:L37 → matched **—**
- ❌ `CWE-916` on `core/security.py`:L52 → matched **—**
- ❌ `CWE-306` on `core/views.py`:L118 → matched **—**
- ❌ `CWE-22` on `core/views.py`:L185 → matched **—**
- ❌ `CWE-312` on `core/views.py`:L234 → matched **—**
- ❌ `CWE-798` on `setup.py`:L49 → matched **—**
- ❌ `CWE-200` on `core/helpers.py`:L21 → matched **—**
- ❌ `CWE-94` on `core/middleware.py`:L34 → matched **—**
- ❌ `CWE-16` on `core/middleware.py`:L92 → matched **—**
- ❌ `CWE-915` on `core/models.py`:L17 → matched **—**
- ❌ `CWE-306` on `core/view_override.py`:L158 → matched **—**
- ❌ `CWE-307` on `core/views.py`:L233 → matched **—**
- ❌ `CWE-352` on `core/views.py`:L508 → matched **—**
- ❌ `CWE-79` on `templates/audit.html`:L32 → matched **dvga-fp-003**
- ❌ `CWE-614` on `app.py`:L9 → matched **—**
- ❌ `CWE-862` on `core/helpers.py`:L14 → matched **—**
- ❌ `CWE-670` on `core/middleware.py`:L35 → matched **—**
- ❌ `CWE-79` on `core/middleware.py`:L82 → matched **—**
- ❌ `CWE-94` on `core/models.py`:L26 → matched **—**
- ❌ `CWE-79` on `core/view_override.py`:L47 → matched **—**
- ❌ `CWE-770` on `core/view_override.py`:L95 → matched **—**
- ❌ `CWE-209` on `core/views.py`:L340 → matched **—**
- ❌ `CWE-770` on `core/views.py`:L98 → matched **—**
- ❌ `CWE-16` on `setup.py`:L109 → matched **—**
- ❌ `CWE-79` on `templates/index.html`:L15 → matched **—**
- ❌ `CWE-352` on `templates/partials/pastes/create_paste.html`:L43 → matched **—**
- ❌ `CWE-319` on `templates/paste.html`:L46 → matched **—**
- ❌ `CWE-200` on `templates/paste.html`:L73 → matched **—**
- ❌ `CWE-770` on `app.py`:L26 → matched **—**

**False Negatives (Missed) (16):**

- ⚠️ `CWE-78` on `core/views.py`:L345 — **dvga-004** (command_injection)
- ⚠️ `CWE-78` on `core/views.py`:L352 — **dvga-005** (command_injection)
- ⚠️ `CWE-347` on `core/helpers.py`:L21 — **dvga-007** (broken_authentication)
- ⚠️ `CWE-79` on `templates/paste.html`:L132 — **dvga-008** (stored_xss)
- ⚠️ `CWE-639` on `core/views.py`:L140 — **dvga-013** (idor)
- ⚠️ `CWE-639` on `core/views.py`:L164 — **dvga-014** (idor)
- ⚠️ `CWE-200` on `core/views.py`:L61 — **dvga-016** (sensitive_data_exposure)
- ⚠️ `CWE-400` on `core/views.py`:L333 — **dvga-017** (denial_of_service)
- ⚠️ `CWE-674` on `core/views.py`:L67 — **dvga-018** (denial_of_service)
- ⚠️ `CWE-117` on `core/models.py`:L58 — **dvga-019** (log_injection)
- ⚠️ `CWE-916` on `core/models.py`:L14 — **dvga-020** (sensitive_data_exposure)
- ⚠️ `CWE-306` on `core/views.py`:L426 — **dvga-022** (missing_authorization)
- ⚠️ `CWE-306` on `core/views.py`:L431 — **dvga-023** (missing_authorization)
- ⚠️ `CWE-306` on `core/views.py`:L441 — **dvga-024** (missing_authorization)
- ⚠️ `CWE-330` on `core/helpers.py`:L14 — **dvga-026** (sensitive_data_exposure)
- ⚠️ `CWE-807` on `core/middleware.py`:L122 — **dvga-027** (broken_access_control)

**True Negatives (3):**

- ⚪ `CWE-89` on `core/views.py`:L234 — **dvga-fp-001** (sql_injection)
- ⚪ `CWE-89` on `core/views.py`:L303 — **dvga-fp-002** (sql_injection)
- ⚪ `CWE-78` on `core/views.py`:L367 — **dvga-fp-004** (command_injection)
