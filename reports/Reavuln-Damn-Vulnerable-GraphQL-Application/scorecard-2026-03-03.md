# RealVuln Scorecard — dvga

**Commit:** `a961308c02d1`  
**Generated:** 2026-03-03T20:13:36.502793+00:00  
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

### kolega.dev-p9-r1

| Metric | Value |
|--------|-------|
| **F2 Score** | **53.6 / 100** |
| Precision | 40.9% |
| Recall | 58.1% |
| F1 | 0.480 |
| F2 | 0.536 |
| TP / FP / FN / TN | 18 / 26 / 13 / 4 |

### kolega.dev-p9-r2

| Metric | Value |
|--------|-------|
| **F2 Score** | **55.6 / 100** |
| Precision | 58.6% |
| Recall | 54.8% |
| F1 | 0.567 |
| F2 | 0.556 |
| TP / FP / FN / TN | 17 / 12 / 14 / 4 |

### kolega.dev-p9-r3

| Metric | Value |
|--------|-------|
| **F2 Score** | **43.2 / 100** |
| Precision | 36.8% |
| Recall | 45.2% |
| F1 | 0.406 |
| F2 | 0.432 |
| TP / FP / FN / TN | 14 / 24 / 17 / 4 |

---

## Scanner Comparison

| Scanner | F2 Score | TP | FP | FN | TN | Prec | Recall | F1 | F2 |
|---------|--------:|---:|---:|---:|---:|-----:|-------:|---:|---:|
| kolega.dev-p9-r1 | **53.6** | 18 | 26 | 13 | 4 | 0.409 | 0.581 | 0.480 | 0.536 |
| kolega.dev-p9-r2 | **55.6** | 17 | 12 | 14 | 4 | 0.586 | 0.548 | 0.567 | 0.556 |
| kolega.dev-p9-r3 | **43.2** | 14 | 24 | 17 | 4 | 0.368 | 0.452 | 0.406 | 0.432 |

---

## Per CWE Family Breakdown

### kolega.dev-p9-r1

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 1 | 0 | 1 | 1.000 | 0.500 |
| Command / OS Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Denial of Service | 1 | 0 | 0 | 1.000 | 1.000 |
| Hardcoded Credentials | 1 | 0 | 0 | 1.000 | 1.000 |
| Missing Authentication / Authorization | 1 | 0 | 4 | 1.000 | 0.200 |
| Other | 8 | 0 | 1 | 1.000 | 0.889 |
| Path Traversal | 1 | 0 | 0 | 1.000 | 1.000 |
| Security Misconfiguration | 1 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 3 | 1.000 | 0.250 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Server-Side Request Forgery | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 2 | 0.000 | 0.000 |

### kolega.dev-p9-r2

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 0 | 0 | 2 | 0.000 | 0.000 |
| Command / OS Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Denial of Service | 1 | 0 | 0 | 1.000 | 1.000 |
| Hardcoded Credentials | 1 | 0 | 0 | 1.000 | 1.000 |
| Missing Authentication / Authorization | 1 | 0 | 4 | 1.000 | 0.200 |
| Other | 6 | 0 | 3 | 1.000 | 0.667 |
| Path Traversal | 1 | 0 | 0 | 1.000 | 1.000 |
| Security Misconfiguration | 1 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 3 | 0 | 1 | 1.000 | 0.750 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Server-Side Request Forgery | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 2 | 0.000 | 0.000 |

### kolega.dev-p9-r3

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 0 | 0 | 2 | 0.000 | 0.000 |
| Command / OS Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Denial of Service | 0 | 0 | 1 | 0.000 | 0.000 |
| Hardcoded Credentials | 0 | 0 | 1 | 0.000 | 0.000 |
| Missing Authentication / Authorization | 1 | 0 | 4 | 1.000 | 0.200 |
| Other | 6 | 0 | 3 | 1.000 | 0.667 |
| Path Traversal | 1 | 0 | 0 | 1.000 | 1.000 |
| Security Misconfiguration | 1 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 3 | 1.000 | 0.250 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Server-Side Request Forgery | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 1 | 0 | 1 | 1.000 | 0.500 |

---

## Per Severity Breakdown

### kolega.dev-p9-r1

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 2 | 0 | 2 | 0.500 |
| High | 7 | 0 | 5 | 0.583 |
| Medium | 9 | 0 | 6 | 0.600 |

### kolega.dev-p9-r2

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 2 | 0 | 2 | 0.500 |
| High | 8 | 0 | 4 | 0.667 |
| Medium | 7 | 0 | 8 | 0.467 |

### kolega.dev-p9-r3

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 2 | 0 | 2 | 0.500 |
| High | 6 | 0 | 6 | 0.500 |
| Medium | 6 | 0 | 9 | 0.400 |

---

## Detailed Results

### kolega.dev-p9-r1

**True Positives (18):**

- ✅ `CWE-321` on `app.py`:L14 → matched **dvga-006**
- ✅ `CWE-347` on `core/helpers.py`:L21 → matched **dvga-007**
- ✅ `CWE-22` on `core/helpers.py`:L23 → matched **dvga-010**
- ✅ `CWE-16` on `core/security.py`:L37 → matched **dvga-028**
- ✅ `CWE-918` on `core/views.py`:L210 → matched **dvga-003**
- ✅ `CWE-78` on `core/views.py`:L352 → matched **dvga-004**
- ✅ `CWE-89` on `core/views.py`:L320 → matched **dvga-001**
- ✅ `CWE-639` on `core/views.py`:L164 → matched **dvga-014**
- ✅ `CWE-807` on `core/middleware.py`:L122 → matched **dvga-027**
- ✅ `CWE-693` on `core/middleware.py`:L111 → matched **dvga-029**
- ✅ `CWE-184` on `core/security.py`:L57 → matched **dvga-030**
- ✅ `CWE-209` on `core/view_override.py`:L48 → matched **dvga-011**
- ✅ `CWE-674` on `core/views.py`:L67 → matched **dvga-018**
- ✅ `CWE-312` on `setup.py`:L63 → matched **dvga-015**
- ✅ `CWE-331` on `core/helpers.py`:L15 → matched **dvga-026**
- ✅ `CWE-117` on `core/models.py`:L57 → matched **dvga-019**
- ✅ `CWE-256` on `core/models.py`:L14 → matched **dvga-020**
- ✅ `CWE-400` on `core/views.py`:L332 → matched **dvga-017**

**False Positives (26):**

- ❌ `CWE-79` on `core/views.py`:L429 → matched **—**
- ❌ `CWE-798` on `app.py`:L10 → matched **—**
- ❌ `CWE-22` on `core/views.py`:L186 → matched **—**
- ❌ `CWE-915` on `core/models.py`:L17 → matched **—**
- ❌ `CWE-312` on `core/models.py`:L98 → matched **—**
- ❌ `CWE-78` on `core/security.py`:L41 → matched **—**
- ❌ `CWE-307` on `core/views.py`:L233 → matched **—**
- ❌ `CWE-312` on `core/views.py`:L427 → matched **—**
- ❌ `CWE-200` on `templates/audit.html`:L33 → matched **—**
- ❌ `CWE-79` on `templates/paste.html`:L46 → matched **—**
- ❌ `CWE-200` on `core/models.py`:L9 → matched **—**
- ❌ `CWE-117` on `core/view_override.py`:L175 → matched **—**
- ❌ `CWE-770` on `core/views.py`:L508 → matched **—**
- ❌ `CWE-78` on `core/helpers.py`:L8 → matched **—**
- ❌ `CWE-862` on `core/views.py`:L61 → matched **—**
- ❌ `CWE-400` on `app.py`:L26 → matched **—**
- ❌ `CWE-693` on `core/security.py`:L57 → matched **—**
- ❌ `CWE-200` on `core/views.py`:L283 → matched **—**
- ❌ `CWE-200` on `templates/paste.html`:L73 → matched **—**
- ❌ `CWE-306` on `core/view_override.py`:L95 → matched **—**
- ❌ `CWE-400` on `core/security.py`:L8 → matched **—**
- ❌ `CWE-16` on `core/middleware.py`:L15 → matched **—**
- ❌ `CWE-807` on `core/view_override.py`:L43 → matched **—**
- ❌ `CWE-117` on `core/views.py`:L105 → matched **—**
- ❌ `CWE-209` on `core/views.py`:L340 → matched **—**
- ❌ `CWE-330` on `core/helpers.py`:L14 → matched **—**

**False Negatives (Missed) (13):**

- ⚠️ `CWE-78` on `core/views.py`:L211 — **dvga-002** (command_injection)
- ⚠️ `CWE-78` on `core/views.py`:L352 — **dvga-005** (command_injection)
- ⚠️ `CWE-79` on `templates/paste.html`:L132 — **dvga-008** (stored_xss)
- ⚠️ `CWE-79` on `templates/paste.html`:L65 — **dvga-009** (stored_xss)
- ⚠️ `CWE-862` on `core/views.py`:L385 — **dvga-012** (missing_authorization)
- ⚠️ `CWE-639` on `core/views.py`:L140 — **dvga-013** (idor)
- ⚠️ `CWE-200` on `core/views.py`:L61 — **dvga-016** (sensitive_data_exposure)
- ⚠️ `CWE-200` on `core/views.py`:L370 — **dvga-021** (sensitive_data_exposure)
- ⚠️ `CWE-306` on `core/views.py`:L426 — **dvga-022** (missing_authorization)
- ⚠️ `CWE-306` on `core/views.py`:L431 — **dvga-023** (missing_authorization)
- ⚠️ `CWE-306` on `core/views.py`:L441 — **dvga-024** (missing_authorization)
- ⚠️ `CWE-209` on `core/security.py`:L48 — **dvga-025** (sensitive_data_exposure)
- ⚠️ `CWE-312` on `core/models.py`:L25 — **dvga-031** (sensitive_data_exposure)

**True Negatives (4):**

- ⚪ `CWE-89` on `core/views.py`:L234 — **dvga-fp-001** (sql_injection)
- ⚪ `CWE-89` on `core/views.py`:L303 — **dvga-fp-002** (sql_injection)
- ⚪ `CWE-79` on `templates/audit.html`:L32 — **dvga-fp-003** (stored_xss)
- ⚪ `CWE-78` on `core/views.py`:L367 — **dvga-fp-004** (command_injection)

### kolega.dev-p9-r2

**True Positives (17):**

- ✅ `CWE-798` on `app.py`:L14 → matched **dvga-006**
- ✅ `CWE-347` on `core/helpers.py`:L21 → matched **dvga-007**
- ✅ `CWE-22` on `core/helpers.py`:L25 → matched **dvga-010**
- ✅ `CWE-256` on `core/models.py`:L9 → matched **dvga-020**
- ✅ `CWE-918` on `core/views.py`:L210 → matched **dvga-003**
- ✅ `CWE-78` on `core/views.py`:L352 → matched **dvga-004**
- ✅ `CWE-89` on `core/views.py`:L320 → matched **dvga-001**
- ✅ `CWE-200` on `core/views.py`:L61 → matched **dvga-016**
- ✅ `CWE-312` on `setup.py`:L63 → matched **dvga-015**
- ✅ `CWE-807` on `core/middleware.py`:L122 → matched **dvga-027**
- ✅ `CWE-532` on `core/models.py`:L25 → matched **dvga-031**
- ✅ `CWE-16` on `core/security.py`:L37 → matched **dvga-028**
- ✅ `CWE-184` on `core/security.py`:L57 → matched **dvga-030**
- ✅ `CWE-400` on `core/views.py`:L332 → matched **dvga-017**
- ✅ `CWE-674` on `core/views.py`:L67 → matched **dvga-018**
- ✅ `CWE-209` on `core/security.py`:L48 → matched **dvga-025**
- ✅ `CWE-209` on `core/view_override.py`:L47 → matched **dvga-011**

**False Positives (12):**

- ❌ `CWE-79` on `static/jquery/graphql.js` → matched **—**
- ❌ `CWE-321` on `app.py`:L15 → matched **—**
- ❌ `CWE-306` on `core/views.py`:L98 → matched **—**
- ❌ `CWE-22` on `core/views.py`:L186 → matched **—**
- ❌ `CWE-78` on `core/security.py`:L41 → matched **—**
- ❌ `CWE-307` on `core/views.py`:L337 → matched **—**
- ❌ `CWE-916` on `core/views.py`:L234 → matched **—**
- ❌ `CWE-862` on `core/views.py`:L314 → matched **—**
- ❌ `CWE-312` on `core/views.py`:L98 → matched **—**
- ❌ `CWE-400` on `app.py`:L26 → matched **—**
- ❌ `CWE-1004` on `core/views.py`:L395 → matched **—**
- ❌ `CWE-352` on `core/views.py`:L508 → matched **—**

**False Negatives (Missed) (14):**

- ⚠️ `CWE-78` on `core/views.py`:L211 — **dvga-002** (command_injection)
- ⚠️ `CWE-78` on `core/views.py`:L352 — **dvga-005** (command_injection)
- ⚠️ `CWE-79` on `templates/paste.html`:L132 — **dvga-008** (stored_xss)
- ⚠️ `CWE-79` on `templates/paste.html`:L65 — **dvga-009** (stored_xss)
- ⚠️ `CWE-862` on `core/views.py`:L385 — **dvga-012** (missing_authorization)
- ⚠️ `CWE-639` on `core/views.py`:L140 — **dvga-013** (idor)
- ⚠️ `CWE-639` on `core/views.py`:L164 — **dvga-014** (idor)
- ⚠️ `CWE-117` on `core/models.py`:L58 — **dvga-019** (log_injection)
- ⚠️ `CWE-200` on `core/views.py`:L370 — **dvga-021** (sensitive_data_exposure)
- ⚠️ `CWE-306` on `core/views.py`:L426 — **dvga-022** (missing_authorization)
- ⚠️ `CWE-306` on `core/views.py`:L431 — **dvga-023** (missing_authorization)
- ⚠️ `CWE-306` on `core/views.py`:L441 — **dvga-024** (missing_authorization)
- ⚠️ `CWE-330` on `core/helpers.py`:L14 — **dvga-026** (sensitive_data_exposure)
- ⚠️ `CWE-693` on `core/middleware.py`:L87 — **dvga-029** (security_misconfiguration)

**True Negatives (4):**

- ⚪ `CWE-89` on `core/views.py`:L234 — **dvga-fp-001** (sql_injection)
- ⚪ `CWE-89` on `core/views.py`:L303 — **dvga-fp-002** (sql_injection)
- ⚪ `CWE-79` on `templates/audit.html`:L32 — **dvga-fp-003** (stored_xss)
- ⚪ `CWE-78` on `core/views.py`:L367 — **dvga-fp-004** (command_injection)

### kolega.dev-p9-r3

**True Positives (14):**

- ✅ `CWE-798` on `app.py`:L15 → matched **dvga-006**
- ✅ `CWE-22` on `core/helpers.py`:L23 → matched **dvga-010**
- ✅ `CWE-78` on `core/views.py`:L352 → matched **dvga-004**
- ✅ `CWE-89` on `core/views.py`:L320 → matched **dvga-001**
- ✅ `CWE-16` on `core/security.py`:L37 → matched **dvga-028**
- ✅ `CWE-184` on `core/security.py`:L57 → matched **dvga-030**
- ✅ `CWE-209` on `core/view_override.py`:L47 → matched **dvga-011**
- ✅ `CWE-674` on `core/views.py`:L67 → matched **dvga-018**
- ✅ `CWE-79` on `templates/paste.html`:L65 → matched **dvga-009**
- ✅ `CWE-331` on `core/helpers.py`:L15 → matched **dvga-026**
- ✅ `CWE-117` on `core/models.py`:L59 → matched **dvga-019**
- ✅ `CWE-347` on `core/helpers.py`:L20 → matched **dvga-007**
- ✅ `CWE-256` on `core/models.py`:L14 → matched **dvga-020**
- ✅ `CWE-918` on `core/views.py`:L209 → matched **dvga-003**

**False Positives (24):**

- ❌ `CWE-306` on `core/views.py`:L98 → matched **—**
- ❌ `CWE-321` on `app.py`:L14 → matched **—**
- ❌ `CWE-78` on `core/helpers.py`:L8 → matched **—**
- ❌ `CWE-312` on `core/models.py`:L47 → matched **—**
- ❌ `CWE-22` on `core/views.py`:L186 → matched **—**
- ❌ `CWE-200` on `core/views.py`:L47 → matched **—**
- ❌ `CWE-489` on `config.py`:L11 → matched **—**
- ❌ `CWE-915` on `core/models.py`:L17 → matched **—**
- ❌ `CWE-78` on `core/security.py`:L41 → matched **—**
- ❌ `CWE-307` on `core/views.py`:L337 → matched **—**
- ❌ `CWE-312` on `core/views.py`:L233 → matched **—**
- ❌ `CWE-400` on `core/views.py`:L508 → matched **—**
- ❌ `CWE-117` on `core/view_override.py`:L175 → matched **—**
- ❌ `CWE-862` on `core/views.py`:L324 → matched **—**
- ❌ `CWE-916` on `core/views.py`:L234 → matched **—**
- ❌ `CWE-400` on `core/security.py`:L8 → matched **—**
- ❌ `CWE-256` on `core/views.py`:L339 → matched **—**
- ❌ `CWE-400` on `app.py`:L26 → matched **—**
- ❌ `CWE-330` on `core/helpers.py`:L14 → matched **—**
- ❌ `CWE-209` on `core/helpers.py`:L28 → matched **—**
- ❌ `CWE-670` on `core/middleware.py`:L35 → matched **—**
- ❌ `CWE-693` on `core/parser.py`:L5 → matched **—**
- ❌ `CWE-117` on `core/views.py`:L128 → matched **—**
- ❌ `CWE-200` on `templates/audit.html`:L33 → matched **—**

**False Negatives (Missed) (17):**

- ⚠️ `CWE-78` on `core/views.py`:L211 — **dvga-002** (command_injection)
- ⚠️ `CWE-78` on `core/views.py`:L352 — **dvga-005** (command_injection)
- ⚠️ `CWE-79` on `templates/paste.html`:L132 — **dvga-008** (stored_xss)
- ⚠️ `CWE-862` on `core/views.py`:L385 — **dvga-012** (missing_authorization)
- ⚠️ `CWE-639` on `core/views.py`:L140 — **dvga-013** (idor)
- ⚠️ `CWE-639` on `core/views.py`:L164 — **dvga-014** (idor)
- ⚠️ `CWE-798` on `setup.py`:L63 — **dvga-015** (hardcoded_credentials)
- ⚠️ `CWE-200` on `core/views.py`:L61 — **dvga-016** (sensitive_data_exposure)
- ⚠️ `CWE-400` on `core/views.py`:L333 — **dvga-017** (denial_of_service)
- ⚠️ `CWE-200` on `core/views.py`:L370 — **dvga-021** (sensitive_data_exposure)
- ⚠️ `CWE-306` on `core/views.py`:L426 — **dvga-022** (missing_authorization)
- ⚠️ `CWE-306` on `core/views.py`:L431 — **dvga-023** (missing_authorization)
- ⚠️ `CWE-306` on `core/views.py`:L441 — **dvga-024** (missing_authorization)
- ⚠️ `CWE-209` on `core/security.py`:L48 — **dvga-025** (sensitive_data_exposure)
- ⚠️ `CWE-807` on `core/middleware.py`:L122 — **dvga-027** (broken_access_control)
- ⚠️ `CWE-693` on `core/middleware.py`:L87 — **dvga-029** (security_misconfiguration)
- ⚠️ `CWE-312` on `core/models.py`:L25 — **dvga-031** (sensitive_data_exposure)

**True Negatives (4):**

- ⚪ `CWE-89` on `core/views.py`:L234 — **dvga-fp-001** (sql_injection)
- ⚪ `CWE-89` on `core/views.py`:L303 — **dvga-fp-002** (sql_injection)
- ⚪ `CWE-79` on `templates/audit.html`:L32 — **dvga-fp-003** (stored_xss)
- ⚪ `CWE-78` on `core/views.py`:L367 — **dvga-fp-004** (command_injection)
