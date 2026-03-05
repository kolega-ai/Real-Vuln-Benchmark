# RealVuln Scorecard — dvga

**Commit:** `a961308c02d1`  
**Generated:** 2026-03-02T20:25:07.634510+00:00  
**Ground Truth:** 19 vulnerabilities, 4 false-positive traps  
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

### our-scanner

| Metric | Value |
|--------|-------|
| **F2 Score** | **38.8 / 100** |
| Precision | 22.5% |
| Recall | 47.4% |
| F1 | 0.305 |
| F2 | 0.388 |
| TP / FP / FN / TN | 9 / 31 / 10 / 4 |

### sonarqube

| Metric | Value |
|--------|-------|
| **F2 Score** | **17.4 / 100** |
| Precision | 30.0% |
| Recall | 15.8% |
| F1 | 0.207 |
| F2 | 0.174 |
| TP / FP / FN / TN | 3 / 7 / 16 / 4 |

---

## Scanner Comparison

| Scanner | F2 Score | TP | FP | FN | TN | Prec | Recall | F1 | F2 |
|---------|--------:|---:|---:|---:|---:|-----:|-------:|---:|---:|
| our-scanner | **38.8** | 9 | 31 | 10 | 4 | 0.225 | 0.474 | 0.305 | 0.388 |
| sonarqube | **17.4** | 3 | 7 | 16 | 4 | 0.300 | 0.158 | 0.207 | 0.174 |

---

## Per CWE Family Breakdown

### our-scanner

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 0 | 0 | 2 | 0.000 | 0.000 |
| Command / OS Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Denial of Service | 0 | 0 | 1 | 0.000 | 0.000 |
| Hardcoded Credentials | 1 | 0 | 0 | 1.000 | 1.000 |
| Missing Authentication / Authorization | 0 | 0 | 1 | 0.000 | 0.000 |
| Other | 2 | 0 | 2 | 1.000 | 0.500 |
| Path Traversal | 1 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 2 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Server-Side Request Forgery | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 2 | 0.000 | 0.000 |

### sonarqube

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 0 | 0 | 2 | 0.000 | 0.000 |
| Command / OS Injection | 0 | 0 | 3 | 0.000 | 0.000 |
| Denial of Service | 0 | 0 | 1 | 0.000 | 0.000 |
| Hardcoded Credentials | 0 | 0 | 1 | 0.000 | 0.000 |
| Missing Authentication / Authorization | 0 | 0 | 1 | 0.000 | 0.000 |
| Other | 2 | 0 | 2 | 1.000 | 0.500 |
| Path Traversal | 1 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 0 | 0 | 2 | 0.000 | 0.000 |
| SQL Injection | 0 | 0 | 1 | 0.000 | 0.000 |
| Server-Side Request Forgery | 0 | 0 | 1 | 0.000 | 0.000 |
| Cross-Site Scripting | 0 | 0 | 2 | 0.000 | 0.000 |

---

## Per Severity Breakdown

### our-scanner

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 2 | 0 | 2 | 0.500 |
| High | 6 | 0 | 2 | 0.750 |
| Medium | 1 | 0 | 6 | 0.143 |

### sonarqube

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 3 | 0.250 |
| High | 2 | 0 | 6 | 0.250 |
| Medium | 0 | 0 | 7 | 0.000 |

---

## Detailed Results

### our-scanner

**True Positives (9):**

- ✅ `CWE-321` on `app.py`:L15 → matched **dvga-006**
- ✅ `CWE-22` on `core/helpers.py`:L23 → matched **dvga-010**
- ✅ `CWE-347` on `core/helpers.py`:L21 → matched **dvga-007**
- ✅ `CWE-209` on `core/view_override.py`:L48 → matched **dvga-011**
- ✅ `CWE-522` on `core/views.py`:L61 → matched **dvga-016**
- ✅ `CWE-78` on `core/views.py`:L352 → matched **dvga-004**
- ✅ `CWE-89` on `core/views.py`:L320 → matched **dvga-001**
- ✅ `CWE-918` on `core/views.py`:L209 → matched **dvga-003**
- ✅ `CWE-798` on `setup.py`:L64 → matched **dvga-015**

**False Positives (31):**

- ❌ `CWE-400` on `app.py`:L26 → matched **—**
- ❌ `CWE-613` on `app.py`:L16 → matched **—**
- ❌ `CWE-22` on `config.py`:L12 → matched **—**
- ❌ `CWE-400` on `config.py`:L15 → matched **—**
- ❌ `CWE-552` on `config.py`:L4 → matched **—**
- ❌ `CWE-94` on `config.py`:L11 → matched **—**
- ❌ `CWE-209` on `core/helpers.py`:L28 → matched **—**
- ❌ `CWE-330` on `core/helpers.py`:L14 → matched **—**
- ❌ `CWE-78` on `core/helpers.py`:L8 → matched **—**
- ❌ `CWE-284` on `core/middleware.py`:L116 → matched **—**
- ❌ `CWE-670` on `core/middleware.py`:L34 → matched **—**
- ❌ `CWE-256` on `core/models.py`:L14 → matched **—**
- ❌ `CWE-284` on `core/parser.py`:L1 → matched **—**
- ❌ `CWE-400` on `core/parser.py`:L5 → matched **—**
- ❌ `CWE-307` on `core/security.py`:L48 → matched **—**
- ❌ `CWE-693` on `core/security.py`:L37 → matched **—**
- ❌ `CWE-78` on `core/security.py`:L41 → matched **—**
- ❌ `CWE-117` on `core/view_override.py`:L175 → matched **—**
- ❌ `CWE-20` on `core/views.py`:L92 → matched **—**
- ❌ `CWE-200` on `core/views.py`:L491 → matched **—**
- ❌ `CWE-22` on `core/views.py`:L186 → matched **—**
- ❌ `CWE-256` on `core/views.py`:L234 → matched **—**
- ❌ `CWE-284` on `core/views.py`:L258 → matched **—**
- ❌ `CWE-295` on `core/views.py`:L211 → matched **—**
- ❌ `CWE-306` on `core/views.py` → matched **—**
- ❌ `CWE-307` on `core/views.py`:L225 → matched **—**
- ❌ `CWE-400` on `core/views.py`:L508 → matched **—**
- ❌ `CWE-614` on `core/views.py`:L395 → matched **—**
- ❌ `CWE-639` on `core/views.py` → matched **—**
- ❌ `CWE-256` on `setup.py`:L63 → matched **—**
- ❌ `CWE-521` on `setup.py`:L48 → matched **—**

**False Negatives (Missed) (10):**

- ⚠️ `CWE-78` on `core/views.py`:L211 — **dvga-002** (command_injection)
- ⚠️ `CWE-78` on `core/views.py`:L352 — **dvga-005** (command_injection)
- ⚠️ `CWE-79` on `templates/paste.html`:L132 — **dvga-008** (stored_xss)
- ⚠️ `CWE-79` on `templates/paste.html`:L65 — **dvga-009** (stored_xss)
- ⚠️ `CWE-862` on `core/views.py`:L385 — **dvga-012** (missing_authorization)
- ⚠️ `CWE-639` on `core/views.py`:L140 — **dvga-013** (idor)
- ⚠️ `CWE-639` on `core/views.py`:L164 — **dvga-014** (idor)
- ⚠️ `CWE-400` on `core/views.py`:L333 — **dvga-017** (denial_of_service)
- ⚠️ `CWE-674` on `core/views.py`:L40 — **dvga-018** (denial_of_service)
- ⚠️ `CWE-117` on `core/models.py`:L58 — **dvga-019** (log_injection)

**True Negatives (4):**

- ⚪ `CWE-89` on `core/views.py`:L234 — **dvga-fp-001** (sql_injection)
- ⚪ `CWE-89` on `core/views.py`:L303 — **dvga-fp-002** (sql_injection)
- ⚪ `CWE-79` on `templates/audit.html`:L32 — **dvga-fp-003** (stored_xss)
- ⚪ `CWE-78` on `core/views.py`:L367 — **dvga-fp-004** (command_injection)

### sonarqube

**True Positives (3):**

- ✅ `CWE-259` on `app.py`:L14 → matched **dvga-006**
- ✅ `CWE-22` on `core/helpers.py`:L25 → matched **dvga-010**
- ✅ `CWE-347` on `core/helpers.py`:L21 → matched **dvga-007**

**False Positives (7):**

- ❌ `CWE-798` on `app.py`:L14 → matched **—**
- ❌ `CWE-78` on `core/helpers.py`:L9 → matched **—**
- ❌ `CWE-209` on `core/views.py`:L522 → matched **—**
- ❌ `CWE-489` on `core/views.py`:L522 → matched **—**
- ❌ `CWE-295` on `tests/common.py`:L19 → matched **—**
- ❌ `CWE-295` on `tests/test_graphiql.py`:L11 → matched **—**
- ❌ `CWE-295` on `tests/test_graphql.py`:L11 → matched **—**

**False Negatives (Missed) (16):**

- ⚠️ `CWE-89` on `core/views.py`:L320 — **dvga-001** (sql_injection)
- ⚠️ `CWE-78` on `core/views.py`:L211 — **dvga-002** (command_injection)
- ⚠️ `CWE-918` on `core/views.py`:L210 — **dvga-003** (ssrf)
- ⚠️ `CWE-78` on `core/views.py`:L345 — **dvga-004** (command_injection)
- ⚠️ `CWE-78` on `core/views.py`:L352 — **dvga-005** (command_injection)
- ⚠️ `CWE-79` on `templates/paste.html`:L132 — **dvga-008** (stored_xss)
- ⚠️ `CWE-79` on `templates/paste.html`:L65 — **dvga-009** (stored_xss)
- ⚠️ `CWE-209` on `core/view_override.py`:L52 — **dvga-011** (sensitive_data_exposure)
- ⚠️ `CWE-862` on `core/views.py`:L385 — **dvga-012** (missing_authorization)
- ⚠️ `CWE-639` on `core/views.py`:L140 — **dvga-013** (idor)
- ⚠️ `CWE-639` on `core/views.py`:L164 — **dvga-014** (idor)
- ⚠️ `CWE-798` on `setup.py`:L63 — **dvga-015** (hardcoded_credentials)
- ⚠️ `CWE-200` on `core/views.py`:L61 — **dvga-016** (sensitive_data_exposure)
- ⚠️ `CWE-400` on `core/views.py`:L333 — **dvga-017** (denial_of_service)
- ⚠️ `CWE-674` on `core/views.py`:L40 — **dvga-018** (denial_of_service)
- ⚠️ `CWE-117` on `core/models.py`:L58 — **dvga-019** (log_injection)

**True Negatives (4):**

- ⚪ `CWE-89` on `core/views.py`:L234 — **dvga-fp-001** (sql_injection)
- ⚪ `CWE-89` on `core/views.py`:L303 — **dvga-fp-002** (sql_injection)
- ⚪ `CWE-79` on `templates/audit.html`:L32 — **dvga-fp-003** (stored_xss)
- ⚪ `CWE-78` on `core/views.py`:L367 — **dvga-fp-004** (command_injection)
