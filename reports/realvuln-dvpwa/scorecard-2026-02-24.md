# RealVuln Scorecard — dvpwa

**Commit:** `a1d8f89fac2e`  
**Generated:** 2026-02-24T21:16:02.961269+00:00  
**Ground Truth:** 21 vulnerabilities, 4 false-positive traps  
**Repository:** https://github.com/anxolerd/dvpwa  
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

### opus-4-6-3

| Metric | Value |
|--------|-------|
| **F2 Score** | **36.5 / 100** |
| Precision | 58.3% |
| Recall | 33.3% |
| F1 | 0.424 |
| F2 | 0.365 |
| TP / FP / FN / TN | 7 / 5 / 14 / 4 |

---

## Per CWE Family Breakdown

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 0 | 0 | 3 | 0.000 | 0.000 |
| Other | 3 | 0 | 5 | 1.000 | 0.375 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 5 | 0.000 | 0.000 |

---

## Per Severity Breakdown

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 1 | 0 | 1 | 0.500 |
| Medium | 2 | 0 | 10 | 0.167 |
| Low | 3 | 0 | 3 | 0.500 |

---

## Detailed Results

**True Positives (7):**

- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-489` on `sqli/app.py`:L24 → matched **dvpwa-015**
- ✅ `CWE-79` on `sqli/app.py`:L33 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L41 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**
- ✅ `CWE-319` on `sqli/services/db.py`:L15 → matched **dvpwa-021**

**False Positives (5):**

- ❌ `CWE-200` on `sqli/dao/user.py`:L21 → matched **—**
- ❌ `CWE-209` on `sqli/middlewares.py`:L61 → matched **—**
- ❌ `CWE-307` on `sqli/routes.py`:L10 → matched **—**
- ❌ `CWE-770` on `sqli/routes.py`:L13 → matched **—**
- ❌ `CWE-312` on `sqli/schema/config.py`:L12 → matched **—**

**False Negatives (Missed) (14):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L22 — **dvpwa-002** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/students.jinja2`:L16 — **dvpwa-003** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L14 — **dvpwa-004** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/courses.jinja2`:L17 — **dvpwa-005** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/student.jinja2`:L19 — **dvpwa-006** (stored_xss)
- ⚠️ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 — **dvpwa-011** (sensitive_data_exposure)
- ⚠️ `CWE-862` on `sqli/views.py`:L54 — **dvpwa-012** (security_misconfiguration)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-384` on `sqli/views.py`:L42 — **dvpwa-014** (security_misconfiguration)
- ⚠️ `CWE-306` on `sqli/schema/config.py`:L12 — **dvpwa-016** (security_misconfiguration)
- ⚠️ `CWE-307` on `sqli/views.py`:L33 — **dvpwa-017** (missing_rate_limiting)
- ⚠️ `CWE-307` on `sqli/views.py`:L50 — **dvpwa-018** (missing_rate_limiting)
- ⚠️ `CWE-312` on `sqli/utils/jinja2.py`:L19 — **dvpwa-019** (sensitive_data_exposure)
- ⚠️ `CWE-312` on `sqli/services/db.py`:L15 — **dvpwa-020** (sensitive_data_exposure)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)
