# RealVuln Scorecard — dvpwa

**Commit:** `a1d8f89fac2e`  
**Generated:** 2026-03-03T07:37:27.310233+00:00  
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

### kolega.dev-t6-c2-opus-4-6-p4-r1

| Metric | Value |
|--------|-------|
| **F2 Score** | **69.7 / 100** |
| Precision | 44.7% |
| Recall | 81.0% |
| F1 | 0.576 |
| F2 | 0.697 |
| TP / FP / FN / TN | 17 / 21 / 4 / 3 |

### kolega.dev-t6-c2-opus-4-6-p4-r2

| Metric | Value |
|--------|-------|
| **F2 Score** | **68.0 / 100** |
| Precision | 41.5% |
| Recall | 81.0% |
| F1 | 0.548 |
| F2 | 0.680 |
| TP / FP / FN / TN | 17 / 24 / 4 / 4 |

### kolega.dev-t6-c2-opus-4-6-p4-r3

| Metric | Value |
|--------|-------|
| **F2 Score** | **83.3 / 100** |
| Precision | 63.3% |
| Recall | 90.5% |
| F1 | 0.745 |
| F2 | 0.833 |
| TP / FP / FN / TN | 19 / 11 / 2 / 4 |

---

## Scanner Comparison

| Scanner | F2 Score | TP | FP | FN | TN | Prec | Recall | F1 | F2 |
|---------|--------:|---:|---:|---:|---:|-----:|-------:|---:|---:|
| kolega.dev-t6-c2-opus-4-6-p4-r1 | **69.7** | 17 | 21 | 4 | 3 | 0.447 | 0.810 | 0.576 | 0.697 |
| kolega.dev-t6-c2-opus-4-6-p4-r2 | **68.0** | 17 | 24 | 4 | 4 | 0.415 | 0.810 | 0.548 | 0.680 |
| kolega.dev-t6-c2-opus-4-6-p4-r3 | **83.3** | 19 | 11 | 2 | 4 | 0.633 | 0.905 | 0.745 | 0.833 |

---

## Per CWE Family Breakdown

### kolega.dev-t6-c2-opus-4-6-p4-r1

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 2 | 0 | 1 | 1.000 | 0.667 |
| Other | 6 | 0 | 2 | 1.000 | 0.750 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 1 | 0 | 0.500 | 1.000 |
| Cross-Site Scripting | 4 | 0 | 1 | 1.000 | 0.800 |

### kolega.dev-t6-c2-opus-4-6-p4-r2

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 2 | 0 | 1 | 1.000 | 0.667 |
| Other | 6 | 0 | 2 | 1.000 | 0.750 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 4 | 0 | 1 | 1.000 | 0.800 |

### kolega.dev-t6-c2-opus-4-6-p4-r3

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 3 | 0 | 0 | 1.000 | 1.000 |
| Other | 7 | 0 | 1 | 1.000 | 0.875 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 4 | 0 | 1 | 1.000 | 0.800 |

---

## Per Severity Breakdown

### kolega.dev-t6-c2-opus-4-6-p4-r1

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 2 | 1 | 0 | 1.000 |
| Medium | 9 | 0 | 3 | 0.750 |
| Low | 5 | 0 | 1 | 0.833 |

### kolega.dev-t6-c2-opus-4-6-p4-r2

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 2 | 0 | 0 | 1.000 |
| Medium | 9 | 0 | 3 | 0.750 |
| Low | 5 | 0 | 1 | 0.833 |

### kolega.dev-t6-c2-opus-4-6-p4-r3

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 2 | 0 | 0 | 1.000 |
| Medium | 11 | 0 | 1 | 0.917 |
| Low | 5 | 0 | 1 | 0.833 |

---

## Detailed Results

### kolega.dev-t6-c2-opus-4-6-p4-r1

**True Positives (17):**

- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-489` on `sqli/app.py`:L24 → matched **dvpwa-015**
- ✅ `CWE-79` on `sqli/app.py`:L33 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L41 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**
- ✅ `CWE-306` on `sqli/schema/config.py`:L12 → matched **dvpwa-016**
- ✅ `CWE-319` on `sqli/services/db.py`:L15 → matched **dvpwa-021**
- ✅ `CWE-79` on `sqli/templates/course.jinja2`:L9 → matched **dvpwa-004**
- ✅ `CWE-79` on `sqli/templates/courses.jinja2`:L17 → matched **dvpwa-005**
- ✅ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 → matched **dvpwa-011**
- ✅ `CWE-79` on `sqli/templates/student.jinja2`:L19 → matched **dvpwa-006**
- ✅ `CWE-79` on `sqli/templates/students.jinja2`:L16 → matched **dvpwa-003**
- ✅ `CWE-307` on `sqli/views.py`:L33 → matched **dvpwa-017**
- ✅ `CWE-384` on `sqli/views.py`:L33 → matched **dvpwa-014**
- ✅ `CWE-770` on `sqli/views.py`:L86 → matched **dvpwa-018**
- ✅ `CWE-862` on `sqli/views.py`:L54 → matched **dvpwa-012**

**False Positives (21):**

- ❌ `CWE-798` on `config/dev.yaml`:L2 → matched **—**
- ❌ `CWE-16` on `docker-compose.yml`:L11 → matched **—**
- ❌ `CWE-284` on `docker-compose.yml`:L8 → matched **—**
- ❌ `CWE-312` on `sqli/app.py`:L34 → matched **—**
- ❌ `CWE-89` on `sqli/dao/course.py`:L37 → matched **dvpwa-fp-003**
- ❌ `CWE-862` on `sqli/dao/mark.py`:L19 → matched **—**
- ❌ `CWE-862` on `sqli/dao/student.py`:L25 → matched **—**
- ❌ `CWE-200` on `sqli/dao/user.py`:L21 → matched **—**
- ❌ `CWE-312` on `sqli/dao/user.py`:L23 → matched **—**
- ❌ `CWE-209` on `sqli/middlewares.py`:L62 → matched **—**
- ❌ `CWE-306` on `sqli/routes.py`:L14 → matched **—**
- ❌ `CWE-307` on `sqli/routes.py`:L11 → matched **—**
- ❌ `CWE-770` on `sqli/routes.py`:L18 → matched **—**
- ❌ `CWE-862` on `sqli/routes.py`:L15 → matched **—**
- ❌ `CWE-306` on `sqli/services/redis.py`:L12 → matched **—**
- ❌ `CWE-79` on `sqli/templates/base.jinja2`:L25 → matched **—**
- ❌ `CWE-79` on `sqli/templates/evaluate.jinja2`:L25 → matched **—**
- ❌ `CWE-79` on `sqli/templates/review.jinja2`:L32 → matched **—**
- ❌ `CWE-306` on `sqli/views.py`:L119 → matched **—**
- ❌ `CWE-312` on `sqli/views.py`:L46 → matched **—**
- ❌ `CWE-89` on `sqli/views.py`:L57 → matched **—**

**False Negatives (Missed) (4):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L22 — **dvpwa-002** (stored_xss)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-312` on `sqli/utils/jinja2.py`:L19 — **dvpwa-019** (sensitive_data_exposure)
- ⚠️ `CWE-312` on `sqli/services/db.py`:L15 — **dvpwa-020** (sensitive_data_exposure)

**True Negatives (3):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### kolega.dev-t6-c2-opus-4-6-p4-r2

**True Positives (17):**

- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-489` on `sqli/app.py`:L24 → matched **dvpwa-015**
- ✅ `CWE-79` on `sqli/app.py`:L33 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L41 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**
- ✅ `CWE-306` on `sqli/schema/config.py`:L12 → matched **dvpwa-016**
- ✅ `CWE-319` on `sqli/services/db.py`:L15 → matched **dvpwa-021**
- ✅ `CWE-79` on `sqli/templates/course.jinja2`:L9 → matched **dvpwa-004**
- ✅ `CWE-79` on `sqli/templates/courses.jinja2`:L17 → matched **dvpwa-005**
- ✅ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 → matched **dvpwa-011**
- ✅ `CWE-79` on `sqli/templates/student.jinja2`:L19 → matched **dvpwa-006**
- ✅ `CWE-79` on `sqli/templates/students.jinja2`:L16 → matched **dvpwa-003**
- ✅ `CWE-312` on `sqli/utils/jinja2.py`:L19 → matched **dvpwa-019**
- ✅ `CWE-306` on `sqli/views.py`:L54 → matched **dvpwa-012**
- ✅ `CWE-307` on `sqli/views.py`:L33 → matched **dvpwa-017**
- ✅ `CWE-384` on `sqli/views.py`:L33 → matched **dvpwa-014**

**False Positives (24):**

- ❌ `CWE-798` on `config/dev.yaml`:L2 → matched **—**
- ❌ `CWE-284` on `docker-compose.yml`:L8 → matched **—**
- ❌ `CWE-312` on `sqli/app.py`:L34 → matched **—**
- ❌ `CWE-862` on `sqli/dao/mark.py`:L29 → matched **—**
- ❌ `CWE-862` on `sqli/dao/review.py`:L28 → matched **—**
- ❌ `CWE-862` on `sqli/dao/student.py`:L25 → matched **—**
- ❌ `CWE-200` on `sqli/dao/user.py`:L21 → matched **—**
- ❌ `CWE-312` on `sqli/dao/user.py`:L7 → matched **—**
- ❌ `CWE-209` on `sqli/middlewares.py`:L61 → matched **—**
- ❌ `CWE-307` on `sqli/routes.py`:L10 → matched **—**
- ❌ `CWE-770` on `sqli/routes.py`:L14 → matched **—**
- ❌ `CWE-916` on `sqli/schema/config.py`:L1 → matched **—**
- ❌ `CWE-79` on `sqli/templates/base.jinja2`:L25 → matched **—**
- ❌ `CWE-79` on `sqli/templates/evaluate.jinja2`:L25 → matched **—**
- ❌ `CWE-79` on `sqli/templates/index.jinja2`:L5 → matched **—**
- ❌ `CWE-79` on `sqli/templates/review.jinja2`:L32 → matched **—**
- ❌ `CWE-384` on `sqli/utils/auth.py`:L26 → matched **—**
- ❌ `CWE-862` on `sqli/utils/auth.py`:L12 → matched **—**
- ❌ `CWE-352` on `sqli/utils/jinja2.py`:L8 → matched **—**
- ❌ `CWE-20` on `sqli/views.py`:L55 → matched **—**
- ❌ `CWE-200` on `sqli/views.py`:L58 → matched **—**
- ❌ `CWE-312` on `sqli/views.py`:L46 → matched **—**
- ❌ `CWE-862` on `sqli/views.py`:L63 → matched **—**
- ❌ `CWE-89` on `sqli/views.py`:L57 → matched **—**

**False Negatives (Missed) (4):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L22 — **dvpwa-002** (stored_xss)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-307` on `sqli/views.py`:L50 — **dvpwa-018** (missing_rate_limiting)
- ⚠️ `CWE-312` on `sqli/services/db.py`:L15 — **dvpwa-020** (sensitive_data_exposure)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### kolega.dev-t6-c2-opus-4-6-p4-r3

**True Positives (19):**

- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-489` on `sqli/app.py`:L24 → matched **dvpwa-015**
- ✅ `CWE-79` on `sqli/app.py`:L33 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L41 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**
- ✅ `CWE-306` on `sqli/schema/config.py`:L12 → matched **dvpwa-016**
- ✅ `CWE-319` on `sqli/services/db.py`:L15 → matched **dvpwa-021**
- ✅ `CWE-79` on `sqli/templates/course.jinja2`:L14 → matched **dvpwa-002**
- ✅ `CWE-79` on `sqli/templates/courses.jinja2`:L17 → matched **dvpwa-005**
- ✅ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 → matched **dvpwa-011**
- ✅ `CWE-79` on `sqli/templates/student.jinja2`:L19 → matched **dvpwa-006**
- ✅ `CWE-79` on `sqli/templates/students.jinja2`:L16 → matched **dvpwa-003**
- ✅ `CWE-312` on `sqli/utils/jinja2.py`:L19 → matched **dvpwa-019**
- ✅ `CWE-306` on `sqli/views.py`:L54 → matched **dvpwa-012**
- ✅ `CWE-307` on `sqli/views.py`:L23 → matched **dvpwa-017**
- ✅ `CWE-384` on `sqli/views.py`:L33 → matched **dvpwa-014**
- ✅ `CWE-770` on `sqli/views.py`:L52 → matched **dvpwa-018**
- ✅ `CWE-862` on `sqli/views.py`:L86 → matched **dvpwa-013**

**False Positives (11):**

- ❌ `CWE-306` on `config/dev.yaml`:L8 → matched **—**
- ❌ `CWE-312` on `config/dev.yaml`:L3 → matched **—**
- ❌ `CWE-798` on `config/dev.yaml`:L2 → matched **—**
- ❌ `CWE-284` on `docker-compose.yml`:L8 → matched **—**
- ❌ `CWE-209` on `sqli/middlewares.py`:L68 → matched **—**
- ❌ `CWE-312` on `sqli/schema/config.py`:L12 → matched **—**
- ❌ `CWE-306` on `sqli/services/redis.py`:L12 → matched **—**
- ❌ `CWE-79` on `sqli/templates/base.jinja2`:L25 → matched **—**
- ❌ `CWE-79` on `sqli/templates/evaluate.jinja2`:L25 → matched **—**
- ❌ `CWE-79` on `sqli/templates/index.jinja2`:L5 → matched **—**
- ❌ `CWE-79` on `sqli/templates/review.jinja2`:L32 → matched **—**

**False Negatives (Missed) (2):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L14 — **dvpwa-004** (stored_xss)
- ⚠️ `CWE-312` on `sqli/services/db.py`:L15 — **dvpwa-020** (sensitive_data_exposure)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)
