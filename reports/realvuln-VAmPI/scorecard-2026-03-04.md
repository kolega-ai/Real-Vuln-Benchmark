# RealVuln Scorecard — vampi

**Commit:** `1713b54b601a`  
**Generated:** 2026-03-04T05:53:43.977389+00:00  
**Ground Truth:** 10 vulnerabilities, 4 false-positive traps  
**Repository:** https://github.com/erev0s/VAmPI  
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
| **F2 Score** | **41.7 / 100** |
| Precision | 18.8% |
| Recall | 60.0% |
| F1 | 0.286 |
| F2 | 0.417 |
| TP / FP / FN / TN | 6 / 26 / 4 / 3 |

### kolega.dev-snapshot-r2

| Metric | Value |
|--------|-------|
| **F2 Score** | **32.9 / 100** |
| Precision | 13.9% |
| Recall | 50.0% |
| F1 | 0.217 |
| F2 | 0.329 |
| TP / FP / FN / TN | 5 / 31 / 5 / 4 |

### kolega.dev-snapshot-r3

| Metric | Value |
|--------|-------|
| **F2 Score** | **58.8 / 100** |
| Precision | 28.6% |
| Recall | 80.0% |
| F1 | 0.421 |
| F2 | 0.588 |
| TP / FP / FN / TN | 8 / 20 / 2 / 4 |

---

## Scanner Comparison

| Scanner | F2 Score | TP | FP | FN | TN | Prec | Recall | F1 | F2 |
|---------|--------:|---:|---:|---:|---:|-----:|-------:|---:|---:|
| kolega.dev-snapshot-r1 | **41.7** | 6 | 26 | 4 | 3 | 0.188 | 0.600 | 0.286 | 0.417 |
| kolega.dev-snapshot-r2 | **32.9** | 5 | 31 | 5 | 4 | 0.139 | 0.500 | 0.217 | 0.329 |
| kolega.dev-snapshot-r3 | **58.8** | 8 | 20 | 2 | 4 | 0.286 | 0.800 | 0.421 | 0.588 |

---

## Per CWE Family Breakdown

### kolega.dev-snapshot-r1

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 2 | 0 | 0 | 1.000 | 1.000 |
| Denial of Service | 0 | 0 | 1 | 0.000 | 0.000 |
| Other | 2 | 0 | 3 | 1.000 | 0.400 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 1 | 0 | 0.500 | 1.000 |

### kolega.dev-snapshot-r2

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 1 | 0 | 1 | 1.000 | 0.500 |
| Denial of Service | 0 | 0 | 1 | 0.000 | 0.000 |
| Other | 2 | 0 | 3 | 1.000 | 0.400 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |

### kolega.dev-snapshot-r3

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 2 | 0 | 0 | 1.000 | 1.000 |
| Denial of Service | 0 | 0 | 1 | 0.000 | 0.000 |
| Other | 4 | 0 | 1 | 1.000 | 0.800 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |

---

## Per Severity Breakdown

### kolega.dev-snapshot-r1

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 3 | 1 | 1 | 0.750 |
| Medium | 2 | 0 | 2 | 0.500 |
| Low | 0 | 0 | 1 | 0.000 |

### kolega.dev-snapshot-r2

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 2 | 0 | 2 | 0.500 |
| Medium | 2 | 0 | 2 | 0.500 |
| Low | 0 | 0 | 1 | 0.000 |

### kolega.dev-snapshot-r3

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 4 | 0 | 0 | 1.000 |
| Medium | 2 | 0 | 2 | 0.500 |
| Low | 1 | 0 | 0 | 1.000 |

---

## Detailed Results

### kolega.dev-snapshot-r1

**True Positives (6):**

- ✅ `CWE-862` on `api_views/books.py`:L50 → matched **vampi-003**
- ✅ `CWE-862` on `api_views/users.py`:L186 → matched **vampi-002**
- ✅ `CWE-798` on `config.py`:L13 → matched **vampi-008**
- ✅ `CWE-89` on `models/user_model.py`:L72 → matched **vampi-001**
- ✅ `CWE-1333` on `api_views/users.py`:L144 → matched **vampi-007**
- ✅ `CWE-306` on `api_views/users.py`:L19 → matched **vampi-005**

**False Positives (26):**

- ❌ `CWE-306` on `api_views/books.py`:L12 → matched **—**
- ❌ `CWE-306` on `api_views/main.py`:L6 → matched **—**
- ❌ `CWE-22` on `api_views/users.py`:L24 → matched **—**
- ❌ `CWE-94` on `api_views/users.py`:L60 → matched **—**
- ❌ `CWE-916` on `api_views/users.py`:L65 → matched **—**
- ❌ `CWE-312` on `api_views/users.py`:L93 → matched **—**
- ❌ `CWE-312` on `models/user_model.py`:L24 → matched **—**
- ❌ `CWE-200` on `models/user_model.py`:L58 → matched **—**
- ❌ `CWE-862` on `models/user_model.py`:L65 → matched **—**
- ❌ `CWE-94` on `models/user_model.py`:L84 → matched **—**
- ❌ `CWE-915` on `models/user_model.py`:L84 → matched **—**
- ❌ `CWE-306` on `openapi_specs/openapi3.yml`:L88 → matched **—**
- ❌ `CWE-307` on `api_views/users.py`:L85 → matched **—**
- ❌ `CWE-94` on `app.py`:L17 → matched **—**
- ❌ `CWE-862` on `models/books_model.py`:L27 → matched **—**
- ❌ `CWE-798` on `models/user_model.py`:L98 → matched **—**
- ❌ `CWE-94` on `api_views/json_schemas.py`:L1 → matched **—**
- ❌ `CWE-89` on `api_views/users.py`:L101 → matched **vampi-fp-002**
- ❌ `CWE-770` on `api_views/users.py`:L179 → matched **—**
- ❌ `CWE-200` on `api_views/users.py`:L45 → matched **—**
- ❌ `CWE-614` on `config.py`:L7 → matched **—**
- ❌ `CWE-209` on `models/user_model.py`:L42 → matched **—**
- ❌ `CWE-16` on `openapi_specs/openapi3.yml`:L1 → matched **—**
- ❌ `CWE-650` on `openapi_specs/openapi3.yml`:L16 → matched **—**
- ❌ `CWE-209` on `openapi_specs/openapi3.yml`:L214 → matched **—**
- ❌ `CWE-862` on `openapi_specs/openapi3.yml`:L486 → matched **—**

**False Negatives (Missed) (4):**

- ⚠️ `CWE-915` on `api_views/users.py`:L60 — **vampi-004** (mass_assignment)
- ⚠️ `CWE-204` on `api_views/users.py`:L101 — **vampi-006** (user_enumeration)
- ⚠️ `CWE-489` on `app.py`:L17 — **vampi-009** (security_misconfiguration)
- ⚠️ `CWE-770` on `config.py`:L27 — **vampi-010** (denial_of_service)

**True Negatives (3):**

- ⚪ `CWE-89` on `api_views/users.py`:L55 — **vampi-fp-001** (sql_injection)
- ⚪ `CWE-639` on `api_views/books.py`:L62 — **vampi-fp-003** (broken_access_control)
- ⚪ `CWE-1333` on `api_views/users.py`:L162 — **vampi-fp-004** (denial_of_service)

### kolega.dev-snapshot-r2

**True Positives (5):**

- ✅ `CWE-862` on `api_views/books.py`:L50 → matched **vampi-003**
- ✅ `CWE-862` on `api_views/users.py`:L24 → matched **vampi-005**
- ✅ `CWE-798` on `config.py`:L13 → matched **vampi-008**
- ✅ `CWE-89` on `models/user_model.py`:L72 → matched **vampi-001**
- ✅ `CWE-489` on `app.py`:L17 → matched **vampi-009**

**False Positives (31):**

- ❌ `CWE-862` on `openapi_specs/openapi3.yml`:L366 → matched **—**
- ❌ `CWE-862` on `models/user_model.py`:L61 → matched **—**
- ❌ `CWE-862` on `api_views/main.py`:L6 → matched **—**
- ❌ `CWE-916` on `api_views/users.py`:L189 → matched **—**
- ❌ `CWE-94` on `api_views/users.py`:L60 → matched **—**
- ❌ `CWE-312` on `api_views/users.py`:L93 → matched **—**
- ❌ `CWE-312` on `models/user_model.py`:L15 → matched **—**
- ❌ `CWE-200` on `models/user_model.py`:L58 → matched **—**
- ❌ `CWE-915` on `models/user_model.py`:L84 → matched **—**
- ❌ `CWE-200` on `openapi_specs/openapi3.yml`:L114 → matched **—**
- ❌ `CWE-306` on `openapi_specs/openapi3.yml`:L16 → matched **—**
- ❌ `CWE-22` on `openapi_specs/openapi3.yml`:L88 → matched **—**
- ❌ `CWE-1336` on `api_views/users.py`:L144 → matched **—**
- ❌ `CWE-307` on `api_views/users.py`:L85 → matched **—**
- ❌ `CWE-79` on `models/user_model.py`:L76 → matched **—**
- ❌ `CWE-307` on `openapi_specs/openapi3.yml`:L162 → matched **—**
- ❌ `CWE-915` on `openapi_specs/openapi3.yml`:L387 → matched **—**
- ❌ `CWE-209` on `api_views/users.py`:L101 → matched **—**
- ❌ `CWE-770` on `api_views/users.py`:L179 → matched **—**
- ❌ `CWE-306` on `api_views/users.py`:L19 → matched **—**
- ❌ `CWE-200` on `api_views/users.py`:L45 → matched **—**
- ❌ `CWE-203` on `api_views/users.py`:L82 → matched **—**
- ❌ `CWE-1188` on `app.py`:L9 → matched **—**
- ❌ `CWE-209` on `config.py`:L17 → matched **—**
- ❌ `CWE-614` on `config.py`:L7 → matched **—**
- ❌ `CWE-862` on `models/books_model.py`:L26 → matched **—**
- ❌ `CWE-209` on `models/user_model.py`:L42 → matched **—**
- ❌ `CWE-203` on `models/user_model.py`:L69 → matched **—**
- ❌ `CWE-798` on `models/user_model.py`:L98 → matched **—**
- ❌ `CWE-770` on `openapi_specs/openapi3.yml`:L131 → matched **—**
- ❌ `CWE-209` on `openapi_specs/openapi3.yml`:L213 → matched **—**

**False Negatives (Missed) (5):**

- ⚠️ `CWE-639` on `api_views/users.py`:L187 — **vampi-002** (broken_access_control)
- ⚠️ `CWE-915` on `api_views/users.py`:L60 — **vampi-004** (mass_assignment)
- ⚠️ `CWE-204` on `api_views/users.py`:L101 — **vampi-006** (user_enumeration)
- ⚠️ `CWE-1333` on `api_views/users.py`:L144 — **vampi-007** (denial_of_service)
- ⚠️ `CWE-770` on `config.py`:L27 — **vampi-010** (denial_of_service)

**True Negatives (4):**

- ⚪ `CWE-89` on `api_views/users.py`:L55 — **vampi-fp-001** (sql_injection)
- ⚪ `CWE-89` on `api_views/users.py`:L92 — **vampi-fp-002** (sql_injection)
- ⚪ `CWE-639` on `api_views/books.py`:L62 — **vampi-fp-003** (broken_access_control)
- ⚪ `CWE-1333` on `api_views/users.py`:L162 — **vampi-fp-004** (denial_of_service)

### kolega.dev-snapshot-r3

**True Positives (8):**

- ✅ `CWE-639` on `api_views/books.py`:L50 → matched **vampi-003**
- ✅ `CWE-639` on `api_views/users.py`:L186 → matched **vampi-002**
- ✅ `CWE-200` on `api_views/users.py`:L24 → matched **vampi-005**
- ✅ `CWE-915` on `api_views/users.py`:L60 → matched **vampi-004**
- ✅ `CWE-798` on `config.py`:L13 → matched **vampi-008**
- ✅ `CWE-89` on `models/user_model.py`:L72 → matched **vampi-001**
- ✅ `CWE-1333` on `api_views/users.py`:L144 → matched **vampi-007**
- ✅ `CWE-204` on `api_views/users.py`:L101 → matched **vampi-006**

**False Positives (20):**

- ❌ `CWE-306` on `api_views/main.py`:L6 → matched **—**
- ❌ `CWE-312` on `api_views/users.py`:L189 → matched **—**
- ❌ `CWE-916` on `api_views/users.py`:L195 → matched **—**
- ❌ `CWE-256` on `models/user_model.py`:L21 → matched **—**
- ❌ `CWE-312` on `models/user_model.py`:L21 → matched **—**
- ❌ `CWE-200` on `models/user_model.py`:L58 → matched **—**
- ❌ `CWE-306` on `openapi_specs/openapi3.yml`:L16 → matched **—**
- ❌ `CWE-22` on `openapi_specs/openapi3.yml`:L88 → matched **—**
- ❌ `CWE-307` on `api_views/users.py`:L85 → matched **—**
- ❌ `CWE-94` on `app.py`:L17 → matched **—**
- ❌ `CWE-915` on `openapi_specs/openapi3.yml`:L127 → matched **—**
- ❌ `CWE-307` on `openapi_specs/openapi3.yml`:L162 → matched **—**
- ❌ `CWE-306` on `api_views/books.py`:L12 → matched **—**
- ❌ `CWE-770` on `api_views/users.py`:L179 → matched **—**
- ❌ `CWE-306` on `api_views/users.py`:L19 → matched **—**
- ❌ `CWE-79` on `models/user_model.py`:L27 → matched **—**
- ❌ `CWE-798` on `models/user_model.py`:L98 → matched **—**
- ❌ `CWE-203` on `openapi_specs/openapi3.yml`:L213 → matched **—**
- ❌ `CWE-770` on `openapi_specs/openapi3.yml`:L426 → matched **—**
- ❌ `CWE-200` on `openapi_specs/openapi3.yml`:L62 → matched **—**

**False Negatives (Missed) (2):**

- ⚠️ `CWE-489` on `app.py`:L17 — **vampi-009** (security_misconfiguration)
- ⚠️ `CWE-770` on `config.py`:L27 — **vampi-010** (denial_of_service)

**True Negatives (4):**

- ⚪ `CWE-89` on `api_views/users.py`:L55 — **vampi-fp-001** (sql_injection)
- ⚪ `CWE-89` on `api_views/users.py`:L92 — **vampi-fp-002** (sql_injection)
- ⚪ `CWE-639` on `api_views/books.py`:L62 — **vampi-fp-003** (broken_access_control)
- ⚪ `CWE-1333` on `api_views/users.py`:L162 — **vampi-fp-004** (denial_of_service)
