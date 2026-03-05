# RealVuln Scorecard — vampi

**Commit:** `1713b54b601a`  
**Generated:** 2026-02-24T07:34:43.514468+00:00  
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

### sonarqube

| Metric | Value |
|--------|-------|
| **F2 Score** | **0.0 / 100** |
| Precision | 0.0% |
| Recall | 0.0% |
| F1 | 0.000 |
| F2 | 0.000 |
| TP / FP / FN / TN | 0 / 2 / 10 / 4 |

---

## Per CWE Family Breakdown

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 0 | 0 | 2 | 0.000 | 0.000 |
| Denial of Service | 0 | 0 | 1 | 0.000 | 0.000 |
| Other | 0 | 0 | 5 | 0.000 | 0.000 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 0 | 0 | 1 | 0.000 | 0.000 |

---

## Per Severity Breakdown

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 0 | 0 | 1 | 0.000 |
| High | 0 | 0 | 4 | 0.000 |
| Medium | 0 | 0 | 4 | 0.000 |
| Low | 0 | 0 | 1 | 0.000 |

---

## Detailed Results

**False Positives (2):**

- ❌ `CWE-259` on `api_views/users.py`:L199 → matched **—**
- ❌ `CWE-798` on `api_views/users.py`:L199 → matched **—**

**False Negatives (Missed) (10):**

- ⚠️ `CWE-89` on `models/user_model.py`:L72 — **vampi-001** (sql_injection)
- ⚠️ `CWE-639` on `api_views/users.py`:L187 — **vampi-002** (broken_access_control)
- ⚠️ `CWE-639` on `api_views/books.py`:L51 — **vampi-003** (broken_access_control)
- ⚠️ `CWE-915` on `api_views/users.py`:L60 — **vampi-004** (mass_assignment)
- ⚠️ `CWE-200` on `api_views/users.py`:L24 — **vampi-005** (sensitive_data_exposure)
- ⚠️ `CWE-204` on `api_views/users.py`:L101 — **vampi-006** (user_enumeration)
- ⚠️ `CWE-1333` on `api_views/users.py`:L144 — **vampi-007** (denial_of_service)
- ⚠️ `CWE-321` on `config.py`:L13 — **vampi-008** (hardcoded_credentials)
- ⚠️ `CWE-489` on `app.py`:L17 — **vampi-009** (security_misconfiguration)
- ⚠️ `CWE-770` on `config.py`:L27 — **vampi-010** (denial_of_service)

**True Negatives (4):**

- ⚪ `CWE-89` on `api_views/users.py`:L55 — **vampi-fp-001** (sql_injection)
- ⚪ `CWE-89` on `api_views/users.py`:L92 — **vampi-fp-002** (sql_injection)
- ⚪ `CWE-639` on `api_views/books.py`:L62 — **vampi-fp-003** (broken_access_control)
- ⚪ `CWE-1333` on `api_views/users.py`:L162 — **vampi-fp-004** (denial_of_service)
