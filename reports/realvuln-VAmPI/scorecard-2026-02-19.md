# RealVuln Scorecard — vampi

**Commit:** `1713b54b601a`  
**Generated:** 2026-02-19T11:30:41.645474+00:00  
**Ground Truth:** 9 vulnerabilities, 4 false-positive traps  
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
| **Precision** | TP / (TP + FP) | Of everything the scanner flagged, what fraction was actually vulnerable? High precision = low noise. |
| **Recall (TPR)** | TP / (TP + FN) | Of all real vulnerabilities, what fraction did the scanner find? High recall = few missed vulns. |
| **F1** | 2 x (Prec x Recall) / (Prec + Recall) | Harmonic mean of precision and recall. Balances both into a single number (0–1). |
| **FPR** | FP / (FP + TN) | Of all non-vulnerable code, what fraction did the scanner incorrectly flag? Lower is better. |
| **Youden's J** | TPR − FPR | Single number summarising overall accuracy (−1 to +1). Positive = better than random. +1 = perfect. Negative = worse than random. This is the primary metric used by the OWASP Benchmark. |

---

## Headline Results

### our-scanner

| Metric | Value |
|--------|-------|
| **Youden's J** | **-19.4%** |
| Precision | 29.4% |
| Recall | 55.6% |
| F1 | 0.385 |
| TPR | 55.6% |
| FPR | 75.0% |
| TP / FP / FN / TN | 5 / 12 / 4 / 4 |

---

## Per CWE Family Breakdown

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 1 | 0 | 1 | 1.000 | 0.500 |
| Other | 2 | 0 | 3 | 1.000 | 0.400 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |

---

## Per Severity Breakdown

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 3 | 0 | 1 | 0.750 |
| Medium | 1 | 0 | 2 | 0.333 |
| Low | 0 | 0 | 1 | 0.000 |

---

## Detailed Results

**True Positives (5):**

- &#9989; `CWE-639` on `api_views/books.py`:L44 → matched **vampi-003**
- &#9989; `CWE-200` on `api_views/users.py`:L18 → matched **vampi-005**
- &#9989; `CWE-915` on `api_views/users.py`:L57 → matched **vampi-004**
- &#9989; `CWE-321` on `config.py`:L13 → matched **vampi-008**
- &#9989; `CWE-89` on `models/user_model.py`:L67 → matched **vampi-001**

**False Positives (12):**

- &#10060; `CWE-1333` on `api_views/users.py`:L120 → matched **—**
- &#10060; `CWE-204` on `api_views/users.py`:L89 → matched **—**
- &#10060; `CWE-256` on `api_views/users.py`:L63 → matched **—**
- &#10060; `CWE-285` on `api_views/users.py`:L148 → matched **—**
- &#10060; `CWE-307` on `api_views/users.py`:L79 → matched **—**
- &#10060; `CWE-94` on `app.py`:L13 → matched **—**
- &#10060; `CWE-256` on `models/user_model.py`:L82 → matched **—**
- &#10060; `CWE-269` on `models/user_model.py`:L82 → matched **—**
- &#10060; `CWE-312` on `models/user_model.py`:L60 → matched **—**
- &#10060; `CWE-321` on `models/user_model.py`:L36 → matched **—**
- &#10060; `CWE-347` on `models/user_model.py` → matched **—**
- &#10060; `CWE-798` on `models/user_model.py`:L97 → matched **—**

**False Negatives (Missed) (4):**

- &#9888;&#65039; `CWE-639` on `api_views/users.py`:L187 — **vampi-002** (broken_access_control)
- &#9888;&#65039; `CWE-204` on `api_views/users.py`:L101 — **vampi-006** (user_enumeration)
- &#9888;&#65039; `CWE-1333` on `api_views/users.py`:L144 — **vampi-007** (denial_of_service)
- &#9888;&#65039; `CWE-489` on `app.py`:L17 — **vampi-009** (security_misconfiguration)

**True Negatives (4):**

- &#9898; `CWE-89` on `api_views/users.py`:L55 — **vampi-fp-001** (sql_injection)
- &#9898; `CWE-89` on `api_views/users.py`:L92 — **vampi-fp-002** (sql_injection)
- &#9898; `CWE-639` on `api_views/books.py`:L62 — **vampi-fp-003** (broken_access_control)
- &#9898; `CWE-1333` on `api_views/users.py`:L162 — **vampi-fp-004** (denial_of_service)
