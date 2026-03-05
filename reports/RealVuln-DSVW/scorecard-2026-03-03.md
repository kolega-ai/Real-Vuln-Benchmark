# RealVuln Scorecard — dsvw

**Commit:** `7d40f4b7939c`  
**Generated:** 2026-03-03T20:56:25.231886+00:00  
**Ground Truth:** 20 vulnerabilities, 4 false-positive traps  
**Repository:** https://github.com/stamparm/DSVW  
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
| **F2 Score** | **62.5 / 100** |
| Precision | 54.2% |
| Recall | 65.0% |
| F1 | 0.591 |
| F2 | 0.625 |
| TP / FP / FN / TN | 13 / 11 / 7 / 4 |

### kolega.dev-t6-c2-opus-4-6-p4-r2

| Metric | Value |
|--------|-------|
| **F2 Score** | **63.1 / 100** |
| Precision | 56.5% |
| Recall | 65.0% |
| F1 | 0.605 |
| F2 | 0.631 |
| TP / FP / FN / TN | 13 / 10 / 7 / 4 |

### kolega.dev-t6-c2-opus-4-6-p4-r3

| Metric | Value |
|--------|-------|
| **F2 Score** | **63.1 / 100** |
| Precision | 56.5% |
| Recall | 65.0% |
| F1 | 0.605 |
| F2 | 0.631 |
| TP / FP / FN / TN | 13 / 10 / 7 / 4 |

---

## Scanner Comparison

| Scanner | F2 Score | TP | FP | FN | TN | Prec | Recall | F1 | F2 |
|---------|--------:|---:|---:|---:|---:|-----:|-------:|---:|---:|
| kolega.dev-t6-c2-opus-4-6-p4-r1 | **62.5** | 13 | 11 | 7 | 4 | 0.542 | 0.650 | 0.591 | 0.625 |
| kolega.dev-t6-c2-opus-4-6-p4-r2 | **63.1** | 13 | 10 | 7 | 4 | 0.565 | 0.650 | 0.605 | 0.631 |
| kolega.dev-t6-c2-opus-4-6-p4-r3 | **63.1** | 13 | 10 | 7 | 4 | 0.565 | 0.650 | 0.605 | 0.631 |

---

## Per CWE Family Breakdown

### kolega.dev-t6-c2-opus-4-6-p4-r1

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Code Injection / RFI | 0 | 0 | 1 | 0.000 | 0.000 |
| Command / OS Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Denial of Service | 1 | 0 | 0 | 1.000 | 1.000 |
| Hardcoded Credentials | 1 | 0 | 0 | 1.000 | 1.000 |
| HTTP Header Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Insecure Deserialization | 1 | 0 | 0 | 1.000 | 1.000 |
| Open Redirect | 1 | 0 | 0 | 1.000 | 1.000 |
| Other | 1 | 0 | 0 | 1.000 | 1.000 |
| Path Traversal | 1 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Server-Side Request Forgery | 0 | 0 | 1 | 0.000 | 0.000 |
| XPath Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 1 | 0 | 3 | 1.000 | 0.250 |
| XML External Entities | 1 | 0 | 0 | 1.000 | 1.000 |

### kolega.dev-t6-c2-opus-4-6-p4-r2

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Code Injection / RFI | 1 | 0 | 0 | 1.000 | 1.000 |
| Command / OS Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Denial of Service | 1 | 0 | 0 | 1.000 | 1.000 |
| Hardcoded Credentials | 1 | 0 | 0 | 1.000 | 1.000 |
| HTTP Header Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Insecure Deserialization | 1 | 0 | 0 | 1.000 | 1.000 |
| Open Redirect | 1 | 0 | 0 | 1.000 | 1.000 |
| Other | 0 | 0 | 1 | 0.000 | 0.000 |
| Path Traversal | 0 | 0 | 1 | 0.000 | 0.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Server-Side Request Forgery | 1 | 0 | 0 | 1.000 | 1.000 |
| XPath Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 1 | 0 | 3 | 1.000 | 0.250 |
| XML External Entities | 1 | 0 | 0 | 1.000 | 1.000 |

### kolega.dev-t6-c2-opus-4-6-p4-r3

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Code Injection / RFI | 1 | 0 | 0 | 1.000 | 1.000 |
| Command / OS Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Denial of Service | 1 | 0 | 0 | 1.000 | 1.000 |
| Hardcoded Credentials | 1 | 0 | 0 | 1.000 | 1.000 |
| HTTP Header Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Insecure Deserialization | 1 | 0 | 0 | 1.000 | 1.000 |
| Open Redirect | 1 | 0 | 0 | 1.000 | 1.000 |
| Other | 0 | 0 | 1 | 0.000 | 0.000 |
| Path Traversal | 1 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Server-Side Request Forgery | 0 | 0 | 1 | 0.000 | 0.000 |
| XPath Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 1 | 0 | 3 | 1.000 | 0.250 |
| XML External Entities | 1 | 0 | 0 | 1.000 | 1.000 |

---

## Per Severity Breakdown

### kolega.dev-t6-c2-opus-4-6-p4-r1

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 3 | 0 | 2 | 0.600 |
| High | 3 | 0 | 3 | 0.500 |
| Medium | 6 | 0 | 2 | 0.750 |
| Low | 1 | 0 | 0 | 1.000 |

### kolega.dev-t6-c2-opus-4-6-p4-r2

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 4 | 0 | 1 | 0.800 |
| High | 4 | 0 | 2 | 0.667 |
| Medium | 4 | 0 | 4 | 0.500 |
| Low | 1 | 0 | 0 | 1.000 |

### kolega.dev-t6-c2-opus-4-6-p4-r3

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 4 | 0 | 1 | 0.800 |
| High | 3 | 0 | 3 | 0.500 |
| Medium | 5 | 0 | 3 | 0.625 |
| Low | 1 | 0 | 0 | 1.000 |

---

## Detailed Results

### kolega.dev-t6-c2-opus-4-6-p4-r1

**True Positives (13):**

- ✅ `CWE-89` on `dsvw.py`:L30 → matched **dsvw-001**
- ✅ `CWE-79` on `dsvw.py`:L33 → matched **dsvw-002**
- ✅ `CWE-94` on `dsvw.py`:L35 → matched **dsvw-003**
- ✅ `CWE-22` on `dsvw.py`:L37 → matched **dsvw-004**
- ✅ `CWE-78` on `dsvw.py`:L39 → matched **dsvw-006**
- ✅ `CWE-611` on `dsvw.py`:L41 → matched **dsvw-007**
- ✅ `CWE-643` on `dsvw.py`:L43 → matched **dsvw-008**
- ✅ `CWE-200` on `dsvw.py`:L67 → matched **dsvw-018**
- ✅ `CWE-798` on `dsvw.py`:L11 → matched **dsvw-017**
- ✅ `CWE-400` on `dsvw.py`:L46 → matched **dsvw-009**
- ✅ `CWE-352` on `dsvw.py`:L48 → matched **dsvw-020**
- ✅ `CWE-113` on `dsvw.py`:L78 → matched **dsvw-016**
- ✅ `CWE-601` on `dsvw.py`:L61 → matched **dsvw-013**

**False Positives (11):**

- ❌ `CWE-312` on `dsvw.py`:L20 → matched **—**
- ❌ `CWE-306` on `dsvw.py`:L24 → matched **—**
- ❌ `CWE-862` on `dsvw.py`:L29 → matched **—**
- ❌ `CWE-918` on `dsvw.py`:L56 → matched **—**
- ❌ `CWE-307` on `dsvw.py`:L66 → matched **—**
- ❌ `CWE-330` on `dsvw.py`:L68 → matched **—**
- ❌ `CWE-668` on `docker-compose.yml`:L9 → matched **—**
- ❌ `CWE-915` on `dsvw.py`:L26 → matched **—**
- ❌ `CWE-1284` on `dsvw.py`:L46 → matched **—**
- ❌ `CWE-770` on `dsvw.py`:L48 → matched **—**
- ❌ `CWE-209` on `dsvw.py`:L72 → matched **—**

**False Negatives (Missed) (7):**

- ⚠️ `CWE-918` on `dsvw.py`:L37 — **dsvw-005** (ssrf)
- ⚠️ `CWE-89` on `dsvw.py`:L50 — **dsvw-010** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L54 — **dsvw-011** (stored_xss)
- ⚠️ `CWE-94` on `dsvw.py`:L56 — **dsvw-012** (remote_file_inclusion)
- ⚠️ `CWE-79` on `dsvw.py`:L65 — **dsvw-014** (reflected_xss)
- ⚠️ `CWE-89` on `dsvw.py`:L67 — **dsvw-015** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L10 — **dsvw-019** (dom_xss)

**True Negatives (4):**

- ⚪ `CWE-89` on `dsvw.py`:L67 — **dsvw-fp-001** (sql_injection)
- ⚪ `CWE-89` on `dsvw.py`:L20 — **dsvw-fp-002** (sql_injection)
- ⚪ `CWE-79` on `dsvw.py`:L10 — **dsvw-fp-003** (xss)
- ⚪ `CWE-89` on `dsvw.py`:L19 — **dsvw-fp-004** (sql_injection)

### kolega.dev-t6-c2-opus-4-6-p4-r2

**True Positives (13):**

- ✅ `CWE-89` on `dsvw.py`:L30 → matched **dsvw-001**
- ✅ `CWE-79` on `dsvw.py`:L33 → matched **dsvw-002**
- ✅ `CWE-502` on `dsvw.py`:L35 → matched **dsvw-003**
- ✅ `CWE-918` on `dsvw.py`:L37 → matched **dsvw-005**
- ✅ `CWE-78` on `dsvw.py`:L39 → matched **dsvw-006**
- ✅ `CWE-611` on `dsvw.py`:L41 → matched **dsvw-007**
- ✅ `CWE-643` on `dsvw.py`:L43 → matched **dsvw-008**
- ✅ `CWE-94` on `dsvw.py`:L57 → matched **dsvw-012**
- ✅ `CWE-798` on `dsvw.py`:L11 → matched **dsvw-017**
- ✅ `CWE-113` on `dsvw.py`:L78 → matched **dsvw-016**
- ✅ `CWE-770` on `dsvw.py`:L48 → matched **dsvw-009**
- ✅ `CWE-601` on `dsvw.py`:L61 → matched **dsvw-013**
- ✅ `CWE-209` on `dsvw.py`:L72 → matched **dsvw-018**

**False Positives (10):**

- ❌ `CWE-312` on `dsvw.py`:L19 → matched **—**
- ❌ `CWE-916` on `dsvw.py`:L20 → matched **—**
- ❌ `CWE-306` on `dsvw.py`:L24 → matched **—**
- ❌ `CWE-22` on `dsvw.py`:L56 → matched **—**
- ❌ `CWE-862` on `dsvw.py`:L64 → matched **—**
- ❌ `CWE-352` on `dsvw.py`:L23 → matched **—**
- ❌ `CWE-307` on `dsvw.py`:L66 → matched **—**
- ❌ `CWE-330` on `dsvw.py`:L68 → matched **—**
- ❌ `CWE-20` on `dsvw.py`:L46 → matched **—**
- ❌ `CWE-915` on `dsvw.py`:L50 → matched **—**

**False Negatives (Missed) (7):**

- ⚠️ `CWE-22` on `dsvw.py`:L37 — **dsvw-004** (path_traversal)
- ⚠️ `CWE-89` on `dsvw.py`:L50 — **dsvw-010** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L54 — **dsvw-011** (stored_xss)
- ⚠️ `CWE-79` on `dsvw.py`:L65 — **dsvw-014** (reflected_xss)
- ⚠️ `CWE-89` on `dsvw.py`:L67 — **dsvw-015** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L10 — **dsvw-019** (dom_xss)
- ⚠️ `CWE-352` on `dsvw.py`:L50 — **dsvw-020** (csrf)

**True Negatives (4):**

- ⚪ `CWE-89` on `dsvw.py`:L67 — **dsvw-fp-001** (sql_injection)
- ⚪ `CWE-89` on `dsvw.py`:L20 — **dsvw-fp-002** (sql_injection)
- ⚪ `CWE-79` on `dsvw.py`:L10 — **dsvw-fp-003** (xss)
- ⚪ `CWE-89` on `dsvw.py`:L19 — **dsvw-fp-004** (sql_injection)

### kolega.dev-t6-c2-opus-4-6-p4-r3

**True Positives (13):**

- ✅ `CWE-798` on `dsvw.py`:L11 → matched **dsvw-017**
- ✅ `CWE-89` on `dsvw.py`:L30 → matched **dsvw-001**
- ✅ `CWE-79` on `dsvw.py`:L33 → matched **dsvw-002**
- ✅ `CWE-502` on `dsvw.py`:L35 → matched **dsvw-003**
- ✅ `CWE-22` on `dsvw.py`:L37 → matched **dsvw-004**
- ✅ `CWE-78` on `dsvw.py`:L39 → matched **dsvw-006**
- ✅ `CWE-611` on `dsvw.py`:L41 → matched **dsvw-007**
- ✅ `CWE-643` on `dsvw.py`:L43 → matched **dsvw-008**
- ✅ `CWE-94` on `dsvw.py`:L57 → matched **dsvw-012**
- ✅ `CWE-400` on `dsvw.py`:L46 → matched **dsvw-009**
- ✅ `CWE-113` on `dsvw.py`:L78 → matched **dsvw-016**
- ✅ `CWE-601` on `dsvw.py`:L61 → matched **dsvw-013**
- ✅ `CWE-200` on `dsvw.py`:L65 → matched **dsvw-018**

**False Positives (10):**

- ❌ `CWE-306` on `dsvw.py`:L24 → matched **—**
- ❌ `CWE-918` on `dsvw.py`:L56 → matched **—**
- ❌ `CWE-312` on `dsvw.py`:L20 → matched **—**
- ❌ `CWE-862` on `dsvw.py`:L64 → matched **—**
- ❌ `CWE-307` on `dsvw.py`:L66 → matched **—**
- ❌ `CWE-330` on `dsvw.py`:L68 → matched **—**
- ❌ `CWE-915` on `dsvw.py`:L26 → matched **—**
- ❌ `CWE-190` on `dsvw.py`:L46 → matched **—**
- ❌ `CWE-770` on `dsvw.py`:L48 → matched **—**
- ❌ `CWE-209` on `dsvw.py`:L72 → matched **—**

**False Negatives (Missed) (7):**

- ⚠️ `CWE-918` on `dsvw.py`:L37 — **dsvw-005** (ssrf)
- ⚠️ `CWE-89` on `dsvw.py`:L50 — **dsvw-010** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L54 — **dsvw-011** (stored_xss)
- ⚠️ `CWE-79` on `dsvw.py`:L65 — **dsvw-014** (reflected_xss)
- ⚠️ `CWE-89` on `dsvw.py`:L67 — **dsvw-015** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L10 — **dsvw-019** (dom_xss)
- ⚠️ `CWE-352` on `dsvw.py`:L50 — **dsvw-020** (csrf)

**True Negatives (4):**

- ⚪ `CWE-89` on `dsvw.py`:L67 — **dsvw-fp-001** (sql_injection)
- ⚪ `CWE-89` on `dsvw.py`:L20 — **dsvw-fp-002** (sql_injection)
- ⚪ `CWE-79` on `dsvw.py`:L10 — **dsvw-fp-003** (xss)
- ⚪ `CWE-89` on `dsvw.py`:L19 — **dsvw-fp-004** (sql_injection)
