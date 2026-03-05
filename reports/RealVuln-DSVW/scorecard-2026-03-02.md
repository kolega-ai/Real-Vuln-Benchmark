# RealVuln Scorecard — dsvw

**Commit:** `7d40f4b7939c`  
**Generated:** 2026-03-02T20:25:06.584431+00:00  
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

### our-scanner

| Metric | Value |
|--------|-------|
| **F2 Score** | **62.9 / 100** |
| Precision | 55.7% |
| Recall | 65.0% |
| F1 | 0.600 |
| F2 | 0.629 |
| TP / FP / FN / TN | 13 / 10 / 7 / 4 |

*Multi-run (3 runs):*

| Metric | Mean | Stddev |
|--------|------|--------|
| F2 Score | 62.900 | 0.346 |
| Precision | 0.557 | 0.014 |
| Recall | 0.650 | 0.000 |
| F1 | 0.600 | 0.008 |
| F2 | 0.629 | 0.004 |

### semgrep

| Metric | Value |
|--------|-------|
| **F2 Score** | **0.0 / 100** |
| Precision | 0.0% |
| Recall | 0.0% |
| F1 | 0.000 |
| F2 | 0.000 |
| TP / FP / FN / TN | 0 / 0 / 20 / 4 |

### sonarqube

| Metric | Value |
|--------|-------|
| **F2 Score** | **56.7 / 100** |
| Precision | 64.7% |
| Recall | 55.0% |
| F1 | 0.595 |
| F2 | 0.567 |
| TP / FP / FN / TN | 11 / 6 / 9 / 4 |

---

## Scanner Comparison

| Scanner | F2 Score | TP | FP | FN | TN | Prec | Recall | F1 | F2 |
|---------|--------:|---:|---:|---:|---:|-----:|-------:|---:|---:|
| our-scanner | **62.9** | 13 | 10 | 7 | 4 | 0.557 | 0.650 | 0.600 | 0.629 |
| semgrep | **0.0** | 0 | 0 | 20 | 4 | 0.000 | 0.000 | 0.000 | 0.000 |
| sonarqube | **56.7** | 11 | 6 | 9 | 4 | 0.647 | 0.550 | 0.595 | 0.567 |

---

## Per CWE Family Breakdown

### our-scanner

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

### semgrep

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Code Injection / RFI | 0 | 0 | 1 | 0.000 | 0.000 |
| Command / OS Injection | 0 | 0 | 1 | 0.000 | 0.000 |
| Denial of Service | 0 | 0 | 1 | 0.000 | 0.000 |
| Hardcoded Credentials | 0 | 0 | 1 | 0.000 | 0.000 |
| HTTP Header Injection | 0 | 0 | 1 | 0.000 | 0.000 |
| Insecure Deserialization | 0 | 0 | 1 | 0.000 | 0.000 |
| Open Redirect | 0 | 0 | 1 | 0.000 | 0.000 |
| Other | 0 | 0 | 1 | 0.000 | 0.000 |
| Path Traversal | 0 | 0 | 1 | 0.000 | 0.000 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 0 | 0 | 3 | 0.000 | 0.000 |
| Server-Side Request Forgery | 0 | 0 | 1 | 0.000 | 0.000 |
| XPath Injection | 0 | 0 | 1 | 0.000 | 0.000 |
| Cross-Site Scripting | 0 | 0 | 4 | 0.000 | 0.000 |
| XML External Entities | 0 | 0 | 1 | 0.000 | 0.000 |

### sonarqube

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Code Injection / RFI | 1 | 0 | 0 | 1.000 | 1.000 |
| Command / OS Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Denial of Service | 1 | 0 | 0 | 1.000 | 1.000 |
| Hardcoded Credentials | 1 | 0 | 0 | 1.000 | 1.000 |
| HTTP Header Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Insecure Deserialization | 1 | 0 | 0 | 1.000 | 1.000 |
| Open Redirect | 0 | 0 | 1 | 0.000 | 0.000 |
| Other | 0 | 0 | 1 | 0.000 | 0.000 |
| Path Traversal | 1 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 0 | 0 | 3 | 0.000 | 0.000 |
| Server-Side Request Forgery | 1 | 0 | 0 | 1.000 | 1.000 |
| XPath Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 4 | 0.000 | 0.000 |
| XML External Entities | 1 | 0 | 0 | 1.000 | 1.000 |

---

## Per Severity Breakdown

### our-scanner

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 3 | 0 | 2 | 0.600 |
| High | 3 | 0 | 3 | 0.500 |
| Medium | 6 | 0 | 2 | 0.750 |
| Low | 1 | 0 | 0 | 1.000 |

### semgrep

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 0 | 0 | 5 | 0.000 |
| High | 0 | 0 | 6 | 0.000 |
| Medium | 0 | 0 | 8 | 0.000 |
| Low | 0 | 0 | 1 | 0.000 |

### sonarqube

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 3 | 0 | 2 | 0.600 |
| High | 4 | 0 | 2 | 0.667 |
| Medium | 3 | 0 | 5 | 0.375 |
| Low | 1 | 0 | 0 | 1.000 |

---

## Detailed Results

### semgrep

**False Negatives (Missed) (20):**

- ⚠️ `CWE-89` on `dsvw.py`:L30 — **dsvw-001** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L33 — **dsvw-002** (reflected_xss)
- ⚠️ `CWE-502` on `dsvw.py`:L35 — **dsvw-003** (insecure_deserialization)
- ⚠️ `CWE-22` on `dsvw.py`:L37 — **dsvw-004** (path_traversal)
- ⚠️ `CWE-918` on `dsvw.py`:L37 — **dsvw-005** (ssrf)
- ⚠️ `CWE-78` on `dsvw.py`:L39 — **dsvw-006** (command_injection)
- ⚠️ `CWE-611` on `dsvw.py`:L41 — **dsvw-007** (xxe)
- ⚠️ `CWE-643` on `dsvw.py`:L43 — **dsvw-008** (xpath_injection)
- ⚠️ `CWE-400` on `dsvw.py`:L46 — **dsvw-009** (denial_of_service)
- ⚠️ `CWE-89` on `dsvw.py`:L50 — **dsvw-010** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L54 — **dsvw-011** (stored_xss)
- ⚠️ `CWE-94` on `dsvw.py`:L56 — **dsvw-012** (remote_file_inclusion)
- ⚠️ `CWE-601` on `dsvw.py`:L61 — **dsvw-013** (open_redirect)
- ⚠️ `CWE-79` on `dsvw.py`:L65 — **dsvw-014** (reflected_xss)
- ⚠️ `CWE-89` on `dsvw.py`:L67 — **dsvw-015** (sql_injection)
- ⚠️ `CWE-113` on `dsvw.py`:L78 — **dsvw-016** (http_header_injection)
- ⚠️ `CWE-798` on `dsvw.py`:L11 — **dsvw-017** (hardcoded_credentials)
- ⚠️ `CWE-209` on `dsvw.py`:L72 — **dsvw-018** (sensitive_data_exposure)
- ⚠️ `CWE-79` on `dsvw.py`:L10 — **dsvw-019** (dom_xss)
- ⚠️ `CWE-352` on `dsvw.py`:L50 — **dsvw-020** (csrf)

**True Negatives (4):**

- ⚪ `CWE-89` on `dsvw.py`:L67 — **dsvw-fp-001** (sql_injection)
- ⚪ `CWE-89` on `dsvw.py`:L20 — **dsvw-fp-002** (sql_injection)
- ⚪ `CWE-79` on `dsvw.py`:L10 — **dsvw-fp-003** (xss)
- ⚪ `CWE-89` on `dsvw.py`:L19 — **dsvw-fp-004** (sql_injection)

### sonarqube

**True Positives (11):**

- ✅ `CWE-113` on `dsvw.py`:L78 → matched **dsvw-016**
- ✅ `CWE-209` on `dsvw.py`:L80 → matched **dsvw-018**
- ✅ `CWE-22` on `dsvw.py`:L37 → matched **dsvw-004**
- ✅ `CWE-259` on `dsvw.py`:L12 → matched **dsvw-017**
- ✅ `CWE-502` on `dsvw.py`:L35 → matched **dsvw-003**
- ✅ `CWE-611` on `dsvw.py`:L41 → matched **dsvw-007**
- ✅ `CWE-643` on `dsvw.py`:L43 → matched **dsvw-008**
- ✅ `CWE-78` on `dsvw.py`:L39 → matched **dsvw-006**
- ✅ `CWE-789` on `dsvw.py`:L46 → matched **dsvw-009**
- ✅ `CWE-918` on `dsvw.py`:L37 → matched **dsvw-005**
- ✅ `CWE-95` on `dsvw.py`:L57 → matched **dsvw-012**

**False Positives (6):**

- ❌ `CWE-22` on `dsvw.py`:L56 → matched **—**
- ❌ `CWE-606` on `dsvw.py`:L46 → matched **—**
- ❌ `CWE-79` on `dsvw.py`:L80 → matched **—**
- ❌ `CWE-798` on `dsvw.py`:L12 → matched **—**
- ❌ `CWE-827` on `dsvw.py`:L41 → matched **—**
- ❌ `CWE-918` on `dsvw.py`:L56 → matched **—**

**False Negatives (Missed) (9):**

- ⚠️ `CWE-89` on `dsvw.py`:L30 — **dsvw-001** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L33 — **dsvw-002** (reflected_xss)
- ⚠️ `CWE-89` on `dsvw.py`:L50 — **dsvw-010** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L54 — **dsvw-011** (stored_xss)
- ⚠️ `CWE-601` on `dsvw.py`:L61 — **dsvw-013** (open_redirect)
- ⚠️ `CWE-79` on `dsvw.py`:L65 — **dsvw-014** (reflected_xss)
- ⚠️ `CWE-89` on `dsvw.py`:L67 — **dsvw-015** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L10 — **dsvw-019** (dom_xss)
- ⚠️ `CWE-352` on `dsvw.py`:L50 — **dsvw-020** (csrf)

**True Negatives (4):**

- ⚪ `CWE-89` on `dsvw.py`:L67 — **dsvw-fp-001** (sql_injection)
- ⚪ `CWE-89` on `dsvw.py`:L20 — **dsvw-fp-002** (sql_injection)
- ⚪ `CWE-79` on `dsvw.py`:L10 — **dsvw-fp-003** (xss)
- ⚪ `CWE-89` on `dsvw.py`:L19 — **dsvw-fp-004** (sql_injection)
