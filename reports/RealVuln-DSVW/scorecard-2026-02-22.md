# RealVuln Scorecard — dsvw

**Commit:** `7d40f4b7939c`  
**Generated:** 2026-02-22T19:22:07.855602+00:00  
**Ground Truth:** 19 vulnerabilities, 4 false-positive traps  
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
| **Youden's J** | **+29.8%** |
| Precision | 85.7% |
| Recall | 63.2% |
| F1 | 0.727 |
| TPR | 63.2% |
| FPR | 33.3% |
| TP / FP / FN / TN | 12 / 2 / 7 / 4 |

### sonarqube

| Metric | Value |
|--------|-------|
| **Youden's J** | **-2.1%** |
| Precision | 64.7% |
| Recall | 57.9% |
| F1 | 0.611 |
| TPR | 57.9% |
| FPR | 60.0% |
| TP / FP / FN / TN | 11 / 6 / 8 / 4 |

---

## Scanner Comparison

| Scanner | TP | FP | FN | TN | Prec | Recall | F1 | Youden's J |
|---------|---:|---:|---:|---:|-----:|-------:|---:|-----------:|
| our-scanner | 12 | 2 | 7 | 4 | 0.857 | 0.632 | 0.727 | +0.298 |
| sonarqube | 11 | 6 | 8 | 4 | 0.647 | 0.579 | 0.611 | -0.021 |

---

## Per CWE Family Breakdown

### our-scanner

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Code Injection / RFI | 1 | 0 | 0 | 1.000 | 1.000 |
| Command / OS Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Denial of Service | 1 | 0 | 0 | 1.000 | 1.000 |
| Hardcoded Credentials | 0 | 0 | 1 | 0.000 | 0.000 |
| HTTP Header Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Insecure Deserialization | 1 | 0 | 0 | 1.000 | 1.000 |
| Open Redirect | 1 | 0 | 0 | 1.000 | 1.000 |
| Path Traversal | 1 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Server-Side Request Forgery | 0 | 0 | 1 | 0.000 | 0.000 |
| XPath Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 1 | 0 | 3 | 1.000 | 0.250 |
| XML External Entities | 1 | 0 | 0 | 1.000 | 1.000 |

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
| Critical | 4 | 0 | 1 | 0.800 |
| High | 2 | 0 | 4 | 0.333 |
| Medium | 5 | 0 | 2 | 0.714 |
| Low | 1 | 0 | 0 | 1.000 |

### sonarqube

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 3 | 0 | 2 | 0.600 |
| High | 4 | 0 | 2 | 0.667 |
| Medium | 3 | 0 | 4 | 0.429 |
| Low | 1 | 0 | 0 | 1.000 |

---

## Detailed Results

### our-scanner

**True Positives (12):**

- ✅ `CWE-113` on `dsvw.py`:L78 → matched **dsvw-016**
- ✅ `CWE-209` on `dsvw.py`:L72 → matched **dsvw-018**
- ✅ `CWE-22` on `dsvw.py`:L37 → matched **dsvw-004**
- ✅ `CWE-400` on `dsvw.py`:L46 → matched **dsvw-009**
- ✅ `CWE-502` on `dsvw.py`:L35 → matched **dsvw-003**
- ✅ `CWE-601` on `dsvw.py`:L61 → matched **dsvw-013**
- ✅ `CWE-611` on `dsvw.py`:L41 → matched **dsvw-007**
- ✅ `CWE-643` on `dsvw.py`:L43 → matched **dsvw-008**
- ✅ `CWE-78` on `dsvw.py`:L39 → matched **dsvw-006**
- ✅ `CWE-79` on `dsvw.py`:L33 → matched **dsvw-002**
- ✅ `CWE-89` on `dsvw.py`:L30 → matched **dsvw-001**
- ✅ `CWE-94` on `dsvw.py`:L56 → matched **dsvw-012**

**False Positives (2):**

- ❌ `CWE-235` on `dsvw.py`:L26 → matched **—**
- ❌ `CWE-338` on `dsvw.py`:L68 → matched **—**

**False Negatives (Missed) (7):**

- ⚠️ `CWE-918` on `dsvw.py`:L37 — **dsvw-005** (ssrf)
- ⚠️ `CWE-89` on `dsvw.py`:L50 — **dsvw-010** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L54 — **dsvw-011** (stored_xss)
- ⚠️ `CWE-79` on `dsvw.py`:L65 — **dsvw-014** (reflected_xss)
- ⚠️ `CWE-89` on `dsvw.py`:L67 — **dsvw-015** (sql_injection)
- ⚠️ `CWE-798` on `dsvw.py`:L11 — **dsvw-017** (hardcoded_credentials)
- ⚠️ `CWE-79` on `dsvw.py`:L10 — **dsvw-019** (dom_xss)

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

**False Negatives (Missed) (8):**

- ⚠️ `CWE-89` on `dsvw.py`:L30 — **dsvw-001** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L33 — **dsvw-002** (reflected_xss)
- ⚠️ `CWE-89` on `dsvw.py`:L50 — **dsvw-010** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L54 — **dsvw-011** (stored_xss)
- ⚠️ `CWE-601` on `dsvw.py`:L61 — **dsvw-013** (open_redirect)
- ⚠️ `CWE-79` on `dsvw.py`:L65 — **dsvw-014** (reflected_xss)
- ⚠️ `CWE-89` on `dsvw.py`:L67 — **dsvw-015** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L10 — **dsvw-019** (dom_xss)

**True Negatives (4):**

- ⚪ `CWE-89` on `dsvw.py`:L67 — **dsvw-fp-001** (sql_injection)
- ⚪ `CWE-89` on `dsvw.py`:L20 — **dsvw-fp-002** (sql_injection)
- ⚪ `CWE-79` on `dsvw.py`:L10 — **dsvw-fp-003** (xss)
- ⚪ `CWE-89` on `dsvw.py`:L19 — **dsvw-fp-004** (sql_injection)
