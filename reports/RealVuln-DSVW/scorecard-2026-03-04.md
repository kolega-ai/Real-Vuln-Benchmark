# RealVuln Scorecard — dsvw

**Commit:** `7d40f4b7939c`  
**Generated:** 2026-03-04T07:02:19.955592+00:00  
**Ground Truth:** 26 vulnerabilities, 4 false-positive traps  
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

### kolega.dev-p9-r1

| Metric | Value |
|--------|-------|
| **F2 Score** | **58.3 / 100** |
| Precision | 87.5% |
| Recall | 53.8% |
| F1 | 0.667 |
| F2 | 0.583 |
| TP / FP / FN / TN | 14 / 2 / 12 / 4 |

### kolega.dev-p9-r2

| Metric | Value |
|--------|-------|
| **F2 Score** | **53.7 / 100** |
| Precision | 76.5% |
| Recall | 50.0% |
| F1 | 0.605 |
| F2 | 0.537 |
| TP / FP / FN / TN | 13 / 4 / 13 / 4 |

### kolega.dev-p9-r3

| Metric | Value |
|--------|-------|
| **F2 Score** | **62.0 / 100** |
| Precision | 88.2% |
| Recall | 57.7% |
| F1 | 0.698 |
| F2 | 0.620 |
| TP / FP / FN / TN | 15 / 2 / 11 / 4 |

---

## Scanner Comparison

| Scanner | F2 Score | TP | FP | FN | TN | Prec | Recall | F1 | F2 |
|---------|--------:|---:|---:|---:|---:|-----:|-------:|---:|---:|
| kolega.dev-p9-r1 | **58.3** | 14 | 2 | 12 | 4 | 0.875 | 0.538 | 0.667 | 0.583 |
| kolega.dev-p9-r2 | **53.7** | 13 | 4 | 13 | 4 | 0.765 | 0.500 | 0.605 | 0.537 |
| kolega.dev-p9-r3 | **62.0** | 15 | 2 | 11 | 4 | 0.882 | 0.577 | 0.698 | 0.620 |

---

## Per CWE Family Breakdown

### kolega.dev-p9-r1

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Code Injection / RFI | 1 | 0 | 0 | 1.000 | 1.000 |
| Command / OS Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Denial of Service | 1 | 0 | 0 | 1.000 | 1.000 |
| Hardcoded Credentials | 0 | 0 | 1 | 0.000 | 0.000 |
| HTTP Header Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Insecure Deserialization | 0 | 0 | 1 | 0.000 | 0.000 |
| Open Redirect | 0 | 0 | 1 | 0.000 | 0.000 |
| Other | 5 | 0 | 0 | 1.000 | 1.000 |
| Path Traversal | 1 | 0 | 0 | 1.000 | 1.000 |
| Security Misconfiguration | 0 | 0 | 2 | 0.000 | 0.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Server-Side Request Forgery | 0 | 0 | 1 | 0.000 | 0.000 |
| XPath Injection | 0 | 0 | 1 | 0.000 | 0.000 |
| Cross-Site Scripting | 1 | 0 | 3 | 1.000 | 0.250 |
| XML External Entities | 1 | 0 | 0 | 1.000 | 1.000 |

### kolega.dev-p9-r2

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Code Injection / RFI | 1 | 0 | 0 | 1.000 | 1.000 |
| Command / OS Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Denial of Service | 1 | 0 | 0 | 1.000 | 1.000 |
| Hardcoded Credentials | 0 | 0 | 1 | 0.000 | 0.000 |
| HTTP Header Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Insecure Deserialization | 0 | 0 | 1 | 0.000 | 0.000 |
| Open Redirect | 1 | 0 | 0 | 1.000 | 1.000 |
| Other | 2 | 0 | 3 | 1.000 | 0.400 |
| Path Traversal | 0 | 0 | 1 | 0.000 | 0.000 |
| Security Misconfiguration | 2 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Server-Side Request Forgery | 0 | 0 | 1 | 0.000 | 0.000 |
| XPath Injection | 0 | 0 | 1 | 0.000 | 0.000 |
| Cross-Site Scripting | 1 | 0 | 3 | 1.000 | 0.250 |
| XML External Entities | 1 | 0 | 0 | 1.000 | 1.000 |

### kolega.dev-p9-r3

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Code Injection / RFI | 1 | 0 | 0 | 1.000 | 1.000 |
| Command / OS Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Denial of Service | 1 | 0 | 0 | 1.000 | 1.000 |
| Hardcoded Credentials | 0 | 0 | 1 | 0.000 | 0.000 |
| HTTP Header Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Insecure Deserialization | 0 | 0 | 1 | 0.000 | 0.000 |
| Open Redirect | 1 | 0 | 0 | 1.000 | 1.000 |
| Other | 3 | 0 | 2 | 1.000 | 0.600 |
| Path Traversal | 0 | 0 | 1 | 0.000 | 0.000 |
| Security Misconfiguration | 1 | 0 | 1 | 1.000 | 0.500 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Server-Side Request Forgery | 1 | 0 | 0 | 1.000 | 1.000 |
| XPath Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 1 | 0 | 3 | 1.000 | 0.250 |
| XML External Entities | 1 | 0 | 0 | 1.000 | 1.000 |

---

## Per Severity Breakdown

### kolega.dev-p9-r1

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 3 | 0 | 2 | 0.600 |
| High | 5 | 0 | 4 | 0.556 |
| Medium | 5 | 0 | 5 | 0.500 |
| Low | 1 | 0 | 1 | 0.500 |

### kolega.dev-p9-r2

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 3 | 0 | 2 | 0.600 |
| High | 4 | 0 | 5 | 0.444 |
| Medium | 4 | 0 | 6 | 0.400 |
| Low | 2 | 0 | 0 | 1.000 |

### kolega.dev-p9-r3

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 3 | 0 | 2 | 0.600 |
| High | 6 | 0 | 3 | 0.667 |
| Medium | 5 | 0 | 5 | 0.500 |
| Low | 1 | 0 | 1 | 0.500 |

---

## Detailed Results

### kolega.dev-p9-r1

**True Positives (14):**

- ✅ `CWE-89` on `dsvw.py`:L67 → matched **dsvw-015**
- ✅ `CWE-79` on `dsvw.py`:L61 → matched **dsvw-011**
- ✅ `CWE-94` on `dsvw.py`:L56 → matched **dsvw-012**
- ✅ `CWE-22` on `dsvw.py`:L37 → matched **dsvw-004**
- ✅ `CWE-78` on `dsvw.py`:L39 → matched **dsvw-006**
- ✅ `CWE-611` on `dsvw.py`:L41 → matched **dsvw-007**
- ✅ `CWE-307` on `dsvw.py`:L66 → matched **dsvw-021**
- ✅ `CWE-113` on `dsvw.py`:L78 → matched **dsvw-016**
- ✅ `CWE-312` on `dsvw.py`:L20 → matched **dsvw-022**
- ✅ `CWE-235` on `dsvw.py`:L26 → matched **dsvw-024**
- ✅ `CWE-400` on `dsvw.py`:L46 → matched **dsvw-009**
- ✅ `CWE-352` on `dsvw.py`:L48 → matched **dsvw-020**
- ✅ `CWE-330` on `dsvw.py`:L68 → matched **dsvw-023**
- ✅ `CWE-209` on `dsvw.py`:L72 → matched **dsvw-018**

**False Positives (2):**

- ❌ `CWE-306` on `dsvw.py`:L48 → matched **—**
- ❌ `CWE-918` on `dsvw.py`:L56 → matched **—**

**False Negatives (Missed) (12):**

- ⚠️ `CWE-89` on `dsvw.py`:L30 — **dsvw-001** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L33 — **dsvw-002** (reflected_xss)
- ⚠️ `CWE-502` on `dsvw.py`:L35 — **dsvw-003** (insecure_deserialization)
- ⚠️ `CWE-918` on `dsvw.py`:L37 — **dsvw-005** (ssrf)
- ⚠️ `CWE-643` on `dsvw.py`:L43 — **dsvw-008** (xpath_injection)
- ⚠️ `CWE-89` on `dsvw.py`:L50 — **dsvw-010** (sql_injection)
- ⚠️ `CWE-601` on `dsvw.py`:L61 — **dsvw-013** (open_redirect)
- ⚠️ `CWE-79` on `dsvw.py`:L65 — **dsvw-014** (reflected_xss)
- ⚠️ `CWE-798` on `dsvw.py`:L11 — **dsvw-017** (hardcoded_credentials)
- ⚠️ `CWE-79` on `dsvw.py`:L10 — **dsvw-019** (dom_xss)
- ⚠️ `CWE-1004` on `dsvw.py`:L68 — **dsvw-025** (insecure_cookie)
- ⚠️ `CWE-16` on `dsvw.py`:L77 — **dsvw-026** (security_misconfiguration)

**True Negatives (4):**

- ⚪ `CWE-89` on `dsvw.py`:L67 — **dsvw-fp-001** (sql_injection)
- ⚪ `CWE-89` on `dsvw.py`:L20 — **dsvw-fp-002** (sql_injection)
- ⚪ `CWE-79` on `dsvw.py`:L10 — **dsvw-fp-003** (xss)
- ⚪ `CWE-89` on `dsvw.py`:L19 — **dsvw-fp-004** (sql_injection)

### kolega.dev-p9-r2

**True Positives (13):**

- ✅ `CWE-256` on `dsvw.py`:L19 → matched **dsvw-022**
- ✅ `CWE-89` on `dsvw.py`:L67 → matched **dsvw-015**
- ✅ `CWE-79` on `dsvw.py`:L44 → matched **dsvw-011**
- ✅ `CWE-94` on `dsvw.py`:L56 → matched **dsvw-012**
- ✅ `CWE-78` on `dsvw.py`:L39 → matched **dsvw-006**
- ✅ `CWE-611` on `dsvw.py`:L41 → matched **dsvw-007**
- ✅ `CWE-307` on `dsvw.py`:L66 → matched **dsvw-021**
- ✅ `CWE-400` on `dsvw.py`:L46 → matched **dsvw-009**
- ✅ `CWE-1004` on `dsvw.py`:L68 → matched **dsvw-025**
- ✅ `CWE-113` on `dsvw.py`:L78 → matched **dsvw-016**
- ✅ `CWE-601` on `dsvw.py`:L61 → matched **dsvw-013**
- ✅ `CWE-209` on `dsvw.py`:L72 → matched **dsvw-018**
- ✅ `CWE-16` on `dsvw.py`:L77 → matched **dsvw-026**

**False Positives (4):**

- ❌ `CWE-312` on `dsvw.py`:L20 → matched **—**
- ❌ `CWE-306` on `dsvw.py`:L64 → matched **—**
- ❌ `CWE-22` on `dsvw.py`:L56 → matched **—**
- ❌ `CWE-200` on `dsvw.py`:L53 → matched **—**

**False Negatives (Missed) (13):**

- ⚠️ `CWE-89` on `dsvw.py`:L30 — **dsvw-001** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L33 — **dsvw-002** (reflected_xss)
- ⚠️ `CWE-502` on `dsvw.py`:L35 — **dsvw-003** (insecure_deserialization)
- ⚠️ `CWE-22` on `dsvw.py`:L37 — **dsvw-004** (path_traversal)
- ⚠️ `CWE-918` on `dsvw.py`:L37 — **dsvw-005** (ssrf)
- ⚠️ `CWE-643` on `dsvw.py`:L43 — **dsvw-008** (xpath_injection)
- ⚠️ `CWE-89` on `dsvw.py`:L50 — **dsvw-010** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L65 — **dsvw-014** (reflected_xss)
- ⚠️ `CWE-798` on `dsvw.py`:L11 — **dsvw-017** (hardcoded_credentials)
- ⚠️ `CWE-79` on `dsvw.py`:L10 — **dsvw-019** (dom_xss)
- ⚠️ `CWE-352` on `dsvw.py`:L50 — **dsvw-020** (csrf)
- ⚠️ `CWE-330` on `dsvw.py`:L68 — **dsvw-023** (weak_prng)
- ⚠️ `CWE-235` on `dsvw.py`:L26 — **dsvw-024** (http_parameter_pollution)

**True Negatives (4):**

- ⚪ `CWE-89` on `dsvw.py`:L67 — **dsvw-fp-001** (sql_injection)
- ⚪ `CWE-89` on `dsvw.py`:L20 — **dsvw-fp-002** (sql_injection)
- ⚪ `CWE-79` on `dsvw.py`:L10 — **dsvw-fp-003** (xss)
- ⚪ `CWE-89` on `dsvw.py`:L19 — **dsvw-fp-004** (sql_injection)

### kolega.dev-p9-r3

**True Positives (15):**

- ✅ `CWE-79` on `dsvw.py`:L54 → matched **dsvw-011**
- ✅ `CWE-89` on `dsvw.py`:L67 → matched **dsvw-015**
- ✅ `CWE-94` on `dsvw.py`:L56 → matched **dsvw-012**
- ✅ `CWE-918` on `dsvw.py`:L37 → matched **dsvw-005**
- ✅ `CWE-78` on `dsvw.py`:L39 → matched **dsvw-006**
- ✅ `CWE-611` on `dsvw.py`:L41 → matched **dsvw-007**
- ✅ `CWE-643` on `dsvw.py`:L43 → matched **dsvw-008**
- ✅ `CWE-113` on `dsvw.py`:L78 → matched **dsvw-016**
- ✅ `CWE-312` on `dsvw.py`:L19 → matched **dsvw-022**
- ✅ `CWE-400` on `dsvw.py`:L46 → matched **dsvw-009**
- ✅ `CWE-352` on `dsvw.py`:L48 → matched **dsvw-020**
- ✅ `CWE-601` on `dsvw.py`:L61 → matched **dsvw-013**
- ✅ `CWE-307` on `dsvw.py`:L66 → matched **dsvw-021**
- ✅ `CWE-614` on `dsvw.py`:L68 → matched **dsvw-025**
- ✅ `CWE-209` on `dsvw.py`:L72 → matched **dsvw-018**

**False Positives (2):**

- ❌ `CWE-306` on `dsvw.py`:L64 → matched **—**
- ❌ `CWE-22` on `dsvw.py`:L56 → matched **—**

**False Negatives (Missed) (11):**

- ⚠️ `CWE-89` on `dsvw.py`:L30 — **dsvw-001** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L33 — **dsvw-002** (reflected_xss)
- ⚠️ `CWE-502` on `dsvw.py`:L35 — **dsvw-003** (insecure_deserialization)
- ⚠️ `CWE-22` on `dsvw.py`:L37 — **dsvw-004** (path_traversal)
- ⚠️ `CWE-89` on `dsvw.py`:L50 — **dsvw-010** (sql_injection)
- ⚠️ `CWE-79` on `dsvw.py`:L65 — **dsvw-014** (reflected_xss)
- ⚠️ `CWE-798` on `dsvw.py`:L11 — **dsvw-017** (hardcoded_credentials)
- ⚠️ `CWE-79` on `dsvw.py`:L10 — **dsvw-019** (dom_xss)
- ⚠️ `CWE-330` on `dsvw.py`:L68 — **dsvw-023** (weak_prng)
- ⚠️ `CWE-235` on `dsvw.py`:L26 — **dsvw-024** (http_parameter_pollution)
- ⚠️ `CWE-16` on `dsvw.py`:L77 — **dsvw-026** (security_misconfiguration)

**True Negatives (4):**

- ⚪ `CWE-89` on `dsvw.py`:L67 — **dsvw-fp-001** (sql_injection)
- ⚪ `CWE-89` on `dsvw.py`:L20 — **dsvw-fp-002** (sql_injection)
- ⚪ `CWE-79` on `dsvw.py`:L10 — **dsvw-fp-003** (xss)
- ⚪ `CWE-89` on `dsvw.py`:L19 — **dsvw-fp-004** (sql_injection)
