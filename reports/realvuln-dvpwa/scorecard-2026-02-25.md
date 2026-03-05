# RealVuln Scorecard — dvpwa

**Commit:** `a1d8f89fac2e`  
**Generated:** 2026-02-25T13:29:45.478611+00:00  
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

### kolega.dev-t2-sonnet-4-6-p1

| Metric | Value |
|--------|-------|
| **F2 Score** | **27.5 / 100** |
| Precision | 71.4% |
| Recall | 23.8% |
| F1 | 0.357 |
| F2 | 0.275 |
| TP / FP / FN / TN | 5 / 2 / 16 / 4 |

### kolega.dev-t2-sonnet-4-6-p4-r1

| Metric | Value |
|--------|-------|
| **F2 Score** | **62.5 / 100** |
| Precision | 50.0% |
| Recall | 66.7% |
| F1 | 0.571 |
| F2 | 0.625 |
| TP / FP / FN / TN | 14 / 14 / 7 / 4 |

### kolega.dev-t2-sonnet-4-6-p4-r2

| Metric | Value |
|--------|-------|
| **F2 Score** | **40.0 / 100** |
| Precision | 50.0% |
| Recall | 38.1% |
| F1 | 0.432 |
| F2 | 0.400 |
| TP / FP / FN / TN | 8 / 8 / 13 / 4 |

### kolega.dev-t2-sonnet-4-6-p4-r3

| Metric | Value |
|--------|-------|
| **F2 Score** | **66.1 / 100** |
| Precision | 43.2% |
| Recall | 76.2% |
| F1 | 0.552 |
| F2 | 0.661 |
| TP / FP / FN / TN | 16 / 21 / 5 / 4 |

### kolega.dev-t3-gemini-3.1-pro-p4-r1

| Metric | Value |
|--------|-------|
| **F2 Score** | **33.0 / 100** |
| Precision | 85.7% |
| Recall | 28.6% |
| F1 | 0.429 |
| F2 | 0.330 |
| TP / FP / FN / TN | 6 / 1 / 15 / 4 |

### kolega.dev-t3-gemini-3.1-pro-p4-r2

| Metric | Value |
|--------|-------|
| **F2 Score** | **63.1 / 100** |
| Precision | 68.4% |
| Recall | 61.9% |
| F1 | 0.650 |
| F2 | 0.631 |
| TP / FP / FN / TN | 13 / 6 / 8 / 4 |

### kolega.dev-t3-gpt-5-2-p4

| Metric | Value |
|--------|-------|
| **F2 Score** | **38.1 / 100** |
| Precision | 38.1% |
| Recall | 38.1% |
| F1 | 0.381 |
| F2 | 0.381 |
| TP / FP / FN / TN | 8 / 13 / 13 / 4 |

### kolega.dev-t3-opus-4-6-p4-r1

| Metric | Value |
|--------|-------|
| **F2 Score** | **36.5 / 100** |
| Precision | 58.3% |
| Recall | 33.3% |
| F1 | 0.424 |
| F2 | 0.365 |
| TP / FP / FN / TN | 7 / 5 / 14 / 4 |

### kolega.dev-t3-opus-4-6-p4-r2

| Metric | Value |
|--------|-------|
| **F2 Score** | **58.3 / 100** |
| Precision | 38.9% |
| Recall | 66.7% |
| F1 | 0.491 |
| F2 | 0.583 |
| TP / FP / FN / TN | 14 / 22 / 7 / 4 |

### kolega.dev-t3-opus-4-6-p4-r3

| Metric | Value |
|--------|-------|
| **F2 Score** | **36.5 / 100** |
| Precision | 58.3% |
| Recall | 33.3% |
| F1 | 0.424 |
| F2 | 0.365 |
| TP / FP / FN / TN | 7 / 5 / 14 / 4 |

### kolega.dev-t3-sonnet-4-6-p1

| Metric | Value |
|--------|-------|
| **F2 Score** | **35.4 / 100** |
| Precision | 46.7% |
| Recall | 33.3% |
| F1 | 0.389 |
| F2 | 0.354 |
| TP / FP / FN / TN | 7 / 8 / 14 / 3 |

### kolega.dev-t3-sonnet-4-6-p1-r0

| Metric | Value |
|--------|-------|
| **F2 Score** | **25.0 / 100** |
| Precision | 31.2% |
| Recall | 23.8% |
| F1 | 0.270 |
| F2 | 0.250 |
| TP / FP / FN / TN | 5 / 11 / 16 / 4 |

### kolega.dev-t3-sonnet-4-6-p3

| Metric | Value |
|--------|-------|
| **F2 Score** | **42.1 / 100** |
| Precision | 72.7% |
| Recall | 38.1% |
| F1 | 0.500 |
| F2 | 0.421 |
| TP / FP / FN / TN | 8 / 3 / 13 / 4 |

### kolega.dev-t3-sonnet-4-6-p4

| Metric | Value |
|--------|-------|
| **F2 Score** | **63.1 / 100** |
| Precision | 51.9% |
| Recall | 66.7% |
| F1 | 0.583 |
| F2 | 0.631 |
| TP / FP / FN / TN | 14 / 13 / 7 / 4 |

### sonarqube

| Metric | Value |
|--------|-------|
| **F2 Score** | **0.0 / 100** |
| Precision | 0.0% |
| Recall | 0.0% |
| F1 | 0.000 |
| F2 | 0.000 |
| TP / FP / FN / TN | 0 / 0 / 21 / 4 |

---

## Scanner Comparison

| Scanner | F2 Score | TP | FP | FN | TN | Prec | Recall | F1 | F2 |
|---------|--------:|---:|---:|---:|---:|-----:|-------:|---:|---:|
| kolega.dev-t2-sonnet-4-6-p1 | **27.5** | 5 | 2 | 16 | 4 | 0.714 | 0.238 | 0.357 | 0.275 |
| kolega.dev-t2-sonnet-4-6-p4-r1 | **62.5** | 14 | 14 | 7 | 4 | 0.500 | 0.667 | 0.571 | 0.625 |
| kolega.dev-t2-sonnet-4-6-p4-r2 | **40.0** | 8 | 8 | 13 | 4 | 0.500 | 0.381 | 0.432 | 0.400 |
| kolega.dev-t2-sonnet-4-6-p4-r3 | **66.1** | 16 | 21 | 5 | 4 | 0.432 | 0.762 | 0.552 | 0.661 |
| kolega.dev-t3-gemini-3.1-pro-p4-r1 | **33.0** | 6 | 1 | 15 | 4 | 0.857 | 0.286 | 0.429 | 0.330 |
| kolega.dev-t3-gemini-3.1-pro-p4-r2 | **63.1** | 13 | 6 | 8 | 4 | 0.684 | 0.619 | 0.650 | 0.631 |
| kolega.dev-t3-gpt-5-2-p4 | **38.1** | 8 | 13 | 13 | 4 | 0.381 | 0.381 | 0.381 | 0.381 |
| kolega.dev-t3-opus-4-6-p4-r1 | **36.5** | 7 | 5 | 14 | 4 | 0.583 | 0.333 | 0.424 | 0.365 |
| kolega.dev-t3-opus-4-6-p4-r2 | **58.3** | 14 | 22 | 7 | 4 | 0.389 | 0.667 | 0.491 | 0.583 |
| kolega.dev-t3-opus-4-6-p4-r3 | **36.5** | 7 | 5 | 14 | 4 | 0.583 | 0.333 | 0.424 | 0.365 |
| kolega.dev-t3-sonnet-4-6-p1 | **35.4** | 7 | 8 | 14 | 3 | 0.467 | 0.333 | 0.389 | 0.354 |
| kolega.dev-t3-sonnet-4-6-p1-r0 | **25.0** | 5 | 11 | 16 | 4 | 0.312 | 0.238 | 0.270 | 0.250 |
| kolega.dev-t3-sonnet-4-6-p3 | **42.1** | 8 | 3 | 13 | 4 | 0.727 | 0.381 | 0.500 | 0.421 |
| kolega.dev-t3-sonnet-4-6-p4 | **63.1** | 14 | 13 | 7 | 4 | 0.519 | 0.667 | 0.583 | 0.631 |
| sonarqube | **0.0** | 0 | 0 | 21 | 4 | 0.000 | 0.000 | 0.000 | 0.000 |

---

## Per CWE Family Breakdown

### kolega.dev-t2-sonnet-4-6-p1

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 0 | 0 | 3 | 0.000 | 0.000 |
| Other | 2 | 0 | 6 | 1.000 | 0.250 |
| Security Misconfiguration | 2 | 0 | 1 | 1.000 | 0.667 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 5 | 0.000 | 0.000 |

### kolega.dev-t2-sonnet-4-6-p4-r1

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 2 | 0 | 1 | 1.000 | 0.667 |
| Other | 4 | 0 | 4 | 1.000 | 0.500 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 4 | 0 | 1 | 1.000 | 0.800 |

### kolega.dev-t2-sonnet-4-6-p4-r2

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 1 | 0 | 2 | 1.000 | 0.333 |
| Other | 3 | 0 | 5 | 1.000 | 0.375 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 5 | 0.000 | 0.000 |

### kolega.dev-t2-sonnet-4-6-p4-r3

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 2 | 0 | 1 | 1.000 | 0.667 |
| Other | 5 | 0 | 3 | 1.000 | 0.625 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 4 | 0 | 1 | 1.000 | 0.800 |

### kolega.dev-t3-gemini-3.1-pro-p4-r1

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 0 | 0 | 3 | 0.000 | 0.000 |
| Other | 2 | 0 | 6 | 1.000 | 0.250 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 5 | 0.000 | 0.000 |

### kolega.dev-t3-gemini-3.1-pro-p4-r2

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 1 | 0 | 2 | 1.000 | 0.333 |
| Other | 4 | 0 | 4 | 1.000 | 0.500 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 3 | 0 | 2 | 1.000 | 0.600 |

### kolega.dev-t3-gpt-5-2-p4

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 1 | 0 | 2 | 1.000 | 0.333 |
| Other | 4 | 0 | 4 | 1.000 | 0.500 |
| Security Misconfiguration | 2 | 0 | 1 | 1.000 | 0.667 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 5 | 0.000 | 0.000 |

### kolega.dev-t3-opus-4-6-p4-r1

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 0 | 0 | 3 | 0.000 | 0.000 |
| Other | 3 | 0 | 5 | 1.000 | 0.375 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 5 | 0.000 | 0.000 |

### kolega.dev-t3-opus-4-6-p4-r2

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 1 | 0 | 2 | 1.000 | 0.333 |
| Other | 5 | 0 | 3 | 1.000 | 0.625 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 3 | 0 | 2 | 1.000 | 0.600 |

### kolega.dev-t3-opus-4-6-p4-r3

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 0 | 0 | 3 | 0.000 | 0.000 |
| Other | 3 | 0 | 5 | 1.000 | 0.375 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 5 | 0.000 | 0.000 |

### kolega.dev-t3-sonnet-4-6-p1

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 0 | 0 | 3 | 0.000 | 0.000 |
| Other | 3 | 0 | 5 | 1.000 | 0.375 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 1 | 1 | 0 | 0.500 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 5 | 0.000 | 0.000 |

### kolega.dev-t3-sonnet-4-6-p1-r0

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 1 | 0 | 2 | 1.000 | 0.333 |
| Other | 3 | 0 | 5 | 1.000 | 0.375 |
| Security Misconfiguration | 0 | 0 | 3 | 0.000 | 0.000 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 5 | 0.000 | 0.000 |

### kolega.dev-t3-sonnet-4-6-p3

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 1 | 0 | 2 | 1.000 | 0.333 |
| Other | 3 | 0 | 5 | 1.000 | 0.375 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 0 | 0 | 5 | 0.000 | 0.000 |

### kolega.dev-t3-sonnet-4-6-p4

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 2 | 0 | 1 | 1.000 | 0.667 |
| Other | 4 | 0 | 4 | 1.000 | 0.500 |
| Security Misconfiguration | 3 | 0 | 0 | 1.000 | 1.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 3 | 0 | 2 | 1.000 | 0.600 |

### sonarqube

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Missing Authentication / Authorization | 0 | 0 | 3 | 0.000 | 0.000 |
| Other | 0 | 0 | 8 | 0.000 | 0.000 |
| Security Misconfiguration | 0 | 0 | 3 | 0.000 | 0.000 |
| Sensitive Data Exposure | 0 | 0 | 1 | 0.000 | 0.000 |
| SQL Injection | 0 | 0 | 1 | 0.000 | 0.000 |
| Cross-Site Scripting | 0 | 0 | 5 | 0.000 | 0.000 |

---

## Per Severity Breakdown

### kolega.dev-t2-sonnet-4-6-p1

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 1 | 0 | 1 | 0.500 |
| Medium | 2 | 0 | 10 | 0.167 |
| Low | 1 | 0 | 5 | 0.167 |

### kolega.dev-t2-sonnet-4-6-p4-r1

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 1 | 0 | 1 | 0.500 |
| Medium | 8 | 0 | 4 | 0.667 |
| Low | 4 | 0 | 2 | 0.667 |

### kolega.dev-t2-sonnet-4-6-p4-r2

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 1 | 0 | 1 | 0.500 |
| Medium | 2 | 0 | 10 | 0.167 |
| Low | 4 | 0 | 2 | 0.667 |

### kolega.dev-t2-sonnet-4-6-p4-r3

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 1 | 0 | 1 | 0.500 |
| Medium | 9 | 0 | 3 | 0.750 |
| Low | 5 | 0 | 1 | 0.833 |

### kolega.dev-t3-gemini-3.1-pro-p4-r1

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 1 | 0 | 1 | 0.500 |
| Medium | 2 | 0 | 10 | 0.167 |
| Low | 2 | 0 | 4 | 0.333 |

### kolega.dev-t3-gemini-3.1-pro-p4-r2

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 2 | 0 | 0 | 1.000 |
| Medium | 7 | 0 | 5 | 0.583 |
| Low | 3 | 0 | 3 | 0.500 |

### kolega.dev-t3-gpt-5-2-p4

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 1 | 0 | 1 | 0.500 |
| Medium | 2 | 0 | 10 | 0.167 |
| Low | 4 | 0 | 2 | 0.667 |

### kolega.dev-t3-opus-4-6-p4-r1

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 1 | 0 | 1 | 0.500 |
| Medium | 2 | 0 | 10 | 0.167 |
| Low | 3 | 0 | 3 | 0.500 |

### kolega.dev-t3-opus-4-6-p4-r2

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 1 | 0 | 1 | 0.500 |
| Medium | 8 | 0 | 4 | 0.667 |
| Low | 4 | 0 | 2 | 0.667 |

### kolega.dev-t3-opus-4-6-p4-r3

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 1 | 0 | 1 | 0.500 |
| Medium | 2 | 0 | 10 | 0.167 |
| Low | 3 | 0 | 3 | 0.500 |

### kolega.dev-t3-sonnet-4-6-p1

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 1 | 1 | 1 | 0.500 |
| Medium | 2 | 0 | 10 | 0.167 |
| Low | 3 | 0 | 3 | 0.500 |

### kolega.dev-t3-sonnet-4-6-p1-r0

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 0 | 0 | 2 | 0.000 |
| Medium | 1 | 0 | 11 | 0.083 |
| Low | 3 | 0 | 3 | 0.500 |

### kolega.dev-t3-sonnet-4-6-p3

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 1 | 0 | 1 | 0.500 |
| Medium | 2 | 0 | 10 | 0.167 |
| Low | 4 | 0 | 2 | 0.667 |

### kolega.dev-t3-sonnet-4-6-p4

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 1 | 0 | 1 | 0.500 |
| Medium | 7 | 0 | 5 | 0.583 |
| Low | 5 | 0 | 1 | 0.833 |

### sonarqube

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 0 | 0 | 1 | 0.000 |
| High | 0 | 0 | 2 | 0.000 |
| Medium | 0 | 0 | 12 | 0.000 |
| Low | 0 | 0 | 6 | 0.000 |

---

## Detailed Results

### kolega.dev-t2-sonnet-4-6-p1

**True Positives (5):**

- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-79` on `sqli/app.py`:L35 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L41 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**

**False Positives (2):**

- ❌ `CWE-94` on `sqli/app.py`:L24 → matched **—**
- ❌ `CWE-307` on `sqli/routes.py`:L10 → matched **—**

**False Negatives (Missed) (16):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L22 — **dvpwa-002** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/students.jinja2`:L16 — **dvpwa-003** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L14 — **dvpwa-004** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/courses.jinja2`:L17 — **dvpwa-005** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/student.jinja2`:L19 — **dvpwa-006** (stored_xss)
- ⚠️ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 — **dvpwa-011** (sensitive_data_exposure)
- ⚠️ `CWE-862` on `sqli/views.py`:L54 — **dvpwa-012** (security_misconfiguration)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-384` on `sqli/views.py`:L42 — **dvpwa-014** (security_misconfiguration)
- ⚠️ `CWE-16` on `sqli/app.py`:L24 — **dvpwa-015** (security_misconfiguration)
- ⚠️ `CWE-306` on `sqli/schema/config.py`:L12 — **dvpwa-016** (security_misconfiguration)
- ⚠️ `CWE-307` on `sqli/views.py`:L33 — **dvpwa-017** (missing_rate_limiting)
- ⚠️ `CWE-307` on `sqli/views.py`:L50 — **dvpwa-018** (missing_rate_limiting)
- ⚠️ `CWE-312` on `sqli/utils/jinja2.py`:L19 — **dvpwa-019** (sensitive_data_exposure)
- ⚠️ `CWE-312` on `sqli/services/db.py`:L15 — **dvpwa-020** (sensitive_data_exposure)
- ⚠️ `CWE-319` on `sqli/services/db.py`:L15 — **dvpwa-021** (security_misconfiguration)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### kolega.dev-t2-sonnet-4-6-p4-r1

**True Positives (14):**

- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-489` on `sqli/app.py`:L24 → matched **dvpwa-015**
- ✅ `CWE-79` on `sqli/app.py`:L35 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L40 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**
- ✅ `CWE-306` on `sqli/schema/config.py`:L12 → matched **dvpwa-016**
- ✅ `CWE-319` on `sqli/services/db.py`:L15 → matched **dvpwa-021**
- ✅ `CWE-79` on `sqli/templates/course.jinja2`:L22 → matched **dvpwa-002**
- ✅ `CWE-79` on `sqli/templates/courses.jinja2`:L17 → matched **dvpwa-005**
- ✅ `CWE-79` on `sqli/templates/student.jinja2`:L19 → matched **dvpwa-006**
- ✅ `CWE-79` on `sqli/templates/students.jinja2`:L16 → matched **dvpwa-003**
- ✅ `CWE-306` on `sqli/views.py`:L52 → matched **dvpwa-012**
- ✅ `CWE-384` on `sqli/views.py`:L33 → matched **dvpwa-014**

**False Positives (14):**

- ❌ `CWE-306` on `config/dev.yaml`:L8 → matched **—**
- ❌ `CWE-798` on `config/dev.yaml`:L2 → matched **—**
- ❌ `CWE-862` on `sqli/dao/mark.py`:L19 → matched **—**
- ❌ `CWE-319` on `sqli/schema/config.py`:L5 → matched **—**
- ❌ `CWE-306` on `sqli/services/redis.py`:L12 → matched **—**
- ❌ `CWE-79` on `sqli/templates/base.jinja2`:L25 → matched **—**
- ❌ `CWE-79` on `sqli/templates/errors/50x.jinja2`:L6 → matched **—**
- ❌ `CWE-79` on `sqli/templates/evaluate.jinja2`:L17 → matched **—**
- ❌ `CWE-352` on `sqli/templates/review.jinja2`:L33 → matched **—**
- ❌ `CWE-79` on `sqli/templates/review.jinja2`:L32 → matched **—**
- ❌ `CWE-20` on `sqli/views.py`:L54 → matched **—**
- ❌ `CWE-307` on `sqli/views.py`:L22 → matched **—**
- ❌ `CWE-613` on `sqli/views.py`:L156 → matched **—**
- ❌ `CWE-862` on `sqli/views.py`:L63 → matched **—**

**False Negatives (Missed) (7):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L14 — **dvpwa-004** (stored_xss)
- ⚠️ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 — **dvpwa-011** (sensitive_data_exposure)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-307` on `sqli/views.py`:L33 — **dvpwa-017** (missing_rate_limiting)
- ⚠️ `CWE-307` on `sqli/views.py`:L50 — **dvpwa-018** (missing_rate_limiting)
- ⚠️ `CWE-312` on `sqli/utils/jinja2.py`:L19 — **dvpwa-019** (sensitive_data_exposure)
- ⚠️ `CWE-312` on `sqli/services/db.py`:L15 — **dvpwa-020** (sensitive_data_exposure)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### kolega.dev-t2-sonnet-4-6-p4-r2

**True Positives (8):**

- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-489` on `sqli/app.py`:L24 → matched **dvpwa-015**
- ✅ `CWE-79` on `sqli/app.py`:L35 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L40 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**
- ✅ `CWE-306` on `sqli/schema/config.py`:L12 → matched **dvpwa-016**
- ✅ `CWE-319` on `sqli/services/db.py`:L15 → matched **dvpwa-021**

**False Positives (8):**

- ❌ `CWE-79` on `sqli/dao/course.py`:L42 → matched **—**
- ❌ `CWE-862` on `sqli/dao/mark.py`:L19 → matched **—**
- ❌ `CWE-79` on `sqli/dao/review.py`:L29 → matched **—**
- ❌ `CWE-79` on `sqli/dao/student.py`:L41 → matched **—**
- ❌ `CWE-862` on `sqli/dao/student.py`:L25 → matched **—**
- ❌ `CWE-209` on `sqli/middlewares.py`:L62 → matched **—**
- ❌ `CWE-312` on `sqli/utils/jinja2.py`:L1 → matched **—**
- ❌ `CWE-307` on `sqli/views.py`:L1 → matched **—**

**False Negatives (Missed) (13):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L22 — **dvpwa-002** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/students.jinja2`:L16 — **dvpwa-003** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L14 — **dvpwa-004** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/courses.jinja2`:L17 — **dvpwa-005** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/student.jinja2`:L19 — **dvpwa-006** (stored_xss)
- ⚠️ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 — **dvpwa-011** (sensitive_data_exposure)
- ⚠️ `CWE-862` on `sqli/views.py`:L54 — **dvpwa-012** (security_misconfiguration)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-384` on `sqli/views.py`:L42 — **dvpwa-014** (security_misconfiguration)
- ⚠️ `CWE-307` on `sqli/views.py`:L33 — **dvpwa-017** (missing_rate_limiting)
- ⚠️ `CWE-307` on `sqli/views.py`:L50 — **dvpwa-018** (missing_rate_limiting)
- ⚠️ `CWE-312` on `sqli/utils/jinja2.py`:L19 — **dvpwa-019** (sensitive_data_exposure)
- ⚠️ `CWE-312` on `sqli/services/db.py`:L15 — **dvpwa-020** (sensitive_data_exposure)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### kolega.dev-t2-sonnet-4-6-p4-r3

**True Positives (16):**

- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-489` on `sqli/app.py`:L24 → matched **dvpwa-015**
- ✅ `CWE-79` on `sqli/app.py`:L35 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L40 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**
- ✅ `CWE-306` on `sqli/schema/config.py`:L12 → matched **dvpwa-016**
- ✅ `CWE-312` on `sqli/services/db.py`:L15 → matched **dvpwa-020**
- ✅ `CWE-79` on `sqli/templates/course.jinja2`:L22 → matched **dvpwa-002**
- ✅ `CWE-79` on `sqli/templates/courses.jinja2`:L17 → matched **dvpwa-005**
- ✅ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 → matched **dvpwa-011**
- ✅ `CWE-79` on `sqli/templates/student.jinja2`:L19 → matched **dvpwa-006**
- ✅ `CWE-79` on `sqli/templates/students.jinja2`:L16 → matched **dvpwa-003**
- ✅ `CWE-312` on `sqli/utils/jinja2.py`:L19 → matched **dvpwa-019**
- ✅ `CWE-306` on `sqli/views.py`:L51 → matched **dvpwa-012**
- ✅ `CWE-384` on `sqli/views.py`:L33 → matched **dvpwa-014**

**False Positives (21):**

- ❌ `CWE-16` on `config/dev.yaml`:L14 → matched **—**
- ❌ `CWE-306` on `config/dev.yaml`:L8 → matched **—**
- ❌ `CWE-312` on `run.py`:L11 → matched **—**
- ❌ `CWE-89` on `sqli/dao/course.py`:L31 → matched **—**
- ❌ `CWE-862` on `sqli/dao/mark.py`:L19 → matched **—**
- ❌ `CWE-862` on `sqli/dao/review.py`:L28 → matched **—**
- ❌ `CWE-312` on `sqli/dao/user.py`:L7 → matched **—**
- ❌ `CWE-798` on `sqli/schema/config.py`:L4 → matched **—**
- ❌ `CWE-770` on `sqli/schema/forms.py`:L8 → matched **—**
- ❌ `CWE-319` on `sqli/services/redis.py`:L12 → matched **—**
- ❌ `CWE-79` on `sqli/templates/base.jinja2`:L25 → matched **—**
- ❌ `CWE-79` on `sqli/templates/errors/40x.jinja2`:L3 → matched **—**
- ❌ `CWE-79` on `sqli/templates/errors/50x.jinja2`:L3 → matched **—**
- ❌ `CWE-79` on `sqli/templates/evaluate.jinja2`:L25 → matched **—**
- ❌ `CWE-79` on `sqli/templates/index.jinja2`:L5 → matched **—**
- ❌ `CWE-79` on `sqli/templates/review.jinja2`:L32 → matched **—**
- ❌ `CWE-209` on `sqli/views.py`:L44 → matched **—**
- ❌ `CWE-307` on `sqli/views.py`:L22 → matched **—**
- ❌ `CWE-352` on `sqli/views.py`:L156 → matched **—**
- ❌ `CWE-770` on `sqli/views.py`:L83 → matched **—**
- ❌ `CWE-862` on `sqli/views.py`:L63 → matched **—**

**False Negatives (Missed) (5):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L14 — **dvpwa-004** (stored_xss)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-307` on `sqli/views.py`:L33 — **dvpwa-017** (missing_rate_limiting)
- ⚠️ `CWE-307` on `sqli/views.py`:L50 — **dvpwa-018** (missing_rate_limiting)
- ⚠️ `CWE-319` on `sqli/services/db.py`:L15 — **dvpwa-021** (security_misconfiguration)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### kolega.dev-t3-gemini-3.1-pro-p4-r1

**True Positives (6):**

- ✅ `CWE-352` on `sqli/app.py`:L25 → matched **dvpwa-009**
- ✅ `CWE-489` on `sqli/app.py`:L23 → matched **dvpwa-015**
- ✅ `CWE-79` on `sqli/app.py`:L33 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L40 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L40 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L19 → matched **dvpwa-010**

**False Positives (1):**

- ❌ `CWE-285` on `sqli/schema/config.py`:L12 → matched **—**

**False Negatives (Missed) (15):**

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
- ⚠️ `CWE-319` on `sqli/services/db.py`:L15 — **dvpwa-021** (security_misconfiguration)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### kolega.dev-t3-gemini-3.1-pro-p4-r2

**True Positives (13):**

- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-489` on `sqli/app.py`:L24 → matched **dvpwa-015**
- ✅ `CWE-79` on `sqli/app.py`:L35 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L40 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**
- ✅ `CWE-79` on `sqli/templates/courses.jinja2`:L17 → matched **dvpwa-005**
- ✅ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 → matched **dvpwa-011**
- ✅ `CWE-79` on `sqli/templates/student.jinja2`:L19 → matched **dvpwa-006**
- ✅ `CWE-79` on `sqli/templates/students.jinja2`:L16 → matched **dvpwa-003**
- ✅ `CWE-307` on `sqli/views.py`:L33 → matched **dvpwa-017**
- ✅ `CWE-384` on `sqli/views.py`:L41 → matched **dvpwa-014**
- ✅ `CWE-862` on `sqli/views.py`:L54 → matched **dvpwa-012**

**False Positives (6):**

- ❌ `CWE-285` on `sqli/schema/config.py`:L12 → matched **—**
- ❌ `CWE-79` on `sqli/templates/course.jinja2`:L3 → matched **—**
- ❌ `CWE-79` on `sqli/templates/errors/50x.jinja2`:L3 → matched **—**
- ❌ `CWE-79` on `sqli/templates/evaluate.jinja2`:L17 → matched **—**
- ❌ `CWE-79` on `sqli/templates/index.jinja2`:L5 → matched **—**
- ❌ `CWE-79` on `sqli/templates/review.jinja2`:L26 → matched **—**

**False Negatives (Missed) (8):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L22 — **dvpwa-002** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L14 — **dvpwa-004** (stored_xss)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-306` on `sqli/schema/config.py`:L12 — **dvpwa-016** (security_misconfiguration)
- ⚠️ `CWE-307` on `sqli/views.py`:L50 — **dvpwa-018** (missing_rate_limiting)
- ⚠️ `CWE-312` on `sqli/utils/jinja2.py`:L19 — **dvpwa-019** (sensitive_data_exposure)
- ⚠️ `CWE-312` on `sqli/services/db.py`:L15 — **dvpwa-020** (sensitive_data_exposure)
- ⚠️ `CWE-319` on `sqli/services/db.py`:L15 — **dvpwa-021** (security_misconfiguration)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### kolega.dev-t3-gpt-5-2-p4

**True Positives (8):**

- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-79` on `sqli/app.py`:L35 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-327` on `sqli/dao/user.py`:L40 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**
- ✅ `CWE-306` on `sqli/schema/config.py`:L12 → matched **dvpwa-016**
- ✅ `CWE-312` on `sqli/services/db.py`:L15 → matched **dvpwa-020**
- ✅ `CWE-319` on `sqli/services/db.py`:L15 → matched **dvpwa-021**

**False Positives (13):**

- ❌ `CWE-20` on `sqli/dao/course.py` → matched **—**
- ❌ `CWE-89` on `sqli/dao/course.py`:L31 → matched **—**
- ❌ `CWE-20` on `sqli/dao/review.py`:L29 → matched **—**
- ❌ `CWE-20` on `sqli/dao/student.py` → matched **—**
- ❌ `CWE-204` on `sqli/dao/user.py`:L31 → matched **—**
- ❌ `CWE-312` on `sqli/dao/user.py`:L7 → matched **—**
- ❌ `CWE-759` on `sqli/dao/user.py`:L40 → matched **—**
- ❌ `CWE-916` on `sqli/dao/user.py` → matched **—**
- ❌ `CWE-20` on `sqli/schema/forms.py`:L9 → matched **—**
- ❌ `CWE-307` on `sqli/schema/forms.py`:L1 → matched **—**
- ❌ `CWE-79` on `sqli/schema/forms.py`:L8 → matched **—**
- ❌ `CWE-306` on `sqli/services/redis.py`:L12 → matched **—**
- ❌ `CWE-307` on `sqli/utils/auth.py`:L12 → matched **—**

**False Negatives (Missed) (13):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L22 — **dvpwa-002** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/students.jinja2`:L16 — **dvpwa-003** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L14 — **dvpwa-004** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/courses.jinja2`:L17 — **dvpwa-005** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/student.jinja2`:L19 — **dvpwa-006** (stored_xss)
- ⚠️ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 — **dvpwa-011** (sensitive_data_exposure)
- ⚠️ `CWE-862` on `sqli/views.py`:L54 — **dvpwa-012** (security_misconfiguration)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-384` on `sqli/views.py`:L42 — **dvpwa-014** (security_misconfiguration)
- ⚠️ `CWE-16` on `sqli/app.py`:L24 — **dvpwa-015** (security_misconfiguration)
- ⚠️ `CWE-307` on `sqli/views.py`:L33 — **dvpwa-017** (missing_rate_limiting)
- ⚠️ `CWE-307` on `sqli/views.py`:L50 — **dvpwa-018** (missing_rate_limiting)
- ⚠️ `CWE-312` on `sqli/utils/jinja2.py`:L19 — **dvpwa-019** (sensitive_data_exposure)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### kolega.dev-t3-opus-4-6-p4-r1

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
- ❌ `CWE-312` on `sqli/schema/config.py`:L12 → matched **—**
- ❌ `CWE-319` on `sqli/services/redis.py`:L12 → matched **—**
- ❌ `CWE-79` on `sqli/static/js/jquery-3.2.1.min.js`:L1 → matched **—**

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

### kolega.dev-t3-opus-4-6-p4-r2

**True Positives (14):**

- ✅ `CWE-16` on `sqli/app.py`:L18 → matched **dvpwa-015**
- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-79` on `sqli/app.py`:L35 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L41 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**
- ✅ `CWE-319` on `sqli/services/db.py`:L15 → matched **dvpwa-021**
- ✅ `CWE-79` on `sqli/templates/courses.jinja2`:L17 → matched **dvpwa-005**
- ✅ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 → matched **dvpwa-011**
- ✅ `CWE-79` on `sqli/templates/student.jinja2`:L19 → matched **dvpwa-006**
- ✅ `CWE-79` on `sqli/templates/students.jinja2`:L16 → matched **dvpwa-003**
- ✅ `CWE-200` on `sqli/utils/jinja2.py`:L19 → matched **dvpwa-019**
- ✅ `CWE-306` on `sqli/views.py`:L52 → matched **dvpwa-012**
- ✅ `CWE-384` on `sqli/views.py`:L33 → matched **dvpwa-014**

**False Positives (22):**

- ❌ `CWE-489` on `sqli/app.py`:L24 → matched **—**
- ❌ `CWE-862` on `sqli/dao/mark.py`:L19 → matched **—**
- ❌ `CWE-862` on `sqli/dao/review.py`:L29 → matched **—**
- ❌ `CWE-200` on `sqli/dao/user.py`:L22 → matched **—**
- ❌ `CWE-209` on `sqli/middlewares.py`:L62 → matched **—**
- ❌ `CWE-287` on `sqli/schema/config.py`:L12 → matched **—**
- ❌ `CWE-287` on `sqli/services/redis.py`:L12 → matched **—**
- ❌ `CWE-352` on `sqli/templates/course.jinja2`:L45 → matched **—**
- ❌ `CWE-79` on `sqli/templates/course.jinja2`:L3 → matched **—**
- ❌ `CWE-862` on `sqli/templates/course.jinja2`:L41 → matched **—**
- ❌ `CWE-862` on `sqli/templates/courses.jinja2`:L25 → matched **—**
- ❌ `CWE-79` on `sqli/templates/evaluate.jinja2`:L17 → matched **—**
- ❌ `CWE-79` on `sqli/templates/review.jinja2`:L32 → matched **—**
- ❌ `CWE-862` on `sqli/templates/students.jinja2`:L21 → matched **—**
- ❌ `CWE-384` on `sqli/utils/auth.py`:L26 → matched **—**
- ❌ `CWE-20` on `sqli/views.py`:L55 → matched **—**
- ❌ `CWE-200` on `sqli/views.py`:L46 → matched **—**
- ❌ `CWE-307` on `sqli/views.py`:L22 → matched **—**
- ❌ `CWE-613` on `sqli/views.py`:L157 → matched **—**
- ❌ `CWE-639` on `sqli/views.py`:L64 → matched **—**
- ❌ `CWE-770` on `sqli/views.py`:L83 → matched **—**
- ❌ `CWE-862` on `sqli/views.py`:L58 → matched **—**

**False Negatives (Missed) (7):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L22 — **dvpwa-002** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L14 — **dvpwa-004** (stored_xss)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-306` on `sqli/schema/config.py`:L12 — **dvpwa-016** (security_misconfiguration)
- ⚠️ `CWE-307` on `sqli/views.py`:L33 — **dvpwa-017** (missing_rate_limiting)
- ⚠️ `CWE-307` on `sqli/views.py`:L50 — **dvpwa-018** (missing_rate_limiting)
- ⚠️ `CWE-312` on `sqli/services/db.py`:L15 — **dvpwa-020** (sensitive_data_exposure)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### kolega.dev-t3-opus-4-6-p4-r3

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

### kolega.dev-t3-sonnet-4-6-p1

**True Positives (7):**

- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-489` on `sqli/app.py`:L24 → matched **dvpwa-015**
- ✅ `CWE-79` on `sqli/app.py`:L35 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L40 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**
- ✅ `CWE-312` on `sqli/services/db.py`:L15 → matched **dvpwa-020**

**False Positives (8):**

- ❌ `CWE-89` on `sqli/dao/course.py`:L36 → matched **dvpwa-fp-003**
- ❌ `CWE-862` on `sqli/dao/mark.py`:L29 → matched **—**
- ❌ `CWE-862` on `sqli/dao/student.py`:L24 → matched **—**
- ❌ `CWE-209` on `sqli/middlewares.py`:L61 → matched **—**
- ❌ `CWE-384` on `sqli/middlewares.py`:L13 → matched **—**
- ❌ `CWE-862` on `sqli/routes.py`:L21 → matched **—**
- ❌ `CWE-306` on `sqli/services/redis.py`:L12 → matched **—**
- ❌ `CWE-307` on `sqli/views.py`:L1 → matched **—**

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
- ⚠️ `CWE-319` on `sqli/services/db.py`:L15 — **dvpwa-021** (security_misconfiguration)

**True Negatives (3):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### kolega.dev-t3-sonnet-4-6-p1-r0

**True Positives (5):**

- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-759` on `sqli/dao/user.py`:L40 → matched **dvpwa-008**
- ✅ `CWE-306` on `sqli/schema/config.py`:L12 → matched **dvpwa-016**
- ✅ `CWE-312` on `sqli/services/db.py`:L15 → matched **dvpwa-020**
- ✅ `CWE-319` on `sqli/services/db.py`:L15 → matched **dvpwa-021**

**False Positives (11):**

- ❌ `CWE-20` on `sqli/dao/course.py` → matched **—**
- ❌ `CWE-20` on `sqli/dao/review.py`:L29 → matched **—**
- ❌ `CWE-20` on `sqli/dao/student.py` → matched **—**
- ❌ `CWE-204` on `sqli/dao/user.py`:L31 → matched **—**
- ❌ `CWE-312` on `sqli/dao/user.py`:L7 → matched **—**
- ❌ `CWE-916` on `sqli/dao/user.py` → matched **—**
- ❌ `CWE-20` on `sqli/schema/forms.py`:L9 → matched **—**
- ❌ `CWE-307` on `sqli/schema/forms.py`:L1 → matched **—**
- ❌ `CWE-79` on `sqli/schema/forms.py`:L8 → matched **—**
- ❌ `CWE-306` on `sqli/services/redis.py`:L12 → matched **—**
- ❌ `CWE-307` on `sqli/utils/auth.py`:L12 → matched **—**

**False Negatives (Missed) (16):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L22 — **dvpwa-002** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/students.jinja2`:L16 — **dvpwa-003** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L14 — **dvpwa-004** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/courses.jinja2`:L17 — **dvpwa-005** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/student.jinja2`:L19 — **dvpwa-006** (stored_xss)
- ⚠️ `CWE-16` on `sqli/app.py`:L35 — **dvpwa-007** (security_misconfiguration)
- ⚠️ `CWE-352` on `sqli/app.py`:L27 — **dvpwa-009** (security_misconfiguration)
- ⚠️ `CWE-1004` on `sqli/middlewares.py`:L20 — **dvpwa-010** (security_misconfiguration)
- ⚠️ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 — **dvpwa-011** (sensitive_data_exposure)
- ⚠️ `CWE-862` on `sqli/views.py`:L54 — **dvpwa-012** (security_misconfiguration)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-384` on `sqli/views.py`:L42 — **dvpwa-014** (security_misconfiguration)
- ⚠️ `CWE-16` on `sqli/app.py`:L24 — **dvpwa-015** (security_misconfiguration)
- ⚠️ `CWE-307` on `sqli/views.py`:L33 — **dvpwa-017** (missing_rate_limiting)
- ⚠️ `CWE-307` on `sqli/views.py`:L50 — **dvpwa-018** (missing_rate_limiting)
- ⚠️ `CWE-312` on `sqli/utils/jinja2.py`:L19 — **dvpwa-019** (sensitive_data_exposure)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### kolega.dev-t3-sonnet-4-6-p3

**True Positives (8):**

- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-489` on `sqli/app.py`:L24 → matched **dvpwa-015**
- ✅ `CWE-79` on `sqli/app.py`:L35 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L43 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L41 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**
- ✅ `CWE-306` on `sqli/schema/config.py`:L12 → matched **dvpwa-016**
- ✅ `CWE-319` on `sqli/services/db.py`:L15 → matched **dvpwa-021**

**False Positives (3):**

- ❌ `CWE-209` on `sqli/middlewares.py`:L62 → matched **—**
- ❌ `CWE-312` on `sqli/utils/jinja2.py`:L1 → matched **—**
- ❌ `CWE-307` on `sqli/views.py`:L1 → matched **—**

**False Negatives (Missed) (13):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L22 — **dvpwa-002** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/students.jinja2`:L16 — **dvpwa-003** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L14 — **dvpwa-004** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/courses.jinja2`:L17 — **dvpwa-005** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/student.jinja2`:L19 — **dvpwa-006** (stored_xss)
- ⚠️ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 — **dvpwa-011** (sensitive_data_exposure)
- ⚠️ `CWE-862` on `sqli/views.py`:L54 — **dvpwa-012** (security_misconfiguration)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-384` on `sqli/views.py`:L42 — **dvpwa-014** (security_misconfiguration)
- ⚠️ `CWE-307` on `sqli/views.py`:L33 — **dvpwa-017** (missing_rate_limiting)
- ⚠️ `CWE-307` on `sqli/views.py`:L50 — **dvpwa-018** (missing_rate_limiting)
- ⚠️ `CWE-312` on `sqli/utils/jinja2.py`:L19 — **dvpwa-019** (sensitive_data_exposure)
- ⚠️ `CWE-312` on `sqli/services/db.py`:L15 — **dvpwa-020** (sensitive_data_exposure)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### kolega.dev-t3-sonnet-4-6-p4

**True Positives (14):**

- ✅ `CWE-352` on `sqli/app.py`:L27 → matched **dvpwa-009**
- ✅ `CWE-489` on `sqli/app.py`:L24 → matched **dvpwa-015**
- ✅ `CWE-79` on `sqli/app.py`:L35 → matched **dvpwa-007**
- ✅ `CWE-89` on `sqli/dao/student.py`:L42 → matched **dvpwa-001**
- ✅ `CWE-916` on `sqli/dao/user.py`:L40 → matched **dvpwa-008**
- ✅ `CWE-1004` on `sqli/middlewares.py`:L20 → matched **dvpwa-010**
- ✅ `CWE-306` on `sqli/schema/config.py`:L12 → matched **dvpwa-016**
- ✅ `CWE-312` on `sqli/services/db.py`:L15 → matched **dvpwa-020**
- ✅ `CWE-79` on `sqli/templates/courses.jinja2`:L17 → matched **dvpwa-005**
- ✅ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 → matched **dvpwa-011**
- ✅ `CWE-79` on `sqli/templates/student.jinja2`:L19 → matched **dvpwa-006**
- ✅ `CWE-79` on `sqli/templates/students.jinja2`:L16 → matched **dvpwa-003**
- ✅ `CWE-306` on `sqli/views.py`:L52 → matched **dvpwa-012**
- ✅ `CWE-384` on `sqli/views.py`:L33 → matched **dvpwa-014**

**False Positives (13):**

- ❌ `CWE-319` on `sqli/services/redis.py`:L12 → matched **—**
- ❌ `CWE-79` on `sqli/templates/base.jinja2`:L25 → matched **—**
- ❌ `CWE-352` on `sqli/templates/course.jinja2`:L45 → matched **—**
- ❌ `CWE-79` on `sqli/templates/errors/40x.jinja2`:L3 → matched **—**
- ❌ `CWE-79` on `sqli/templates/errors/50x.jinja2`:L3 → matched **—**
- ❌ `CWE-79` on `sqli/templates/evaluate.jinja2`:L17 → matched **—**
- ❌ `CWE-79` on `sqli/templates/index.jinja2`:L5 → matched **—**
- ❌ `CWE-79` on `sqli/templates/review.jinja2`:L32 → matched **—**
- ❌ `CWE-20` on `sqli/views.py`:L54 → matched **—**
- ❌ `CWE-209` on `sqli/views.py`:L44 → matched **—**
- ❌ `CWE-307` on `sqli/views.py`:L22 → matched **—**
- ❌ `CWE-770` on `sqli/views.py`:L84 → matched **—**
- ❌ `CWE-862` on `sqli/views.py`:L63 → matched **—**

**False Negatives (Missed) (7):**

- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L22 — **dvpwa-002** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L14 — **dvpwa-004** (stored_xss)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-307` on `sqli/views.py`:L33 — **dvpwa-017** (missing_rate_limiting)
- ⚠️ `CWE-307` on `sqli/views.py`:L50 — **dvpwa-018** (missing_rate_limiting)
- ⚠️ `CWE-312` on `sqli/utils/jinja2.py`:L19 — **dvpwa-019** (sensitive_data_exposure)
- ⚠️ `CWE-319` on `sqli/services/db.py`:L15 — **dvpwa-021** (security_misconfiguration)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)

### sonarqube

**False Negatives (Missed) (21):**

- ⚠️ `CWE-89` on `sqli/dao/student.py`:L42 — **dvpwa-001** (sql_injection)
- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L22 — **dvpwa-002** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/students.jinja2`:L16 — **dvpwa-003** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/course.jinja2`:L14 — **dvpwa-004** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/courses.jinja2`:L17 — **dvpwa-005** (stored_xss)
- ⚠️ `CWE-79` on `sqli/templates/student.jinja2`:L19 — **dvpwa-006** (stored_xss)
- ⚠️ `CWE-16` on `sqli/app.py`:L35 — **dvpwa-007** (security_misconfiguration)
- ⚠️ `CWE-916` on `sqli/dao/user.py`:L41 — **dvpwa-008** (sensitive_data_exposure)
- ⚠️ `CWE-352` on `sqli/app.py`:L27 — **dvpwa-009** (security_misconfiguration)
- ⚠️ `CWE-1004` on `sqli/middlewares.py`:L20 — **dvpwa-010** (security_misconfiguration)
- ⚠️ `CWE-209` on `sqli/templates/errors/50x.jinja2`:L6 — **dvpwa-011** (sensitive_data_exposure)
- ⚠️ `CWE-862` on `sqli/views.py`:L54 — **dvpwa-012** (security_misconfiguration)
- ⚠️ `CWE-862` on `sqli/views.py`:L86 — **dvpwa-013** (security_misconfiguration)
- ⚠️ `CWE-384` on `sqli/views.py`:L42 — **dvpwa-014** (security_misconfiguration)
- ⚠️ `CWE-16` on `sqli/app.py`:L24 — **dvpwa-015** (security_misconfiguration)
- ⚠️ `CWE-306` on `sqli/schema/config.py`:L12 — **dvpwa-016** (security_misconfiguration)
- ⚠️ `CWE-307` on `sqli/views.py`:L33 — **dvpwa-017** (missing_rate_limiting)
- ⚠️ `CWE-307` on `sqli/views.py`:L50 — **dvpwa-018** (missing_rate_limiting)
- ⚠️ `CWE-312` on `sqli/utils/jinja2.py`:L19 — **dvpwa-019** (sensitive_data_exposure)
- ⚠️ `CWE-312` on `sqli/services/db.py`:L15 — **dvpwa-020** (sensitive_data_exposure)
- ⚠️ `CWE-319` on `sqli/services/db.py`:L15 — **dvpwa-021** (security_misconfiguration)

**True Negatives (4):**

- ⚪ `CWE-89` on `sqli/dao/user.py`:L33 — **dvpwa-fp-001** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/review.py`:L31 — **dvpwa-fp-002** (sql_injection)
- ⚪ `CWE-89` on `sqli/dao/course.py`:L44 — **dvpwa-fp-003** (sql_injection)
- ⚪ `CWE-79` on `sqli/templates/student.jinja2`:L14 — **dvpwa-fp-004** (stored_xss)
