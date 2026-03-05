# RealVuln Scorecard — vampi

**Commit:** `1713b54b601a`  
**Generated:** 2026-02-20T10:59:12.966633+00:00  
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
| **Youden's J** | **-23.2%** |
| Precision | 31.4% |
| Recall | 50.0% |
| F1 | 0.385 |
| TPR | 50.0% |
| FPR | 73.2% |
| TP / FP / FN / TN | 5 / 11 / 5 / 4 |

*Multi-run (2 runs):*

| Metric | Mean | Stddev |
|--------|------|--------|
| Precision | 0.314 | 0.028 |
| Recall | 0.500 | 0.000 |
| F1 | 0.385 | 0.021 |
| Youden's J | -0.232 | 0.025 |

---

## Per CWE Family Breakdown

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 1 | 0 | 1 | 1.000 | 0.500 |
| Denial of Service | 0 | 0 | 1 | 0.000 | 0.000 |
| Other | 2 | 0 | 3 | 1.000 | 0.400 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 0 | 1.000 | 1.000 |

---

## Per Severity Breakdown

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 0 | 1.000 |
| High | 3 | 0 | 1 | 0.750 |
| Medium | 1 | 0 | 3 | 0.250 |
| Low | 0 | 0 | 1 | 0.000 |

---

## Detailed Results
