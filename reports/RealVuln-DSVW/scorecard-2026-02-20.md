# RealVuln Scorecard — dsvw

**Commit:** `7d40f4b7939c`  
**Generated:** 2026-02-20T10:01:47.128677+00:00  
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
| **Youden's J** | **-26.8%** |
| Precision | 50.0% |
| Recall | 36.8% |
| F1 | 0.424 |
| TPR | 36.8% |
| FPR | 63.6% |
| TP / FP / FN / TN | 7 / 7 / 12 / 4 |

---

## Per CWE Family Breakdown

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Code Injection / RFI | 1 | 0 | 0 | 1.000 | 1.000 |
| Command / OS Injection | 0 | 0 | 1 | 0.000 | 0.000 |
| Denial of Service | 0 | 0 | 1 | 0.000 | 0.000 |
| Hardcoded Credentials | 0 | 0 | 1 | 0.000 | 0.000 |
| HTTP Header Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Insecure Deserialization | 0 | 0 | 1 | 0.000 | 0.000 |
| Open Redirect | 1 | 0 | 0 | 1.000 | 1.000 |
| Path Traversal | 0 | 0 | 1 | 0.000 | 0.000 |
| Sensitive Data Exposure | 1 | 0 | 0 | 1.000 | 1.000 |
| SQL Injection | 1 | 0 | 2 | 1.000 | 0.333 |
| Server-Side Request Forgery | 0 | 0 | 1 | 0.000 | 0.000 |
| XPath Injection | 1 | 0 | 0 | 1.000 | 1.000 |
| Cross-Site Scripting | 1 | 0 | 3 | 1.000 | 0.250 |
| XML External Entities | 0 | 0 | 1 | 0.000 | 0.000 |

---

## Per Severity Breakdown

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 4 | 0.200 |
| High | 3 | 0 | 3 | 0.500 |
| Medium | 2 | 0 | 5 | 0.286 |
| Low | 1 | 0 | 0 | 1.000 |

---

## Detailed Results

**True Positives (7):**

- &#9989; `CWE-113` on `dsvw.py`:L72 → matched **dsvw-016**
- &#9989; `CWE-209` on `dsvw.py`:L69 → matched **dsvw-018**
- &#9989; `CWE-601` on `dsvw.py`:L62 → matched **dsvw-013**
- &#9989; `CWE-643` on `dsvw.py`:L53 → matched **dsvw-008**
- &#9989; `CWE-79` on `dsvw.py`:L46 → matched **dsvw-011**
- &#9989; `CWE-89` on `dsvw.py`:L44 → matched **dsvw-010**
- &#9989; `CWE-94` on `dsvw.py`:L60 → matched **dsvw-012**

**False Positives (7):**

- &#10060; `CWE-22` on `dsvw.py`:L49 → matched **—**
- &#10060; `CWE-307` on `dsvw.py`:L65 → matched **—**
- &#10060; `CWE-330` on `dsvw.py`:L66 → matched **—**
- &#10060; `CWE-502` on `dsvw.py`:L47 → matched **—**
- &#10060; `CWE-611` on `dsvw.py`:L52 → matched **—**
- &#10060; `CWE-693` on `dsvw.py`:L71 → matched **—**
- &#10060; `CWE-78` on `dsvw.py`:L51 → matched **—**

**False Negatives (Missed) (12):**

- &#9888;&#65039; `CWE-89` on `dsvw.py`:L30 — **dsvw-001** (sql_injection)
- &#9888;&#65039; `CWE-79` on `dsvw.py`:L33 — **dsvw-002** (reflected_xss)
- &#9888;&#65039; `CWE-502` on `dsvw.py`:L35 — **dsvw-003** (insecure_deserialization)
- &#9888;&#65039; `CWE-22` on `dsvw.py`:L37 — **dsvw-004** (path_traversal)
- &#9888;&#65039; `CWE-918` on `dsvw.py`:L37 — **dsvw-005** (ssrf)
- &#9888;&#65039; `CWE-78` on `dsvw.py`:L39 — **dsvw-006** (command_injection)
- &#9888;&#65039; `CWE-611` on `dsvw.py`:L41 — **dsvw-007** (xxe)
- &#9888;&#65039; `CWE-400` on `dsvw.py`:L46 — **dsvw-009** (denial_of_service)
- &#9888;&#65039; `CWE-79` on `dsvw.py`:L65 — **dsvw-014** (reflected_xss)
- &#9888;&#65039; `CWE-89` on `dsvw.py`:L67 — **dsvw-015** (sql_injection)
- &#9888;&#65039; `CWE-798` on `dsvw.py`:L11 — **dsvw-017** (hardcoded_credentials)
- &#9888;&#65039; `CWE-79` on `dsvw.py`:L10 — **dsvw-019** (dom_xss)

**True Negatives (4):**

- &#9898; `CWE-89` on `dsvw.py`:L67 — **dsvw-fp-001** (sql_injection)
- &#9898; `CWE-89` on `dsvw.py`:L20 — **dsvw-fp-002** (sql_injection)
- &#9898; `CWE-79` on `dsvw.py`:L10 — **dsvw-fp-003** (xss)
- &#9898; `CWE-89` on `dsvw.py`:L19 — **dsvw-fp-004** (sql_injection)
