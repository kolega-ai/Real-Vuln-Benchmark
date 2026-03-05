# RealVuln Scorecard — oss-oopssec-store

**Commit:** `ddf442559883`  
**Generated:** 2026-02-24T07:34:43.597713+00:00  
**Ground Truth:** 23 vulnerabilities, 5 false-positive traps  
**Repository:** https://github.com/kOaDT/oss-oopssec-store  
**Type:** 1 | **Language:** typescript | **Authorship:** human_authored

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
| **F2 Score** | **5.3 / 100** |
| Precision | 33.3% |
| Recall | 4.3% |
| F1 | 0.077 |
| F2 | 0.053 |
| TP / FP / FN / TN | 1 / 2 / 22 / 5 |

---

## Per CWE Family Breakdown

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 0 | 0 | 2 | 0.000 | 0.000 |
| Command / OS Injection | 0 | 0 | 1 | 0.000 | 0.000 |
| Hardcoded Credentials | 0 | 0 | 3 | 0.000 | 0.000 |
| Missing Authentication / Authorization | 0 | 0 | 1 | 0.000 | 0.000 |
| Other | 0 | 0 | 5 | 0.000 | 0.000 |
| Path Traversal | 0 | 0 | 2 | 0.000 | 0.000 |
| Sensitive Data Exposure | 0 | 0 | 3 | 0.000 | 0.000 |
| SQL Injection | 0 | 0 | 4 | 0.000 | 0.000 |
| Server-Side Request Forgery | 0 | 0 | 1 | 0.000 | 0.000 |
| XML External Entities | 1 | 0 | 0 | 1.000 | 1.000 |

---

## Per Severity Breakdown

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 1 | 0 | 6 | 0.143 |
| High | 0 | 0 | 12 | 0.000 |
| Medium | 0 | 0 | 4 | 0.000 |

---

## Detailed Results

**True Positives (1):**

- ✅ `CWE-611` on `app/api/admin/suppliers/import-order/route.ts`:L30 → matched **oss-oopssec-store-005**

**False Positives (2):**

- ❌ `CWE-266` on `.github/workflows/deploy-docs.yml`:L11 → matched **—**
- ❌ `CWE-827` on `app/api/admin/suppliers/import-order/route.ts`:L30 → matched **—**

**False Negatives (Missed) (22):**

- ⚠️ `CWE-89` on `app/api/products/search/route.ts`:L88 — **oss-oopssec-store-001** (sql_injection)
- ⚠️ `CWE-89` on `app/api/orders/search/route.ts`:L83 — **oss-oopssec-store-002** (sql_injection)
- ⚠️ `CWE-89` on `app/api/admin/reviews/route.ts`:L117 — **oss-oopssec-store-003** (sql_injection)
- ⚠️ `CWE-89` on `app/api/tracking/route.ts`:L93 — **oss-oopssec-store-004** (sql_injection)
- ⚠️ `CWE-918` on `app/api/support/route.ts`:L18 — **oss-oopssec-store-006** (ssrf)
- ⚠️ `CWE-22` on `app/api/files/route.ts`:L44 — **oss-oopssec-store-007** (path_traversal)
- ⚠️ `CWE-22` on `app/api/files/route.ts`:L15 — **oss-oopssec-store-008** (path_traversal)
- ⚠️ `CWE-798` on `app/api/monitoring/auth/route.ts`:L3 — **oss-oopssec-store-009** (hardcoded_credentials)
- ⚠️ `CWE-798` on `app/api/monitoring/logs/route.ts`:L5 — **oss-oopssec-store-010** (hardcoded_credentials)
- ⚠️ `CWE-798` on `lib/server-auth.ts`:L12 — **oss-oopssec-store-011** (hardcoded_credentials)
- ⚠️ `CWE-639` on `app/api/orders/[id]/route.ts`:L66 — **oss-oopssec-store-012** (broken_access_control)
- ⚠️ `CWE-639` on `app/api/wishlists/[id]/route.ts`:L80 — **oss-oopssec-store-013** (broken_access_control)
- ⚠️ `CWE-915` on `app/api/auth/signup/route.ts`:L61 — **oss-oopssec-store-014** (mass_assignment)
- ⚠️ `CWE-532` on `app/api/auth/login/route.ts`:L12 — **oss-oopssec-store-015** (sensitive_data_exposure)
- ⚠️ `CWE-209` on `app/api/user/export/route.ts`:L96 — **oss-oopssec-store-016** (sensitive_data_exposure)
- ⚠️ `CWE-200` on `app/api/user/export/route.ts`:L5 — **oss-oopssec-store-017** (sensitive_data_exposure)
- ⚠️ `CWE-352` on `app/api/orders/[id]/route.ts`:L148 — **oss-oopssec-store-018** (cross_site_request_forgery)
- ⚠️ `CWE-328` on `lib/server-auth.ts`:L14 — **oss-oopssec-store-019** (insecure_cryptography)
- ⚠️ `CWE-862` on `app/api/user/support-access/route.ts`:L59 — **oss-oopssec-store-020** (broken_access_control)
- ⚠️ `CWE-77` on `app/api/ai-assistant/route.ts`:L86 — **oss-oopssec-store-021** (prompt_injection)
- ⚠️ `CWE-602` on `app/api/orders/route.ts`:L114 — **oss-oopssec-store-022** (client_side_price_manipulation)
- ⚠️ `CWE-434` on `app/api/admin/products/[id]/image/route.ts`:L92 — **oss-oopssec-store-023** (malicious_file_upload)

**True Negatives (5):**

- ⚪ `CWE-89` on `app/api/admin/analytics/route.ts`:L29 — **oss-oopssec-store-fp-001** (sql_injection)
- ⚪ `CWE-22` on `app/api/uploads/[...path]/route.ts`:L22 — **oss-oopssec-store-fp-002** (path_traversal)
- ⚪ `CWE-89` on `app/api/admin/reviews/route.ts`:L168 — **oss-oopssec-store-fp-003** (sql_injection)
- ⚪ `CWE-22` on `app/api/monitoring/logs/route.ts`:L31 — **oss-oopssec-store-fp-004** (path_traversal)
- ⚪ `CWE-798` on `app/api/ai-assistant/route.ts`:L17 — **oss-oopssec-store-fp-005** (hardcoded_credentials)
