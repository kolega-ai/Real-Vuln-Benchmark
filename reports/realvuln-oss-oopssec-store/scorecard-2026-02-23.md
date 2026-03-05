# RealVuln Scorecard — oss-oopssec-store

**Commit:** `ddf442559883`  
**Generated:** 2026-02-23T12:42:04.727102+00:00  
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

### our-scanner

| Metric | Value |
|--------|-------|
| **F2 Score** | **20.7 / 100** |
| Precision | 17.2% |
| Recall | 21.7% |
| F1 | 0.192 |
| F2 | 0.207 |
| TP / FP / FN / TN | 5 / 24 / 18 / 3 |

---

## Per CWE Family Breakdown

| Family | TP | FP | FN | Precision | Recall |
|--------|---:|---:|---:|----------:|-------:|
| Broken Access Control / IDOR | 0 | 0 | 2 | 0.000 | 0.000 |
| Command / OS Injection | 0 | 0 | 1 | 0.000 | 0.000 |
| Hardcoded Credentials | 1 | 1 | 2 | 0.500 | 0.333 |
| Missing Authentication / Authorization | 0 | 0 | 1 | 0.000 | 0.000 |
| Other | 2 | 0 | 3 | 1.000 | 0.400 |
| Path Traversal | 1 | 1 | 1 | 0.500 | 0.500 |
| Sensitive Data Exposure | 0 | 0 | 3 | 0.000 | 0.000 |
| SQL Injection | 1 | 0 | 3 | 1.000 | 0.250 |
| Server-Side Request Forgery | 0 | 0 | 1 | 0.000 | 0.000 |
| XML External Entities | 0 | 0 | 1 | 0.000 | 0.000 |

---

## Per Severity Breakdown

| Severity | TP | FP | FN | Recall |
|----------|---:|---:|---:|-------:|
| Critical | 3 | 0 | 4 | 0.429 |
| High | 2 | 1 | 10 | 0.167 |
| Medium | 0 | 1 | 4 | 0.000 |

---

## Detailed Results

**True Positives (5):**

- ✅ `CWE-915` on `app/api/auth/signup/route.ts`:L61 → matched **oss-oopssec-store-014**
- ✅ `CWE-22` on `app/api/files/route.ts`:L8 → matched **oss-oopssec-store-008**
- ✅ `CWE-89` on `app/api/tracking/route.ts`:L93 → matched **oss-oopssec-store-004**
- ✅ `CWE-798` on `lib/server-auth.ts`:L12 → matched **oss-oopssec-store-011**
- ✅ `CWE-916` on `lib/server-auth.ts`:L14 → matched **oss-oopssec-store-019**

**False Positives (24):**

- ❌ `CWE-441` on `app/api/ai-assistant/route.ts`:L38 → matched **—**
- ❌ `CWE-693` on `app/api/ai-assistant/route.ts`:L25 → matched **—**
- ❌ `CWE-770` on `app/api/ai-assistant/route.ts`:L36 → matched **—**
- ❌ `CWE-798` on `app/api/ai-assistant/route.ts`:L17 → matched **oss-oopssec-store-fp-005**
- ❌ `CWE-200` on `app/api/auth/login/route.ts`:L48 → matched **—**
- ❌ `CWE-204` on `app/api/auth/login/route.ts`:L34 → matched **—**
- ❌ `CWE-307` on `app/api/auth/login/route.ts`:L7 → matched **—**
- ❌ `CWE-312` on `app/api/auth/login/route.ts`:L12 → matched **—**
- ❌ `CWE-613` on `app/api/auth/logout/route.ts`:L4 → matched **—**
- ❌ `CWE-307` on `app/api/auth/signup/route.ts`:L8 → matched **—**
- ❌ `CWE-598` on `app/api/auth/support-login/route.ts`:L5 → matched **—**
- ❌ `CWE-613` on `app/api/auth/support-login/route.ts`:L49 → matched **—**
- ❌ `CWE-306` on `app/api/files/route.ts` → matched **—**
- ❌ `CWE-548` on `app/api/files/route.ts`:L14 → matched **—**
- ❌ `CWE-184` on `app/api/tracking/route.ts`:L4 → matched **—**
- ❌ `CWE-346` on `app/api/tracking/route.ts`:L54 → matched **—**
- ❌ `CWE-22` on `app/api/uploads/[...path]/route.ts`:L22 → matched **oss-oopssec-store-fp-002**
- ❌ `CWE-79` on `app/api/uploads/[...path]/route.ts`:L12 → matched **—**
- ❌ `CWE-922` on `lib/client-auth.ts`:L7 → matched **—**
- ❌ `CWE-284` on `lib/invoice.ts`:L37 → matched **—**
- ❌ `CWE-532` on `lib/prisma.ts`:L18 → matched **—**
- ❌ `CWE-284` on `prisma/seed.ts`:L710 → matched **—**
- ❌ `CWE-521` on `prisma/seed.ts`:L461 → matched **—**
- ❌ `CWE-916` on `prisma/seed.ts`:L340 → matched **—**

**False Negatives (Missed) (18):**

- ⚠️ `CWE-89` on `app/api/products/search/route.ts`:L88 — **oss-oopssec-store-001** (sql_injection)
- ⚠️ `CWE-89` on `app/api/orders/search/route.ts`:L83 — **oss-oopssec-store-002** (sql_injection)
- ⚠️ `CWE-89` on `app/api/admin/reviews/route.ts`:L117 — **oss-oopssec-store-003** (sql_injection)
- ⚠️ `CWE-611` on `app/api/admin/suppliers/import-order/route.ts`:L30 — **oss-oopssec-store-005** (xxe)
- ⚠️ `CWE-918` on `app/api/support/route.ts`:L18 — **oss-oopssec-store-006** (ssrf)
- ⚠️ `CWE-22` on `app/api/files/route.ts`:L44 — **oss-oopssec-store-007** (path_traversal)
- ⚠️ `CWE-798` on `app/api/monitoring/auth/route.ts`:L3 — **oss-oopssec-store-009** (hardcoded_credentials)
- ⚠️ `CWE-798` on `app/api/monitoring/logs/route.ts`:L5 — **oss-oopssec-store-010** (hardcoded_credentials)
- ⚠️ `CWE-639` on `app/api/orders/[id]/route.ts`:L66 — **oss-oopssec-store-012** (broken_access_control)
- ⚠️ `CWE-639` on `app/api/wishlists/[id]/route.ts`:L80 — **oss-oopssec-store-013** (broken_access_control)
- ⚠️ `CWE-532` on `app/api/auth/login/route.ts`:L12 — **oss-oopssec-store-015** (sensitive_data_exposure)
- ⚠️ `CWE-209` on `app/api/user/export/route.ts`:L96 — **oss-oopssec-store-016** (sensitive_data_exposure)
- ⚠️ `CWE-200` on `app/api/user/export/route.ts`:L5 — **oss-oopssec-store-017** (sensitive_data_exposure)
- ⚠️ `CWE-352` on `app/api/orders/[id]/route.ts`:L148 — **oss-oopssec-store-018** (cross_site_request_forgery)
- ⚠️ `CWE-862` on `app/api/user/support-access/route.ts`:L59 — **oss-oopssec-store-020** (broken_access_control)
- ⚠️ `CWE-77` on `app/api/ai-assistant/route.ts`:L86 — **oss-oopssec-store-021** (prompt_injection)
- ⚠️ `CWE-602` on `app/api/orders/route.ts`:L114 — **oss-oopssec-store-022** (client_side_price_manipulation)
- ⚠️ `CWE-434` on `app/api/admin/products/[id]/image/route.ts`:L92 — **oss-oopssec-store-023** (malicious_file_upload)

**True Negatives (3):**

- ⚪ `CWE-89` on `app/api/admin/analytics/route.ts`:L29 — **oss-oopssec-store-fp-001** (sql_injection)
- ⚪ `CWE-89` on `app/api/admin/reviews/route.ts`:L168 — **oss-oopssec-store-fp-003** (sql_injection)
- ⚪ `CWE-22` on `app/api/monitoring/logs/route.ts`:L31 — **oss-oopssec-store-fp-004** (path_traversal)
