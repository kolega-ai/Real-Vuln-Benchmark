# RealVuln GT Enrichment Todo

Last updated: 2026-05-27

This tracks the 40 vibe-coded seeded v2 repos that need GT enrichment after their initial seeded GT import.

## Status Summary

| Workstream | Done | Remaining | Notes |
|---|---:|---:|---|
| Scanner-driven GT enrichment | 40 | 0 | All 40 have stable v2 artifacts; most use the partial profile excluding the unstable missing-auth detector. |
| Manual 3-agent audit layer | 40 | 0 | Claude Code, Codex Medium, Codex X-High, and Kimi Code completed with independent auth/access-control, injection/data-flow, and config/crypto/storage audit scopes. |

## Definition Of Done

A repo is scanner-enriched only when all of these are complete:

- Stable Kolega v2 scan exists or has been loaded.
- Baseline score against current GT has been recorded.
- Unmatched scanner findings have been reviewed as duplicate, false positive, or legitimate.
- Confirmed missing vulnerabilities have been added with provenance.
- `benchmark-manifest.json` counts and checksum have been updated.
- `python3 validate_gt.py <repo_id>`, `python3 validate_gt.py`, and JSON validation pass.
- The repo has been rescored after enrichment.

A repo is manually audited only when all of these are complete:

- Three independent audit scopes have been reviewed: auth/access control, injection/data flow, and config/crypto/storage.
- Candidate findings have been deduped against GT and scanner-enriched findings.
- Confirmed vulnerabilities have been added with `discovered_by: "manual_subagent_audit"` or equivalent provenance.
- Manifest, validation, and rescore have been repeated.

## Repo Tracker

| Provider | Repo ID | Source Repo | Scanner Enrichment | Manual 3-Agent Audit |
|---|---|---|---|---|
| Claude Code | `vc-claude-code-seeded-v2-crm-saas-django` | `vc_repos/claude-code/generated-crm-saas-django` | DONE | DONE |
| Claude Code | `vc-claude-code-seeded-v2-education-lms-django` | `vc_repos/claude-code/generated-education-lms-django` | PARTIAL (43/44; missing-auth timeout) | DONE |
| Claude Code | `vc-claude-code-seeded-v2-fintech-lending-fastapi` | `vc_repos/claude-code/generated-fintech-lending-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Claude Code | `vc-claude-code-seeded-v2-healthcare-clinic-django` | `vc_repos/claude-code/generated-healthcare-clinic-django` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Claude Code | `vc-claude-code-seeded-v2-hr-payroll-django` | `vc_repos/claude-code/generated-hr-payroll-django` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Claude Code | `vc-claude-code-seeded-v2-legal-case-django` | `vc_repos/claude-code/generated-legal-case-django` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Claude Code | `vc-claude-code-seeded-v2-logistics-dispatch-fastapi` | `vc_repos/claude-code/generated-logistics-dispatch-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Claude Code | `vc-claude-code-seeded-v2-marketplace-commerce-fastapi` | `vc_repos/claude-code/generated-marketplace-commerce-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Claude Code | `vc-claude-code-seeded-v2-property-management-fastapi` | `vc_repos/claude-code/generated-property-management-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Claude Code | `vc-claude-code-seeded-v2-support-desk-fastapi` | `vc_repos/claude-code/generated-support-desk-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex Medium | `vc-codex-seeded-v2-crm-saas-django` | `vc_repos/codex/generated-crm-saas-django` | DONE | DONE |
| Codex Medium | `vc-codex-seeded-v2-education-lms-django` | `vc_repos/codex/generated-education-lms-django` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex Medium | `vc-codex-seeded-v2-fintech-lending-fastapi` | `vc_repos/codex/generated-fintech-lending-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex Medium | `vc-codex-seeded-v2-healthcare-clinic-django` | `vc_repos/codex/generated-healthcare-clinic-django` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex Medium | `vc-codex-seeded-v2-hr-payroll-django` | `vc_repos/codex/generated-hr-payroll-django` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex Medium | `vc-codex-seeded-v2-legal-case-django` | `vc_repos/codex/generated-legal-case-django` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex Medium | `vc-codex-seeded-v2-logistics-dispatch-fastapi` | `vc_repos/codex/generated-logistics-dispatch-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex Medium | `vc-codex-seeded-v2-marketplace-commerce-fastapi` | `vc_repos/codex/generated-marketplace-commerce-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex Medium | `vc-codex-seeded-v2-property-management-fastapi` | `vc_repos/codex/generated-property-management-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex Medium | `vc-codex-seeded-v2-support-desk-fastapi` | `vc_repos/codex/generated-support-desk-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex X-High | `vc-codex-high-seeded-v2-crm-saas-django` | `vc_repos/codex-high/generated-crm-saas-django` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex X-High | `vc-codex-high-seeded-v2-education-lms-django` | `vc_repos/codex-high/generated-education-lms-django` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex X-High | `vc-codex-high-seeded-v2-fintech-lending-fastapi` | `vc_repos/codex-high/generated-fintech-lending-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex X-High | `vc-codex-high-seeded-v2-healthcare-clinic-django` | `vc_repos/codex-high/generated-healthcare-clinic-django` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex X-High | `vc-codex-high-seeded-v2-hr-payroll-django` | `vc_repos/codex-high/generated-hr-payroll-django` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex X-High | `vc-codex-high-seeded-v2-legal-case-django` | `vc_repos/codex-high/generated-legal-case-django` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex X-High | `vc-codex-high-seeded-v2-logistics-dispatch-fastapi` | `vc_repos/codex-high/generated-logistics-dispatch-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex X-High | `vc-codex-high-seeded-v2-marketplace-commerce-fastapi` | `vc_repos/codex-high/generated-marketplace-commerce-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex X-High | `vc-codex-high-seeded-v2-property-management-fastapi` | `vc_repos/codex-high/generated-property-management-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Codex X-High | `vc-codex-high-seeded-v2-support-desk-fastapi` | `vc_repos/codex-high/generated-support-desk-fastapi` | PARTIAL (43/44; missing-auth hung/excluded) | DONE |
| Kimi Code | `vc-kimi-code-seeded-v2-crm-saas-django` | `vc_repos/kimi-code/generated-crm-saas-django` | PARTIAL (43/44; missing-auth excluded; 43/43 selected passed) | DONE |
| Kimi Code | `vc-kimi-code-seeded-v2-education-lms-django` | `vc_repos/kimi-code/generated-education-lms-django` | PARTIAL (43/44; missing-auth excluded; 43/43 selected passed) | DONE |
| Kimi Code | `vc-kimi-code-seeded-v2-fintech-lending-fastapi` | `vc_repos/kimi-code/generated-fintech-lending-fastapi` | PARTIAL (43/44; missing-auth excluded; 43/43 selected passed) | DONE |
| Kimi Code | `vc-kimi-code-seeded-v2-healthcare-clinic-django` | `vc_repos/kimi-code/generated-healthcare-clinic-django` | PARTIAL (43/44; missing-auth excluded; 43/43 selected passed) | DONE |
| Kimi Code | `vc-kimi-code-seeded-v2-hr-payroll-django` | `vc_repos/kimi-code/generated-hr-payroll-django` | PARTIAL (43/44; missing-auth excluded; 43/43 selected passed) | DONE |
| Kimi Code | `vc-kimi-code-seeded-v2-legal-case-django` | `vc_repos/kimi-code/generated-legal-case-django` | PARTIAL (43/44; missing-auth excluded; 43/43 selected passed) | DONE |
| Kimi Code | `vc-kimi-code-seeded-v2-logistics-dispatch-fastapi` | `vc_repos/kimi-code/generated-logistics-dispatch-fastapi` | PARTIAL (43/44; missing-auth excluded; 43/43 selected passed) | DONE |
| Kimi Code | `vc-kimi-code-seeded-v2-marketplace-commerce-fastapi` | `vc_repos/kimi-code/generated-marketplace-commerce-fastapi` | PARTIAL (43/44; missing-auth excluded; 43/43 selected passed) | DONE |
| Kimi Code | `vc-kimi-code-seeded-v2-property-management-fastapi` | `vc_repos/kimi-code/generated-property-management-fastapi` | PARTIAL (43/44; missing-auth excluded; 43/43 selected passed) | DONE |
| Kimi Code | `vc-kimi-code-seeded-v2-support-desk-fastapi` | `vc_repos/kimi-code/generated-support-desk-fastapi` | PARTIAL (43/44; missing-auth excluded; 43/43 selected passed) | DONE |

- `vc-claude-code-seeded-v2-healthcare-clinic-django` (2026-05-26): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/claude-code/generated-healthcare-clinic-django/kolega-v2-python-v0.0.1/results.json` with 24 deduped findings. Baseline score against pre-enrichment GT: TP=8, FP=16, FN=11, TN=4, precision=0.333, recall=0.421, F2=40.0. Added 10 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-claude-code-seeded-v2-hr-payroll-django` (2026-05-26): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/claude-code/generated-hr-payroll-django/kolega-v2-python-v0.0.1/results.json` with 23 deduped findings. Baseline score against pre-enrichment GT: TP=9, FP=14, FN=10, TN=4, precision=0.391, recall=0.474, F2=45.5. Added 8 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-claude-code-seeded-v2-legal-case-django` (2026-05-26): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/claude-code/generated-legal-case-django/kolega-v2-python-v0.0.1/results.json` with 31 deduped findings. Baseline score against pre-enrichment GT: TP=10, FP=21, FN=9, TN=4, precision=0.323, recall=0.526, F2=46.7. Added 12 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-claude-code-seeded-v2-logistics-dispatch-fastapi` (2026-05-26): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/claude-code/generated-logistics-dispatch-fastapi/kolega-v2-python-v0.0.1/results.json` with 40 deduped findings. Baseline score against pre-enrichment GT: TP=12, FP=29, FN=7, TN=4, precision=0.293, recall=0.632, F2=51.3. Added 14 verified runtime findings from scanner validation and manual 3-agent audit.

- `vc-claude-code-seeded-v2-marketplace-commerce-fastapi` (2026-05-26): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/claude-code/generated-marketplace-commerce-fastapi/kolega-v2-python-v0.0.1/results.json` with 25 deduped findings. Baseline score against pre-enrichment GT: TP=9, FP=17, FN=9, TN=4, precision=0.346, recall=0.500, F2=45.9. Added 14 verified runtime findings from scanner validation and manual 3-agent audit.

- `vc-claude-code-seeded-v2-property-management-fastapi` (2026-05-26): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/claude-code/generated-property-management-fastapi/kolega-v2-python-v0.0.1/results.json` with 23 deduped findings. Baseline score against pre-enrichment GT: TP=10, FP=14, FN=8, TN=4, precision=0.417, recall=0.556, F2=52.1. Added 15 verified runtime findings from scanner validation and manual 3-agent audit.

- `vc-claude-code-seeded-v2-support-desk-fastapi` (2026-05-26): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/claude-code/generated-support-desk-fastapi/kolega-v2-python-v0.0.1/results.json` with 32 deduped findings. Baseline score against pre-enrichment GT: TP=7, FP=26, FN=11, TN=4, precision=0.212, recall=0.389, F2=33.3. Added 16 verified runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-seeded-v2-crm-saas-django` (2026-05-26): scanner enrichment had already been completed from the stable v2 result at `vc_repos/scan-results/codex/generated-crm-saas-django/kolega-v2-python-v0.0.1/results.json`. Manual 3-agent audit added 13 verified normal-runtime findings. Post-manual score against the existing stable-v2 artifact: TP=13, FP=28, FN=21, TN=4, precision=0.317, recall=0.382, F2=36.7.

- `vc-codex-seeded-v2-education-lms-django` (2026-05-26): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex/generated-education-lms-django/kolega-v2-python-v0.0.1/results.json` with 18 deduped findings. Baseline score against pre-enrichment GT: TP=9, FP=9, FN=10, TN=4, precision=0.500, recall=0.474, F2=47.9. Added 16 verified normal-runtime findings from manual 3-agent audit and broadened scanner duplicate aliases for seeded upload/logging entries. Post-enrichment score: TP=9, FP=9, FN=26, TN=4, precision=0.500, recall=0.257, F2=28.5.

- `vc-codex-seeded-v2-fintech-lending-fastapi` (2026-05-26): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex/generated-fintech-lending-fastapi/kolega-v2-python-v0.0.1/results.json` with 20 deduped findings. Baseline score against pre-enrichment GT: TP=9, FP=11, FN=10, TN=4, precision=0.450, recall=0.474, F2=46.9. Added 18 verified findings from scanner validation and manual 3-agent audit, plus duplicate aliases for seeded route findings. Post-enrichment score: TP=15, FP=5, FN=22, TN=4, precision=0.750, recall=0.405, F2=44.6.

- `vc-codex-seeded-v2-healthcare-clinic-django` (2026-05-26): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex/generated-healthcare-clinic-django/kolega-v2-python-v0.0.1/results.json` with 22 deduped findings. Baseline score against pre-enrichment GT: TP=8, FP=14, FN=11, TN=4, precision=0.364, recall=0.421, F2=40.8. Added 22 verified normal-runtime findings from scanner validation and manual 3-agent audit, plus duplicate aliases for seeded route findings. Post-enrichment score: TP=9, FP=13, FN=32, TN=4, precision=0.409, recall=0.220, F2=24.2.

- `vc-codex-seeded-v2-hr-payroll-django` (2026-05-26): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex/generated-hr-payroll-django/kolega-v2-python-v0.0.1/results.json` with 31 deduped findings. Baseline score against pre-enrichment GT: TP=11, FP=20, FN=8, TN=4, precision=0.355, recall=0.579, F2=51.4. Added 20 verified findings from scanner validation and manual 3-agent audit, plus duplicate aliases for seeded route findings. Post-enrichment score: TP=13, FP=18, FN=26, TN=4, precision=0.419, recall=0.333, F2=34.8.


- `vc-kimi-code-seeded-v2-crm-saas-django` (2026-05-27): stable v2 partial scan used 43/43 selected detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/kimi-code/generated-crm-saas-django/kolega-v2-python-v0.0.1/results.json` with 27 parsed findings. Baseline score against pre-enrichment GT: TP=9, FP=18, FN=10, TN=4, precision=0.333, recall=0.474, F2=0.437. After enrichment: TP=9, FP=18, FN=18, TN=4, precision=0.333, recall=0.333, F2=0.333. Added 8 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-kimi-code-seeded-v2-education-lms-django` (2026-05-27): stable v2 partial scan used 43/43 selected detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/kimi-code/generated-education-lms-django/kolega-v2-python-v0.0.1/results.json` with 52 parsed findings. Baseline score against pre-enrichment GT: TP=7, FP=45, FN=12, TN=4, precision=0.135, recall=0.368, F2=0.273. After enrichment: TP=8, FP=44, FN=20, TN=4, precision=0.154, recall=0.286, F2=0.244. Added 9 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-kimi-code-seeded-v2-fintech-lending-fastapi` (2026-05-27): stable v2 partial scan used 43/43 selected detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/kimi-code/generated-fintech-lending-fastapi/kolega-v2-python-v0.0.1/results.json` with 47 parsed findings. Baseline score against pre-enrichment GT: TP=10, FP=37, FN=9, TN=4, precision=0.213, recall=0.526, F2=0.407. After enrichment: TP=14, FP=33, FN=19, TN=4, precision=0.298, recall=0.424, F2=0.391. Added 14 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-kimi-code-seeded-v2-healthcare-clinic-django` (2026-05-27): stable v2 partial scan used 43/43 selected detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/kimi-code/generated-healthcare-clinic-django/kolega-v2-python-v0.0.1/results.json` with 45 parsed findings. Baseline score against pre-enrichment GT: TP=8, FP=37, FN=11, TN=4, precision=0.178, recall=0.421, F2=0.331. After enrichment: TP=10, FP=35, FN=20, TN=4, precision=0.222, recall=0.333, F2=0.303. Added 11 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-kimi-code-seeded-v2-hr-payroll-django` (2026-05-27): stable v2 partial scan used 43/43 selected detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/kimi-code/generated-hr-payroll-django/kolega-v2-python-v0.0.1/results.json` with 54 parsed findings. Baseline score against pre-enrichment GT: TP=9, FP=45, FN=10, TN=4, precision=0.167, recall=0.474, F2=0.346. After enrichment: TP=10, FP=44, FN=19, TN=4, precision=0.185, recall=0.345, F2=0.294. Added 10 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-kimi-code-seeded-v2-legal-case-django` (2026-05-27): stable v2 partial scan used 43/43 selected detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/kimi-code/generated-legal-case-django/kolega-v2-python-v0.0.1/results.json` with 35 parsed findings. Baseline score against pre-enrichment GT: TP=10, FP=25, FN=9, TN=4, precision=0.286, recall=0.526, F2=0.450. After enrichment: TP=10, FP=25, FN=16, TN=4, precision=0.286, recall=0.385, F2=0.360. Added 7 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-kimi-code-seeded-v2-logistics-dispatch-fastapi` (2026-05-27): stable v2 partial scan used 43/43 selected detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/kimi-code/generated-logistics-dispatch-fastapi/kolega-v2-python-v0.0.1/results.json` with 34 parsed findings. Baseline score against pre-enrichment GT: TP=12, FP=22, FN=7, TN=4, precision=0.353, recall=0.632, F2=0.545. After enrichment: TP=16, FP=18, FN=15, TN=4, precision=0.471, recall=0.516, F2=0.506. Added 12 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-kimi-code-seeded-v2-marketplace-commerce-fastapi` (2026-05-27): stable v2 partial scan used 43/43 selected detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/kimi-code/generated-marketplace-commerce-fastapi/kolega-v2-python-v0.0.1/results.json` with 27 parsed findings. Baseline score against pre-enrichment GT: TP=8, FP=19, FN=10, TN=4, precision=0.296, recall=0.444, F2=0.404. After enrichment: TP=12, FP=15, FN=15, TN=4, precision=0.444, recall=0.444, F2=0.444. Added 9 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-kimi-code-seeded-v2-property-management-fastapi` (2026-05-27): stable v2 partial scan used 43/43 selected detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/kimi-code/generated-property-management-fastapi/kolega-v2-python-v0.0.1/results.json` with 26 parsed findings. Baseline score against pre-enrichment GT: TP=11, FP=15, FN=7, TN=4, precision=0.423, recall=0.611, F2=0.561. After enrichment: TP=15, FP=11, FN=15, TN=4, precision=0.577, recall=0.500, F2=0.514. Added 12 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-kimi-code-seeded-v2-support-desk-fastapi` (2026-05-27): stable v2 partial scan used 43/43 selected detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/kimi-code/generated-support-desk-fastapi/kolega-v2-python-v0.0.1/results.json` with 31 parsed findings. Baseline score against pre-enrichment GT: TP=8, FP=23, FN=9, TN=4, precision=0.258, recall=0.471, F2=0.404. After enrichment: TP=11, FP=20, FN=17, TN=4, precision=0.355, recall=0.393, F2=0.385. Added 11 verified normal-runtime findings from scanner validation and manual 3-agent audit.

## Artifact Convention

Use this scan result path pattern:

```text
vc_repos/scan-results/<provider>/<generated-app>/kolega-v2-python-v0.0.1/results.json
```

Use the matching GT path:

```text
ground-truth/<repo_id>/ground-truth.json
```

## Enrichment Run Notes

- `vc-claude-code-seeded-v2-fintech-lending-fastapi` (2026-05-26): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint` after the full pinned run hung in that detector. Scan artifact: `vc_repos/scan-results/claude-code/generated-fintech-lending-fastapi/kolega-v2-python-v0.0.1/results.json` with 36 deduped findings. Baseline score against pre-enrichment GT: TP=11, FP=26, FN=8, TN=4, precision=0.297, recall=0.579, F2=48.7. After enrichment: TP=13, FP=24, FN=16, TN=4, precision=0.351, recall=0.448, F2=42.5. Added 10 verified normal-runtime findings; 2 were matched by this partial scanner run and the rest came from manual 3-agent audit validation.

- `vc-codex-seeded-v2-legal-case-django` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex/generated-legal-case-django/kolega-v2-python-v0.0.1/results.json` with 21 parsed findings. Baseline score against pre-enrichment GT: TP=9, FP=12, FN=10, TN=4, precision=0.429, recall=0.474, F2=46.4. After enrichment: TP=9, FP=12, FN=24, TN=4, precision=0.429, recall=0.273, F2=29.4. Added 14 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-seeded-v2-logistics-dispatch-fastapi` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex/generated-logistics-dispatch-fastapi/kolega-v2-python-v0.0.1/results.json` with 26 parsed findings. Baseline score against pre-enrichment GT: TP=12, FP=14, FN=7, TN=4, precision=0.462, recall=0.632, F2=58.8. After enrichment: TP=17, FP=9, FN=13, TN=4, precision=0.654, recall=0.567, F2=58.2. Added 11 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-seeded-v2-marketplace-commerce-fastapi` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex/generated-marketplace-commerce-fastapi/kolega-v2-python-v0.0.1/results.json` with 23 parsed findings. Baseline score against pre-enrichment GT: TP=8, FP=15, FN=10, TN=4, precision=0.348, recall=0.444, F2=42.1. After enrichment: TP=13, FP=10, FN=16, TN=4, precision=0.565, recall=0.448, F2=46.8. Added 11 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-seeded-v2-property-management-fastapi` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex/generated-property-management-fastapi/kolega-v2-python-v0.0.1/results.json` with 30 parsed findings. Baseline score against pre-enrichment GT: TP=11, FP=19, FN=7, TN=4, precision=0.367, recall=0.611, F2=53.9. After enrichment: TP=16, FP=14, FN=15, TN=4, precision=0.533, recall=0.516, F2=51.9. Added 13 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-seeded-v2-support-desk-fastapi` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex/generated-support-desk-fastapi/kolega-v2-python-v0.0.1/results.json` with 26 parsed findings. Baseline score against pre-enrichment GT: TP=11, FP=15, FN=7, TN=4, precision=0.423, recall=0.611, F2=56.1. After enrichment: TP=17, FP=9, FN=13, TN=4, precision=0.654, recall=0.567, F2=58.2. Added 12 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-high-seeded-v2-crm-saas-django` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex-high/generated-crm-saas-django/kolega-v2-python-v0.0.1/results.json` with 29 parsed findings. Baseline score against pre-enrichment GT: TP=9, FP=20, FN=10, TN=4, precision=0.310, recall=0.474, F2=42.9. After enrichment: TP=9, FP=20, FN=16, TN=4, precision=0.310, recall=0.360, F2=34.5. Added 6 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-high-seeded-v2-education-lms-django` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex-high/generated-education-lms-django/kolega-v2-python-v0.0.1/results.json` with 22 parsed findings. Baseline score against pre-enrichment GT: TP=9, FP=13, FN=10, TN=4, precision=0.409, recall=0.474, F2=45.9. After enrichment: TP=9, FP=13, FN=16, TN=4, precision=0.409, recall=0.360, F2=36.8. Added 6 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-high-seeded-v2-fintech-lending-fastapi` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex-high/generated-fintech-lending-fastapi/kolega-v2-python-v0.0.1/results.json` with 28 parsed findings. Baseline score against pre-enrichment GT: TP=11, FP=17, FN=8, TN=4, precision=0.393, recall=0.579, F2=52.9. After enrichment: TP=19, FP=9, FN=10, TN=4, precision=0.679, recall=0.655, F2=65.9. Added 10 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-high-seeded-v2-healthcare-clinic-django` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex-high/generated-healthcare-clinic-django/kolega-v2-python-v0.0.1/results.json` with 28 parsed findings. Baseline score against pre-enrichment GT: TP=8, FP=20, FN=11, TN=4, precision=0.286, recall=0.421, F2=38.5. After enrichment: TP=9, FP=19, FN=17, TN=4, precision=0.321, recall=0.346, F2=34.1. Added 7 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-high-seeded-v2-hr-payroll-django` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex-high/generated-hr-payroll-django/kolega-v2-python-v0.0.1/results.json` with 32 parsed findings. Baseline score against pre-enrichment GT: TP=10, FP=22, FN=9, TN=4, precision=0.312, recall=0.526, F2=46.3. After enrichment: TP=10, FP=22, FN=15, TN=4, precision=0.312, recall=0.400, F2=38.1. Added 6 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-high-seeded-v2-legal-case-django` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex-high/generated-legal-case-django/kolega-v2-python-v0.0.1/results.json` with 18 parsed findings. Baseline score against pre-enrichment GT: TP=9, FP=9, FN=10, TN=4, precision=0.500, recall=0.474, F2=47.9. After enrichment: TP=9, FP=9, FN=16, TN=4, precision=0.500, recall=0.360, F2=38.8. Added 6 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-high-seeded-v2-logistics-dispatch-fastapi` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex-high/generated-logistics-dispatch-fastapi/kolega-v2-python-v0.0.1/results.json` with 32 parsed findings. Baseline score against pre-enrichment GT: TP=11, FP=21, FN=8, TN=4, precision=0.344, recall=0.579, F2=50.9. After enrichment: TP=17, FP=15, FN=12, TN=4, precision=0.531, recall=0.586, F2=57.4. Added 10 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-high-seeded-v2-marketplace-commerce-fastapi` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex-high/generated-marketplace-commerce-fastapi/kolega-v2-python-v0.0.1/results.json` with 34 parsed findings. Baseline score against pre-enrichment GT: TP=10, FP=24, FN=8, TN=4, precision=0.294, recall=0.556, F2=47.2. After enrichment: TP=15, FP=19, FN=10, TN=4, precision=0.441, recall=0.600, F2=55.9. Added 7 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-high-seeded-v2-property-management-fastapi` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex-high/generated-property-management-fastapi/kolega-v2-python-v0.0.1/results.json` with 21 parsed findings. Baseline score against pre-enrichment GT: TP=10, FP=11, FN=8, TN=4, precision=0.476, recall=0.556, F2=53.8. After enrichment: TP=16, FP=5, FN=10, TN=4, precision=0.762, recall=0.615, F2=64.0. Added 8 verified normal-runtime findings from scanner validation and manual 3-agent audit.

- `vc-codex-high-seeded-v2-support-desk-fastapi` (2026-05-27): stable v2 partial scan used 43/44 detectors, excluding only `missing_auth_decorator_on_sensitive_endpoint`. Scan artifact: `vc_repos/scan-results/codex-high/generated-support-desk-fastapi/kolega-v2-python-v0.0.1/results.json` with 23 parsed findings. Baseline score against pre-enrichment GT: TP=7, FP=16, FN=10, TN=4, precision=0.304, recall=0.412, F2=38.5. After enrichment: TP=14, FP=9, FN=14, TN=4, precision=0.609, recall=0.500, F2=51.9. Added 11 verified normal-runtime findings from scanner validation and manual 3-agent audit.
