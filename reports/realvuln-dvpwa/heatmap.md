# DVPWA Scanner Coverage Heatmap

**Repo:** dvpwa | **GT:** 21 vulns + 4 FP tests | **Scanners:** 15

## Column Key

| # | GT ID | CWE | Sev | Description |
|---|-------|-----|-----|-------------|
| 1 | dvpwa-001 | CWE-89 | C | SQLi student create |
| 2 | dvpwa-002 | CWE-79 | M | XSS review text |
| 3 | dvpwa-003 | CWE-79 | M | XSS student names |
| 4 | dvpwa-004 | CWE-79 | M | XSS course title/desc |
| 5 | dvpwa-005 | CWE-79 | M | XSS courses listing |
| 6 | dvpwa-006 | CWE-79 | M | XSS student detail |
| 7 | dvpwa-007 | CWE-16 | H | autoescape=False |
| 8 | dvpwa-008 | CWE-916 | M | MD5 password hash |
| 9 | dvpwa-009 | CWE-352 | M | CSRF disabled |
| 10 | dvpwa-010 | CWE-1004 | L | httponly=False |
| 11 | dvpwa-011 | CWE-209 | L | Error info leak |
| 12 | dvpwa-012 | CWE-862 | M | Missing auth students |
| 13 | dvpwa-013 | CWE-862 | M | Missing auth courses |
| 14 | dvpwa-014 | CWE-384 | M | Session fixation |
| 15 | dvpwa-015 | CWE-16 | L | debug=True |
| 16 | dvpwa-016 | CWE-306 | L | Redis no password |
| 17 | dvpwa-017 | CWE-307 | H | No rate limit login |
| 18 | dvpwa-018 | CWE-307 | M | No rate limit forms |
| 19 | dvpwa-019 | CWE-312 | M | pwd_hash in context |
| 20 | dvpwa-020 | CWE-312 | L | DB DSN credential |
| 21 | dvpwa-021 | CWE-319 | L | No TLS on DB |
| 22 | dvpwa-fp-001 | CWE-89 | FP | Safe param (user) |
| 23 | dvpwa-fp-002 | CWE-89 | FP | Safe param (review) |
| 24 | dvpwa-fp-003 | CWE-89 | FP | Safe param (course) |
| 25 | dvpwa-fp-004 | CWE-79 | FP | Escaped template |

**Legend:** `+` = TP (found) | `-` = FN (missed) | `.` = TN (correctly ignored) | `!` = FP (false alarm on safe code)

## Coverage Matrix

| Scanner | F2 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 | TP | Recall |
|---------|-----|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|----|--------|
| `t2-sonnet-4-6-p4-r3` | **66.1** | + | + | + | - | + | + | + | + | + | + | + | + | - | + | + | + | - | - | + | + | - | . | . | . | . | 16 | 0.762 |
| `t3-gemini-3.1-pro-p4-r2` | **63.1** | + | - | + | - | + | + | + | + | + | + | + | + | - | + | + | - | + | - | - | - | - | . | . | . | . | 13 | 0.619 |
| `t3-sonnet-4-6-p4` | **63.1** | + | - | + | - | + | + | + | + | + | + | + | + | - | + | + | + | - | - | - | + | - | . | . | . | . | 14 | 0.667 |
| `t2-sonnet-4-6-p4-r1` | **62.5** | + | + | + | - | + | + | + | + | + | + | - | + | - | + | + | + | - | - | - | - | + | . | . | . | . | 14 | 0.667 |
| `t3-opus-4-6-p4-r2` | **58.3** | + | - | + | - | + | + | + | + | + | + | + | + | - | + | + | - | - | - | + | - | + | . | . | . | . | 14 | 0.667 |
| `t3-sonnet-4-6-p3` | **42.1** | + | - | - | - | - | - | + | + | + | + | - | - | - | - | + | + | - | - | - | - | + | . | . | . | . | 8 | 0.381 |
| `t2-sonnet-4-6-p4-r2` | **40.0** | + | - | - | - | - | - | + | + | + | + | - | - | - | - | + | + | - | - | - | - | + | . | . | . | . | 8 | 0.381 |
| `t3-gpt-5-2-p4` | **38.1** | + | - | - | - | - | - | + | + | + | + | - | - | - | - | - | + | - | - | - | + | + | . | . | . | . | 8 | 0.381 |
| `t3-opus-4-6-p4-r1` | **36.5** | + | - | - | - | - | - | + | + | + | + | - | - | - | - | + | - | - | - | - | - | + | . | . | . | . | 7 | 0.333 |
| `t3-opus-4-6-p4-r3` | **36.5** | + | - | - | - | - | - | + | + | + | + | - | - | - | - | + | - | - | - | - | - | + | . | . | . | . | 7 | 0.333 |
| `t3-sonnet-4-6-p1` | **35.4** | + | - | - | - | - | - | + | + | + | + | - | - | - | - | + | - | - | - | - | + | - | . | . | ! | . | 7 | 0.333 |
| `t3-gemini-3.1-pro-p4-r1` | **33.0** | + | - | - | - | - | - | + | + | + | + | - | - | - | - | + | - | - | - | - | - | - | . | . | . | . | 6 | 0.286 |
| `t2-sonnet-4-6-p1` | **27.5** | + | - | - | - | - | - | + | + | + | + | - | - | - | - | - | - | - | - | - | - | - | . | . | . | . | 5 | 0.238 |
| `t3-sonnet-4-6-p1-r0` | **25.0** | + | - | - | - | - | - | - | + | - | - | - | - | - | - | - | + | - | - | - | + | + | . | . | . | . | 5 | 0.238 |
| `sonarqube` | **0.0** | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | . | . | . | . | 0 | 0.000 |

| **Detection rate** | | 93% | 13% | 33% | 0% | 33% | 33% | 86% | 93% | 86% | 86% | 26% | 33% | 0% | 33% | 73% | 46% | 6% | 0% | 13% | 33% | 53% | 15 | 15 | 14 | 15 | | |

## Insights

### Never Found (0% detection)

- **dvpwa-004** (CWE-79): XSS course title/desc
- **dvpwa-013** (CWE-862): Missing auth courses
- **dvpwa-018** (CWE-307): No rate limit forms

### Always Found (by all kolega.dev scanners)

- **dvpwa-001** (CWE-89): SQLi student create
- **dvpwa-008** (CWE-916): MD5 password hash
