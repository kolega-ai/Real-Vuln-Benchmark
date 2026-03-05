# dvpwa Score Analysis — F2 Score: 13.2 / 100

App: `c0ec6f54-9980-4819-a142-5f3d1dbc6d50`

## True Positives (2) — What we got right

| CWE | File | GT ID | Finding |
|-----|------|-------|---------|
| CWE-89 | sqli/dao/student.py:42 | dvpwa-001 | [f9387249-a22d-4b60-b153-af2f369e845d](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/f9387249-a22d-4b60-b153-af2f369e845d) |
| CWE-759 | sqli/dao/user.py:40 | dvpwa-008 | [acd50916-c95a-4865-b5b7-29a7512e1877](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/acd50916-c95a-4865-b5b7-29a7512e1877) |

## False Positives (14) — Findings with no ground truth match

### line=0 / duplicate issue (1)

| CWE | File | Why FP | Finding |
|-----|------|--------|---------|
| CWE-916 | sqli/dao/user.py:**0** | Same vuln as TP CWE-759 above, but line=0 so can't match GT line 41 | [fffdc33c-1f24-46d5-b30e-ec14471ab6e7](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/fffdc33c-1f24-46d5-b30e-ec14471ab6e7) |

### XSS — right vuln, wrong file (1)

| CWE | File | Why FP | Finding |
|-----|------|--------|---------|
| CWE-79 | sqli/schema/forms.py:8 | Found XSS risk at the validation/input layer, but GT expects the template render sinks (.jinja2 files) | [352c1190-cac0-48f8-a988-0ef08b18990c](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/352c1190-cac0-48f8-a988-0ef08b18990c) |

### Not in ground truth at all (12)

| CWE | File | Description | Finding |
|-----|------|-------------|---------|
| CWE-306 | sqli/schema/config.py:12 | Redis config missing password field | [8b6b9458-e5c6-464a-bbfa-f0e34d16ed60](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/8b6b9458-e5c6-464a-bbfa-f0e34d16ed60) |
| CWE-306 | sqli/services/redis.py:12 | Redis connection no auth | [86ca75e8-f784-4863-a492-dd47e4de1961](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/86ca75e8-f784-4863-a492-dd47e4de1961) |
| CWE-307 | sqli/utils/auth.py:12 | No rate limiting on auth | [26c1ec81-4651-49b2-b0c1-4b33d0c70385](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/26c1ec81-4651-49b2-b0c1-4b33d0c70385) |
| CWE-307 | sqli/schema/forms.py:1 | No rate limiting on forms | [66fc8786-f512-4eca-a60f-6ca5b7556a75](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/66fc8786-f512-4eca-a60f-6ca5b7556a75) |
| CWE-204 | sqli/dao/user.py:31 | User enumeration via username lookup | [ab34e90c-7cb2-4fa1-90eb-ee18499f7973](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/ab34e90c-7cb2-4fa1-90eb-ee18499f7973) |
| CWE-312 | sqli/dao/user.py:7 | PII/pwd_hash in User NamedTuple | [06edeae2-24e9-4f80-9a09-89db79fc8642](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/06edeae2-24e9-4f80-9a09-89db79fc8642) |
| CWE-312 | sqli/services/db.py:15 | DB DSN credential exposure in logs | [c59d388c-6b86-4996-9b10-dadbb38bee2b](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/c59d388c-6b86-4996-9b10-dadbb38bee2b) |
| CWE-319 | sqli/services/db.py:15 | No TLS/SSL on DB connection | [dca7f8be-4cc2-44c1-a1c4-f9ba0d843f1c](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/dca7f8be-4cc2-44c1-a1c4-f9ba0d843f1c) |
| CWE-20 | sqli/dao/course.py:**0** | Stray '+' in get_many() SQL | [caba3fd7-062b-4b83-b235-bf74d129f11c](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/caba3fd7-062b-4b83-b235-bf74d129f11c) |
| CWE-20 | sqli/dao/review.py:29 | No input validation on review_text | [d256e951-44e2-477e-b1d1-9970f6c40a9c](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/d256e951-44e2-477e-b1d1-9970f6c40a9c) |
| CWE-20 | sqli/dao/student.py:**0** | Stray '+' in get_many() SQL | [1f595ac6-5acf-4ca7-97e5-f24e01be4a8f](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/1f595ac6-5acf-4ca7-97e5-f24e01be4a8f) |
| CWE-20 | sqli/schema/forms.py:9 | No max_length on review_text | [b2a5e0a1-1251-444b-a1c0-e2bd0ff7e97c](http://localhost:3000/applications/c0ec6f54-9980-4819-a142-5f3d1dbc6d50/findings/b2a5e0a1-1251-444b-a1c0-e2bd0ff7e97c) |

## False Negatives (13) — Ground truth vulns we missed

| GT ID | CWE | File | Vulnerability |
|-------|-----|------|---------------|
| dvpwa-002 | CWE-79 | sqli/templates/course.jinja2:22 | Stored XSS via review_text |
| dvpwa-003 | CWE-79 | sqli/templates/students.jinja2:16 | Stored XSS via student name |
| dvpwa-004 | CWE-79 | sqli/templates/course.jinja2:14 | Stored XSS via course title/desc |
| dvpwa-005 | CWE-79 | sqli/templates/courses.jinja2:17 | Stored XSS via course title/desc |
| dvpwa-006 | CWE-79 | sqli/templates/student.jinja2:19 | Stored XSS via course title/desc |
| dvpwa-007 | CWE-16 | sqli/app.py:35 | autoescape=False |
| dvpwa-009 | CWE-352 | sqli/app.py:27 | CSRF middleware commented out |
| dvpwa-010 | CWE-1004 | sqli/middlewares.py:20 | Cookie httponly=False |
| dvpwa-011 | CWE-209 | sqli/templates/errors/50x.jinja2:6 | Error page leaks error.__dict__ |
| dvpwa-012 | CWE-862 | sqli/views.py:54 | No auth on student creation |
| dvpwa-013 | CWE-862 | sqli/views.py:86 | No auth on course creation |
| dvpwa-014 | CWE-384 | sqli/views.py:42 | Session fixation (no rotation) |
| dvpwa-015 | CWE-16 | sqli/app.py:24 | debug=True |

## True Negatives (4) — Correctly not flagged

| GT ID | CWE | File | Why safe |
|-------|-----|------|----------|
| dvpwa-fp-001 | CWE-89 | sqli/dao/user.py:33 | Parameterized query (%s placeholder) |
| dvpwa-fp-002 | CWE-89 | sqli/dao/review.py:31 | Parameterized query (%(name)s placeholder) |
| dvpwa-fp-003 | CWE-89 | sqli/dao/course.py:44 | Parameterized query (%(name)s placeholder) |
| dvpwa-fp-004 | CWE-79 | sqli/templates/student.jinja2:14 | Uses `| e` escape filter |

## Key Takeaways

1. **XSS: right vuln, wrong file** — We found XSS risk but pointed at `forms.py` instead of the 5 `.jinja2` template sinks. Fixing file attribution alone would turn 5 FN → TP and remove 1 FP.
2. **line=0 bug** — CWE-916 finding has no line number, creating a duplicate FP instead of matching the GT entry (already consumed by CWE-759).
3. **Security misconfigs completely missed** — 8 findings about CSRF, sessions, cookies, debug mode, auth checks. Our scanner doesn't detect config-level issues.
4. **Noisy findings not in GT** — 12 findings (CWE-20, CWE-306, CWE-307, CWE-312, CWE-319) are arguably real concerns but aren't in the ground truth.
