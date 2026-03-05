# Internal Scorecard — dsvw

**Commit:** `7d40f4b7939c`  
**Generated:** 2026-03-02T09:32:34.584338+00:00  
**Ground Truth:** 19 vulnerabilities, 4 false-positive traps  
**Application:** [5a0c29dd-5154-4baf-ba18-c429eef57531](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531)

---

## our-scanner — F2 Score: 65.7 / 100

| TP | FP | FN | TN | Precision | Recall | F1 |
|---:|---:|---:|---:|----------:|-------:|---:|
| 13 | 10 | 6 | 4 | 56.5% | 68.4% | 0.619 |

### True Positives (13)

Scanner correctly identified these real vulnerabilities.

- ✅ [CWE-113 on dsvw.py:L78](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/a5ed7e5d-873a-49a3-be59-7db2c0f2f797) → **dsvw-016** — http_header_injection: HTTP header injection via charset parameter injected into Content-Type header without CRLF filtering
- ✅ [CWE-200 on dsvw.py:L65](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/37029872-ba6d-4104-8775-12562b6703e1) → **dsvw-018** — sensitive_data_exposure: Full stack trace returned to client via traceback.format_exc() on any unhandled exception
- ✅ [CWE-22 on dsvw.py:L37](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/3ee256a1-d8e6-43e4-bb36-f9b653f73822) → **dsvw-004** — path_traversal: Path traversal via path parameter passed to open() with os.path.abspath but no path restriction
- ✅ [CWE-400 on dsvw.py:L46](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/4b842fcb-1eeb-4d1f-8550-8fbda0bf4789) → **dsvw-009** — denial_of_service: Memory-based DoS via size parameter controlling O(n^2) string allocation with no upper bound
- ✅ [CWE-502 on dsvw.py:L35](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/089240cc-4e56-4318-87a2-689056115984) → **dsvw-003** — insecure_deserialization: Arbitrary code execution via pickle.loads on user-controlled object parameter
- ✅ [CWE-601 on dsvw.py:L61](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/23a157df-2cc0-43a0-a893-d23b0f672213) → **dsvw-013** — open_redirect: Open redirect via redir parameter injected into meta refresh URL without validation
- ✅ [CWE-611 on dsvw.py:L41](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/5e18fca9-c691-4479-88d9-0754dd7f6e4c) → **dsvw-007** — xxe: XXE via xml parameter parsed by lxml with load_dtd=True, resolve_entities=True, no_network=False
- ✅ [CWE-643 on dsvw.py:L43](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/54f73e0d-2d04-4e9d-b79f-467ac8bbd355) → **dsvw-008** — xpath_injection: XPath injection via name parameter directly interpolated into XPath query string
- ✅ [CWE-78 on dsvw.py:L39](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/c6663e0f-33cf-4ec3-9d0e-53a0eaff6cff) → **dsvw-006** — command_injection: OS command injection via domain parameter concatenated into nslookup command with shell=True
- ✅ [CWE-79 on dsvw.py:L33](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/c571230d-6253-4745-92d1-bac7f7f9079b) → **dsvw-002** — reflected_xss: Reflected XSS via v parameter injected into HTML response via re.sub without escaping
- ✅ [CWE-798 on dsvw.py:L11](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/d5d73487-ff7f-4988-9393-ce1586703392) → **dsvw-017** — hardcoded_credentials: Plaintext hardcoded passwords in USERS_XML constant including admin password '7en8aiDoh!'
- ✅ [CWE-89 on dsvw.py:L30](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/d6c1fdf3-1605-494e-a584-80c115f7d787) → **dsvw-001** — sql_injection: SQL injection via id parameter directly concatenated into SELECT query without sanitization
- ✅ [CWE-94 on dsvw.py:L57](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/6f6fffaa-64f2-4ea8-87c1-d9972f08b63b) → **dsvw-012** — remote_file_inclusion: Remote code execution via include parameter: fetches arbitrary local/remote file and passes it to exec()

### False Positives (10)

Scanner flagged these but they are not real vulnerabilities. Review and dismiss.

- ❌ [CWE-190 on dsvw.py:L46](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/5150748d-3fd4-4402-a2cd-a0ab752b5b73) — no GT entry. Scanner says: Integer Overflow / Unvalidated Integer Input in size parameter
- ❌ [CWE-209 on dsvw.py:L72](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/49c4833f-b007-473a-9889-934bdd4baea9) — no GT entry. Scanner says: Information Disclosure via Exception Traceback
- ❌ [CWE-306 on dsvw.py:L24](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/1c16caef-49a3-44be-902c-17309ea34854) — no GT entry. Scanner says: Missing Authentication on All Endpoints (No Auth Framework)
- ❌ [CWE-307 on dsvw.py:L66](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/d92410a2-bdd1-44e2-a8fe-045c212fde12) — no GT entry. Scanner says: Missing Rate Limiting on Login Endpoint
- ❌ [CWE-312 on dsvw.py:L20](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/2854c21b-7a92-410d-85f8-090acc55d29d) — no GT entry. Scanner says: Cleartext Storage of Passwords in SQLite Database
- ❌ [CWE-330 on dsvw.py:L68](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/7e94786d-0890-4d69-afdf-9ceeda96e2e1) — no GT entry. Scanner says: Weak Session Token Generation Using random.sample
- ❌ [CWE-770 on dsvw.py:L48](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/9ea2a8df-b8d2-415f-878c-3c2aa43e6cbe) — no GT entry. Scanner says: Missing Rate Limiting on Comment Submission
- ❌ [CWE-862 on dsvw.py:L64](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/4b235aba-3502-444f-9691-47cca9c87b19) — no GT entry. Scanner says: JSONP Endpoint Without Callback Validation Enables Data Theft
- ❌ [CWE-915 on dsvw.py:L26](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/dfc66ec7-9d37-4a1a-92a7-ba22538f4bc3) — no GT entry. Scanner says: Mass Assignment - All Query Parameters Accepted Without Whitelisting
- ❌ [CWE-918 on dsvw.py:L56](https://comply.kolegatestapps.com/applications/5a0c29dd-5154-4baf-ba18-c429eef57531/findings/de37fb05-dd5c-4d63-a8cd-b51fc6703d4f) — no GT entry. Scanner says: SSRF via 'include' parameter with remote URL

### False Negatives (6)

Scanner missed these real vulnerabilities.

- ⚠️ **dsvw-005** `CWE-918` on `dsvw.py`:L37 (high) — SSRF via path parameter passed to urllib.request.urlopen when URL scheme is detected
- ⚠️ **dsvw-010** `CWE-89` on `dsvw.py`:L50 (high) — SQL injection via comment parameter directly interpolated into INSERT statement with string formatting
- ⚠️ **dsvw-011** `CWE-79` on `dsvw.py`:L54 (high) — Stored XSS via comments rendered from database into HTML without any output encoding
- ⚠️ **dsvw-014** `CWE-79` on `dsvw.py`:L65 (medium) — Reflected XSS via unsanitized JSONP callback parameter allowing arbitrary JavaScript execution
- ⚠️ **dsvw-015** `CWE-89` on `dsvw.py`:L67 (critical) — SQL injection via password parameter in login query concatenated without sanitization, enabling authentication bypass
- ⚠️ **dsvw-019** `CWE-79` on `dsvw.py`:L10 (medium) — DOM-based XSS via document.write with decodeURIComponent of location.hash fragment in inline JavaScript

### True Negatives (4)

Scanner correctly ignored these false-positive traps.

- ⚪ **dsvw-fp-001** `CWE-89` on `dsvw.py`:L67 — Username parameter in login query is sanitized with re.sub(r'[^\w]', '', ...) stripping all non-word characters before concatenation, preventing SQL injection through the username field
- ⚪ **dsvw-fp-002** `CWE-89` on `dsvw.py`:L20 — cursor.executemany uses parameterized query with ? placeholders — not vulnerable despite dynamic data insertion
- ⚪ **dsvw-fp-003** `CWE-79` on `dsvw.py`:L10 — NAME variable is passed through html.escape() before insertion into HTML title via %s formatting — properly sanitized
- ⚪ **dsvw-fp-004** `CWE-89` on `dsvw.py`:L19 — CREATE TABLE statement is a static string literal with no user input — not vulnerable despite cursor.execute usage
