# Internal Scorecard — dsvw

**Commit:** `7d40f4b7939c`  
**Generated:** 2026-03-02T09:32:34.584338+00:00  
**Ground Truth:** 19 vulnerabilities, 4 false-positive traps  
**Application:** [ae67a105-4297-452c-bd5e-88bd64bacf8b](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b)

---

## our-scanner — F2 Score: 60.0 / 100

| TP | FP | FN | TN | Precision | Recall | F1 |
|---:|---:|---:|---:|----------:|-------:|---:|
| 12 | 12 | 7 | 4 | 50.0% | 63.2% | 0.558 |

### True Positives (12)

Scanner correctly identified these real vulnerabilities.

- ✅ [CWE-113 on dsvw.py:L78](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/00d4e67f-5ce3-4ae7-bfcd-e050bc69051e) → **dsvw-016** — http_header_injection: HTTP header injection via charset parameter injected into Content-Type header without CRLF filtering
- ✅ [CWE-200 on dsvw.py:L67](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/57c7a9cd-d6b9-4917-9ed2-8d4afdff4447) → **dsvw-018** — sensitive_data_exposure: Full stack trace returned to client via traceback.format_exc() on any unhandled exception
- ✅ [CWE-22 on dsvw.py:L37](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/d84c84cd-4430-405f-8a38-f79ed518e60b) → **dsvw-004** — path_traversal: Path traversal via path parameter passed to open() with os.path.abspath but no path restriction
- ✅ [CWE-400 on dsvw.py:L46](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/a331a7c7-7b6f-4fd8-9531-f0640770a8b7) → **dsvw-009** — denial_of_service: Memory-based DoS via size parameter controlling O(n^2) string allocation with no upper bound
- ✅ [CWE-601 on dsvw.py:L61](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/f90f249b-4cc6-4235-ade8-cbea6ae6ad28) → **dsvw-013** — open_redirect: Open redirect via redir parameter injected into meta refresh URL without validation
- ✅ [CWE-611 on dsvw.py:L41](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/606595ca-294e-4228-a5a2-ce1af4281260) → **dsvw-007** — xxe: XXE via xml parameter parsed by lxml with load_dtd=True, resolve_entities=True, no_network=False
- ✅ [CWE-643 on dsvw.py:L43](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/6f9fd329-91cb-4178-9f4f-ce97e3547872) → **dsvw-008** — xpath_injection: XPath injection via name parameter directly interpolated into XPath query string
- ✅ [CWE-78 on dsvw.py:L39](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/608c7592-b6b2-4f45-92fb-98146bcd782f) → **dsvw-006** — command_injection: OS command injection via domain parameter concatenated into nslookup command with shell=True
- ✅ [CWE-79 on dsvw.py:L33](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/67e31a0d-1921-4a99-91eb-c3f3047670f0) → **dsvw-002** — reflected_xss: Reflected XSS via v parameter injected into HTML response via re.sub without escaping
- ✅ [CWE-798 on dsvw.py:L11](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/b198e617-951e-417b-89ae-79376ffb4e19) → **dsvw-017** — hardcoded_credentials: Plaintext hardcoded passwords in USERS_XML constant including admin password '7en8aiDoh!'
- ✅ [CWE-89 on dsvw.py:L30](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/ca30c757-5585-40c7-a0a4-0dd666ff1416) → **dsvw-001** — sql_injection: SQL injection via id parameter directly concatenated into SELECT query without sanitization
- ✅ [CWE-94 on dsvw.py:L35](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/380ab6c5-e118-41e2-b090-ec420d431848) → **dsvw-003** — insecure_deserialization: Arbitrary code execution via pickle.loads on user-controlled object parameter

### False Positives (12)

Scanner flagged these but they are not real vulnerabilities. Review and dismiss.

- ❌ [CWE-668 on docker-compose.yml:L9](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/dfb3165d-2171-4d50-a53f-416b236462e7) — no GT entry. Scanner says: Docker Container Exposes Port to All Interfaces
- ❌ [CWE-1284 on dsvw.py:L46](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/b1353e00-e8ed-45b7-bdac-358805153b3f) — no GT entry. Scanner says: Missing Input Validation on size parameter (Integer Overflow/DoS)
- ❌ [CWE-209 on dsvw.py:L72](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/e6fe98a2-63d3-4dfa-a60f-8dd9448bac82) — no GT entry. Scanner says: Information Disclosure via traceback in error responses
- ❌ [CWE-306 on dsvw.py:L24](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/be5a592f-8cda-404b-a24d-870851bab40d) — no GT entry. Scanner says: No Authentication on Any Endpoint - do_GET Handler
- ❌ [CWE-307 on dsvw.py:L66](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/9d4734b6-54fc-45ce-a826-7f77e4617d41) — no GT entry. Scanner says: No Rate Limiting on Login Endpoint
- ❌ [CWE-312 on dsvw.py:L20](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/92f26350-65e6-49fb-a798-20404c1792c5) — no GT entry. Scanner says: Plaintext Password Storage in Database
- ❌ [CWE-330 on dsvw.py:L68](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/2f35b254-a2ae-4237-b291-66e3acf16e57) — no GT entry. Scanner says: Weak session token generation using random.sample
- ❌ [CWE-352 on dsvw.py:L48](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/8c782c45-dc13-4ee9-bfae-33e75c6f472f) — no GT entry. Scanner says: No CSRF Protection on State-Changing Operations
- ❌ [CWE-770 on dsvw.py:L48](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/f77b740d-87e3-49e2-bc0b-395b30aaadc0) — no GT entry. Scanner says: No Rate Limiting on Comment Submission
- ❌ [CWE-862 on dsvw.py:L29](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/3595cae2-d335-4fa4-9cc2-5e203b1183be) — no GT entry. Scanner says: Unscoped User Data Access - No Authorization on User Query
- ❌ [CWE-915 on dsvw.py:L26](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/205cde5b-45c3-497c-a529-6dc7b24e6af0) — no GT entry. Scanner says: Mass Assignment - No Input Field Whitelisting on User Queries
- ❌ [CWE-918 on dsvw.py:L56](https://comply.kolegatestapps.com/applications/ae67a105-4297-452c-bd5e-88bd64bacf8b/findings/38ed3ef5-7161-4b6a-8180-467f57d7876f) — no GT entry. Scanner says: SSRF via 'include' parameter (remote file fetch)

### False Negatives (7)

Scanner missed these real vulnerabilities.

- ⚠️ **dsvw-005** `CWE-918` on `dsvw.py`:L37 (high) — SSRF via path parameter passed to urllib.request.urlopen when URL scheme is detected
- ⚠️ **dsvw-010** `CWE-89` on `dsvw.py`:L50 (high) — SQL injection via comment parameter directly interpolated into INSERT statement with string formatting
- ⚠️ **dsvw-011** `CWE-79` on `dsvw.py`:L54 (high) — Stored XSS via comments rendered from database into HTML without any output encoding
- ⚠️ **dsvw-012** `CWE-94` on `dsvw.py`:L56 (critical) — Remote code execution via include parameter: fetches arbitrary local/remote file and passes it to exec()
- ⚠️ **dsvw-014** `CWE-79` on `dsvw.py`:L65 (medium) — Reflected XSS via unsanitized JSONP callback parameter allowing arbitrary JavaScript execution
- ⚠️ **dsvw-015** `CWE-89` on `dsvw.py`:L67 (critical) — SQL injection via password parameter in login query concatenated without sanitization, enabling authentication bypass
- ⚠️ **dsvw-019** `CWE-79` on `dsvw.py`:L10 (medium) — DOM-based XSS via document.write with decodeURIComponent of location.hash fragment in inline JavaScript

### True Negatives (4)

Scanner correctly ignored these false-positive traps.

- ⚪ **dsvw-fp-001** `CWE-89` on `dsvw.py`:L67 — Username parameter in login query is sanitized with re.sub(r'[^\w]', '', ...) stripping all non-word characters before concatenation, preventing SQL injection through the username field
- ⚪ **dsvw-fp-002** `CWE-89` on `dsvw.py`:L20 — cursor.executemany uses parameterized query with ? placeholders — not vulnerable despite dynamic data insertion
- ⚪ **dsvw-fp-003** `CWE-79` on `dsvw.py`:L10 — NAME variable is passed through html.escape() before insertion into HTML title via %s formatting — properly sanitized
- ⚪ **dsvw-fp-004** `CWE-89` on `dsvw.py`:L19 — CREATE TABLE statement is a static string literal with no user input — not vulnerable despite cursor.execute usage
