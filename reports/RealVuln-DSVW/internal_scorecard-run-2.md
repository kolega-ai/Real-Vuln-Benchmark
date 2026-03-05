# Internal Scorecard — dsvw

**Commit:** `7d40f4b7939c`  
**Generated:** 2026-03-02T09:32:34.584338+00:00  
**Ground Truth:** 19 vulnerabilities, 4 false-positive traps  
**Application:** [724eed17-357c-4a5d-aecf-95e9ca054ebb](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb)

---

## our-scanner — F2 Score: 65.7 / 100

| TP | FP | FN | TN | Precision | Recall | F1 |
|---:|---:|---:|---:|----------:|-------:|---:|
| 13 | 10 | 6 | 4 | 56.5% | 68.4% | 0.619 |

### True Positives (13)

Scanner correctly identified these real vulnerabilities.

- ✅ [CWE-113 on dsvw.py:L78](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/ddb1f7fb-45d0-4330-9271-23b960ba2981) → **dsvw-016** — http_header_injection: HTTP header injection via charset parameter injected into Content-Type header without CRLF filtering
- ✅ [CWE-209 on dsvw.py:L72](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/7858b623-4cf8-4951-b3bd-64f3884c000a) → **dsvw-018** — sensitive_data_exposure: Full stack trace returned to client via traceback.format_exc() on any unhandled exception
- ✅ [CWE-502 on dsvw.py:L35](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/b0bfaee3-601b-4298-8ebc-aca0ed55d5f0) → **dsvw-003** — insecure_deserialization: Arbitrary code execution via pickle.loads on user-controlled object parameter
- ✅ [CWE-601 on dsvw.py:L61](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/52de264e-cbef-4990-9853-39b4c404e31e) → **dsvw-013** — open_redirect: Open redirect via redir parameter injected into meta refresh URL without validation
- ✅ [CWE-611 on dsvw.py:L41](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/07af8892-c762-4898-96a1-d97366392655) → **dsvw-007** — xxe: XXE via xml parameter parsed by lxml with load_dtd=True, resolve_entities=True, no_network=False
- ✅ [CWE-643 on dsvw.py:L43](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/4a090d7c-8898-418d-9afd-869d385d2214) → **dsvw-008** — xpath_injection: XPath injection via name parameter directly interpolated into XPath query string
- ✅ [CWE-770 on dsvw.py:L48](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/b0b0f012-948d-4f19-b718-54238b75bde7) → **dsvw-009** — denial_of_service: Memory-based DoS via size parameter controlling O(n^2) string allocation with no upper bound
- ✅ [CWE-78 on dsvw.py:L39](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/446161c8-3cd1-4a96-b43d-0538ded4b50b) → **dsvw-006** — command_injection: OS command injection via domain parameter concatenated into nslookup command with shell=True
- ✅ [CWE-79 on dsvw.py:L33](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/d040fe77-e7a3-4c5c-adcc-af1b61581a5c) → **dsvw-002** — reflected_xss: Reflected XSS via v parameter injected into HTML response via re.sub without escaping
- ✅ [CWE-798 on dsvw.py:L11](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/6f49d4e5-0750-4e35-9947-b3660ca6b174) → **dsvw-017** — hardcoded_credentials: Plaintext hardcoded passwords in USERS_XML constant including admin password '7en8aiDoh!'
- ✅ [CWE-89 on dsvw.py:L30](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/66e8db95-dfca-4898-b00d-5a7243f9d870) → **dsvw-001** — sql_injection: SQL injection via id parameter directly concatenated into SELECT query without sanitization
- ✅ [CWE-918 on dsvw.py:L37](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/01669cab-2dda-4897-beb2-e1054b351344) → **dsvw-005** — ssrf: SSRF via path parameter passed to urllib.request.urlopen when URL scheme is detected
- ✅ [CWE-94 on dsvw.py:L57](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/5e37a8da-bae5-4c99-903b-2623304b4b83) → **dsvw-012** — remote_file_inclusion: Remote code execution via include parameter: fetches arbitrary local/remote file and passes it to exec()

### False Positives (10)

Scanner flagged these but they are not real vulnerabilities. Review and dismiss.

- ❌ [CWE-20 on dsvw.py:L46](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/31810eb9-6312-4fb7-85ed-8df8758e95af) — no GT entry. Scanner says: Integer Conversion Without Validation on `size` Parameter
- ❌ [CWE-22 on dsvw.py:L56](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/d315b2da-a411-400f-8cd3-88f27a92d12e) — no GT entry. Scanner says: Path Traversal via include parameter (file read)
- ❌ [CWE-306 on dsvw.py:L24](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/5c56ce17-db42-480e-94e0-92486445c6db) — no GT entry. Scanner says: No Authentication on Any Endpoint — All Handlers Publicly Accessible
- ❌ [CWE-307 on dsvw.py:L66](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/ec8a1d99-1e4f-404a-8c1c-57fdf197d159) — no GT entry. Scanner says: Missing Rate Limiting on Login Endpoint
- ❌ [CWE-312 on dsvw.py:L19](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/bb8343ed-dd18-48d9-a982-a3b36f1b6a35) — no GT entry. Scanner says: Cleartext Storage of Passwords in SQLite Database
- ❌ [CWE-330 on dsvw.py:L68](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/654ee24e-7606-4b8f-9375-d4fd5307c61b) — no GT entry. Scanner says: Weak Session Token Generation Using random.sample
- ❌ [CWE-352 on dsvw.py:L23](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/8bfc78ce-b2c0-4ebd-8f4b-f21f63803c66) — no GT entry. Scanner says: CSRF Protection Completely Missing
- ❌ [CWE-862 on dsvw.py:L64](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/9c8efd01-d615-4aaf-9380-5ad0de242325) — no GT entry. Scanner says: JSONP Endpoint Exposes User Data Without Authentication
- ❌ [CWE-915 on dsvw.py:L50](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/578d138f-2463-45a7-9825-9c75dff99b83) — no GT entry. Scanner says: Mass Assignment - No Input Field Whitelisting on Comment Insert
- ❌ [CWE-916 on dsvw.py:L20](https://comply.kolegatestapps.com/applications/724eed17-357c-4a5d-aecf-95e9ca054ebb/findings/90481c39-1234-4762-b761-e9d54151cb08) — no GT entry. Scanner says: Plaintext Password Storage in SQLite Database

### False Negatives (6)

Scanner missed these real vulnerabilities.

- ⚠️ **dsvw-004** `CWE-22` on `dsvw.py`:L37 (medium) — Path traversal via path parameter passed to open() with os.path.abspath but no path restriction
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
