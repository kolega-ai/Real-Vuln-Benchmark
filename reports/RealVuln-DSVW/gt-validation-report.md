# Ground Truth Validation Report: dsvw

**Date**: 2026-03-02
**Ground Truth**: realvuln/ground-truth/RealVuln-DSVW/ground-truth.json
**Repo**: https://github.com/stamparm/DSVW

## Summary

- Vulnerabilities in GT: 19
- False-positive traps in GT: 4
- Potential gaps found: 1 (confirmed), 2 (lower confidence)
- Sources checked: repo code, README/docs, CASES tuple (in-app vulnerability list), CVE/NVD, web searches

The ground truth is in strong shape. It covers all major vulnerability sinks in the application. Line numbers are accurate against the source code at the pinned commit. The FP trap ratio is healthy at 1:4.75 (better than the 1:5 minimum). One confirmed gap was found: a missing CSRF entry that DSVW explicitly demonstrates in its CASES tuple. Two lower-confidence items are noted below as likely correct omissions.

## Coverage by Vulnerability Class

| Class | In GT | Found in Sources | Status |
|-------|-------|-----------------|--------|
| sql_injection | 3 (dsvw-001, dsvw-010, dsvw-015) | 3 sinks (id param, comment param, password param) | Covered |
| reflected_xss | 2 (dsvw-002, dsvw-014) | 2 sinks (v param, JSONP callback) | Covered |
| stored_xss | 1 (dsvw-011) | 1 sink (comment rendering) | Covered |
| dom_xss | 1 (dsvw-019) | 1 sink (document.write + location.hash) | Covered |
| insecure_deserialization | 1 (dsvw-003) | 1 sink (pickle.loads) | Covered |
| path_traversal | 1 (dsvw-004) | 1 sink (open with path param) | Covered |
| ssrf | 1 (dsvw-005) | 1 sink (urlopen with path param) | Covered |
| command_injection | 1 (dsvw-006) | 1 sink (subprocess.run shell=True) | Covered |
| xxe | 1 (dsvw-007) | 1 sink (lxml with unsafe parser config) | Covered |
| xpath_injection | 1 (dsvw-008) | 1 sink (xpath with string interpolation) | Covered |
| denial_of_service | 1 (dsvw-009) | 1 sink (O(n^2) string allocation) | Covered |
| remote_file_inclusion | 1 (dsvw-012) | 1 sink (fetch + exec) | Covered |
| open_redirect | 1 (dsvw-013) | 1 sink (meta refresh with redir param) | Covered |
| http_header_injection | 1 (dsvw-016) | 1 sink (charset in Content-Type header) | Covered |
| hardcoded_credentials | 1 (dsvw-017) | 1 instance (USERS_XML with plaintext passwords) | Covered |
| sensitive_data_exposure | 1 (dsvw-018) | 1 sink (traceback.format_exc to client) | Covered |
| csrf | 0 | 1 (in CASES tuple) | GAP -- 1 missing |

## Confirmed Gaps

### Gap 1: Cross-Site Request Forgery (CSRF)

- **Source**: CASES tuple in dsvw.py line 12 -- explicitly listed as "Cross Site Request Forgery" with an exploit URL and OWASP reference link
- **Vulnerability class**: `csrf`
- **Primary CWE**: CWE-352
- **Location**: dsvw.py, line 50 (the state-changing INSERT endpoint that the CASES exploit targets)
- **Evidence**: The DSVW application sets cookies via `meta http-equiv="Set-Cookie"` (line 68) without any CSRF protection mechanisms. The application performs state-changing operations (INSERT INTO comments) on GET requests with no anti-CSRF tokens. The CASES tuple demonstrates CSRF by showing that a crafted image tag can trigger a comment insertion cross-origin without the user's knowledge.
- **Suggested GT entry**:

```json
{
  "id": "dsvw-020",
  "is_vulnerable": true,
  "vulnerability_class": "csrf",
  "primary_cwe": "CWE-352",
  "acceptable_cwes": ["CWE-352"],
  "file": "dsvw.py",
  "location": {
    "start_line": 50,
    "end_line": 50,
    "function": "do_GET"
  },
  "severity": "medium",
  "evidence": {
    "source": "manual_review",
    "cve_id": null,
    "description": "CSRF on comment insertion endpoint: state-changing INSERT operation performed via GET request with no anti-CSRF tokens, no SameSite cookie attribute, and no Origin/Referer validation. The CASES tuple explicitly demonstrates this with an img tag that triggers comment creation cross-origin."
  }
}
```

**Note**: CSRF is borderline for SAST ground truth since it is an architectural flaw rather than a specific code sink. Some SAST scanners do flag the absence of CSRF protections, especially on state-changing endpoints. The CASES tuple in DSVW explicitly lists it as a supported vulnerability, which argues for inclusion. However, if your GT is focused strictly on sink-level SAST findings, it would be reasonable to exclude this entry.

## Potential Gaps (Lower Confidence)

### Potential Gap A: HTTP Parameter Pollution (HPP)

- **Source**: CASES tuple in dsvw.py line 12 -- listed as "HTTP Parameter Pollution" with OWASP reference
- **Reasoning for exclusion**: HPP is a technique/attack vector rather than a distinct vulnerability class. In DSVW, HPP is used as an alternative exploitation technique for the login SQL injection (dsvw-015). The underlying vulnerability is still SQL injection via the password parameter. HPP itself is a request-handling behavior where the application concatenates multiple values of the same parameter with commas (line 26: `','.join(re.findall(...))`), which an attacker uses to bypass WAFs or reassemble a SQL injection payload split across multiple `password=` parameters. Most SAST scanners would not flag HPP separately. The GT schema does not include HPP as a vulnerability class. **Likely a correct omission.**

### Potential Gap B: Clickjacking / Frame Injection

- **Source**: CASES tuple -- lists "Frame Injection (phishing)", "Frame Injection (content spoofing)", and "Clickjacking"
- **Reasoning for exclusion**: These are all exploitation techniques that leverage the reflected XSS vulnerability already documented in dsvw-002. The DSVW app does send `X-XSS-Protection: 0` (line 77) and lacks `X-Frame-Options` or `Content-Security-Policy` headers, but per the GT schema guidelines, "Missing HTTP security headers with no concrete exploit" should not be documented. Since the frame injection attacks require the reflected XSS as a prerequisite, they are already covered by dsvw-002. Clickjacking as a standalone issue (missing X-Frame-Options) falls under the "do not document" category per schema rules. **Correct omission.**

### Potential Gap C: Full Path Disclosure / Source Code Disclosure

- **Source**: CASES tuple -- lists both as separate entries
- **Reasoning for coverage**: Full Path Disclosure occurs when an invalid path triggers an exception, exposing file system paths in the traceback. This is covered by dsvw-018 (sensitive_data_exposure via traceback.format_exc). Source Code Disclosure occurs when the attacker reads the application's own source via the path parameter (e.g., `?path=dsvw.py`), which is covered by dsvw-004 (path_traversal). These are specific exploitation scenarios of already-documented vulnerabilities, not distinct sinks. **Correct omissions as separate entries.**

## Existing GT Entries Validated

| ID | Class | Line(s) | Line Correct? | Confirmed By |
|----|-------|---------|---------------|-------------|
| dsvw-001 | sql_injection | 30 | Yes -- `cursor.execute("SELECT ... WHERE id=" + params["id"])` | CASES tuple (3 entries: blind boolean, blind time, UNION), code review |
| dsvw-002 | reflected_xss | 33 | Yes -- `re.sub(... params["v"] ...)` injects into HTML | CASES tuple ("Cross Site Scripting (reflected)"), code review |
| dsvw-003 | insecure_deserialization | 35 | Yes -- `pickle.loads(params["object"].encode())` | CASES tuple ("Component with Known Vulnerability (pickle)"), code review |
| dsvw-004 | path_traversal | 37 | Yes -- `open(os.path.abspath(params["path"]))` | CASES tuple ("Path Traversal", "Source Code Disclosure"), code review |
| dsvw-005 | ssrf | 37 | Yes -- `urllib.request.urlopen(params["path"])` | CASES tuple ("Server Side Request Forgery"), code review |
| dsvw-006 | command_injection | 39 | Yes -- `subprocess.run("nslookup " + params["domain"], shell=True...)` | CASES tuple ("Arbitrary Code Execution"), code review |
| dsvw-007 | xxe | 41 | Yes -- `lxml.etree.XMLParser(load_dtd=True, resolve_entities=True, no_network=False)` | CASES tuple ("XML External Entity (local/remote)"), code review |
| dsvw-008 | xpath_injection | 43 | Yes -- `.xpath(".//user[name/text()='%s']" % params["name"])` | CASES tuple ("Blind XPath Injection (boolean)"), code review |
| dsvw-009 | denial_of_service | 46-47 | Yes -- O(n^2) string allocation with `int(params["size"])` | CASES tuple ("Denial of Service (memory)"), code review |
| dsvw-010 | sql_injection | 50 | Yes -- `"INSERT INTO comments VALUES(NULL, '%s', '%s')" % (params["comment"]...)` | CASES tuple (stored XSS chain implies comment injection), code review |
| dsvw-011 | stored_xss | 54 | Yes -- comments rendered from DB without encoding | CASES tuple ("Cross Site Scripting (stored)"), code review |
| dsvw-012 | remote_file_inclusion | 56-57 | Yes -- `exec(program, envs)` where program is fetched from user URL | CASES tuple ("File Inclusion (remote)"), code review |
| dsvw-013 | open_redirect | 61 | Yes -- `meta http-equiv="refresh" content="0; url=%s"` with params["redir"] | CASES tuple ("Unvalidated Redirect"), code review |
| dsvw-014 | reflected_xss | 65 | Yes -- JSONP callback without sanitization: `"%s(" % params["callback"]` | CASES tuple ("Cross Site Scripting (JSONP)"), code review |
| dsvw-015 | sql_injection | 67 | Yes -- `password='" + params.get("password", "") + "'"` | CASES tuple ("Login Bypass"), code review |
| dsvw-016 | http_header_injection | 78 | Yes -- `charset=%s" % params.get("charset", "utf8")` in Content-Type header | CASES tuple ("HTTP Header Injection (phishing)"), code review |
| dsvw-017 | hardcoded_credentials | 11 | Yes -- USERS_XML contains `<password>7en8aiDoh!</password>` etc. | Code review, USERS_XML constant |
| dsvw-018 | sensitive_data_exposure | 72 | Yes -- `traceback.format_exc()` returned to client | CASES tuple ("Full Path Disclosure"), code review |
| dsvw-019 | dom_xss | 10 | Yes -- `document.write(... decodeURIComponent(document.location.hash...))` | CASES tuple ("Cross Site Scripting (DOM)"), code review |
| dsvw-fp-001 | sql_injection (FP) | 67 | Yes -- username sanitized via `re.sub(r"[^\w]", "", ...)` | Code review confirms non-word chars stripped |
| dsvw-fp-002 | sql_injection (FP) | 20 | Yes -- `cursor.executemany` with `?` placeholders | Code review confirms parameterized query |
| dsvw-fp-003 | xss (FP) | 10 | Yes -- NAME passed through `html.escape()` in HTML_PREFIX | Code review confirms proper escaping |
| dsvw-fp-004 | sql_injection (FP) | 19 | Yes -- `CREATE TABLE` is a static string literal | Code review confirms no user input |

**All 23 GT entries (19 vulns + 4 FP traps) have accurate line numbers and are confirmed by source code inspection.**

## FP Trap Ratio Assessment

- Vulnerabilities: 19
- FP traps: 4
- Ratio: 1 trap per 4.75 vulns (meets the minimum requirement of 1 per 5)

The FP traps are well-designed:
- dsvw-fp-001 tests whether scanners can distinguish sanitized vs. unsanitized parameters in the same SQL query
- dsvw-fp-002 tests parameterized query recognition
- dsvw-fp-003 tests HTML escaping recognition
- dsvw-fp-004 tests static string vs. dynamic query distinction

## Sources Consulted

1. **Source code**: `repos/RealVuln-DSVW/dsvw.py` -- full manual review of all 99 lines
2. **CASES tuple**: Line 12 of dsvw.py -- the application's own vulnerability manifest listing 26 attack entries
3. **README.md**: `repos/RealVuln-DSVW/README.md` -- mentions lxml-dependent vulns but does not provide a full vulnerability list
4. **GitHub repository**: https://github.com/stamparm/DSVW -- confirmed README matches local copy
5. **CVE/NVD search**: No CVEs assigned to DSVW (expected for an intentionally vulnerable educational app)
6. **Web searches**: Searched for "DSVW vulnerability writeup", "DSVW CVE", "DSVW exploit", "DSVW HTTP Parameter Pollution" -- no additional vulnerabilities found beyond what the CASES tuple documents
7. **GT schema reference**: `realvuln/gt-generation-prompt.md` -- used to determine what should and should not be documented
