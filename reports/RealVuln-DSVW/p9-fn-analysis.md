# DSVW p9 — False Negative Analysis

**GT**: 20 vulnerabilities, 4 FP traps | **Always found**: 8/20 | **Inconsistent**: 5/20 | **Never found**: 7/20

**Scores**: r1 F2=52.1 (TP=10, FP=6) | r2 F2=46.4 (TP=9, FP=8) | r3 F2=61.9 (TP=12, FP=5)

## Detection Matrix

| GT ID | Vulnerability | r1 | r2 | r3 | Rate |
|-------|--------------|-----|-----|-----|------|
| dsvw-001 | SQL Injection (SELECT, id param) | FN | FN | FN | 0/3 |
| dsvw-002 | Reflected XSS (v param) | FN | FN | FN | 0/3 |
| dsvw-003 | Insecure Deserialization (pickle) | FN | FN | FN | 0/3 |
| dsvw-004 | Path Traversal (path param) | TP | FN | FN | 1/3 |
| dsvw-005 | SSRF (path param, URL scheme) | FN | FN | TP | 1/3 |
| dsvw-006 | Command Injection (domain param) | TP | TP | TP | 3/3 |
| dsvw-007 | XXE (xml param) | TP | TP | TP | 3/3 |
| dsvw-008 | XPath Injection (name param) | FN | FN | TP | 1/3 |
| dsvw-009 | DoS (size param) | TP | TP | TP | 3/3 |
| dsvw-010 | SQL Injection (INSERT, comment param) | FN | FN | FN | 0/3 |
| dsvw-011 | Stored XSS (comment rendering) | TP | TP | TP | 3/3 |
| dsvw-012 | RFI/RCE (include param + exec) | TP | TP | TP | 3/3 |
| dsvw-013 | Open Redirect (redir param) | FN | TP | TP | 2/3 |
| dsvw-014 | Reflected XSS (JSONP callback) | FN | FN | FN | 0/3 |
| dsvw-015 | SQL Injection (login bypass, password) | TP | TP | TP | 3/3 |
| dsvw-016 | HTTP Header Injection (charset param) | TP | TP | TP | 3/3 |
| dsvw-017 | Hardcoded Credentials (USERS_XML) | FN | FN | FN | 0/3 |
| dsvw-018 | Stack Trace Disclosure (traceback) | TP | TP | TP | 3/3 |
| dsvw-019 | DOM XSS (location.hash in inline JS) | FN | FN | FN | 0/3 |
| dsvw-020 | CSRF (comment via GET, no token) | TP | FN | TP | 2/3 |

---

## NEVER FOUND (0/3)

### dsvw-001 — SQL Injection via `id` parameter (SELECT query)

**File**: `dsvw.py:30`

```python
if "id" in params:
    cursor.execute("SELECT id, username, name, surname FROM users WHERE id=" + params["id"])
    content += "<div><span>Result(s):</span></div><table>..." % ("".join(...) for row in cursor.fetchall()), HTML_POSTFIX)
```

**What it is**: The `id` parameter from `/?id=2` is directly concatenated into a SELECT query with zero sanitization. Supports boolean-blind, time-blind, and UNION-based extraction.

**Why it's a vulnerability**: `/?id=2 UNION ALL SELECT NULL, NULL, NULL, password FROM users WHERE username='admin'` extracts the admin password directly. No parameterized query, no input validation, no type casting.

**What the scanner reported instead**: In all 3 runs, the scanner reports CWE-89 at L67 — but the L67 finding describes "SQL Injection via 'id' parameter" with the L30 code in its message. The scanner found this vulnerability but wrote it at the wrong line number (L67 is the /login query, not the /?id= query). The CWE-89 at L67 finding then gets consumed matching dsvw-015 (login bypass), leaving dsvw-001 unmatched.

**Root cause**: Scanner conflates the L30 SELECT query and L67 login query into a single CWE-89 finding at L67. It needs to report each SQL injection at its own line.

**Acceptable CWEs**: CWE-89, CWE-564, CWE-943

---

### dsvw-002 — Reflected XSS via `v` parameter

**File**: `dsvw.py:33`

```python
elif "v" in params:
    content += re.sub(r"(v<b>)[^<]+(</b>)", r"\g<1>%s\g<2>" % params["v"], HTML_POSTFIX)
```

**What it is**: The `v` parameter is interpolated directly into the HTML response body via `re.sub` with `%s` formatting. No encoding, no escaping.

**Why it's a vulnerability**: `/?v=0.4<script>alert(1)</script>` injects arbitrary JavaScript into the response. The `re.sub` replaces a version number placeholder with raw user input.

**What the scanner reported instead**: The scanner reports CWE-79 but at wrong lines:
- r1: CWE-79 at L61 — describes "Reflected XSS via 'v' parameter" but at L61 (the redirect line). L61 is 28 lines from L33, outside the +/-10 tolerance. Gets matched to dsvw-011 (L54, diff=7).
- r2: CWE-79 at L44 — describes "Reflected XSS via v parameter" at L44. L44 is 11 lines from L33 (outside +/-10) but within +/-10 of L54, so it matches dsvw-011.
- r3: CWE-79 at L54 — describes "DOM-based XSS" (actually dsvw-019). Matches dsvw-011 (L54, exact).

**Root cause**: Scanner reports only ONE CWE-79 finding per run but there are FOUR distinct XSS vulnerabilities (dsvw-002, 011, 014, 019). Whichever single finding it produces gets consumed by dsvw-011, leaving the other 3 as FNs.

**Acceptable CWEs**: CWE-79, CWE-80

---

### dsvw-003 — Insecure Deserialization via `pickle.loads`

**File**: `dsvw.py:35`

```python
elif "object" in params:
    content = str(pickle.loads(params["object"].encode()))
```

**What it is**: User-supplied `object` parameter is passed directly to `pickle.loads()`. Python's pickle can execute arbitrary code during deserialization via `__reduce__`.

**Why it's a vulnerability**: An attacker sends a crafted pickle payload: `cos\nsystem\n(S'id'\ntR.\n` which executes `os.system('id')` on the server. Full RCE with no authentication.

**What the scanner reported instead**: In all 3 runs, the scanner reports CWE-94 at L56 with a message mentioning "pickle.loads" or "pickle deserialization" — but L56 is the `include` handler, not the `object` handler. The pickle code is at L35 (21 lines away, outside +/-10). CWE-94 at L56 matches dsvw-012 (RFI at L56) instead.

**Root cause**: The scanner correctly identifies the pickle vulnerability but reports it at L56 (the `include` line) instead of L35 (the `object` line). It appears to confuse the two code paths because both handle user input leading to code execution. The finding gets consumed by dsvw-012.

**Acceptable CWEs**: CWE-502, CWE-94

---

### dsvw-010 — SQL Injection via `comment` parameter (INSERT)

**File**: `dsvw.py:50`

```python
elif "comment" in params or query == "comment=":
    if "comment" in params:
        cursor.execute("INSERT INTO comments VALUES(NULL, '%s', '%s')" % (params["comment"], time.ctime()))
```

**What it is**: The `comment` parameter is interpolated into an INSERT statement via `%s` string formatting with single-quote delimiters. No parameterized query.

**Why it's a vulnerability**: `/?comment=' || (SELECT password FROM users WHERE username='admin') || '` injects into the INSERT and can exfiltrate data via the stored comment. Also enables stored XSS via the comment rendering (dsvw-011).

**What the scanner reported instead**: No CWE-89 finding near L50 in any run. The scanner's single CWE-89 finding is always at L67 (login query). The scanner doesn't recognize that the INSERT query at L50 is also SQL injection — it only finds SELECT/WHERE-style injection.

**Root cause**: Scanner only reports one SQL injection finding per run despite there being three distinct SQLi sinks (L30 SELECT, L50 INSERT, L67 login). INSERT-based injection appears to be a blind spot.

**Acceptable CWEs**: CWE-89, CWE-943

---

### dsvw-014 — Reflected XSS via JSONP callback

**File**: `dsvw.py:65`

```python
elif path == "/users.json":
    content = "%s%s%s" % ("" if not "callback" in params else "%s(" % params["callback"],
              json.dumps(dict(...)),
              "" if not "callback" in params else ")")
```

**What it is**: The `callback` parameter is inserted directly into the response body wrapping a JSON payload. The JSONP pattern allows JavaScript execution when loaded via a script tag.

**Why it's a vulnerability**: `/users.json?callback=alert(document.cookie)//` returns `alert(document.cookie)//{...json...})`. When loaded as a script tag from an attacker's page, this executes arbitrary JavaScript with access to the victim's cookies.

**What the scanner reported instead**: No scanner finding targets the `/users.json` endpoint in any run. The scanner only looks at the `path == '/'` branch and never examines the `elif path == "/users.json"` branch.

**Root cause**: The scanner appears to focus on the main `do_GET` handler's `if path == '/'` branch and completely ignores the `/users.json` JSONP endpoint. This is a separate route within the same handler that needs its own analysis.

**Acceptable CWEs**: CWE-79

---

### dsvw-017 — Hardcoded Credentials in `USERS_XML`

**File**: `dsvw.py:11`

```python
USERS_XML = """<?xml version="1.0" encoding="utf-8"?>
<users>
  <user id="0"><username>admin</username><name>admin</name>
    <surname>admin</surname><password>7en8aiDoh!</password></user>
  <user id="1"><username>dricci</username>...
    <password>12345</password></user>
  ...
</users>"""
```

**What it is**: The `USERS_XML` constant on line 11 contains plaintext usernames and passwords embedded directly in the source code. Four user accounts with their passwords: `admin/7en8aiDoh!`, `dricci/12345`, `amason/gandalf`, `svargas/phest1945`.

**Why it's a vulnerability**: Hardcoded credentials in source code are accessible to anyone with read access to the repository. These passwords are used for authentication at the `/login` endpoint and are the actual production credentials.

**What the scanner reported instead**: The scanner reports CWE-312 at L20 ("Cleartext Password Storage in SQLite Database") in all 3 runs — this describes the passwords being stored unhashed in the database at the INSERT line, not the hardcoded credentials in the source constant at L11. CWE-312 is not in the acceptable CWE list (CWE-798, CWE-259, CWE-321).

**Root cause**: The scanner identifies the password handling issue but classifies it as "cleartext storage" (CWE-312) at the database INSERT (L20) rather than "hardcoded credentials" (CWE-798) at the source constant (L11). It sees the storage problem but misses that the credentials themselves are hardcoded.

**Acceptable CWEs**: CWE-798, CWE-259, CWE-321

---

### dsvw-019 — DOM-based XSS via `location.hash`

**File**: `dsvw.py:10` (inline JavaScript in `HTML_PREFIX` constant)

```javascript
var index=document.location.hash.indexOf('lang=');
if (index != -1)
  document.write(
    '<div ...>Chosen language: <b>'
    + decodeURIComponent(document.location.hash.substring(index + 5))
    + '</b></div>');
```

**What it is**: Inline JavaScript in the HTML_PREFIX string reads the URL hash fragment, extracts the `lang=` value, decodes it with `decodeURIComponent`, and writes it directly into the DOM using `document.write` without sanitization.

**Why it's a vulnerability**: `/?#lang=<script>alert(1)</script>` executes arbitrary JavaScript. The hash fragment is never sent to the server, making this a pure client-side (DOM-based) XSS. `document.write` with unsanitized `decodeURIComponent` is the classic DOM XSS sink.

**What the scanner reported instead**: r3 reports CWE-79 at L54 with message "DOM-based Cross-Site Scripting via URL hash fragment" — this correctly describes dsvw-019 but at L54 (the comment rendering line) instead of L10 (where the JavaScript lives in the HTML_PREFIX constant). L54 is 44 lines away from L10, so it matches dsvw-011 instead.

**Root cause**: The scanner found this vulnerability in r3 (correct description, correct CWE) but at the completely wrong line. The DOM XSS code is in a JavaScript string embedded in a Python constant at L10, which is hard for the scanner to pin to the right line. The scanner seems to know the vuln exists but can't locate it in the dense single-file structure.

**Acceptable CWEs**: CWE-79

---

## INCONSISTENTLY FOUND (1-2/3)

### dsvw-004 — Path Traversal via `path` parameter (1/3: r1)

**File**: `dsvw.py:37`

```python
elif "path" in params:
    content = (open(os.path.abspath(params["path"]), "rb") if not "://" in params["path"]
               else urllib.request.urlopen(params["path"])).read().decode()
```

**What it is**: When `path` doesn't contain `://`, it's passed to `open(os.path.abspath(...))`. `os.path.abspath` resolves `../` sequences but doesn't restrict to any base directory.

**Why it's a vulnerability**: `/?path=../../etc/passwd` reads arbitrary files. `os.path.abspath` does NOT prevent traversal — it just resolves the path to an absolute form and opens whatever file it resolves to.

**Why inconsistent**:
- r1: CWE-22 at L37 (correct line, matches)
- r2: CWE-22 at L56 (describes "path parameter" but at L56, the `include` handler — 19 lines away, outside +/-10)
- r3: CWE-22 at L56 (same problem — describes "include parameter" path traversal at L56 instead of L37)

**Root cause**: The scanner conflates the `path` handler (L37) with the `include` handler (L56) because both use `open()` and `urllib.request.urlopen()` with the same `if not "://"` pattern. In r2/r3 it reports the finding at L56 instead of L37.

**Acceptable CWEs**: CWE-22, CWE-23, CWE-36, CWE-73

---

### dsvw-005 — SSRF via `path` parameter (URL scheme) (1/3: r3)

**File**: `dsvw.py:37`

```python
elif "path" in params:
    content = (open(os.path.abspath(params["path"]), "rb") if not "://" in params["path"]
               else urllib.request.urlopen(params["path"])).read().decode()
```

**What it is**: When `path` CONTAINS `://`, the `else` branch passes it to `urllib.request.urlopen()`, making the server fetch arbitrary URLs including internal services.

**Why it's a vulnerability**: `/?path=http://169.254.169.254/latest/meta-data/` makes the server fetch the AWS metadata endpoint. Any `http://`, `file://`, `ftp://` URL is accepted.

**Why inconsistent**:
- r1: CWE-918 at L56 (reports SSRF for the `include` parameter at L56, not the `path` parameter at L37)
- r2: No CWE-918 finding at all
- r3: CWE-918 at L37 (correct line, matches)

**Root cause**: Same conflation issue as dsvw-004. The `path` handler (L37) and `include` handler (L56) both have `urllib.request.urlopen()`, and the scanner often reports the finding at L56 instead of L37.

**Acceptable CWEs**: CWE-918, CWE-441

---

### dsvw-008 — XPath Injection via `name` parameter (1/3: r3)

**File**: `dsvw.py:43`

```python
elif "name" in params:
    found = lxml.etree.parse(io.BytesIO(USERS_XML.encode())).xpath(
        ".//user[name/text()='%s']" % params["name"])
    content += "<b>Surname:</b> %s%s" % (found[-1].find("surname").text if found else "-", HTML_POSTFIX)
```

**What it is**: The `name` parameter is interpolated directly into an XPath expression using `%s` string formatting. No sanitization.

**Why it's a vulnerability**: `/?name=admin' and substring(password/text(),1,1)='7` performs blind XPath injection to extract passwords character by character from the USERS_XML document.

**Why inconsistent**: r1 and r2 don't report CWE-643 at all. r3 correctly reports CWE-643 at L43. The scanner appears to deprioritize XPath injection — it's a less common vulnerability class and gets crowded out by the more obvious findings.

**Acceptable CWEs**: CWE-643, CWE-91, CWE-116

---

### dsvw-013 — Open Redirect via `redir` parameter (2/3: r2, r3)

**File**: `dsvw.py:61`

```python
elif "redir" in params:
    content = content.replace("<head>",
        "<head><meta http-equiv=\"refresh\" content=\"0; url=%s\"/>" % params["redir"])
```

**What it is**: The `redir` parameter is injected into a `<meta http-equiv="refresh">` tag with zero URL validation.

**Why it's a vulnerability**: `/?redir=https://evil.com` redirects the user's browser to an attacker-controlled site. Useful for phishing by exploiting the trust of the legitimate domain.

**Why inconsistent**: r1 doesn't report CWE-601 at all. r2 and r3 both report CWE-601 at L61 (correct). The scanner nondeterministically omits this finding.

**Acceptable CWEs**: CWE-601

---

### dsvw-020 — CSRF on comment submission (2/3: r1, r3)

**File**: `dsvw.py:48-54`

```python
elif "comment" in params or query == "comment=":
    if "comment" in params:
        cursor.execute("INSERT INTO comments VALUES(NULL, '%s', '%s')"
                       % (params["comment"], time.ctime()))
        content += "Thank you for leaving the comment..."
    else:
        cursor.execute("SELECT id, comment, time FROM comments")
```

**What it is**: The comment submission is a state-changing operation (INSERT into database) performed via GET request with no CSRF token.

**Why it's a vulnerability**: An attacker embeds `<img src="http://target/?comment=hacked">` on their page. When a victim visits, their browser sends the GET request, inserting a comment without the victim's knowledge.

**Why inconsistent**: r1 and r3 report CWE-352 at L48 (correct). r2 doesn't report CSRF at all. Nondeterministic.

**Acceptable CWEs**: CWE-352

---

## FP Analysis

| FP CWE | r1 | r2 | r3 | Issue |
|--------|-----|-----|-----|-------|
| CWE-306 (missing auth) | L48 | L64 | L64 | Entire app has no auth — true but not a specific vuln finding |
| CWE-307 (rate limiting) | L66 | L66 | L66 | Missing rate limiting — defense-in-depth, not a vuln |
| CWE-312 (cleartext storage) | L20 | L20 | L19 | Passwords stored unhashed — true but CWE doesn't match any GT |
| CWE-330 (weak PRNG) | L68 | — | — | random.sample for session IDs — true but not in GT |
| CWE-235 (param pollution) | L26 | — | — | HPP via multi-value params — true but not in GT |
| CWE-918 (SSRF) | L56 | — | — | SSRF on include param — misplaced, should be on path param |
| CWE-256 (plaintext storage) | — | L19 | — | Same as CWE-312, different CWE |
| CWE-22 (path traversal) | — | L56 | L56 | Correct vuln, wrong line (should be L37) |
| CWE-1004 (no HttpOnly) | — | L68 | — | Cookie without HttpOnly — true but not in GT |
| CWE-200 (info exposure) | — | L53 | — | Comments visible without auth — true but not in GT |
| CWE-16 (XSS-Protection:0) | — | L77 | — | Deliberate XSS-Protection disable — true but not in GT |
| CWE-614 (no Secure flag) | — | — | L68 | Cookie without Secure flag — true but not in GT |

---

## Root Cause Summary

| Root Cause | Affected Vulns | Count |
|------------|---------------|-------|
| **Only reports ONE finding per CWE** — scanner bundles all SQLi into one CWE-89, all XSS into one CWE-79 | dsvw-001, 002, 010, 014, 019 | 5 |
| **Wrong line number** — describes correct vuln but places it at wrong line (often L56 instead of actual location) | dsvw-001, 002, 003, 004(r2/r3), 005(r1), 019(r3) | 6 |
| **L37/L56 conflation** — confuses `path` handler (L37) and `include` handler (L56) because both use `open()`/`urlopen()` | dsvw-004, 005 | 2 |
| **CWE mismatch** — finds the issue but uses wrong CWE (CWE-312 instead of CWE-798 for hardcoded creds) | dsvw-017 | 1 |
| **Blind spot for INSERT SQLi** — only recognizes SELECT/WHERE injection, not INSERT-based | dsvw-010 | 1 |
| **Ignores non-root routes** — never examines `/users.json` endpoint (JSONP XSS) | dsvw-014 | 1 |
| **Nondeterministic** — sometimes found, sometimes not, with no clear pattern | dsvw-008, 013, 020 | 3 |

**Critical insight**: The single biggest problem is **"one finding per CWE" bundling**. DSVW has 3 SQLi vulns and 4 XSS vulns in a single file. The scanner reports one of each, and the rest become FNs. If the scanner reported each distinct sink/handler separately, TP would jump by ~5 per run.

**Comparison with older t6-c2-opus-4-6-p4 runs** (F2=62.5/63.1/63.1, TP=13): Those runs found dsvw-001, 002, 003, 004, 008, 017, and 020 consistently — all of which p9 misses or finds inconsistently. The older prompt was better at reporting multiple findings per CWE and placing them at the correct line numbers.
