# DVGA p7 — False Negative Analysis

**GT**: 31 vulnerabilities | **Always found**: 9/31 | **Inconsistent**: 15/31 | **Never found**: 7/31

### dvga-002 — OS Command Injection in `ImportPaste` (1/3) — CRITICAL

**File**: `core/views.py:209-211`

```python
def mutate(self, info, host='pastebin.com', port=443, path='/', scheme="http"):
    url = security.strip_dangerous_characters(f"{scheme}://{host}:{port}{path}")
    cmd = helpers.run_cmd(f'curl --insecure {url}')
```

**What it is**: User-controlled `host`, `port`, `path`, and `scheme` GraphQL arguments are assembled into a URL string, passed through `strip_dangerous_characters()` (which only removes `;` and `&` in hard mode, and is a no-op in easy mode), then executed via `os.popen()` inside `run_cmd()`.

**Why it's a vulnerability**: An attacker can inject shell commands via any of the four parameters. For example, `scheme="http; id #"` produces `curl --insecure http; id #://host:443/` — the shell executes `curl --insecure http` then `id`. Backticks, `$()`, pipes, and newlines also work since `strip_dangerous_characters` doesn't filter them.

**Why inconsistent**: r2/r3 report CWE-918 (SSRF) at L209 but not CWE-78 (command injection) at L211. The SSRF match consumes the nearby line range, and the scanner doesn't report both the SSRF and the command injection as separate findings at the same location.

**Acceptable CWEs**: CWE-78, CWE-77, CWE-88

---

### dvga-004 — OS Command Injection in `resolve_system_diagnostics` (2/3) — CRITICAL

**File**: `core/views.py:337-346`

```python
def resolve_system_diagnostics(self, info, username, password, cmd='whoami'):
    q = User.query.filter_by(username='admin').first()
    real_passw = q.password
    res, msg = security.check_creds(username, password, real_passw)
    Audit.create_audit_entry(info)
    if res:
      output = f'{cmd}: command not found'
      if security.allowed_cmds(cmd):
        output = helpers.run_cmd(cmd)
      return output
    return msg
```

**What it is**: The `cmd` argument from the `systemDiagnostics` GraphQL query is passed to `helpers.run_cmd()` after a credential check and an allow-list check. In easy mode, `allowed_cmds()` returns `True` for everything. In hard mode, the allow-list has a missing comma bug (dvga-028).

**Why it's a vulnerability**: After providing valid admin credentials (which are hardcoded as `admin`/`changeme` per dvga-015), an attacker can execute any command. In easy mode there are zero restrictions. In hard mode the broken allow-list (`'ps' 'whoami'` concatenates to `'pswhoami'`) makes the restriction ineffective.

**Why inconsistent**: r1 misses it — the scanner finds command injection at L211 (ImportPaste) and doesn't trace the other `run_cmd` call site. r2/r3 find it.

**Acceptable CWEs**: CWE-78, CWE-77, CWE-88

---

### dvga-008 — Stored XSS via Paste Gallery AJAX (1/3) — MEDIUM

**File**: `templates/paste.html:131-142`

```javascript
if(page_public){
  $("#public_gallery").append(
    `<div class="card-header">
      <i class="fa fa-paste"></i> &nbsp; ${title}
    </div>
    <div class="card-body">
      <p class="card-text">
      <pre>${content}</pre>
      <br><hr />
      <i class="fa fa-user"></i>
      <i><small><b>${owner}</b><br>- ${ip_addr}<br>- (${uas})</small></i></p>
    </div>`
  )
```

**What it is**: The `get_pastes()` JavaScript function fetches paste data from the GraphQL API and renders it directly into the DOM via jQuery `.append()` using template literals. The variables `${title}`, `${content}`, `${owner}`, `${ip_addr}`, and `${uas}` come from the API response with zero sanitization.

**Why it's a vulnerability**: An attacker creates a paste with `title: "<img src=x onerror=alert(document.cookie)>"`. When any user views the public or private pastes page, the AJAX handler fetches the data and injects the unsanitized HTML into the DOM. This is stored XSS — the payload persists in the database and fires for every viewer.

**Why inconsistent**: This is a **second** XSS vector in the same file — dvga-009 (WebSocket subscription handler at L65) does the exact same thing. The scanner typically finds one but not the other, never both in the same run.

**Acceptable CWEs**: CWE-79, CWE-80

---

### dvga-009 — Stored XSS via WebSocket Subscription (1/3) — MEDIUM

**File**: `templates/paste.html:65-74`

```javascript
var pasteHTML = `<div class="card-header">
    <i class="fa fa-paste"></i> &nbsp; ${paste.title}
  </div>
  <div class="card-body">
    <p class="card-text">
    <pre>${paste.content}</pre>
    <br><hr />
    <i class="fa fa-user"></i>
    <i><small><b>${paste.owner.name}</b><br>- ${paste.ipAddr}<br>- (${paste.userAgent})</small></i></p>
  </div>`;
```

**What it is**: The WebSocket `subscribeToPastes()` handler receives real-time paste data and interpolates `paste.title`, `paste.content`, `paste.owner.name`, `paste.ipAddr`, and `paste.userAgent` directly into HTML via template literals, then injects via jQuery `.prependTo()`.

**Why it's a vulnerability**: When a new paste is created with malicious content, the WebSocket pushes it to all connected clients, which render the unsanitized HTML into their DOM. This is a live-updating stored XSS — every connected browser executes the payload the moment the paste is created.

**Why inconsistent**: Same issue as dvga-008 — the scanner randomly picks one of the two XSS handlers but doesn't systematically find both.

**Acceptable CWEs**: CWE-79, CWE-80

---

### dvga-010 — Path Traversal in `save_file` (2/3) — HIGH

**File**: `core/helpers.py:23-30`

```python
def save_file(filename, text):
  try:
    f = open(WEB_UPLOADDIR + filename, 'w')
    f.write(text)
    f.close()
  except Exception as e:
    text = str(e)
  return text
```

**What it is**: The `filename` parameter is concatenated directly with `WEB_UPLOADDIR` (`'pastes/'`) to form the file path. No sanitization, no `os.path.basename()`, no check that the resolved path stays within the upload directory.

**Why it's a vulnerability**: An attacker calls the `UploadPaste` mutation with `filename: "../../etc/cron.d/evil"` and the server writes to `/etc/cron.d/evil`, achieving arbitrary file write and potential RCE.

**Why inconsistent**: r3 missed it. The scanner found CWE-347 (JWT bypass) at L21 in that run but not the path traversal 4 lines below.

**Acceptable CWEs**: CWE-22, CWE-23, CWE-36, CWE-73

---

### dvga-012 — `deleteAllPastes` Missing Authorization (1/3) — HIGH

**File**: `core/views.py:385-389`

```python
def resolve_delete_all_pastes(self, info):
    Audit.create_audit_entry(info)
    Paste.query.delete()
    db.session.commit()
    return Paste.query.count() == 0
```

**What it is**: The `deleteAllPastes` GraphQL query calls `Paste.query.delete()` to wipe every paste in the database, then commits. No authentication or authorization check.

**Why it's a vulnerability**: Any anonymous user can send `{ deleteAllPastes }` and all paste data is permanently destroyed. This is a completely unauthenticated destructive operation.

**Why inconsistent**: Only r3 found it. r1 reported CWE-312 at L370 (wrong line, wrong vuln). r2 reported nothing nearby. The scanner inconsistently discovers missing-auth on GraphQL queries.

**Acceptable CWEs**: CWE-862, CWE-306, CWE-284, CWE-287, CWE-285

---

### dvga-013 — IDOR in `EditPaste` Mutation (2/3) — MEDIUM

**File**: `core/views.py:140-148`

```python
def mutate(self, info, id, title=None, content=None):
    paste_obj = Paste.query.filter_by(id=id).first()

    if title == None:
      title = paste_obj.title
    if content == None:
      content = paste_obj.content

    Paste.query.filter_by(id=id).update(dict(title=title, content=content))
```

**What it is**: The `EditPaste` mutation takes a paste `id` from user input and directly uses it to query and update any paste. No ownership check, no authentication.

**Why it's a vulnerability**: Paste IDs are sequential integers. Any user can modify any paste by calling `editPaste(id: 1, title: "hacked")` — they don't need to own the paste or be authenticated.

**Why inconsistent**: r3 didn't report it. The scanner found it as CWE-639 in r1/r2 but missed it in r3.

**Acceptable CWEs**: CWE-639, CWE-284, CWE-285, CWE-862

---

### dvga-014 — IDOR in `DeletePaste` Mutation (1/3) — MEDIUM

**File**: `core/views.py:164-169`

```python
def mutate(self, info, id):
    result = False

    if Paste.query.filter_by(id=id).delete():
      result = True
      db.session.commit()
```

**What it is**: The `DeletePaste` mutation takes a paste `id` and deletes it without any ownership or authentication check.

**Why it's a vulnerability**: Any user can delete any paste by guessing its sequential integer ID. Unlike `deleteAllPastes` (which wipes everything), this is targeted deletion of specific records by enumeration.

**Why inconsistent**: Only r3 found it (as CWE-862). r1/r2 missed it entirely. This is the sibling of dvga-013 (EditPaste IDOR) — when the scanner finds one, it often skips the other.

**Acceptable CWEs**: CWE-639, CWE-284, CWE-285, CWE-862

---

### dvga-016 — Password Exposed via `resolve_password` (2/3) — HIGH

**File**: `core/views.py:60-65`

```python
@staticmethod
def resolve_password(self, info, **kwargs):
    if info.context.json.get('identity') == 'admin':
      return self.password
    else:
      return '******'
```

**What it is**: The `resolve_password` method on the `UserObject` GraphQL type returns the actual plaintext password when the request context contains `identity == 'admin'`. The identity is set from a JWT token that is decoded without signature verification (dvga-007).

**Why it's a vulnerability**: An attacker forges a JWT with `{"identity": "admin"}` (trivial since verification is disabled), then queries `{ users { username password } }` and gets back every user's plaintext password.

**Why inconsistent**: r1 missed it — the scanner reported CWE-674 at L67 (circular types DoS) in the same area but didn't flag the password exposure at L61.

**Acceptable CWEs**: CWE-200, CWE-522, CWE-256, CWE-312

---

### dvga-019 — Log Injection via `create_audit_entry` (1/3) — MEDIUM

**File**: `core/models.py:58-70`

```python
"""Queries and Mutations"""
try:
  gql_operation = info.operation.name.value
except:
  gql_operation = "No Operation"

if isinstance(info, ResolveInfo):
  if isinstance(info.context.json, list):
    """Array-based Batch"""
    for i in info.context.json:
      gql_query = i.get("query")
      gql_query = clean_query(gql_query)
      obj = cls(**{"gqloperation":gql_operation, "gqlquery":gql_query})
      db.session.add(obj)
```

**What it is**: The `create_audit_entry` method records `info.operation.name.value` as `gql_operation` into the audit log. The operation name is a client-controlled field in GraphQL requests — it can be set to any arbitrary string.

**Why it's a vulnerability**: An attacker performs a destructive operation (e.g., `deleteAllPastes`) but names it `operationName: "getPastes"` in the request. The audit log records "getPastes" as the operation, hiding the real action. This defeats forensic analysis and security monitoring.

**Why inconsistent**: Only r2 found it. r1/r3 reported CWE-117 at `views.py:L105` or `models.py:L39` — close but either the wrong file or the wrong line to match the GT entry at L58-70.

**Acceptable CWEs**: CWE-117, CWE-116, CWE-74

---

### dvga-020 — Plaintext Password Storage (2/3) — HIGH

**File**: `core/models.py:9-22`

```python
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20),unique=True,nullable=False)
    email = db.Column(db.String(20),unique=True,nullable=False)
    password = db.Column(db.String(60),nullable=False)

    @classmethod
    def create_user(cls, **kw):
      obj = cls(**kw)
      db.session.add(obj)
      db.session.commit()

      return obj
```

**What it is**: The `User` model stores passwords as a plain `db.String(60)` column. The `create_user` classmethod passes `**kw` directly to the constructor — no hashing, no transformation.

**Why it's a vulnerability**: Passwords are stored in cleartext in the SQLite database. If the database is compromised (e.g., via the SQL injection in dvga-001), all user passwords are immediately readable. Combined with the GraphQL password exposure (dvga-016), this creates a full credential theft chain.

**Why inconsistent**: r3 reported CWE-915 (mass assignment) at L17 in the same area — correct location, wrong vulnerability. The scanner identified the `**kw` pattern as mass assignment but missed the plaintext password storage.

**Acceptable CWEs**: CWE-916, CWE-312, CWE-256, CWE-522, CWE-257

---

### dvga-022 — Unauthenticated `/audit` Endpoint (1/3) — MEDIUM

**File**: `core/views.py:426-429`

```python
@app.route('/audit')
def audit():
  audit = Audit.query.order_by(Audit.timestamp.desc())
  return render_template("audit.html", audit=audit)
```

**What it is**: The `/audit` HTTP route displays all GraphQL operation audit logs without any authentication check.

**Why it's a vulnerability**: The audit log contains full GraphQL queries, which may include sensitive data — tokens, passwords, and other arguments that bypassed the incomplete `clean_query` regex sanitization (dvga-031). Any unauthenticated user can view the full operational history and potentially extract credentials from logged queries.

**Why inconsistent**: r2 found `/start_over` at L431 (which matched dvga-023), but the single CWE-306 finding consumed the match, leaving `/audit` at L426 unmatched. r1/r3 reported nothing for HTTP routes at all.

**Acceptable CWEs**: CWE-306, CWE-862, CWE-287, CWE-284, CWE-425

---

### dvga-025 — User Enumeration via Error Messages (1/3) — MEDIUM

**File**: `core/security.py:48-55`

```python
def check_creds(username, password, real_password):
  if username != 'admin':
    return (False, 'Username is invalid')

  if password == real_password:
    return (True, 'Password Accepted.')

  return (False, 'Password Incorrect')
```

**What it is**: The `check_creds()` function returns different error messages for invalid username (`'Username is invalid'`) versus incorrect password (`'Password Incorrect'`).

**Why it's a vulnerability**: An attacker can determine whether a username exists by observing the error response difference. Sending `username: "admin"` with a wrong password returns "Password Incorrect" (confirming the username exists), while `username: "bob"` returns "Username is invalid" (confirming it doesn't). This enables targeted brute-force attacks.

**Why inconsistent**: Only r3 found it. r1/r2 reported CWE-16 at L37 and CWE-78 at L41 (nearby on security.py) but never analyzed the `check_creds` function.

**Acceptable CWEs**: CWE-209, CWE-200, CWE-203, CWE-204

---

### dvga-027 — GraphiQL Cookie Bypass (1/3) — MEDIUM

**File**: `core/middleware.py:116-126`

```python
class IGQLProtectionMiddleware(object):
  @run_only_once
  def resolve(self, next, root, info, **kwargs):
    if helpers.is_level_hard():
      raise werkzeug.exceptions.SecurityError('GraphiQL is disabled')

    cookie = request.cookies.get('env')
    if cookie and cookie == 'graphiql:enable':
      return next(root, info, **kwargs)

    raise werkzeug.exceptions.SecurityError('GraphiQL Access Rejected')
```

**What it is**: The `IGQLProtectionMiddleware` controls access to the GraphiQL interactive IDE. In easy mode, it checks if the client's `env` cookie equals `'graphiql:enable'`. Access is granted solely based on this client-controlled cookie value.

**Why it's a vulnerability**: Cookies are set by the client. Any attacker can set `Cookie: env=graphiql:enable` in their request headers and gain access to GraphiQL, which provides an interactive interface to explore the schema and execute any query/mutation. The "protection" relies entirely on a value the attacker controls.

**Why inconsistent**: Only r3 found it (as CWE-807). r1/r2 reported nothing in this area of middleware.py. The scanner doesn't consistently analyze cookie-based access control patterns.

**Acceptable CWEs**: CWE-807, CWE-284, CWE-863, CWE-302, CWE-565

---

### dvga-028 — Broken Command Allow-List (2/3) — MEDIUM

**File**: `core/security.py:33-39`

```python
def allowed_cmds(cmd):
  if helpers.is_level_easy():
    return True
  elif helpers.is_level_hard():
    if cmd.startswith(('echo', 'ps' 'whoami', 'tail')):
      return True
  return False
```

**What it is**: The tuple `('echo', 'ps' 'whoami', 'tail')` is missing a comma between `'ps'` and `'whoami'`. Python's implicit string concatenation produces `('echo', 'pswhoami', 'tail')` — meaning `'ps'` and `'whoami'` are not individually in the allow-list.

**Why it's a vulnerability**: In hard mode, the allow-list is supposed to restrict commands to `echo`, `ps`, `whoami`, and `tail`. But due to the missing comma, the actual allow-list is `echo`, `pswhoami`, and `tail`. Neither `ps` nor `whoami` alone passes the `startswith` check. The security control is silently broken.

**Why inconsistent**: r1/r2 found it as CWE-16 (configuration). r3 reported CWE-78 at L41 (`strip_dangerous_characters`) instead — nearby but wrong function, wrong CWE.

**Acceptable CWEs**: CWE-16, CWE-693, CWE-183
