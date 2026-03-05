# Internal Scorecard — vampi

**Commit:** `1713b54b601a`  
**Generated:** 2026-02-20T10:59:12.966633+00:00  
**Ground Truth:** 10 vulnerabilities, 4 false-positive traps  
**Application:** [7e30158f-7e19-4caa-bd1c-c3ece05307e1](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1)

---

## our-scanner — Youden's J: -21.4%

| TP | FP | FN | TN | Precision | Recall | F1 |
|---:|---:|---:|---:|----------:|-------:|---:|
| 5 | 10 | 5 | 4 | 33.3% | 50.0% | 0.400 |

### True Positives (5)

Scanner correctly identified these real vulnerabilities.

- ✅ [CWE-639 on api_views/books.py:L44](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/35880a4f-f40f-42d2-a67f-dade80493b6f) → **vampi-003** — broken_access_control: Broken Object Level Authorization (BOLA). When vuln=1, get_by_title queries the book by title only (Book.query.filter_by(book_title=str(book_title)).first()) without verifying the authenticated user is the owner. Any authenticated user can read any book's secret_content by sending GET /books/v1/{book_title}.
- ✅ [CWE-200 on api_views/users.py:L18](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/5dc053b7-8dae-43a8-9cc1-2c886676d01b) → **vampi-005** — sensitive_data_exposure: Excessive data exposure through unauthenticated debug endpoint. GET /users/v1/_debug returns all user details including plaintext passwords, email addresses, and admin status for every user via User.get_all_users_debug(). No authentication or authorization is required.
- ✅ [CWE-915 on api_views/users.py:L60](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/2c8a7cdc-4176-41a1-9979-f6cba3cdfee7) → **vampi-004** — mass_assignment: Mass assignment vulnerability allowing privilege escalation. When vuln=1, the register_user function checks if 'admin' is present in the user-supplied JSON body and uses it to set the admin flag on the new user. An attacker can register as admin by including '"admin": true' in the POST /users/v1/register request body.
- ✅ [CWE-321 on config.py:L13](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/3e715d3a-e214-4e60-a92f-538bbc258faa) → **vampi-008** — hardcoded_credentials: JWT authentication bypass via weak/hardcoded signing key. The SECRET_KEY used for signing and verifying JWT tokens is hardcoded as the string 'random' (config.py line 13). An attacker who knows this trivially guessable key can forge valid JWT tokens for any user, including admin accounts, achieving complete authentication bypass.
- ✅ [CWE-89 on models/user_model.py:L67](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/e02c2148-ce51-49e4-90f1-50e37f18ee3e) → **vampi-001** — sql_injection: SQL injection via f-string interpolation of unsanitized username path parameter into raw SQL query: user_query = f"SELECT * FROM users WHERE username = '{username}'" followed by db.session.execute(text(user_query)). Reachable from GET /users/v1/{username} without authentication.

### False Positives (10)

Scanner flagged these but they are not real vulnerabilities. Review and dismiss.

- ❌ [CWE-1333 on api_views/users.py:L110](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/75595923-00cc-47e8-84ae-291e4e5bceeb) — no GT entry. Scanner says: ReDoS - Regular Expression Denial of Service
- ❌ [CWE-204 on api_views/users.py:L78](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/17da267f-dca8-4f48-8460-9705e7cf11fe) — no GT entry. Scanner says: User and Password Enumeration
- ❌ [CWE-256 on api_views/users.py:L71](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/1d17df74-724c-4992-b98a-b11d36827492) — no GT entry. Scanner says: Plaintext Password Storage
- ❌ [CWE-306 on api_views/users.py:L14](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/e59cc468-cd30-4164-a26b-683b3c6981e4) — no GT entry. Scanner says: Unauthenticated Access to All Users Listing
- ❌ [CWE-307 on api_views/users.py:L56](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/ae5f0d73-4be4-49aa-a16b-3d685b0d7d56) — no GT entry. Scanner says: Missing Rate Limiting on Authentication Endpoints
- ❌ [CWE-639 on api_views/users.py:L131](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/4a12f263-e575-479d-b186-e56a14a239e6) — no GT entry. Scanner says: Broken Function Level Authorization - Unauthorized Password Update (IDOR)
- ❌ [CWE-94 on app.py:L13](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/0cd62dec-9950-4cfd-b1e3-17ab55c0060e) — no GT entry. Scanner says: Debug Mode Enabled in Production
- ❌ [CWE-312 on models/user_model.py:L60](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/a79424d3-2b6d-4c60-9ef9-ed1aa3b09f88) — no GT entry. Scanner says: Sensitive Data Exposure via json_debug() Method
- ❌ [CWE-328 on models/user_model.py](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/1829c76b-ebd5-4e8c-8b23-ce84971bd222) — no GT entry. Scanner says: Plaintext Password Storage
- ❌ [CWE-798 on models/user_model.py:L95](https://comply.kolegatestapps.com/applications/7e30158f-7e19-4caa-bd1c-c3ece05307e1/findings/a13b28e7-af07-43a9-875d-1e40aaf8f994) — no GT entry. Scanner says: Hardcoded Credentials in Database Initialization

### False Negatives (5)

Scanner missed these real vulnerabilities.

- ⚠️ **vampi-002** `CWE-639` on `api_views/users.py`:L187 (high) — Unauthorized password change (IDOR). When vuln=1, the update_password function uses the username from the URL path parameter to look up the user whose password to change, instead of using the authenticated user from the JWT token (resp['sub']). Any authenticated user can change any other user's password by sending PUT /users/v1/{victim_username}/password.
- ⚠️ **vampi-006** `CWE-204` on `api_views/users.py`:L101 (low) — User and password enumeration via differential error messages. When vuln=1, login_user returns 'Password is not correct for the given username.' for valid usernames with wrong passwords (line 103) and 'Username does not exist' for invalid usernames (line 106). This allows attackers to enumerate valid usernames.
- ⚠️ **vampi-007** `CWE-1333` on `api_views/users.py`:L144 (medium) — Regular Expression Denial of Service (ReDoS). When vuln=1, update_email uses a complex regex with nested quantifiers: r"^([0-9a-zA-Z]([-.\.\w]*[0-9a-zA-Z])*@{1}([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$". The nested groups ([-.\.\w]*[0-9a-zA-Z])* cause catastrophic backtracking with crafted input, consuming excessive CPU.
- ⚠️ **vampi-009** `CWE-489` on `app.py`:L17 (medium) — Flask application runs with debug=True (vuln_app.run(host='0.0.0.0', port=5000, debug=True)). This enables the Werkzeug interactive debugger which exposes detailed stack traces with local variable values on errors and may allow arbitrary code execution if the debugger PIN is compromised.
- ⚠️ **vampi-010** `CWE-770` on `config.py`:L27 (medium) — Lack of resources and rate limiting. All API endpoints are registered (vuln_app.add_api('openapi3.yml')) without any rate-limiting middleware or throttling mechanism. This allows unlimited requests to authentication endpoints (login, register) enabling brute-force attacks, and unlimited requests to all other endpoints enabling denial of service. No Flask-Limiter or equivalent is used.

### True Negatives (4)

Scanner correctly ignored these false-positive traps.

- ⚪ **vampi-fp-001** `CWE-89` on `api_views/users.py`:L55 — Safe parameterized ORM query. User.query.filter_by(username=request_data.get('username')).first() uses SQLAlchemy ORM's filter_by which automatically parameterizes the query, preventing SQL injection. The username from user input is safely bound as a parameter.
- ⚪ **vampi-fp-002** `CWE-89` on `api_views/users.py`:L92 — Safe parameterized ORM query. User.query.filter_by(username=request_data.get('username')).first() uses SQLAlchemy ORM's filter_by which automatically parameterizes the query, preventing SQL injection. User-supplied username from the login JSON body is safely bound.
- ⚪ **vampi-fp-003** `CWE-639` on `api_views/books.py`:L62 — Safe book retrieval with proper authorization (non-vulnerable path). When vuln=0, get_by_title first resolves the authenticated user from the JWT token, then queries Book.query.filter_by(user=user, book_title=str(book_title)).first(), ensuring only the book owner can access the book's secret content.
- ⚪ **vampi-fp-004** `CWE-1333` on `api_views/users.py`:L162 — Safe email regex (non-vulnerable path). When vuln=0, update_email uses the simpler regex '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$' which does not contain nested quantifiers and is not vulnerable to catastrophic backtracking/ReDoS.
