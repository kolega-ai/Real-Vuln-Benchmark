# Internal Scorecard — vampi

**Commit:** `1713b54b601a`  
**Generated:** 2026-02-20T10:59:12.966633+00:00  
**Ground Truth:** 10 vulnerabilities, 4 false-positive traps  
**Application:** [3bac7567-84eb-4a40-9c7d-f1f96d50bf23](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23)

---

## our-scanner — Youden's J: -25.0%

| TP | FP | FN | TN | Precision | Recall | F1 |
|---:|---:|---:|---:|----------:|-------:|---:|
| 5 | 12 | 5 | 4 | 29.4% | 50.0% | 0.370 |

### True Positives (5)

Scanner correctly identified these real vulnerabilities.

- ✅ [CWE-639 on api_views/books.py:L44](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/e94256c0-ca2e-474e-b56f-596822835123) → **vampi-003** — broken_access_control: Broken Object Level Authorization (BOLA). When vuln=1, get_by_title queries the book by title only (Book.query.filter_by(book_title=str(book_title)).first()) without verifying the authenticated user is the owner. Any authenticated user can read any book's secret_content by sending GET /books/v1/{book_title}.
- ✅ [CWE-200 on api_views/users.py:L18](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/60f45baf-9d0e-4619-a0e4-94f567b4e5e3) → **vampi-005** — sensitive_data_exposure: Excessive data exposure through unauthenticated debug endpoint. GET /users/v1/_debug returns all user details including plaintext passwords, email addresses, and admin status for every user via User.get_all_users_debug(). No authentication or authorization is required.
- ✅ [CWE-915 on api_views/users.py:L57](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/1ac00ae6-be0d-4e5d-8407-b01957b26c53) → **vampi-004** — mass_assignment: Mass assignment vulnerability allowing privilege escalation. When vuln=1, the register_user function checks if 'admin' is present in the user-supplied JSON body and uses it to set the admin flag on the new user. An attacker can register as admin by including '"admin": true' in the POST /users/v1/register request body.
- ✅ [CWE-321 on config.py:L13](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/386c1645-002e-4053-b1ac-04e7421637c5) → **vampi-008** — hardcoded_credentials: JWT authentication bypass via weak/hardcoded signing key. The SECRET_KEY used for signing and verifying JWT tokens is hardcoded as the string 'random' (config.py line 13). An attacker who knows this trivially guessable key can forge valid JWT tokens for any user, including admin accounts, achieving complete authentication bypass.
- ✅ [CWE-89 on models/user_model.py:L67](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/2e5d81ff-607c-46e1-b102-7c103254c2b6) → **vampi-001** — sql_injection: SQL injection via f-string interpolation of unsanitized username path parameter into raw SQL query: user_query = f"SELECT * FROM users WHERE username = '{username}'" followed by db.session.execute(text(user_query)). Reachable from GET /users/v1/{username} without authentication.

### False Positives (12)

Scanner flagged these but they are not real vulnerabilities. Review and dismiss.

- ❌ [CWE-1333 on api_views/users.py:L120](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/02de1e9f-ed5f-45fb-bf0e-7f6188bfcdb5) — no GT entry. Scanner says: ReDoS Vulnerability in Email Validation Regex
- ❌ [CWE-204 on api_views/users.py:L89](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/8af79e48-eb70-4f25-8329-24de184c0734) — no GT entry. Scanner says: User and Password Enumeration
- ❌ [CWE-256 on api_views/users.py:L63](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/1bcecfdc-b094-45ac-9f97-37a1b2422255) — no GT entry. Scanner says: Plaintext Password Storage
- ❌ [CWE-285 on api_views/users.py:L148](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/07bdd9cd-1e09-4588-a44c-44bcde497d81) — no GT entry. Scanner says: Unauthorized Password Update (Broken Function Level Authorization)
- ❌ [CWE-307 on api_views/users.py:L79](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/cde4fd19-9005-4d7a-b802-51286b32a75b) — no GT entry. Scanner says: Missing Rate Limiting on Authentication Endpoints
- ❌ [CWE-94 on app.py:L13](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/a62d81bc-2f34-4b62-92e6-f99352073036) — no GT entry. Scanner says: Application Running in Debug Mode
- ❌ [CWE-256 on models/user_model.py:L82](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/dc83e125-e6fd-473d-805f-4a17c4c05c13) — no GT entry. Scanner says: Plaintext Password Storage
- ❌ [CWE-269 on models/user_model.py:L82](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/75601f43-1655-49fb-bc74-c56f4090023f) — no GT entry. Scanner says: Mass Assignment / Privilege Escalation via admin Parameter
- ❌ [CWE-312 on models/user_model.py:L60](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/248efced-330c-4683-8683-6c232a31848e) — no GT entry. Scanner says: Sensitive Data Exposure via Debug Endpoint (Plaintext Passwords in API Response)
- ❌ [CWE-321 on models/user_model.py:L36](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/5f5c3163-185f-4aeb-a7c6-7efcb6b2d5cb) — no GT entry. Scanner says: JWT Secret Key Potentially Weak or Hardcoded
- ❌ [CWE-347 on models/user_model.py](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/ed94f621-b1cc-4c54-bb14-f2f212e6e8f4) — no GT entry. Scanner says: JWT Token Decoded Without Algorithm Verification
- ❌ [CWE-798 on models/user_model.py:L97](https://comply.kolegatestapps.com/applications/3bac7567-84eb-4a40-9c7d-f1f96d50bf23/findings/703b94bd-b69a-4aaa-884d-f47a4fb35da8) — no GT entry. Scanner says: Hardcoded Credentials in Database Initialization

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
