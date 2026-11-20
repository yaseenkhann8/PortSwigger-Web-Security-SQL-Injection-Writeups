# Lab 02: SQL Injection Vulnerability Allowing Login Bypass

- **Platform:** PortSwigger Web Security Academy
- **Category:** SQL Injection (SQLi)
- **Difficulty:** Apprentice
- **OWASP Top 10:** A03:2021 – Injection
- **CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **Author:** Yaseen Khan
- **Date:** November 21, 2026

---

## 1. Objective
Exploit an in-band SQL injection vulnerability in the authentication endpoint (`/login`) to bypass password verification and log in directly as the `administrator` user.

---

## 2. Reconnaissance & Vulnerability Discovery
- **Target Endpoint:** `POST /login`
- **Vulnerable Parameter:** `username` (HTTP POST Body Parameter)

### Initial Probe
1. Navigated to the **My account** login page (`/login`) and inspected how the authentication form handles SQL syntax characters.
2. Appended a single quote (`'`) to the `username` field (`administrator'`) with an arbitrary password.
3. The application returned an **HTTP 500 Internal Server Error**, confirming that user input in the `username` parameter is concatenated directly into the backend authentication query without parameterization.

**Inferred Backend SQL Query:**
```sql
```

SELECT * FROM users WHERE username = 'administrator' AND password = 'password123'

3. Exploitation & Proof of Concept (PoC)
To authenticate as administrator without knowing the password, the payload must:

Supply the target account name (administrator) followed by a single quote (') to close the string literal early.

Append the SQL double-dash comment sequence (--) so the database engine ignores the entire password check (AND password = '...').

Payload Submitted
Username: administrator'--

Password: anything123 (ignored by the SQL parser)

Modified HTTP Request
HTTP
POST /login HTTP/2
Host: <lab-id>.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

csrf=[REDACTED]&username=administrator'--&password=anything123
Resulting SQL Query Executed on Backend:

SQL
SELECT * FROM users WHERE username = 'administrator'--' AND password = 'anything123'
Proof of Exploitation Screenshots
1. Login Form Submission with administrator'-- Payload:

2. Authenticated Administrator Session & Lab Completion Banner:

4. Impact
An unauthenticated attacker can bypass authentication controls entirely and gain full administrative account takeover (administrator), exposing privileged functionality and user data without credentials.

5. Remediation
Primary Fix (Parameterized Queries): Use prepared statements with bound parameters for all authentication queries so user input is never interpreted as SQL syntax:

Python
# Secure Python Example
cursor.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
Secure Password Verification: Fetch the user record by username using a parameterized query first, then verify the submitted password against a strong cryptographic hash (bcrypt or Argon2) in application code rather than comparing plaintext passwords inside SQL.
