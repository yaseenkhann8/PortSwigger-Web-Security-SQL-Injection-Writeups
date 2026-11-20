# Lab 01: SQL Injection Vulnerability in WHERE Clause Allowing Retrieval of Hidden Data

- **Platform:** PortSwigger Web Security Academy
- **Category:** SQL Injection (SQLi)
- **Difficulty:** Apprentice
- **OWASP Top 10:** A03:2021 – Injection
- **CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **Author:** Yaseen Khan
- **Date:** November 20, 2026

---

## 1. Objective
Exploit an in-band SQL injection vulnerability in the product category filter to bypass the backend `released = 1` visibility restriction and display all unreleased (hidden) products in the storefront.

---

## 2. Reconnaissance & Vulnerability Discovery
- **Target Endpoint:** `GET /filter?category=Gifts`
- **Vulnerable Parameter:** `category` (URL Query Parameter)

### Initial Probe
1. Navigated to the **Gifts** product category on the storefront and intercepted the request in **Burp Proxy**.
2. Sent the request to **Burp Repeater** (`Ctrl + R`) and appended a single quote (`'`) to the `category` parameter (`GET /filter?category=Gifts'`) to test how the application handles SQL syntax characters.
3. The server returned an **HTTP 500 Internal Server Error**, confirming that user-supplied input is concatenated directly into the backend SQL query without sanitization or parameterization.

**Inferred Backend SQL Query:**
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
