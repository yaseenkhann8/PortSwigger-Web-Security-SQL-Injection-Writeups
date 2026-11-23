# PortSwigger Web Security Academy — SQL Injection (SQLi) Write-Ups

Structured VAPT write-ups, Burp Suite workflows, exploitation proofs, and defensive remediation guides for all 18 PortSwigger Web Security Academy SQL Injection labs.

**Author:** [Yaseen Khan](https://www.linkedin.com/in/yaseenkhann8) | **Focus:** Web Application Penetration Testing & VAPT

## SQL Injection (SQLi) Progress (`8 / 18`)

| # | Lab Title | Difficulty | Technique / Payload | Write-Up |
| :--- | :--- | :--- | :--- | :--- |
| 01 | SQL injection vulnerability in WHERE clause allowing retrieval of hidden data | Apprentice | `' OR 1=1--` | [View Write-Up](SQL-Injection/01-sqli-where-clause-hidden-data.md) |
| 02 | SQL injection vulnerability allowing login bypass | Apprentice | `administrator'--` | [View Write-Up](SQL-Injection/02-sqli-login-bypass.md) |
| 03 | SQL injection attack, querying the database type and version on Oracle | Practitioner | `' UNION SELECT banner, NULL from v$version--` | [View Write-Up](SQL-Injection/03-sqli-oracle-database-version.md) |
| 04 | SQL injection attack, querying the database type and version on MySQL and Microsoft | Practitioner | `' UNION select @@version, NULL#` | [View Write-Up](SQL-Injection/04-sqli-mysql-microsoft-version.md) |
| 05 | SQL injection attack, listing the database contents on non-Oracle databases | Practitioner | `' UNION SELECT username_qolwnm, password_kzgxme from users_ypbwpv--` | [View Write-Up](SQL-Injection/05-sqli-listing-database-contents-non-oracle.md) |
| 06 | SQL injection attack, listing the database contents on Oracle | Practitioner | `' UNION select USERNAME_ELCFDQ, PASSWORD_TVHDLX from USERS_CDHBZF--` | [View Write-Up](SQL-Injection/06-sqli-listing-database-contents-oracle.md) |
| 07 | SQL injection UNION attack, determining the number of columns returned by the query | Practitioner | `' UNION select NULL, NULL, NULL--` | [View Write-Up](SQL-Injection/07-sqli-union-determining-columns.md) |
| 08 | SQL injection UNION attack, finding a column containing text | Practitioner | `' UNION select NULL, 'J5Yk2B', NULL--` | [View Write-Up](SQL-Injection/08-sqli-union-finding-column-with-text.md) |
