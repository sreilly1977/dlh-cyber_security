# Identify CWEs

If we take the below code snippet, we can dissect and, using CWE classifications, identify weaknesses, communicate them in a common understood terminology as well as propose steps for remediation.

### Python Code Snippet
```python
import sqlite3 
def get_user(username): 
    conn = sqlite3.connect('users.db') 
    cursor = conn.cursor() 
    query = "SELECT * FROM users WHERE username='" + username + "';" 
    cursor.execute(query) 
    user = cursor.fetchone() 
    conn.close() 
    return user
```

## CWE Identification & Analysis

### 1. CWE Identification & Classification

#### Primary Weakness
*   **CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')**
    *   **Class:** Input Validation
    *   **Weakness Level:** Severe
    *   **Likelihood of Exploit:** Very High

#### Secondary/Related Weaknesses
*   **CWE-470:** Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
    *   *Note:* Indirectly related if the input influences logic flow beyond just the query, though here it's strictly data manipulation.
*   **CWE-311:** Missing Encryption of Sensitive Data
    *   *Note:* If the `users.db` isn't encrypted at rest, the impact is higher, though not the direct coding error in the snippet.
*   **CWE-465:** Database Error Messages Leaked
    *   *Note:* While not explicitly shown, `sqlite3` often leaks verbose stack traces on syntax errors caused by injection payloads, aiding attackers.

---

### 2. Security Implications & Attack Scenarios

The core issue is that the code constructs an SQL query by concatenating user-supplied input directly into the query string. This breaks the boundary between code (the query structure) and data (the username).

#### Attack Vectors

1.  **Authentication Bypass**
    *   **Payload:** `' OR '1'='1`
    *   **Resulting Query:** `SELECT * FROM users WHERE username='' OR '1'='1';`
    *   **Outcome:** The query returns the first row in the table (often an admin), effectively logging the attacker in as that user without a password.

2.  **Data Extraction (Blind/Union-Based)**
    *   **Payload:** `' UNION SELECT name, sql FROM sqlite_master;--`
    *   **Outcome:** The application might leak the database schema, table names, or even sensitive columns like passwords or hashes.

3.  **Data Manipulation (Write/Delete)**
    *   **Payload:** `; DROP TABLE users;--`
    *   **Outcome:** Complete destruction of the dataset. While SQLite doesn't always support multiple statements in one execution by default (depending on the driver flags), a skilled attacker can often bypass this or use it in conjunction with other queries if the application executes multiple lines.

4.  **Denial of Service (DoS)**
    *   **Mechanism:** Injecting malformed syntax or extremely long strings.
    *   **Outcome:** Can crash the application process or lock the database file, causing service unavailability.

---

### 3. Recommended Mitigations

Never trust user input. The solution is to separate the SQL command from the data using **Parameterized Queries** (also known as Prepared Statements).

#### Vulnerable Code
```python
query = "SELECT * FROM users WHERE username='" + username + "';"
cursor.execute(query)

#### Secure Code (Parameterized)

The `?` placeholder tells SQLite to treat the argument strictly as data, automatically handling escaping and quoting. This ensures that user input can never be interpreted as executable SQL code.

```python
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Use parameterized query
    # Note the ? placeholder and passing parameters as a tuple
    query = "SELECT * FROM users WHERE username=?"
    
    try:
        cursor.execute(query, (username,)) 
        user = cursor.fetchone()
    except sqlite3.Error as e:
        # Log error securely (don't expose raw DB errors to user)
        print(f"Database error: {e}")
        return None
    finally:
        conn.close()
        
    return user
```

### Additional Controls:

1. **Input Validation**: Enforce strict allow-lists for usernames (e.g., alphanumeric only, length limits) before reaching the database layer.
2. **Principle of Least Privilege**: Ensure the database user account used by the application has minimal permissions (e.g., `SELECT` only, no `DROP` or `INSERT`).
3. **ORM Usage**: Consider using an ORM (like SQLAlchemy or Django ORM) which handles parameterization automatically by design.
4. **Error Handling**: Catch database exceptions and return generic error messages to prevent information leakage about the database structure.

### Conclusion

The code snippet represents a classic and severe SQL injection vulnerability (**CWE-89**) that undermines the fundamental separation between code and data. What makes this particularly dangerous is how easily exploitable it is—simple payloads like `' OR '1'='1` can completely bypass authentication without any sophisticated tooling. While the string concatenation pattern may have seemed innocent at first glance, its implications cascade into authentication bypass, data exfiltration, manipulation, and even total database destruction.

Parameterized queries are **non-negotiable** here—they're not a "best practice" but a hard requirement for any database-facing application. Beyond that core fix, layering controls like input validation, least-privilege database accounts, and proper error handling creates defense-in-depth that can catch what slips through.
