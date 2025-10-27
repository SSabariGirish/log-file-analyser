import re
from collections import defaultdict

# --- Configuration ---
LOG_FILE = 'sample_access.log'
REPORT_FILE = 'incident_report.txt'
BRUTE_FORCE_THRESHOLD = 5  # Num of failed logins to trigger an alert

# --- 1. Define Regex Patterns for Attacks ---
# We compile these patterns so Python can run them more efficiently.
# re.IGNORECASE makes the search case-insensitive.

# SQL Injection: Looks for common keywords, tautologies, comments, and blind SQLi functions
SQLI_PATTERN = re.compile(
    r"('|\%27)\s*(OR|AND)\s*(\d+|'\w')=(\d+|'\w')|"  # Catches ' OR 1=1, ' OR 'a'='a'
    r"UNION\s+(ALL\s+)?SELECT|"                      # Catches UNION SELECT and UNION ALL SELECT
    r"SLEEP\(\d+\)|WAITFOR\s+DELAY|BENCHMARK\("
    r"|INFORMATION_SCHEMA|"                          # Catches schema enumeration
    r"\s*(\-\-|\#|/\*)|"                             # Catches comment-out attacks
    r"xp_cmdshell",                                  # Catches command execution
    re.IGNORECASE
)

# Directory Traversal: Looks for '../' or its URL-encoded '..%2F'
DIR_TRAVERSAL_PATTERN = re.compile(r"\.\./|\.\.%2F")

# Web Shell & Command Injection: Looks for common shell names or 'cmd=' / 'wget'
WEB_SHELL_PATTERN = re.compile(
    r"c99\.php|shell\.php|r57\.php|cmd=|wget\s+http", 
    re.IGNORECASE
)

# Scanner Tools: Looks for common scanner user agents
SCANNER_PATTERN = re.compile(r"Nmap|sqlmap", re.IGNORECASE)


def analyze_log():
    """
    Reads the log file, analyzes it for threats, 
    and writes a report.
    """
    print(f"Starting analysis of {LOG_FILE}...")
    
    # This will store IPs and their failed login counts
    # defaultdict(int) means "if a key doesn't exist, create it with a value of 0"
    failed_logins = defaultdict(int)
    
    # We'll write all findings to this list first
    findings = []

    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                
                # --- 2. Line-by-Line Attack Detection ---
                # We use 'elif' so a single line is only flagged for one thing
                if SQLI_PATTERN.search(line):
                    findings.append(f"[SQL INJECTION]: {line.strip()}")
                
                elif DIR_TRAVERSAL_PATTERN.search(line):
                    findings.append(f"[DIR TRAVERSAL]: {line.strip()}")
                    
                elif WEB_SHELL_PATTERN.search(line):
                    findings.append(f"[WEB SHELL/CMD INJECTION]: {line.strip()}")
                    
                elif SCANNER_PATTERN.search(line):
                    findings.append(f"[SCANNER ACTIVITY]: {line.strip()}")

                # --- 3. Brute Force Data Collection ---
                # This regex looks for: 
                # 1. An IP address (group 1)
                # 2. 'POST /login.php'
                # 3. A '401' status code
                brute_force_match = re.search(
                    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*POST /login\.php.* 401', 
                    line
                )
                
                if brute_force_match:
                    ip = brute_force_match.group(1)
                    failed_logins[ip] += 1
                        
    except FileNotFoundError:
        print(f"Error: {LOG_FILE} not found. Make sure it's in the same folder.")
        return

    # --- 4. Process Brute Force Findings ---
    # Now that we've read the whole file, let's check our failed login counts
    brute_force_findings = []
    for ip, count in failed_logins.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            brute_force_findings.append(
                f"[BRUTE FORCE]: IP {ip} had {count} failed login attempts."
            )
    
    # --- 5. Write the Report ---
    try:
        with open(REPORT_FILE, 'w') as report:
            if not findings and not brute_force_findings:
                report.write("--- ANALYSIS COMPLETE --- \n\n")
                report.write("No suspicious activity detected.\n")
                print(f"Analysis complete. No suspicious activity found. Report saved to {REPORT_FILE}")
                return

            report.write("--- INCIDENT REPORT --- \n")
            report.write(f"Analysis of: {LOG_FILE}\n\n")
            
            if brute_force_findings:
                report.write("=== BRUTE FORCE ATTEMPTS ===\n")
                for finding in brute_force_findings:
                    report.write(finding + "\n")
                report.write("\n")

            if findings:
                report.write("=== OTHER DETECTED THREATS ===\n")
                for finding in findings:
                    report.write(finding + "\n")
                report.write("\n")
            
            report.write("--- END OF REPORT --- \n")
        
        print(f"✅ Analysis complete! Report saved to {REPORT_FILE}")

    except IOError as e:
        print(f"Error writing report file: {e}")


# --- Run the function when the script is executed ---
if __name__ == "__main__":
    analyze_log()