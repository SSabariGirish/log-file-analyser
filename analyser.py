import re
from collections import defaultdict


LOG_FILE = 'sample_access.log'
REPORT_FILE = 'incident_report.txt'
BRUTE_FORCE_THRESHOLD = 5 

SQLI_PATTERN = re.compile(
    r"('|\%27)\s*(OR|AND)\s*(\d+|'\w')=(\d+|'\w')|"  
    r"UNION\s+(ALL\s+)?SELECT|"                      
    r"SLEEP\(\d+\)|WAITFOR\s+DELAY|BENCHMARK\("
    r"|INFORMATION_SCHEMA|"                          
    r"\s*(\-\-|\#|/\*)|"                            
    r"xp_cmdshell",                         
    re.IGNORECASE
)


DIR_TRAVERSAL_PATTERN = re.compile(r"\.\./|\.\.%2F")


WEB_SHELL_PATTERN = re.compile(
    r"c99\.php|shell\.php|r57\.php|cmd=|wget\s+http", 
    re.IGNORECASE
)


SCANNER_PATTERN = re.compile(r"Nmap|sqlmap", re.IGNORECASE)


def analyze_log():

    print(f"Starting analysis of {LOG_FILE}...")
    
    failed_logins = defaultdict(int)
    
    findings = []

    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                
                
                if SQLI_PATTERN.search(line):
                    findings.append(f"[SQL INJECTION]: {line.strip()}")
                
                elif DIR_TRAVERSAL_PATTERN.search(line):
                    findings.append(f"[DIR TRAVERSAL]: {line.strip()}")
                    
                elif WEB_SHELL_PATTERN.search(line):
                    findings.append(f"[WEB SHELL/CMD INJECTION]: {line.strip()}")
                    
                elif SCANNER_PATTERN.search(line):
                    findings.append(f"[SCANNER ACTIVITY]: {line.strip()}")

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

    brute_force_findings = []
    for ip, count in failed_logins.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            brute_force_findings.append(
                f"[BRUTE FORCE]: IP {ip} had {count} failed login attempts."
            )
    
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
        
        print(f"Analysis complete! Report saved to {REPORT_FILE}")

    except IOError as e:
        print(f"Error writing report file: {e}")

if __name__ == "__main__":
    analyze_log()