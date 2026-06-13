import csv
import re
from collections import Counter

LOG_FILE = "server_access.log"
FAILED_THRESHOLD = 5
REPORT_FILE = "suspicious_ip.csv"


def analyze_logs():
    #Regex to extract IP address from failed attempt
    failed_pattern = re.compile(r"Failed login attempt.*from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    failed_ip_counter = Counter()

    print(f"[*] Reading the log file: {LOG_FILE}...")

    with open(LOG_FILE, "r") as file:
        for line in file:
            match = failed_pattern.search(line)
            if match:
                ip_address = match.group(1)
                failed_ip_counter[ip_address] += 1

    flagged_alerts = {ip: count for ip, count in failed_ip_counter.items() if count >= FAILED_THRESHOLD}

    if flagged_alerts:
        print(f"[!] Found {len(flagged_alerts)} suspicious IP(s) matching threshold.")
        with open(REPORT_FILE, "w", newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Flagged IP address", "Failed attempts count"])
            for ip, count in flagged_alerts.items():
                writer.writerow([ip, count])
        print(f"[+] Alert report generated successfully: {REPORT_FILE}")
    else:
        print(f"[+] Scan completed. No suspicious brute-force behaviour was found.")

if __name__ == "__main__":
    analyze_logs()