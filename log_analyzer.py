
import re
from collections import Counter

LOG_FILE = "auth.log"
THRESHOLD = 3

def analyze_logs():
    failed_attempts = Counter()
    total_lines = 0

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            for line in file:
                total_lines += 1

                if "Failed login" in line or "Failed password" in line:
                    match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)

                    if match:
                        ip = match.group(1)
                        failed_attempts[ip] += 1

        print("=== Basic Security Log Analyzer ===")
        print(f"Total log entries: {total_lines}")
        print(f"IPs with failed attempts: {len(failed_attempts)}")

        for ip, count in failed_attempts.items():
            print(f"{ip}: {count} failed attempts")

            if count >= THRESHOLD:
                print(f"WARNING: Repeated failed login attempts detected for {ip}")

    except FileNotFoundError:
        print(f"Log file '{LOG_FILE}' not found.")

if __name__ == "__main__":
    analyze_logs()
