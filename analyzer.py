import sys
import re
from collections import Counter

FAILED_PATTERNS = [
    r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    r"Failed password for invalid user .* from (?P<ip>\d+\.\d+\.\d+\.\d+)",
]

def extract_failed_ips(lines):
    ips = []
    for line in lines:
        for pat in FAILED_PATTERNS:
            m = re.search(pat, line)
            if m:
                ips.append(m.group("ip"))
                break
    return ips

def main():
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <logfile>")
        sys.exit(1)

    logfile = sys.argv[1]
    try:
        with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: file not found: {logfile}")
        sys.exit(1)

    failed_ips = extract_failed_ips(lines)
    total_failed = len(failed_ips)
    counts = Counter(failed_ips)

    print("\n=== Python Security Log Analyzer ===")
    print(f"Log file: {logfile}")
    print(f"Total failed login attempts: {total_failed}\n")

    if total_failed == 0:
        print("No failed login attempts detected.")
        return

    print("Top offending IPs:")
    for ip, n in counts.most_common(10):
        flag = " <== suspicious" if n >= 10 else ""
        print(f"- {ip}: {n}{flag}")

if __name__ == "__main__":
    main()
