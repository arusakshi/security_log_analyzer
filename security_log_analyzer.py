#!/usr/bin/env python3
"""
Security Log Analyzer

Analyzes authentication-style logs and reports failed logins,
successful logins, suspicious IP activity, and repeated failures.

Use only with logs you are authorized to analyze.
"""

import argparse
import re
from collections import Counter

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FAILED_PATTERN = re.compile(r"failed\s+(?:password|login|authentication)", re.IGNORECASE)
SUCCESS_PATTERN = re.compile(r"(?:accepted|successful)\s+(?:password|login|authentication)", re.IGNORECASE)
USER_PATTERN = re.compile(r"(?:for\s+(?:invalid\s+user\s+)?|user[=:]\s*)([A-Za-z0-9_.-]+)", re.IGNORECASE)


def extract_ip(line):
    match = IP_PATTERN.search(line)
    return match.group(0) if match else None


def extract_user(line):
    match = USER_PATTERN.search(line)
    return match.group(1) if match else "unknown"


def analyze_log(path, threshold=3):
    failed_ips = Counter()
    successful_ips = Counter()
    failed_users = Counter()
    total_lines = 0
    failed_events = 0
    successful_events = 0

    with open(path, "r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            total_lines += 1
            ip = extract_ip(line)
            user = extract_user(line)

            if FAILED_PATTERN.search(line):
                failed_events += 1
                if ip:
                    failed_ips[ip] += 1
                failed_users[user] += 1

            if SUCCESS_PATTERN.search(line):
                successful_events += 1
                if ip:
                    successful_ips[ip] += 1

    suspicious_ips = {
        ip: count for ip, count in failed_ips.items() if count >= threshold
    }

    return {
        "total_lines": total_lines,
        "failed_events": failed_events,
        "successful_events": successful_events,
        "failed_ips": failed_ips,
        "successful_ips": successful_ips,
        "failed_users": failed_users,
        "suspicious_ips": suspicious_ips,
    }


def print_report(report, threshold):
    print("\nSecurity Log Analysis Report")
    print("=" * 30)
    print(f"Lines analyzed:       {report['total_lines']}")
    print(f"Failed logins:        {report['failed_events']}")
    print(f"Successful logins:    {report['successful_events']}")

    print("\nFailed attempts by IP:")
    if report["failed_ips"]:
        for ip, count in report["failed_ips"].most_common():
            print(f"  {ip}: {count}")
    else:
        print("  None")

    print("\nSuccessful logins by IP:")
    if report["successful_ips"]:
        for ip, count in report["successful_ips"].most_common():
            print(f"  {ip}: {count}")
    else:
        print("  None")

    print("\nFailed attempts by user:")
    if report["failed_users"]:
        for user, count in report["failed_users"].most_common():
            print(f"  {user}: {count}")
    else:
        print("  None")

    print(f"\nSuspicious IPs ({threshold}+ failed attempts):")
    if report["suspicious_ips"]:
        for ip, count in sorted(report["suspicious_ips"].items(), key=lambda x: -x[1]):
            print(f"  ⚠ {ip}: {count} failed attempts")
    else:
        print("  None detected")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious activity."
    )
    parser.add_argument("log_file", help="Path to the log file")
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Failed attempts required to flag an IP (default: 3)",
    )
    args = parser.parse_args()

    if args.threshold < 1:
        raise SystemExit("Threshold must be at least 1.")

    try:
        report = analyze_log(args.log_file, args.threshold)
    except FileNotFoundError:
        raise SystemExit(f"Log file not found: {args.log_file}")

    print_report(report, args.threshold)


if __name__ == "__main__":
    main()
