# 🛡️ Security Log Analyzer

A Python-based cybersecurity tool that analyzes authentication logs to identify failed login attempts, successful logins, repeated failures, and potentially suspicious IP addresses.

## Features

- Parses authentication-style log files
- Counts failed login attempts
- Counts successful logins
- Groups failed attempts by IP address
- Groups failed attempts by username
- Flags IP addresses that exceed a configurable failure threshold
- Provides a clear command-line security report
- Uses only Python standard-library modules

## Requirements

- Python 3.8+
- No external packages required

## Usage

Run the analyzer against the included sample log:

```bash
python security_log_analyzer.py sample_logs/auth.log
```

Set a custom suspicious-activity threshold:

```bash
python security_log_analyzer.py sample_logs/auth.log --threshold 2
```

## Example Output

```text
Security Log Analysis Report
==============================
Lines analyzed:       6
Failed logins:        4
Successful logins:    2

Failed attempts by IP:
  203.0.113.50: 3
  198.51.100.25: 1

Suspicious IPs (3+ failed attempts):
  ⚠ 203.0.113.50: 3 failed attempts
```

## Security Concepts

- Security log analysis
- Authentication monitoring
- Failed-login detection
- IP-based event analysis
- Threshold-based alerting
- Security auditing
- Incident investigation

## Project Structure

```text
security_log_analyzer/
├── security_log_analyzer.py
├── README.md
├── .gitignore
└── sample_logs/
    └── auth.log
```

## Learning Objectives

This project demonstrates how security logs can be processed programmatically to identify authentication events and highlight repeated failures that may require further investigation.

> **Security note:** The analyzer is intended for authorized security monitoring and educational lab environments. The included IP addresses are documentation/test addresses.

## Author

**Sakshi Aru**  
MCA — Cybersecurity & Digital Forensics
