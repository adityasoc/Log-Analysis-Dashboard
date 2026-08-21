# Log Analysis Dashboard

A Python and Flask-based cybersecurity dashboard for analyzing security logs, detecting suspicious activities, identifying risky IP addresses, and generating PDF security reports.

---

## Overview

Log Analysis Dashboard is a defensive cybersecurity project designed to simulate a basic Security Operations Center (SOC) log-analysis workflow.

The application allows users to analyze log files and identify potentially suspicious activities such as:

- Failed login attempts
- Brute-force attacks
- Suspicious requests
- Unauthorized access attempts
- High-risk IP addresses
- Critical security events

The analyzed information is displayed through a web-based dashboard and can also be exported as a PDF security report.

---

## Features

- Log file upload and analysis
- Automatic log parsing
- Security event detection
- Failed login analysis
- Brute-force attack detection
- Suspicious activity detection
- Unauthorized access detection
- IP address risk scoring
- Security severity classification
- Log-level statistics
- Security findings summary
- Flask-based web dashboard
- PDF security report generation
- Sample log file for testing
- Defensive cybersecurity analysis

---

## Security Analysis

The application analyzes security-related events and assigns severity levels.

| Severity | Description |
|----------|-------------|
| Critical | Highly suspicious or potentially dangerous activity |
| High | Serious security-related activity requiring investigation |
| Medium | Suspicious activity that should be reviewed |
| Low | Lower-risk activity |

The project also calculates an IP risk score based on detected security events.

### Example

```text
IP Address: 192.168.1.20
Risk: Critical
Score: 20
Events: 3