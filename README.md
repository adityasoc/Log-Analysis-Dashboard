# 🛡️ Log Analysis Dashboard

A Python + Flask based defensive cybersecurity dashboard for analyzing security logs, detecting suspicious activities, mapping events to MITRE ATT&CK techniques, calculating IP risk, and generating PDF security reports.

---

## 📌 Project Overview

**Log Analysis Dashboard** is a lightweight SOC-style security monitoring and log analysis application.

The system takes structured `.log` or `.txt` files, parses security events, detects suspicious activities using predefined detection rules, assigns severity and risk scores, maps detections to MITRE ATT&CK techniques, and displays the results through a web-based dashboard.

### Security Analysis Workflow

```text
Log File
   ↓
Log Parser
   ↓
Security Analyzer
   ↓
Detection Rules
   ↓
Severity & Risk Scoring
   ↓
MITRE ATT&CK Mapping
   ↓
Flask Dashboard
   ↓
PDF Security Report


🚀 Key Features
📄 Security log parsing
📤 Log file upload
🔍 Automated security event detection
🚨 Failed login detection
🔐 Brute-force / repeated failed login detection
⚡ Suspicious PowerShell activity detection
🌐 Blocked network connection detection
🔑 Credential dumping detection
🎯 Security severity classification
🌍 IP-based risk scoring
📊 Security statistics
📈 Log-level distribution
🎯 MITRE ATT&CK technique mapping
🖥️ Flask-based security dashboard
📑 PDF security report generation
🧪 Sample security log for testing
🔎 Security Detection Rules

The analyzer currently identifies the following security events:

DetectionSeverityScoreMITRE ATT&CK
Repeated Failed Login / Brute ForceHigh8T1110
Suspicious PowerShell ActivityHigh8T1059.001
Blocked Network ConnectionMedium4T1071
Credential DumpingCritical10T1003
Critical Log EventCritical10T1204
Unauthorized AccessHigh8T1078
Suspicious ActivityMedium5T1059
Generic System ErrorLow2T1562
Severity Levels
SeverityMeaning
🔴 CriticalImmediate investigation required
🟠 HighSerious suspicious activity
🟡 MediumSuspicious activity requiring review
🟢 LowLower-risk security event
🎯 MITRE ATT&CK Mapping

Detected activities are mapped to relevant MITRE ATT&CK techniques.

Current sample analysis includes:

Technique IDTechniqueEvents
T1110Brute Force4
T1059.001PowerShell1
T1071Application Layer Protocol1
T1003OS Credential Dumping1

This provides a basic detection-engineering workflow similar to how SOC analysts correlate security events with adversary techniques.

📊 Sample Analysis

The included data/sample.log contains 12 security events.

Current sample analysis:

Total Logs        : 12
Security Findings : 7
Critical          : 1
High              : 5
Medium            : 1
Low               : 0
IP Risk Analysis
192.168.1.50 | Risk: Critical | Score: 32 | Events: 4
192.168.1.77 | Risk: High     | Score: 12 | Events: 2
10.0.0.44    | Risk: Medium   | Score: 10 | Events: 1
Risk Calculation

The dashboard aggregates security finding scores for each suspicious IP.

Score >= 20  → Critical
Score >= 12  → High
Score >= 5   → Medium
Score < 5    → Low
🏗️ Project Architecture
                    ┌────────────────────┐
                    │   Security Log     │
                    │    (.log / .txt)   │
                    └─────────┬──────────┘
                              │
                              ▼
                    ┌────────────────────┐
                    │    Log Parser      │
                    │  log_parser.py     │
                    └─────────┬──────────┘
                              │
                              ▼
                    ┌────────────────────┐
                    │ Security Analyzer  │
                    │   analyzer.py      │
                    └─────────┬──────────┘
                              │
              ┌───────────────┴────────────────┐
              ▼                                ▼
     ┌─────────────────┐              ┌─────────────────┐
     │ Detection Rules │              │  Risk Scoring   │
     │ Severity        │              │  IP Analysis    │
     └────────┬────────┘              └────────┬────────┘
              │                                │
              └──────────────┬─────────────────┘
                             ▼
                  ┌─────────────────────┐
                  │ MITRE ATT&CK        │
                  │ Technique Mapping   │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │   Flask Dashboard   │
                  │       app.py        │
                  └──────────┬──────────┘
                             │
                   ┌─────────┴─────────┐
                   ▼                   ▼
            ┌────────────┐      ┌────────────┐
            │ Web UI     │      │ PDF Report │
            │ Dashboard  │      │ report.py  │
            └────────────┘      └────────────┘

🛠️ Technologies Used
Python
Flask
Regular Expressions
HTML5
CSS3
FPDF / PDF Generation
Git
GitHub
MITRE ATT&CK
📁 Project Structure
Log-Analysis-Dashboard/
│
├── app.py
├── analyzer.py
├── log_parser.py
├── report.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── data/
│   └── sample.log
│
├── templates/
│   └── dashboard.html
│
├── static/
│   └── style.css
│
├── screenshots/
│   └── dashboard.png
│
└── reports/
    └── Security_Log_Report.pdf


⚙️ Installation
1. Clone the Repository
git clone https://github.com/adityasoc/Log-Analysis-Dashboard.git
cd Log-Analysis-Dashboard


2. Create Virtual Environment
python -m venv venv
3. Activate Virtual Environment

Windows PowerShell:

.\venv\Scripts\Activate.ps1

If PowerShell blocks script execution:

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

Then:

.\venv\Scripts\Activate.ps1
4. Install Dependencies
pip install -r requirements.txt
▶️ Running the Application

Start the Flask application:

python app.py

Open the dashboard in your browser:

http://127.0.0.1:5000
🧪 Testing the Log Parser

Run:

python -c "from log_parser import parse_log_file; logs=parse_log_file('data/sample.log'); print('LOG COUNT:', len(logs)); print(logs)"
🔍 Testing the Security Analyzer

Run:

python -c "from log_parser import parse_log_file; from analyzer import analyze_logs, get_statistics; logs=parse_log_file('data/sample.log'); findings=analyze_logs(logs); stats=get_statistics(logs, findings); print('LOGS:', len(logs)); print('FINDINGS:', len(findings)); print('CRITICAL:', stats['critical']); print('HIGH:', stats['high']); print('MEDIUM:', stats['medium']); print('LOW:', stats['low']); print('MITRE:', stats['mitre_summary'])"

Expected result:

LOGS: 12
FINDINGS: 7
CRITICAL: 1
HIGH: 5
MEDIUM: 1
LOW: 0
📑 PDF Security Report

The dashboard includes an Export Security Report feature.

The report contains security analysis information generated from the parsed logs and detected findings.

Generated reports are stored locally as:

reports/Security_Log_Report.pdf
📤 Log File Upload

The dashboard supports:

.log
.txt

files.

Uploaded logs are parsed and analyzed automatically after submission.

🔐 Example Log Format
2026-08-12 09:03:21 | WARN | src_ip=192.168.1.50 | user=admin | event=LOGIN | status=FAILED | message=Invalid password

The parser extracts:

Timestamp
Log level
Source IP
User
Event
Status
Message
🖥️ Dashboard

The dashboard provides:

Total log count
Security finding count
Critical / High / Medium / Low statistics
Log-level distribution
Severity distribution
Suspicious IP analysis
IP risk scoring
MITRE ATT&CK summary
Detailed security findings
Parsed log events
Log upload
PDF report generation
Dashboard Preview

🎯 Project Purpose

This project was developed as a practical cybersecurity project to demonstrate:

Security log analysis
SOC monitoring concepts
Detection engineering
Security event classification
MITRE ATT&CK mapping
IP risk assessment
Python automation
Flask web application development
Security reporting
Basic incident detection workflow
🔄 Defensive Security Workflow

The project demonstrates a simplified SOC workflow:

Collect Logs
     ↓
Parse Events
     ↓
Identify Suspicious Activity
     ↓
Classify Severity
     ↓
Map MITRE ATT&CK
     ↓
Calculate Risk
     ↓
Investigate Findings
     ↓
Generate Security Report
⚠️ Limitations

This project is intentionally lightweight and uses predefined detection rules.

It is not a replacement for enterprise SIEM platforms such as Splunk, Microsoft Sentinel, or IBM QRadar.

Current limitations include:

No real-time streaming
No persistent database
No authentication system
No automated incident response
No advanced machine-learning detection
Limited log formats
Basic IP risk calculation
No external threat-intelligence enrichment
🔮 Future Improvements

Planned improvements include:

Real-time log monitoring
Windows Event Log integration
Linux authentication log integration
GeoIP-based analysis
Threat intelligence integration
Email security alerts
Splunk / SIEM integration
Database-backed event storage
User authentication
Advanced anomaly detection
Machine-learning based detection
Docker deployment
Automated incident response
Interactive MITRE ATT&CK matrix
👨‍💻 Author

Aditya Kumar

Cybersecurity / SOC Analyst Project

GitHub:

https://github.com/adityasoc

📜 License

This project is provided for educational and portfolio purposes.

⚠️ Disclaimer

This project is intended for educational and defensive cybersecurity purposes only.

The detection rules are simplified and should not be considered a replacement for production-grade SIEM, EDR, or enterprise security monitoring systems.
