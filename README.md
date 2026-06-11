# Python Security Automation Tool

A professional SOC-style Python automation project that scans security logs, detects suspicious activities, checks malicious IP reputation using AbuseIPDB, sends real-time Telegram alerts, stores incidents in SQLite, generates CSV reports, and creates a threat dashboard.

## Features

- Suspicious log detection
- IP address extraction
- AbuseIPDB threat intelligence integration
- Telegram real-time alerting
- SQLite alert history database
- Duplicate alert prevention
- CSV incident report generation
- Threat level classification
- Dashboard chart generation
- Windows Security Event Log monitoring

## Tech Stack

- Python
- AbuseIPDB API
- Telegram Bot API
- SQLite
- Pandas
- Matplotlib
- Windows Event Logs

## Folder Structure

```text
Python-Security-Automation-Tool/
│
├── main.py
├── windows_log_monitor.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
│
├── modules/
│   ├── log_scanner.py
│   ├── ip_checker.py
│   ├── telegram_alert.py
│   ├── report_generator.py
│   ├── database.py
│   └── dashboard.py
│
├── logs/
│   └── suspicious_logs.txt
│
└── reports/
    ├── security_report.csv
    ├── alerts.db
    └── threat_dashboard.png
```

## Installation

```bash
git clone https://github.com/your-username/Python-Security-Automation-Tool.git
cd Python-Security-Automation-Tool
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Environment Setup

Create a `.env` file in the project root:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
TELEGRAM_CHAT_ID=your_telegram_chat_id_here
```

## Run the Project

```bash
python main.py
```

## Run Windows Event Log Monitor

```bash
python windows_log_monitor.py
```

Run PowerShell or Command Prompt as Administrator for Windows Security Event Logs.

## Sample Output

```text
[ALERT] Suspicious Activity Detected
Log: Brute force detected from 185.220.101.1
IP Address: 185.220.101.1
Threat Level: CRITICAL | Score: 100
```

## Description

Built a Python-based Security Automation Tool that detects suspicious log activities, extracts attacker IP addresses, checks IP reputation using AbuseIPDB, sends Telegram alerts, stores incidents in SQLite, and generates CSV reports and dashboards for SOC-style monitoring.

- Developed a SOC-style security monitoring tool using Python to detect suspicious logs and failed login attempts.
- Integrated AbuseIPDB API for IP reputation analysis and automated threat classification.
- Implemented Telegram alerting for real-time security incident notifications.
- Designed SQLite-based alert history to prevent duplicate incident reporting.
- Generated CSV reports and visual dashboards for security analysis and incident tracking.
- Added Windows Event Log monitoring for detecting failed logins, privileged account changes, and audit log clearing.

## Future Improvements

- Add Flask web dashboard
- Add VirusTotal API integration
- Add email alerting
- Add PDF incident reports
- Add real-time log tailing

## Author

Mahi Surani

- LinkedIn: https://www.linkedin.com/in/mahi-surani-9bab5333b/
- GitHub: https://github.com/mahisurani06
