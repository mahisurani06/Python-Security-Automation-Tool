import re
from datetime import datetime
from colorama import Fore

from modules.ip_checker import check_ip_reputation
from modules.telegram_alert import send_telegram_alert
from modules.database import alert_exists, insert_alert

SUSPICIOUS_KEYWORDS = [
    "failed login", "brute force", "unauthorized", "sql injection", "xss attack",
    "port scan", "malware detected", "ddos", "ransomware", "phishing",
    "suspicious activity", "access denied", "multiple login attempts",
    "privilege escalation", "remote access", "botnet", "exploit attempt",
    "firewall breach", "trojan", "virus detected", "backdoor", "shell access",
    "root access", "credential stuffing", "data breach", "suspicious ip",
    "attack detected", "intrusion detected", "vpn detected", "proxy detected"
]


def extract_ip(log_line):
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_line)
    return match.group(0) if match else "Unknown"


def classify_threat(score):
    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 0

    if score >= 90:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def is_suspicious(log_line):
    lower_line = log_line.lower()
    return any(keyword in lower_line for keyword in SUSPICIOUS_KEYWORDS)


def scan_log_file(log_file_path):
    alerts = []

    try:
        with open(log_file_path, "r", encoding="utf-8") as file:
            logs = file.readlines()
    except FileNotFoundError:
        print(Fore.RED + f"[-] Log file not found: {log_file_path}")
        return alerts

    for line in logs:
        clean_log = line.strip()

        if not clean_log or not is_suspicious(clean_log):
            continue

        ip = extract_ip(clean_log)

        if alert_exists(ip, clean_log):
            print(Fore.BLUE + f"[i] Duplicate alert skipped: {ip}")
            continue

        reputation_data = check_ip_reputation(ip)
        score = reputation_data.get("abuse_confidence_score", 0)
        country = reputation_data.get("country", "Unknown")
        isp = reputation_data.get("isp", "Unknown")
        threat_level = classify_threat(score)

        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "score": score,
            "threat_level": threat_level,
            "country": country,
            "isp": isp,
            "log": clean_log,
        }

        insert_alert(alert)
        alerts.append(alert)

        print(Fore.RED + "[ALERT] Suspicious Activity Detected")
        print(Fore.YELLOW + f"Log: {clean_log}")
        print(Fore.GREEN + f"IP Address: {ip}")
        print(Fore.MAGENTA + f"Threat Level: {threat_level} | Score: {score}\n")

        send_telegram_alert(alert)

    return alerts
