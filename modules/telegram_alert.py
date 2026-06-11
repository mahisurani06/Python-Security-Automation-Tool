import os
import requests
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


def send_telegram_alert(alert):
    if not BOT_TOKEN or not CHAT_ID:
        print("[i] Telegram alert skipped. Bot token or chat ID missing.")
        return

    message = f"""
🚨 Security Alert Detected

Time: {alert['timestamp']}
IP Address: {alert['ip']}
Threat Level: {alert['threat_level']}
Abuse Score: {alert['score']}
Country: {alert['country']}
ISP: {alert['isp']}

Log Event:
{alert['log']}
"""

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
    }

    try:
        response = requests.post(url, data=payload, timeout=10)
        response.raise_for_status()
        print("[✓] Telegram alert sent successfully.")
    except requests.RequestException as error:
        print(f"[-] Telegram alert failed: {error}")
