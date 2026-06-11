import os
import ipaddress
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global
    except ValueError:
        return False


def check_ip_reputation(ip):
    if ip == "Unknown" or not is_public_ip(ip):
        return {
            "abuse_confidence_score": 0,
            "country": "Private/Unknown",
            "isp": "Private/Unknown",
        }

    if not ABUSEIPDB_API_KEY:
        return {
            "abuse_confidence_score": 0,
            "country": "API key missing",
            "isp": "API key missing",
        }

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY,
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True,
    }

    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})

        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown"),
        }

    except requests.RequestException as error:
        print(f"[-] AbuseIPDB API error for {ip}: {error}")
        return {
            "abuse_confidence_score": 0,
            "country": "API Error",
            "isp": "API Error",
        }
