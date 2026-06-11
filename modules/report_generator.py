import csv
import os

REPORT_PATH = "reports/security_report.csv"

FIELDNAMES = [
    "timestamp",
    "ip",
    "score",
    "threat_level",
    "country",
    "isp",
    "log",
]


def save_csv_report(alerts):
    os.makedirs("reports", exist_ok=True)
    file_exists = os.path.exists(REPORT_PATH)

    with open(REPORT_PATH, "a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)

        if not file_exists:
            writer.writeheader()

        for alert in alerts:
            writer.writerow(alert)
