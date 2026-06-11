import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

DATABASE_PATH = "reports/alerts.db"
DASHBOARD_PATH = "reports/threat_dashboard.png"


def generate_dashboard():
    if not os.path.exists(DATABASE_PATH):
        print("[i] Dashboard skipped. No database found.")
        return

    connection = sqlite3.connect(DATABASE_PATH)
    df = pd.read_sql_query("SELECT * FROM alerts", connection)
    connection.close()

    if df.empty:
        print("[i] Dashboard skipped. No alert data found.")
        return

    os.makedirs("reports", exist_ok=True)

    threat_counts = df["threat_level"].value_counts()

    plt.figure(figsize=(8, 5))
    threat_counts.plot(kind="bar")
    plt.title("Threat Level Summary")
    plt.xlabel("Threat Level")
    plt.ylabel("Number of Alerts")
    plt.tight_layout()
    plt.savefig(DASHBOARD_PATH)
    plt.close()
