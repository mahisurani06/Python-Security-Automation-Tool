import sqlite3

DATABASE_PATH = "reports/alerts.db"


def get_connection():
    return sqlite3.connect(DATABASE_PATH)


def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            score INTEGER,
            threat_level TEXT,
            country TEXT,
            isp TEXT,
            log TEXT NOT NULL,
            UNIQUE(ip, log)
        )
        """
    )

    connection.commit()
    connection.close()


def alert_exists(ip, log):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT id FROM alerts WHERE ip = ? AND log = ?", (ip, log))
    result = cursor.fetchone()

    connection.close()
    return result is not None


def insert_alert(alert):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT OR IGNORE INTO alerts
        (timestamp, ip, score, threat_level, country, isp, log)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert["timestamp"],
            alert["ip"],
            alert["score"],
            alert["threat_level"],
            alert["country"],
            alert["isp"],
            alert["log"],
        ),
    )

    connection.commit()
    connection.close()
