from colorama import Fore, Style, init
from modules.log_scanner import scan_log_file
from modules.report_generator import save_csv_report
from modules.dashboard import generate_dashboard
from modules.database import initialize_database

init(autoreset=True)

LOG_FILE = "logs/suspicious_logs.txt"


def main():
    print(Fore.CYAN + "\n[+] Python Security Automation Tool Started")
    print(Fore.CYAN + "[+] Initializing database...\n")

    initialize_database()

    print(Fore.YELLOW + "[+] Scanning log file for suspicious activity...\n")
    alerts = scan_log_file(LOG_FILE)

    if not alerts:
        print(Fore.GREEN + "[✓] No suspicious activity detected.")
        return

    save_csv_report(alerts)
    generate_dashboard()

    print(Fore.GREEN + f"\n[✓] Scan completed successfully.")
    print(Fore.GREEN + f"[✓] Total alerts detected: {len(alerts)}")
    print(Fore.GREEN + "[✓] CSV report saved in reports/security_report.csv")
    print(Fore.GREEN + "[✓] Dashboard saved in reports/threat_dashboard.png")
    print(Style.BRIGHT + "\nProject ready for GitHub, resume, and demo video.\n")


if __name__ == "__main__":
    main()
