try:
    import win32evtlog
except ImportError:
    print("pywin32 is required. Install it using: pip install pywin32")
    raise SystemExit

SECURITY_EVENTS = {
    4625: "Failed Login Attempt",
    4624: "Successful Login",
    4720: "User Account Created",
    4726: "User Account Deleted",
    4728: "User Added to Privileged Group",
    1102: "Audit Log Cleared",
}


def monitor_windows_security_logs():
    server = "localhost"
    logtype = "Security"

    handle = win32evtlog.OpenEventLog(server, logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    print("[+] Reading Windows Security Event Logs...\n")

    events = win32evtlog.ReadEventLog(handle, flags, 0)

    for event in events:
        event_id = event.EventID & 0xFFFF

        if event_id in SECURITY_EVENTS:
            print("[ALERT] Windows Security Event Detected")
            print(f"Event ID: {event_id}")
            print(f"Meaning: {SECURITY_EVENTS[event_id]}")
            print(f"Source: {event.SourceName}")
            print(f"Time: {event.TimeGenerated}\n")


if __name__ == "__main__":
    monitor_windows_security_logs()
