import win32evtlog
from datetime import datetime, timedelta


def analyze_logs():
    print("Analyzing Windows Security logs for failed logins...")

    server = "localhost"
    log_type = "Security"

    failed_logins = []

    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        events = win32evtlog.ReadEventLog(hand, flags, 0)

        while events:
            for event in events:
                event_id = event.EventID & 0xFFFF

                if event_id == 4625:
                    failed_logins.append({
                        "timestamp": event.TimeGenerated,
                        "source": event.SourceName
                    })

            events = win32evtlog.ReadEventLog(hand, flags, 0)

        print(f"\nTotal failed logins found: {len(failed_logins)}")

        if failed_logins:
            print("\nMost recent failed logins:")
            for entry in failed_logins[:10]:
                print(f"[!] {entry['timestamp']} | Source: {entry['source']}")

            detect_burst_activity(failed_logins)
        else:
            print("No failed login events detected.")

    except Exception as e:
        print(f"Error reading logs: {e}")


def detect_burst_activity(failed_logins, threshold=5, window_minutes=5):
    print("\nChecking for burst activity...")

    timestamps = sorted(entry["timestamp"] for entry in failed_logins)

    burst_found = False

    for i in range(len(timestamps)):
        window_start = timestamps[i]
        window_end = window_start + timedelta(minutes=window_minutes)

        count = sum(1 for ts in timestamps if window_start <= ts <= window_end)

        if count >= threshold:
            print(
                f"[ALERT] Detected {count} failed logins within "
                f"{window_minutes} minutes starting at {window_start}"
            )
            burst_found = True
            break

    if not burst_found:
        print("No burst activity detected.")