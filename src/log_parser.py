import win32evtlog

def analyze_logs():
    print("Analyzing Windows Security logs for failed logins...")

    server = 'localhost'
    log_type = 'Security'

    try:
        hand = win32evtlog.OpenEventLog(server, log_type)

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        total = 0

        events = win32evtlog.ReadEventLog(hand, flags, 0)

        while events:
            for event in events:
                if event.EventID == 4625:
                    total += 1
                    print(f"[!] Failed login detected at {event.TimeGenerated}")

            events = win32evtlog.ReadEventLog(hand, flags, 0)

        print(f"\nTotal failed logins found: {total}")

    except Exception as e:
        print(f"Error reading logs: {e}")