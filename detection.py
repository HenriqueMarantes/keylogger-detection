import psutil

# List of suspicious keywords
SUSPICIOUS_KEYWORDS = ["keylog", "logger", "hook", "capture"]

def detect_suspicious_processes():
    print("Scanning running processes...\n")

    for process in psutil.process_iter(['pid', 'name']):
        try:
            process_name = process.info['name'].lower()

            for word in SUSPICIOUS_KEYWORDS:
                if word in process_name:
                    print(f"[!] Suspicious process detected: {process_name} (PID: {process.info['pid']})")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    print("\nScan completed.")

if __name__ == "__main__":
    detect_suspicious_processes()
``
