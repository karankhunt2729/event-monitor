import json
import time
import os
import requests
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

LOG_FILE = "events.json"

# ===== TELEGRAM CONFIG =====
BOT_TOKEN = "BOT_TOKEN"   # Telegram bot token
CHAT_ID = "CHAT_ID"       # Telegram chat id

def send_telegram_alert(message):
    """Send alert message to Telegram"""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": message}
    try:
        requests.post(url, data=payload, timeout=5)
    except Exception as e:
        print(f"[!] Failed to send Telegram alert: {e}")

# ===== VIRUSTOTAL CONFIG =====
VT_API_KEY = "VT_API_KEY"  # VirusTotal API Key
VT_URL = "https://www.virustotal.com/api/v3/files/"

def check_virustotal(file_path):
    """Check file hash in VirusTotal"""
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return "File not found"

    try:
        # Calculate SHA256 hash
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(VT_URL + file_hash, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats["malicious"]
            if malicious > 0:
                return f"⚠️ Malicious ({malicious} vendors flagged)"
            else:
                return "✅ Clean (0 detections)"
        else:
            return "⚠️ Not found in VirusTotal"
    except Exception as e:
        return f"[ERROR] VT check failed: {e}"

# ===== IGNORE / SENSITIVE CONFIG =====
IGNORE_PATHS = [
    "C:\\Program Files\\Splunk\\",  # ignore all Splunk files
]

SENSITIVE_PATHS = [
    "C:\\Windows\\System32\\config\\",  # example sensitive files
]

USB_DRIVES = ["E:\\", "F:\\", "G:\\"]

# To store already alerted events permanently in runtime
alerted_events = set()

def log_event(event_type, path, is_alert=False, check_vt=False):
    # Skip ignored paths
    if any(path.startswith(ignore) for ignore in IGNORE_PATHS):
        return

    event = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "path": path,
        "alert": is_alert
    }

    # Store in JSON (all events except ignored)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

    # Show alert only once per unique suspicious event
    if is_alert:
        key = f"{event_type}:{path}"
        if key not in alerted_events:
            alerted_events.add(key)
            alert_msg = f"🚨 ALERT\nType: {event_type}\nPath: {path}\nTime: {event['timestamp']}"

            # Optional: VirusTotal Check
            if check_vt:
                vt_result = check_virustotal(path)
                alert_msg += f"\nVirusTotal: {vt_result}"

            print(alert_msg)
            send_telegram_alert(alert_msg)

class SecurityHandler(FileSystemEventHandler):
    def on_deleted(self, event):
        log_event("File Deleted", event.src_path, is_alert=True, check_vt=True)

    def on_moved(self, event):
        log_event("File Renamed/Moved", f"{event.src_path} → {event.dest_path}", is_alert=True)

    def on_modified(self, event):
        # Detect access to sensitive files
        if any(event.src_path.startswith(s) for s in SENSITIVE_PATHS):
            log_event("Sensitive File Accessed", event.src_path, is_alert=True, check_vt=True)

    def on_created(self, event):
        # Detect files transferred to USB drives
        if any(event.src_path.startswith(drive) for drive in USB_DRIVES):
            log_event("File Transferred to USB", event.src_path, is_alert=True, check_vt=True)

def main():
    paths_to_monitor = ["C:\\"]  # Monitor main drive

    event_handler = SecurityHandler()
    observer = Observer()

    for path in paths_to_monitor:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=True)

    observer.start()
    print("[*] Monitoring started... Press CTRL+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
