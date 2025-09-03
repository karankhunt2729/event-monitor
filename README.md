# 🛡️ Windows Event Monitoring & Threat Intelligence Tool

## 📌 Overview
This project is a **real-time Windows Event Monitoring and Threat Intelligence Tool**.  
It continuously monitors system events, detects **suspicious activities**, logs them into JSON files, and generates **alerts**.  

Key highlights:  
- 🖥️ **Event Monitoring**: Captures live system events from your PC.  
- 🔎 **Suspicious Activity Detection**: Flags critical/suspicious events.  
- 📤 **Alerts**: Sends instant alerts (e.g., via Telegram).  
- 🧠 **Threat Intelligence**: Integrates with **VirusTotal API** to check suspicious files, IPs, or hashes.  
- 🗂️ **Logging**: Saves all detected events in structured JSON for analysis.  

---

## 🚀 Features
- ✅ File deletion and rename/move monitoring
- ✅ Sensitive file access detection
- ✅ USB file transfer alerts
- ✅ VirusTotal malware scan integration (SHA256 hash check)
- ✅ Telegram real-time alerts
- ✅ JSON logging (`events.json`) 

---

## 🛠️ Requirements
- **Python 3.9+**  
- Works on **Windows (Event Logs)**  

Dependencies (in `requirements.txt`):
```txt
watchdog
requests
python-telegram-bot
virustotal-python

## 📦 Requirements

- Python 3.8+  
- Install dependencies:

```bash
pip install -r requirements.txt

python main.py
