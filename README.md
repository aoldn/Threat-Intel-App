# Threat-Intel-App

# ThreatCheck: Network Threat Detection Tool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-green)
[![License](https://img.shields.io/badge/License-MIT-orange)](LICENSE)

A cross-platform Python application to detect malicious IP addresses by checking active network connections against **AbuseIPDB**'s threat intelligence database. Developed for the Payhawk IT Helpdesk Engineer role.

---

## Features
- 🕵️ **Network Scanning**: Lists active/past network connections using `psutil`.
- 🔍 **Threat Intelligence**: Checks IP reputations via AbuseIPDB’s API.
- 📂 **CSV Export**: Saves results for further analysis.
- 📝 **Logging**: Tracks all scans and errors.
- 🖥️ **Cross-Platform**: Works on Windows, macOS, and Linux.

---

## Installation

### Prerequisites
- Python 3.8+
- [AbuseIPDB API Key](https://www.abuseipdb.com/api) (Free tier available)

### Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/aoldn/threatcheck.git
   cd threatcheck

#Install Dependacies
pip install -r requirements.txt

Configure API Key
ABUSEIPDB_API_KEY = 7cfe068a910dcb55e9d1e621e2ebc6af346da3e15d533a88741d1d1bfa5ab614af6da4ea30532566

USAGE
python threatcheck.py

Screenshots

![Screenshot 2025-03-04 131351](https://github.com/user-attachments/assets/df6e7f5b-aa31-4458-ac19-fe74a0b74cd0)

![Screenshot 2025-03-02 221927](https://github.com/user-attachments/assets/c7a15011-d771-4dac-a86b-7807eee78117)

![Screenshot 2025-03-04 135844](https://github.com/user-attachments/assets/7a3cf26c-4b0e-4dc9-9f48-1b3978838a4f)

![Screenshot 2025-03-03 094029](https://github.com/user-attachments/assets/2f0735f4-f502-45c9-864b-76edfc422d99)


Threat Results

[threat_results.csv](https://github.com/user-attachments/files/19072248/threat_results.csv)
