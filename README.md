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
   git clone https://github.com/[USERNAME]/threatcheck.git
   cd threatcheck
