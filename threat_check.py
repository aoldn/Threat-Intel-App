import psutil
import requests
import platform
import argparse
import csv
import logging
import tkinter as tk
from tkinter import messagebox
from unittest.mock import patch
import unittest

# ========== Configuration ==========
logging.basicConfig(
    filename='threat_check.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ========== Core Functionality ==========
def get_active_connections():
    """Get unique established connections with remote addresses."""
    connections = []
    try:
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED' and conn.raddr:
                connections.append(conn.raddr.ip)
        return list(set(connections))
    except Exception as e:
        logging.error(f"Error getting connections: {str(e)}")
        return []

def check_ip_reputation(ip, api_key):
    """Check IP reputation using AbuseIPDB API."""
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {'Key': api_key, 'Accept': 'application/json'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        return {
            "ip": ip,
            "abuse_score": data['data']['abuseConfidenceScore'],
            "country": data['data'].get('countryCode', 'N/A'),
            "isp": data['data']['isp']
        }
    except Exception as e:
        logging.error(f"Error checking {ip}: {str(e)}")
        return None

# ========== OS-Specific Handling ==========
def get_log_path():
    """Determine appropriate log path for different OSes."""
    os_name = platform.system()
    return {
        "Linux": "/var/log/syslog",
        "Windows": "C:\\Windows\\System32\\Logs\\Firewall\\pfirewall.log",
        "Darwin": "/var/log/system.log"
    }.get(os_name, "/var/log/system.log")

# ========== Data Management ==========
def save_results(results, filename='results.csv'):
    """Save malicious IPs to CSV file."""
    try:
        if not results:
            logging.info("No results to save")
            return
            
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Score', 'Country', 'ISP'])
            for res in results:
                writer.writerow([res['ip'], res['abuse_score'], res['country'], res['isp']])
        logging.info(f"Saved {len(results)} entries to {filename}")
    except Exception as e:
        logging.error(f"CSV save failed: {str(e)}")

# ========== CLI Interface ==========
def cli_main(api_key, threshold=10):
    """Command-line interface main function."""
    active_ips = get_active_connections()
    logging.info(f"Active IPs: {active_ips}")
    
    malicious = []
    for ip in active_ips:
        if result := check_ip_reputation(ip, api_key):
            if result['abuse_score'] > threshold:
                malicious.append(result)
                print(f"Threat found: {result}")
    
    save_results(malicious)

# ========== GUI Interface ==========
class ThreatCheckGUI:
    def __init__(self, master):
        self.master = master
        master.title("Threat Check")
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create GUI components."""
        self.api_key_label = tk.Label(self.master, text="API Key:")
        self.api_key_entry = tk.Entry(self.master, width=40)
        self.run_btn = tk.Button(self.master, text="Scan", command=self.run_scan)
        
        self.api_key_label.pack(pady=5)
        self.api_key_entry.pack(pady=5)
        self.run_btn.pack(pady=10)
    
    def run_scan(self):
        """Handle scan button click."""
        api_key = self.api_key_entry.get()
        if not api_key:
            messagebox.showerror("Error", "API key required!")
            return
        
        try:
            active_ips = get_active_connections()
            results = [check_ip_reputation(ip, api_key) for ip in active_ips]
            malicious = [res for res in results if res and res['abuse_score'] > 0]
            
            if malicious:
                save_results(malicious)
                messagebox.showinfo("Results", f"{len(malicious)} threats found!\nSaved to results.csv")
            else:
                messagebox.showinfo("Results", "No threats detected")
        except Exception as e:
            messagebox.showerror("Error", str(e))

# ========== Testing ==========
class TestThreatCheck(unittest.TestCase):
    @patch('requests.get')
    def test_ip_check(self, mock_get):
        """Test IP reputation check with mock response."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'data': {
                'abuseConfidenceScore': 100,
                'countryCode': 'US',
                'isp': 'Test ISP'
            }
        }
        
        result = check_ip_reputation('8.8.8.8', 'test_key')
        self.assertEqual(result['abuse_score'], 100)
        self.assertEqual(result['country'], 'US')

# ==== GUI Interface ====
class ThreatCheckApp:
    def __init__(self, master):
        self.master = master
        master.title("Threat Checker")
        
        # Create UI elements
        self.api_label = tk.Label(master, text="Enter AbuseIPDB API Key:")
        self.api_entry = tk.Entry(master, width=40)
        self.scan_btn = tk.Button(master, text="Start Scan", command=self.run_scan)
        
        # Layout
        self.api_label.pack(pady=10)
        self.api_entry.pack(pady=5)
        self.scan_btn.pack(pady=15)
    
    def run_scan(self):
        """Handle scan execution"""
        api_key = self.api_entry.get()
        
        if not api_key:
            messagebox.showerror("Error", "API key required!")
            return
        
        try:
            active_ips = get_active_connections()
            results = []
            
            for ip in active_ips:
                if result := check_ip_reputation(ip, api_key):
                    if result['abuse_score'] > 10:
                        results.append(result)
            
            if results:
                with open('threat_results.csv', 'w') as f:
                    writer = csv.writer(f)
                    writer.writerow(['IP', 'Risk Score', 'Country', 'ISP'])
                    for res in results:
                        writer.writerow([res['ip'], res['abuse_score'], res['country'], res['isp']])
                messagebox.showinfo("Results", f"Found {len(results)} threats!\nSaved to threat_results.csv")
            else:
                messagebox.showinfo("Results", "No threats detected")
                
        except Exception as e:
            messagebox.showerror("Error", f"Scan failed: {str(e)}")

# ==== Launch Application ====
if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatCheckApp(root)
    root.mainloop()







    
