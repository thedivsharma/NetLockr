import socket
import requests
import csv
import json
from scapy.all import sniff
from requests.auth import HTTPBasicAuth
from datetime import datetime
from threading import Thread

# Set of IPs already blocked
blocked_ips = set()
import requests
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

# A custom adapter to allow HTTPS with SSL verification
# A custom adapter to allow HTTPS with SSL verification
class SSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context()
        # context.load_verify_locations('/path/to/ca_certificate.pem')  # Optional: Path to CA cert
        kwargs['ssl_context'] = context

        # Print the URL being used for the HTTPS request
        print(f"Sending request to {ONOS_REST_API_URL} using HTTPS")

        return super().init_poolmanager(*args, **kwargs)

# Your ONOS REST API URL, make sure it's using HTTPS
ONOS_REST_API_URL = "https://onos-controller-ip:8181/v1/flows"

# Create a session and mount it with the custom SSL adapter
session = requests.Session()
session.mount('https://', SSLAdapter())
# Log file paths
csv_log_file = "detected_ips.csv"
json_log_file = "detected_ips.json"

# ONOS Controller credentials and URL
onos_url = "http://127.0.0.1:8181/onos/v1/flows"
auth = HTTPBasicAuth('onos', 'rocks')

# Device IDs for ONOS (update these if needed)
device_ids = [
    "of:0000000000000001",
    "of:0000000000000002",
    "of:0000000000000003",
]

# Function to alert ONOS and block the suspicious IP
def alert_controller(suspicious_ip):
    if suspicious_ip in blocked_ips:
        return  # Already blocked

    print(f"[!] Suspicious IP detected: {suspicious_ip}")

    for device_id in device_ids:
        flow = {
            "priority": 40000,
            "timeout": 60,
            "isPermanent": False,
            "deviceId": device_id,
            "treatment": {
                "instructions": []
            },
            "selector": {
                "criteria": [
                    {
                        "type": "IPV4_SRC",
                        "ip": f"{suspicious_ip}/32"
                    }
                ]
            }
        }

        try:
            response = requests.post(f"{onos_url}/{device_id}", json=flow, auth=auth)
            if response.status_code == 201:
                print(f"[+] Installed block rule for {suspicious_ip} on {device_id}")
            else:
                print(f"[-] Failed to install rule on {device_id}. Status: {response.status_code}, Error: {response.text}")
        except Exception as e:
            print(f"[!] Error installing rule on {device_id}: {e}")

    blocked_ips.add(suspicious_ip)
    log_detected_ip(suspicious_ip)

# Log detected suspicious IP to CSV and JSON
def log_detected_ip(suspicious_ip):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    try:
        with open(csv_log_file, mode='a', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow([timestamp, suspicious_ip])
            print(f"[+] Logged suspicious IP {suspicious_ip} to CSV")
    except Exception as e:
        print(f"[!] Error logging to CSV: {e}")

    try:
        with open(json_log_file, mode='a') as json_file:
            log_entry = {"timestamp": timestamp, "ip": suspicious_ip}
            json.dump(log_entry, json_file)
            json_file.write("\n")
            print(f"[+] Logged suspicious IP {suspicious_ip} to JSON")
    except Exception as e:
        print(f"[!] Error logging to JSON: {e}")

# Packet callback function for sniffing
from scapy.all import sniff

from collections import defaultdict

# Initialize a counter dictionary to track the frequency of IP addresses
ip_counter = defaultdict(int)

def packet_callback(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        print(f"Captured IP packet: {src_ip} -> {dst_ip}")

        # Increment the count for this source IP
        ip_counter[src_ip] += 1

        # Check for the most frequent IP (i.e., the source IP with the highest count)
        frequent_ip = max(ip_counter, key=ip_counter.get)
        print(f"Most frequent IP: {frequent_ip} (appeared {ip_counter[frequent_ip]} times)")

        # Suspicious IP list or IP prefixes
        suspicious_ips = ["10.14.143.24", "10.14.142.129", "10.14.143.240"]
        suspicious_ranges = ["162.247.243.", "98.85.154."]

        if src_ip in suspicious_ips or any(src_ip.startswith(prefix) for prefix in suspicious_ranges):
            alert_controller(src_ip)
        
        # You can also add an alert for the most frequent IP, if desired:
        if src_ip == frequent_ip:
            print(f"ALERT: Frequent packet source IP: {src_ip} (frequency: {ip_counter[src_ip]})")
            alert_controller(src_ip)

# Start the packet sniffer
def start_sniffer():
    print("[*] Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

# Start the alert server
def run_alert_server(host='127.0.0.1', port=65433):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"[*] Alert server listening on {host}:{port}...")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                print(f"[+] Connection established with {addr}")
                suspicious_ip = conn.recv(1024).decode('utf-8')
                if suspicious_ip:
                    print(f"[+] Received suspicious IP: {suspicious_ip}")
                    alert_controller(suspicious_ip)
                conn.sendall(f"Suspicious IP {suspicious_ip} blocked.".encode('utf-8'))

# Start both sniffer and server
def start_sniffer_and_alert_server():
    sniffer_thread = Thread(target=start_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()

    run_alert_server()

# Main entry point
if __name__ == "__main__":
    start_sniffer_and_alert_server()

