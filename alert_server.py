import socket
import requests
from requests.auth import HTTPBasicAuth

# Set of IPs already blocked
blocked_ips = set()

# ONOS Controller credentials and URL
onos_url = "http://127.0.0.1:8181/onos/v1/flows"
auth = HTTPBasicAuth('onos', 'rocks')

# Device IDs for ONOS (replace with actual values)
device_ids = [
    "of:0000000000000001",  # s1
    "of:0000000000000002",  # s2
    "of:0000000000000003",  # s3
]

# Function to alert ONOS and block the suspicious IP
def alert_controller(suspicious_ip):
    if suspicious_ip in blocked_ips:
        return  # Already blocked, skip

    print(f"[!] Suspicious IP detected: {suspicious_ip}")

    # Loop through all devices to install block rule
    for device_id in device_ids:
        flow = {
            "priority": 40000,
            "timeout": 60,  # Auto-expire after 60s
            "isPermanent": False,  # Set to True for permanent block
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
            # Send the flow rule to ONOS via REST API
            response = requests.post(f"{onos_url}/{device_id}", json=flow, auth=auth)
            if response.status_code == 201:
                print(f"[+] Installed block rule for {suspicious_ip} on {device_id}")
            else:
                print(f"[-] Failed to install rule on {device_id}. Status: {response.status_code}, Error: {response.text}")
        except Exception as e:
            print(f"[!] Error installing rule on {device_id}: {e}")

    blocked_ips.add(suspicious_ip)  # Mark as blocked

# Function to handle incoming alerts from the socket client
def handle_alert_connection(conn, addr):
    print(f"[+] Connection established with {addr}")
    try:
        # Receive the suspicious IP from the client
        suspicious_ip = conn.recv(1024).decode('utf-8')
        if suspicious_ip:
            print(f"[+] Received suspicious IP: {suspicious_ip}")
            alert_controller(suspicious_ip)  # Block IP on ONOS
        conn.sendall(f"Suspicious IP {suspicious_ip} blocked.".encode('utf-8'))  # Send confirmation to client
    finally:
        conn.close()

# Function to start the alert server
def start_alert_server(host='127.0.0.1', port=65433):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"[*] Alert server listening on {host}:{port}...")

        while True:
            conn, addr = server_socket.accept()
            # Handle each alert connection in a separate thread or process
            handle_alert_connection(conn, addr)

if __name__ == "__main__":
    start_alert_server()
