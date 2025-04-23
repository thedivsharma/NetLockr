import socket

def send_suspicious_ip(suspicious_ip):
    host = '127.0.0.1'  # The host where the sniffer server is running
    port = 65432         # Same port as the sniffer server

    # Create a socket object and connect to the sniffer server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(suspicious_ip.encode('utf-8'))  # Send suspicious IP as a byte stream
        print(f"[+] Sent suspicious IP {suspicious_ip} to server")

# Example usage: you can replace this with logic to send suspicious IPs detected by any part of your network
if __name__ == "__main__":
    suspicious_ip = "192.168.1.28"  # Example IP to be sent
    send_suspicious_ip(suspicious_ip)
