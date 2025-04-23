import socket
import ssl

HOST = '127.0.0.1'
PORT = 8444  # Control port

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        print("[+] Connected to Control channel")
        ssock.sendall(b"BLOCK IP 10.0.0.1")
        response = ssock.recv(1024)
        print("[*] Server (Control):", response.decode())
