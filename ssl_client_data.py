import socket
import ssl

HOST = '127.0.0.1'
PORT = 8443  # Data port

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        print("[+] Connected to Data channel")
        ssock.sendall(b"This is DATA traffic")
        response = ssock.recv(1024)
        print("[*] Server (Data):", response.decode())
