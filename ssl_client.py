import socket
import ssl

HOST = '127.0.0.1'
PORT = 8443

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE  # For self-signed cert

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        print("[+] Connected to SSL server")
        ssock.sendall(b"Hello from client!")
        data = ssock.recv(1024)
        print("[*] Server says:", data.decode())
