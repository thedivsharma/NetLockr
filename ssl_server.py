import socket
import ssl
import threading

DATA_PORT = 8443
CONTROL_PORT = 8444
HOST = '0.0.0.0'

def handle_client(connstream, addr, channel_type):
    print(f"[+] {channel_type} Channel - Connected to {addr}")
    try:
        while True:
            data = connstream.recv(1024)
            if not data:
                break
            print(f"[*] {channel_type} Channel - Received from {addr}: {data.decode()}")
            connstream.sendall(f"{channel_type} Channel Acknowledged".encode())
    except Exception as e:
        print(f"[!] {channel_type} Error: {e}")
    finally:
        connstream.shutdown(socket.SHUT_RDWR)
        connstream.close()
        print(f"[-] {channel_type} Channel - Connection closed: {addr}")

def start_server(port, channel_type):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, port))
    server_socket.listen(5)

    print(f"[+] {channel_type} Channel listening on port {port}...")

    while True:
        client_sock, addr = server_socket.accept()
        connstream = context.wrap_socket(client_sock, server_side=True)
        threading.Thread(target=handle_client, args=(connstream, addr, channel_type)).start()

# Start both servers (data + control) in separate threads
threading.Thread(target=start_server, args=(DATA_PORT, "Data")).start()
threading.Thread(target=start_server, args=(CONTROL_PORT, "Control")).start()
