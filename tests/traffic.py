"""Bounded local HTTP fixture for the browser test, executed inside WSL."""
import socket
import threading

with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen(4)
    listener.settimeout(5)

    def serve():
        for _ in range(4):
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                connection.recv(4096)
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest")

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        for index in range(4):
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.sendall(f"GET /browser-{index}-<img> HTTP/1.1\r\nHost: local.test\r\n\r\n".encode())
                while client.recv(4096):
                    pass
    finally:
        worker.join(6)
print("PASS: bounded WSL HTTP fixture")
