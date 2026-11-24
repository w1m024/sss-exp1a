import os
import socket
import time

with socket.create_connection(("127.0.0.1", 18080)) as first, \
        socket.create_connection(("127.0.0.1", 18080)) as second:
    print(f"客户端 PID: {os.getpid()}", flush=True)
    for index, conn in enumerate((first, second), 1):
        print(f"连接 {index}: {conn.getsockname()} -> {conn.getpeername()}", flush=True)

    # 等待进程快照刷新后再发送请求首行，两条连接保持打开。
    time.sleep(0.3)
    for conn in (first, second):
        conn.sendall(b"GET /demo.txt HTTP/1.1\r\n")

    input("网页演示完成后按 Enter 关闭连接：")
