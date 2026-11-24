import socket

query = bytes.fromhex("123401000001000000000000") + b"\x03www\x07example\x03com\0\0\x01\0\x01"
response = query[:2] + b"\x81\x80" + query[4:6] + b"\0\x01" + query[8:]
response += bytes.fromhex("c00c000100010000003c0004c000027b")

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    server.bind(("127.0.0.1", 5353))
    server.settimeout(2)
    client.settimeout(2)
    client.sendto(query, server.getsockname())
    received, peer = server.recvfrom(4096)
    assert received == query
    server.sendto(response, peer)
    assert client.recvfrom(4096)[0] == response

print("DNS: www.example.com -> 192.0.2.123")
