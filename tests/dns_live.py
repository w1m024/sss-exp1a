#!/usr/bin/env python3
"""Live loopback DNS: exercise libpcap, protocol fields, filters and export."""
import argparse
from pathlib import Path
import socket
import subprocess
import tempfile

from integration import Service, eventually, require


def main():
    args = argparse.Namespace(server=str(Path('build/wirelens').resolve()),
                              helper='/opt/wirelens/libexec/wirelens-capture', port=18893)
    query = bytes.fromhex('123401000001000000000000') + b'\x03www\x07example\x03com\0\0\x01\0\x01'
    response = query[:2] + b'\x81\x80' + query[4:6] + b'\0\x01' + query[8:]
    response += bytes.fromhex('c00c000100010000003c0004c000027b')
    with Service(args, 5000) as service:
        interfaces = service.request('/api/interfaces')['interfaces']
        require(any(x['name'] == 'any' for x in interfaces), 'any interface')
        service.start('udp and host 127.0.0.1 and port 5353')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            server.bind(('127.0.0.1', 5353))
            server.settimeout(2); client.settimeout(2)
            client.sendto(query, server.getsockname())
            received, peer = server.recvfrom(4096)
            require(received == query, 'query received')
            server.sendto(response, peer)
            require(client.recvfrom(4096)[0] == response, 'response received')
        records = eventually(lambda: service.request('/api/packets', params={'protocol': 'DNS'})['packets'], 'DNS packets')
        service.request('/api/stop', method='POST')
        records = service.request('/api/packets', params={'protocol': 'DNS'})['packets']
        require(any('DNS query www.example.com' in p['summary'] for p in records), 'content-based query')
        replies = [p for p in records if 'DNS response' in p['summary']]
        require(replies, 'DNS response classified')
        detail = service.request('/api/packets/' + str(replies[0]['id']))
        require(any(f['name'] == 'address_ipv4' and f['value'] == '192.0.2.123' for f in detail['fields']), 'decoded A record')
        overview = service.request('/api/timeline', params={'protocol': 'DNS'})
        require(overview['matched'] == len(records), 'DNS overview filter')
        pcap = service.request('/api/export', binary=True)
        with tempfile.NamedTemporaryFile(suffix='.pcap') as capture:
            capture.write(pcap); capture.flush()
            decoded = subprocess.check_output(['tcpdump', '-n', '-r', capture.name], stderr=subprocess.DEVNULL).decode()
            require('www.example.com' in decoded and '192.0.2.123' in decoded, 'independent tcpdump DNS decoding')
    print('PASS live DNS query/response, record fields, filtering, timeline and pcap/tcpdump')


if __name__ == '__main__':
    main()
