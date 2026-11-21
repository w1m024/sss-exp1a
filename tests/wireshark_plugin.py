#!/usr/bin/env python3
"""Load the real Lua plugin in TShark and assert fields and expert notes."""
import argparse
import csv
import io
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile


def frame(name, response=False, transaction=0x1234):
    encoded = b''.join(bytes([len(part)]) + part.encode() for part in name.split('.')) + b'\0'
    dns = struct.pack('!6H', transaction, 0x8183 if response else 0x100, 1, 0, 0, 0) + encoded + struct.pack('!HH', 1, 1)
    udp = struct.pack('!HHHH', 53 if response else 43210, 43210 if response else 53, 8 + len(dns), 0) + dns
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), transaction, 0, 64, 17, 0,
                               socket.inet_aton('192.0.2.53' if response else '192.0.2.1'),
                               socket.inet_aton('192.0.2.1' if response else '192.0.2.53')))
    checksum = sum(struct.unpack('!10H', ip))
    while checksum >> 16: checksum = (checksum & 65535) + (checksum >> 16)
    struct.pack_into('!H', ip, 10, ~checksum & 65535)
    return b'\0' * 12 + b'\x08\x00' + ip + udp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tshark', default=shutil.which('tshark'))
    args = parser.parse_args()
    if not args.tshark: raise RuntimeError('TShark is required for real plugin validation')
    plugin = Path('wireshark/dns_analysis.lua').resolve()
    with tempfile.TemporaryDirectory() as directory:
        capture = Path(directory) / 'dns.pcap'
        with capture.open('wb') as output:
            output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for micros, packet in [(0, frame('www.example.com')), (125000, frame('www.example.com', True)),
                                   (250000, frame('a' * 41 + '.example.com', transaction=0x5678))]:
                output.write(struct.pack('<IIII', 1700000000, micros, len(packet), len(packet)) + packet)
        fields = ['frame.number', 'dns_analysis.query', 'dns_analysis.labels', 'dns_analysis.longest_label',
                  'dns_analysis.long_label', 'dns_analysis.nxdomain', 'dns_analysis.response_ms', '_ws.expert.message']
        command = [args.tshark, '-n', '-2', '-X', 'lua_script:' + str(plugin), '-r', str(capture), '-T', 'fields']
        for field in fields: command += ['-e', field]
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        assert 'Lua Error' not in result.stderr and 'Dissector bug' not in result.stderr, result.stderr
        rows = list(csv.reader(io.StringIO(result.stdout), delimiter='\t'))
        assert len(rows) == 3, rows
        assert rows[0][1:5] == ['www.example.com', '3', '7', '0'], rows
        assert rows[1][5] == '1' and abs(float(rows[1][6]) - 125) < .001, rows
        assert rows[2][3:5] == ['41', '1'] and 'Long DNS label' in rows[2][7], rows
        filtered = subprocess.check_output([args.tshark, '-n', '-X', 'lua_script:' + str(plugin), '-r', str(capture),
                                            '-Y', 'dns_analysis.long_label == 1', '-T', 'fields', '-e', 'frame.number'], text=True)
        assert filtered.strip() == '3', filtered
        # 调整阈值必须改变实际分析结果。
        overridden = subprocess.check_output(command + ['-o', 'dns_analysis.long_label:50'], text=True)
        assert list(csv.reader(io.StringIO(overridden), delimiter='\t'))[2][4] == '0', overridden
        # 后置解析器还应能读取跨 TCP 段的 DNS 消息。
        dns = frame('split.example.com')[42:]
        payload = struct.pack('!H', len(dns)) + dns
        def tcp(sequence, acknowledgment, flags, body=b'', reverse=False):
            ip = bytearray(frame('split.example.com', reverse)[14:34])
            ip[9] = 6; struct.pack_into('!H', ip, 2, 40 + len(body)); ip[10:12] = b'\0\0'
            checksum = sum(struct.unpack('!10H', ip))
            while checksum >> 16: checksum = (checksum & 65535) + (checksum >> 16)
            struct.pack_into('!H', ip, 10, ~checksum & 65535)
            header = struct.pack('!HHIIBBHHH', 53 if reverse else 43211, 43211 if reverse else 53,
                                 sequence, acknowledgment, 0x50, flags, 65535, 0, 0)
            return b'\0' * 12 + b'\x08\x00' + ip + header + body
        split_capture = Path(directory) / 'split.pcap'
        with split_capture.open('wb') as output:
            output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            packets = [tcp(100, 0, 2), tcp(200, 101, 18, reverse=True), tcp(101, 201, 16),
                       tcp(101, 201, 24, payload[:10]), tcp(111, 201, 24, payload[10:])]
            for i, packet in enumerate(packets):
                output.write(struct.pack('<IIII', 1700000001, i * 10000, len(packet), len(packet)) + packet)
        split = subprocess.check_output([args.tshark, '-n', '-2', '-X', 'lua_script:' + str(plugin), '-r', str(split_capture),
                                         '-Y', 'dns_analysis.query', '-T', 'fields', '-e', 'frame.number', '-e', 'dns_analysis.query'], text=True)
        assert split.strip() == '5\tsplit.example.com', split
    print('PASS real TShark Lua loading, DNS fields, 125ms response, NXDOMAIN, expert note, filter, preference and split TCP reassembly')


if __name__ == '__main__':
    main()
