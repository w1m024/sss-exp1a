#!/usr/bin/env python3
"""Ordinary-user integration checks; run from the repository root in Linux.

Example: python3 tests/integration.py --server build/wirelens
Only loopback traffic is generated. No packages or system settings are changed.
"""

import argparse
import contextlib
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def eventually(probe, description, timeout=5):
    deadline = time.monotonic() + timeout
    while True:
        result = probe()
        if result:
            return result
        if time.monotonic() >= deadline:
            raise AssertionError("Timed out: " + description)
        time.sleep(0.05)


def children(pid):
    result = set()
    for entry in Path('/proc', str(pid), 'task').glob('*/children'):
        try:
            result.update(map(int, entry.read_text().split()))
        except FileNotFoundError:
            pass
    return result


class Service:
    def __init__(self, args, capacity):
        self.args = args
        self.capacity = capacity
        self.token = None
        self.seen_children = set()

    def request(self, path, method='GET', params=None, expected=200,
                headers=None, authenticated=True, binary=False):
        if params is not None:
            path += '?' + urllib.parse.urlencode(params)
        h = {}
        if authenticated and self.token:
            h['X-Capture-Token'] = self.token
        h.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.args.port, timeout=5)
        try:
            connection.request(method, path, body=b'' if method == 'POST' else None, headers=h)
            response = connection.getresponse()
            body = response.read()
            require(response.status == expected,
                    f'{method} {path}: expected {expected}, got {response.status}: {body[:400]!r}')
            return body if binary else json.loads(body)
        finally:
            connection.close()

    def __enter__(self):
        self.log = tempfile.TemporaryFile()
        self.process = subprocess.Popen([
            self.args.server, '--port', str(self.args.port), '--capture-helper', self.args.helper,
            '--capacity', str(self.capacity)], stdout=self.log, stderr=self.log,
            start_new_session=True)
        try:
            def ready():
                if self.process.poll() is not None:
                    self.log.seek(0)
                    raise AssertionError('Server exited: ' + self.log.read().decode(errors='replace'))
                try:
                    return self.request('/api/session', authenticated=False)
                except (OSError, http.client.HTTPException):
                    return None
            self.token = eventually(ready, 'server startup')['token']
            require(isinstance(self.token, str) and len(self.token) == 64, 'session token shape')
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *unused):
        self.seen_children.update(children(self.process.pid))
        graceful = True
        try:
            if self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                graceful = False
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
            survivors = [p for p in self.seen_children if Path('/proc', str(p)).exists()]
            for pid in survivors:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.kill(pid, signal.SIGKILL)
            require(graceful, 'server shutdown exceeded 4 seconds')
            require(not survivors, f'capture children survived server shutdown: {survivors}')
            require(self.process.returncode == 0, f'server exit code {self.process.returncode}')
        finally:
            self.log.close()

    def start(self, filter_text, interface='any', expected=200):
        response = self.request('/api/start', 'POST',
                                {'interface': interface, 'filter': filter_text}, expected)
        self.seen_children.update(children(self.process.pid))
        return response

    def status(self):
        return self.request('/api/status')

    def stop(self):
        begin = time.monotonic()
        result = self.request('/api/stop', 'POST')
        elapsed = time.monotonic() - begin
        require(elapsed < 2, f'stop took {elapsed:.3f}s (limit 2s)')
        require(result['state'] in ('idle', 'stopped') and not result['error'], f'stop status: {result}')
        eventually(lambda: not children(self.process.pid), 'capture child reaped')
        print(f'  stop {elapsed:.3f}s', flush=True)
        return result

    def packets(self, **params):
        return self.request('/api/packets', params=params)


@contextlib.contextmanager
def traffic_endpoints():
    sockets = []
    threads = []
    failures = []
    done = threading.Event()
    try:
        for family, kind, address in [
            (socket.AF_INET, socket.SOCK_STREAM, ('127.0.0.1', 19877)),
            (socket.AF_INET, socket.SOCK_DGRAM, ('127.0.0.1', 19878)),
            (socket.AF_INET6, socket.SOCK_DGRAM, ('::1', 19879)),
        ]:
            sock = socket.socket(family, kind)
            sockets.append(sock)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(address)
            sock.settimeout(0.1)
            if kind == socket.SOCK_STREAM:
                sock.listen(4)

            def serve(s=sock, tcp=(kind == socket.SOCK_STREAM)):
                while not done.is_set():
                    try:
                        if tcp:
                            client, _ = s.accept()
                            with client:
                                client.settimeout(2)
                                data = b''
                                while b'\r\n\r\n' not in data and len(data) < 4096:
                                    part = client.recv(4096)
                                    if not part:
                                        break
                                    data += part
                                client.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nwirelens')
                        else:
                            data, peer = s.recvfrom(2048)
                            s.sendto(data, peer)
                    except socket.timeout:
                        continue
                    except OSError as exc:
                        if not done.is_set():
                            failures.append(str(exc))
                        break
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            threads.append(thread)
        yield
        require(not failures, f'traffic endpoint errors: {failures}')
    finally:
        done.set()
        for sock in sockets:
            sock.close()
        for thread in threads:
            thread.join(timeout=3)
            require(not thread.is_alive(), 'traffic thread failed to stop')


def udp(family=socket.AF_INET, count=1):
    address = ('127.0.0.1', 19878) if family == socket.AF_INET else ('::1', 19879)
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        for i in range(count):
            data = f'wirelens-local-udp-{i}'.encode()
            sock.sendto(data, address)
            require(sock.recvfrom(2048)[0] == data, 'UDP echo mismatch')


def traffic():
    with socket.create_connection(('127.0.0.1', 19877), timeout=2) as sock:
        sock.sendall(b'GET /wirelens-integration HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
        reply = b''
        while True:
            part = sock.recv(4096)
            if not part:
                break
            reply += part
        require(reply.endswith(b'wirelens'), 'HTTP response mismatch')
    udp()
    udp(socket.AF_INET6)
    for family, address in [('-4', '127.0.0.1'), ('-6', '::1')]:
        result = subprocess.run(['ping', family, '-n', '-c', '1', '-W', '1', address],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        require(result.returncode == 0, f'ping {family} failed: {result.stderr.decode(errors="replace")}')


def export_check(service, packets):
    raw = service.request('/api/export', binary=True)
    require(len(raw) >= 24, 'pcap global header missing')
    magic, major, minor, zone, sigfigs, snaplen, datalink = struct.unpack('<IHHIIII', raw[:24])
    require((magic, major, minor, zone, sigfigs, snaplen) ==
            (0xa1b2c3d4, 2, 4, 0, 0, 65535), 'pcap header mismatch')
    require(datalink in (1, 113, 276), f'unexpected any datalink {datalink}')
    position = 24
    for packet in packets:
        require(position + 16 <= len(raw), 'missing pcap record')
        sec, usec, caplen, wirelen = struct.unpack_from('<IIII', raw, position)
        position += 16
        detail = service.request('/api/packets/' + str(packet['id']))
        require((sec * 1000000 + usec, caplen, wirelen) ==
                (packet['timestamp_us'], packet['caplen'], packet['length']), 'pcap record metadata mismatch')
        require(raw[position:position + caplen] == bytes.fromhex(detail['hex']), 'pcap bytes mismatch')
        position += caplen
    require(position == len(raw), 'extra/truncated pcap bytes')
    with tempfile.TemporaryDirectory(prefix='wirelens-test-') as directory:
        path = Path(directory, 'capture.pcap')
        path.write_bytes(raw)
        result = subprocess.run(['tcpdump', '-nn', '-tt', '-r', str(path)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        require(result.returncode == 0, f'tcpdump failed: {result.stderr!r}')
        lines = result.stdout.decode().splitlines()
        require(len(lines) == len(packets), 'tcpdump packet count differs from API')
        for line, packet in zip(lines, packets):
            timestamp = round(float(line.split()[0]) * 1000000)
            require(abs(timestamp - packet['timestamp_us']) <= 1, 'tcpdump timestamp differs')
        text = '\n'.join(lines)
        for marker in ('19877', '19878', '19879', 'ICMP echo', 'ICMP6, echo'):
            require(marker in text, f'tcpdump missing {marker}')
    print(f'  export: {len(packets)} records match API bytes, metadata and tcpdump', flush=True)


def full_suite(args):
    capture_filter = '(tcp port 19877) or (udp port 19878) or (udp port 19879) or icmp or icmp6'
    with Service(args, 512) as service:
        service.request('/api/status', expected=401, authenticated=False)
        service.request('/api/status', headers={'X-Capture-Token': 'bad'}, expected=401)
        service.request('/api/status', headers={'Host': 'evil.invalid'}, expected=403)
        service.request('/api/status', headers={'Origin': 'http://evil.invalid'}, expected=403)
        service.request('/api/status', headers={'Sec-Fetch-Site': 'cross-site'}, expected=403)
        for value in ('', '-1', '+1', '1.5', 'x', '18446744073709551616'):
            service.request('/api/packets', params={'after': value}, expected=422)
        service.request('/api/packets', params={'protocol': 'BOGUS'}, expected=422)
        interfaces = service.request('/api/interfaces')['interfaces']
        require(any(item['name'] == 'any' for item in interfaces), 'any interface missing')
        for item in interfaces:
            require(isinstance(item['name'], str) and isinstance(item['description'], str)
                    and isinstance(item['addresses'], list) and isinstance(item['loopback'], bool)
                    and all(isinstance(a, str) for a in item['addresses']), 'interface schema')
        helper = subprocess.run([args.helper, '--interfaces'], capture_output=True, timeout=5)
        require(helper.returncode == 0, 'helper --interfaces failed')
        require({i['name'] for i in json.loads(helper.stdout)['interfaces']} ==
                {i['name'] for i in interfaces}, 'helper/API interfaces differ')
        service.stop()  # Initially idle and idempotent.
        initial = service.start(capture_filter)
        require(initial['state'] == 'running', 'capture did not start')
        service.start(capture_filter, expected=409)
        traffic()
        eventually(lambda: {'HTTP', 'UDP', 'ICMP', 'ICMPv6'} <=
                   {p['protocol'] for p in service.packets()['packets']}, 'all traffic protocols captured')
        eventually(lambda: service.status()['stats']['supported'], 'periodic pcap statistics', timeout=3)
        stopped = service.stop()
        require(stopped['retained'] > 0 and stopped['evicted'] == 0, 'unexpected retention')
        snapshot = service.packets()
        traffic()  # Stopped capture must not ingest new traffic.
        time.sleep(0.2)
        require(service.status() == stopped and service.packets() == snapshot, 'counts/data changed after stop')
        require(service.stop() == stopped, 'stop is not idempotent')
        for interface, bpf in [('wirelens-no-such-interface', ''), ('any', 'tcp and (')]:
            service.start(bpf, interface, expected=422)
            require(service.status() == stopped and service.packets() == snapshot,
                    'failed start changed old session/data')
            require(not children(service.process.pid), 'failed start leaked child')
        packets = snapshot['packets']
        for protocol in ('HTTP', 'TCP', 'UDP', 'IPv4', 'IPv6', 'ICMP', 'ICMPv6'):
            expected = [p for p in packets if protocol in (p['protocol'], p['network'], p['transport'])]
            require(expected and service.packets(protocol=protocol)['packets'] == expected,
                    f'{protocol} filter mismatch')
        for query in ('19877', '127.0.0.1', 'WIRELENS-INTEGRATION', 'no-match-wirelens-zz'):
            expected = [p for p in packets if query.lower() in
                        f"{p['source']} {p['destination']} {p['summary']} {p['protocol']} {p['source_port']} {p['destination_port']}".lower()]
            require(service.packets(search=query)['packets'] == expected, 'search mismatch: ' + query)
        require(not service.packets(after=snapshot['cursor'])['packets'], 'cursor repeats packets')
        details = []
        for packet in packets:
            detail = service.request('/api/packets/' + str(packet['id']))
            details.append(detail)
            raw = bytes.fromhex(detail['hex'])
            require(len(raw) == packet['caplen'] and detail['fields'], 'detail hex/fields missing')
            for field in detail['fields']:
                offset, length = field['offset'], field['length']
                require(0 <= offset <= len(raw) and 0 <= length <= len(raw) - offset, 'field out of bounds')
                value = raw[offset:offset + length]
                if field['name'] in ('source_port', 'destination_port'):
                    require(int.from_bytes(value, 'big') == int(field['value']), 'port field offset mismatch')
                if field['section'] == 'HTTP':
                    require(value.decode().rstrip('\r\n') == detail['http_line'], 'HTTP field offset mismatch')
        tcp = [p for p in packets if p['transport'] == 'TCP']
        flow_ids = {p['flow_id'] for p in tcp}
        require(len(flow_ids) == 1 and '' not in flow_ids, 'TCP directions do not share one flow ID')
        require(any(p['source_port'] == 19877 for p in tcp) and
                any(p['destination_port'] == 19877 for p in tcp), 'TCP bidirectional traffic missing')
        flow_id = next(iter(flow_ids))
        require(service.packets(flow=flow_id)['packets'] == tcp, 'flow filter mismatch')
        flows = service.request('/api/flows')['flows']
        require(len(flows) == 1 and flows[0]['id'] == flow_id and flows[0]['packets'] == len(tcp)
                and flows[0]['bytes'] == sum(p['length'] for p in tcp), 'flow aggregate mismatch')
        export_check(service, packets)
        restarted = service.start('udp port 19878')
        require(restarted['session'] == initial['session'] + 1 and restarted['received'] == 0
                and restarted['retained'] == 0 and restarted['evicted'] == 0, 'restart did not clear session')
        require(not service.packets()['packets'] and not service.request('/api/flows')['flows'], 'restart data not cleared')
        service.request('/api/packets/' + str(packets[0]['id']), expected=404)
        time.sleep(1.1)  # Idle helper must still emit stats and stop promptly.
        service.stop()
        service.start('udp port 19878')  # Exit context while active: exercises shutdown child cleanup.
    print('PASS security, interfaces, real IPv4/IPv6 traffic, filters, details, flows, export, lifecycle', flush=True)


def eviction_suite(args):
    with Service(args, args.capacity) as service:
        service.start('udp port 19878')
        udp()
        first = eventually(lambda: service.packets()['packets'], 'first retained packet')[0]['id']
        udp(count=args.capacity * 3)
        eventually(lambda: service.status()['evicted'] > args.capacity, 'capacity eviction')
        service.stop()
        status = service.status()
        page = service.packets(after=first)
        require(status['retained'] == args.capacity and status['evicted'] == status['received'] - args.capacity,
                'capacity/eviction accounting mismatch')
        require(page['gap'] and page['oldest_id'] == status['oldest_id'] > first + 1,
                'eviction gap missing')
        require(len(page['packets']) == args.capacity and page['cursor'] == status['latest_id'], 'eviction cursor mismatch')
        service.request('/api/packets/' + str(first), expected=404)
    print(f'PASS capacity={args.capacity}, eviction gap, expired detail 404, child cleanup', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', default='build/wirelens')
    parser.add_argument('--helper', default='/opt/wirelens/libexec/wirelens-capture')
    parser.add_argument('--port', type=int, default=18888)
    parser.add_argument('--capacity', type=int, default=8, help='small-capacity eviction phase (2..64)')
    args = parser.parse_args()
    require(os.getuid() != 0 and os.geteuid() != 0, 'Run as an ordinary user, for example runuser -u exp1a -- python3 tests/integration.py')
    require(2 <= args.capacity <= 64, '--capacity must be 2..64')
    for command in ('ping', 'tcpdump'):
        require(shutil.which(command), command + ' must already be installed')
    with traffic_endpoints():
        full_suite(args)
        eviction_suite(args)
    print('ALL INTEGRATION TESTS PASSED', flush=True)


if __name__ == '__main__':
    main()
