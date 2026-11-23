#!/usr/bin/env python3
"""Test eBPF attribution after both ends of a loopback connection have exited."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from integration import Service, eventually, require

TRAFFIC = """
import socket, subprocess, sys
family, host = (socket.AF_INET, '127.0.0.1') if sys.argv[1] == '4' else (socket.AF_INET6, '::1')
with socket.socket(family) as listener:
    listener.bind((host, 0))
    listener.listen()
    port = listener.getsockname()[1]
    code = 'import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2]))).close()'
    client = subprocess.Popen([sys.executable, '-c', code, host, str(port)])
    peer, _ = listener.accept()
    peer.close()
    if client.wait() != 0:
        raise SystemExit(1)
    print(port, client.pid)
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', default='/opt/wirelens/libexec/wirelens-capture')
    parser.add_argument('--port', type=int, default=18895)
    parser.add_argument('--rounds', type=int, default=1, help='Connections per IP family')
    args = parser.parse_args()
    require(args.rounds > 0, 'rounds must be positive')
    args.server = str(Path('build/wirelens').resolve())
    require(os.environ.get('WIRELENS_TCP_OWNER_EVENTS'), 'Start the collector and set WIRELENS_TCP_OWNER_EVENTS')
    expected_count = missed_count = incorrect_count = 0
    with Service(args, 5000) as service:
        service.start(f'tcp and not port {args.port}')
        for version in ('4', '6') * args.rounds:
            # Pause the snapshot reader so it cannot observe either process alive.
            os.kill(service.process.pid, signal.SIGSTOP)
            try:
                with subprocess.Popen([sys.executable, '-c', TRAFFIC, version],
                                      stdout=subprocess.PIPE, text=True) as server:
                    output, _ = server.communicate(timeout=5)
                    require(server.returncode == 0, 'short loopback connection')
                    port, client = map(int, output.split())
                    pids = {server.pid, client}
                require(all(not Path('/proc', str(pid)).exists() for pid in pids), 'both endpoints exited')
            finally:
                os.kill(service.process.pid, signal.SIGCONT)

            def observed():
                rows = service.request('/api/flows')['flows']
                # 确认本轮的服务端端口，再检查受测 PID 在所有会话中的归属。
                matches = [row for row in rows if any(
                    row[side].endswith(f':{port}') for side in ('endpoint_a', 'endpoint_b'))]
                if len(matches) != 1:
                    return None
                flow = matches[0]
                actual = {(row['id'], p['pid']) for row in rows
                          for p in row['processes'] if p['pid'] in pids}
                expected = {(flow['id'], pid) for pid in pids}
                return flow, expected, actual

            flow, expected, actual = eventually(observed, f'IPv{version} flow')
            # 给事件文件读取和待匹配队列留出时间。失败时仍统计缺失的关联。
            deadline = time.monotonic() + 2
            while not expected <= actual and time.monotonic() < deadline:
                time.sleep(.05)
                flow, expected, actual = observed()
            expected_count += len(expected)
            missed_count += len(expected - actual)
            incorrect_count += len(actual - expected)
            for owner in flow['processes']:
                if owner['pid'] not in pids:
                    continue
                require(owner['uid'] == os.getuid() and owner['start_ticks'].isdigit(), 'owner identity')
                packets = service.packets(search='process:' + owner['key'])['packets']
                require(flow['id'] in {packet['flow_id'] for packet in packets}, 'process filter')
        service.stop()
    print(f'Live associations: matched={expected_count - missed_count}/{expected_count}, '
          f'missed={missed_count}, incorrect={incorrect_count}')
    require(not missed_count and not incorrect_count, 'unexpected live attribution errors')
    print('PASS eBPF IPv4/IPv6 short-lived connect and accept, process exit and API filtering')


if __name__ == '__main__':
    main()
