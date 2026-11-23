#!/usr/bin/env python3
"""Test eBPF attribution after both ends of a loopback connection have exited."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys

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
    args = parser.parse_args()
    args.server = str(Path('build/wirelens').resolve())
    require(os.environ.get('WIRELENS_TCP_OWNER_EVENTS'), 'Start the collector and set WIRELENS_TCP_OWNER_EVENTS')
    with Service(args, 5000) as service:
        service.start(f'tcp and not port {args.port}')
        for version in ('4', '6'):
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

            def attributed():
                rows = service.request('/api/flows')['flows']
                for row in rows:
                    owners = {p['pid']: p for p in row['processes']}
                    if pids <= owners.keys():
                        return row, owners
                return None

            flow, owners = eventually(attributed, f'IPv{version} attribution after process exit')
            for pid in pids:
                owner = owners[pid]
                require(owner['uid'] == os.getuid() and owner['start_ticks'].isdigit(), 'owner identity')
                packets = service.packets(search='process:' + owner['key'])['packets']
                require({packet['flow_id'] for packet in packets} == {flow['id']}, 'process filter')
                require(any(packet['source_port'] == port or packet['destination_port'] == port
                            for packet in packets), 'endpoint identity')
        service.stop()
    print('PASS eBPF IPv4/IPv6 short-lived connect and accept, process exit and API filtering')


if __name__ == '__main__':
    main()
