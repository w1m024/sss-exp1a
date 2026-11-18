#!/usr/bin/env python3
"""Observe real PID ownership, multiple connections, isolation and exit history."""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import socket
import subprocess
import sys

from integration import Service, eventually, require

CHILD = '''
import socket,sys
s=socket.socket(socket.AF_INET6 if sys.argv[1]=='6' else socket.AF_INET)
s.bind(('::1' if sys.argv[1]=='6' else '127.0.0.1',0));s.listen(4)
print(s.getsockname()[1],flush=True)
connections=[s.accept()[0] for _ in range(3)]
print('ready',flush=True)
sys.stdin.readline()
for c in connections:c.close()
s.close()
'''


def main():
    args = argparse.Namespace(server=str(Path('build/wirelens').resolve()),
                              helper='/opt/wirelens/libexec/wirelens-capture', port=18894)
    with Service(args, 5000) as service:
        service.start('tcp and not port 18894 and not port 8080 and not port 8081')
        for version in (4, 6):
            child = subprocess.Popen([sys.executable, '-u', '-c', CHILD, str(version)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            try:
                port = int(child.stdout.readline())
                with ExitStack() as stack:
                    clients = [stack.enter_context(socket.socket(socket.AF_INET6 if version == 6 else socket.AF_INET)) for _ in range(3)]
                    for client in clients: client.connect(('::1' if version == 6 else '127.0.0.1', port))
                    require(child.stdout.readline().strip() == 'ready', 'child accepted three connections')
                    def owned():
                        for client in clients: client.sendall(b'ownership observation\n')
                        rows = service.request('/api/flows')['flows']
                        matches = [f for f in rows if any(p['pid'] == child.pid for p in f.get('processes', []))]
                        return matches if len(matches) == 3 else None
                    flows = eventually(owned, f'IPv{version} PID ownership')
                    owner = next(p for p in flows[0]['processes'] if p['pid'] == child.pid)
                    require(owner['uid'] == os.getuid() and owner['start_ticks'].isdigit(), 'UID and PID reuse identity')
                    expected = {f['id'] for f in flows}
                    packets = service.request('/api/packets', params={'search': 'process:' + owner['key']})['packets']
                    require({p['flow_id'] for p in packets} == expected, 'one process selects all three flows')
                    require(all(any(p['pid'] == child.pid for p in row['processes']) for row in packets), 'no unrelated ownership')
                    timeline = service.request('/api/timeline', params={'search': 'process:' + owner['key']})
                    require(timeline['matched'] >= len(packets), 'process filtering reaches timeline')
                    require(service.request('/api/packets', params={'search': 'process:99999999:1'})['packets'] == [], 'unknown process never guessed')
                    child.stdin.write('\n'); child.stdin.flush(); child.wait(timeout=3)
                    historical = service.request('/api/flows')['flows']
                    require(all(any(p['key'] == owner['key'] for p in f['processes']) for f in historical if f['id'] in expected), 'exit preserves observed history')
            finally:
                if child.poll() is None: child.terminate()
                child.wait(timeout=3)
                child.stdin.close(); child.stdout.close()
        service.request('/api/stop', method='POST')
    print('PASS IPv4/IPv6 real child PID, three flows per process, exact identity filter, unknown PID and exit history')


if __name__ == '__main__':
    main()
