#!/usr/bin/env python3
"""Ordinary-user deterministic timeline integration: python3 tests/timeline.py.
Uses only the standard library, a private loopback port and temporary IPC helper.
Bucket intervals are [start, end), except the final bucket includes end.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

from faults import Service, eventually, require
from replay_helper import ethernet_tcp, message
import struct

BASE = 1700000000000000


def fixtures(mode):
    if mode.startswith('http-'):
        request = b'GET /index HTTP/1.1\r\nHost: local.test\r\n\r\nHEAD /next HTTP/1.1\r\n\r\n'
        response = b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntestHTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n'
        if mode in ('http-chunked', 'http-bad-chunk', 'http-short-chunk'):
            chunk = {'http-chunked': b'4;part=1\r\ntest\r\n0\r\nX-End: yes\r\n\r\n',
                     'http-bad-chunk': b'Z\r\ntest\r\n',
                     'http-short-chunk': b'4\r\nte'}[mode]
            response = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n' + chunk
            if mode == 'http-chunked':
                response += b'HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n'
        if mode.startswith('http-close-'):
            request = request.split(b'HEAD')[0]
            response = b'HTTP/1.0 200 OK\r\n\r\nclose-delimited'
        if mode == 'http-unsupported':
            response = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: custom\r\n\r\nencoded'
        if mode == 'http-limit':
            response = b'HTTP/1.1 200 OK\r\nX-Long: ' + b'x' * 33000
        frames = [ethernet_tcp(100, 2), ethernet_tcp(200, 18, True, ack=101),
                  ethernet_tcp(108, body=request[7:])]
        if mode != 'http-gap':
            frames += [ethernet_tcp(101, body=request[:7]), ethernet_tcp(101, body=request[:7])]
        if mode == 'http-conflict':
            frames.append(ethernet_tcp(101, body=b'X'))
        step = 8192 if mode == 'http-limit' else 18
        if mode.startswith('http-close-'):
            step = 20
        frames += [ethernet_tcp(201 + i, reverse=True, body=response[i:i+step])
                   for i in range(0, len(response), step)]
        if mode.startswith('http-close-'):
            fin_seq = 201 + len(response)
            if mode == 'http-close-gap':
                frames.pop()
            if mode == 'http-close-reset':
                frames.append(ethernet_tcp(fin_seq, 20, True))
            if mode == 'http-close-client':
                frames.append(ethernet_tcp(101 + len(request), 17))
            elif mode == 'http-close-fin-data':
                frames[-1] = ethernet_tcp(201 + step, 17, True, body=response[step:])
            elif mode != 'http-close-open':
                frames.append(ethernet_tcp(fin_seq, 17, True))
            if mode == 'http-close-early-fin':
                frames[-2], frames[-1] = frames[-1], frames[-2]
            if mode == 'http-close-midstream':
                frames = frames[2:]
        if mode == 'http-midstream':
            frames = frames[2:]
        elif mode == 'http-midstream-syn':
            del frames[1]
        elif mode == 'http-midstream-response-first':
            frames = frames[5:6] + frames[2:5] + frames[6:]
            # 先观察到响应时，不应把它配给稍后捕获的请求。
        elif mode == 'http-midstream-body':
            frames = [ethernet_tcp(91, body=b'body\r\n'), *frames[2:]]
        return [(BASE + i * 1000, len(frame) + (1 if mode == 'http-truncated' and i == len(frames)-1 else 0), frame)
                for i, frame in enumerate(frames)]
    if mode == "empty":
        return []
    if mode == "single":
        return [(BASE, 101, ethernet_tcp())]
    # 构造非递增时间戳、重复时间、分桶边界、
    # 原始长度大于捕获长度的包，以及另一种协议。
    stamps = [BASE + (i * 7919 % 16001) for i in range(1201)]
    stamps[-7:] = [BASE, BASE + 16000, BASE + 1000, BASE + 999,
                  BASE + 1000, BASE + 15999, BASE + 2000]
    return [(stamp, 100 + i % 97,
             ethernet_tcp() if i % 5 else bytes.fromhex("00112233445566778899aabb88b5"))
            for i, stamp in enumerate(stamps)]


def helper_main():
    mode = sys.argv[3]
    message(1, struct.pack("!I", 1))
    for stamp, length, data in fixtures(mode):
        message(2, struct.pack("!QII", stamp, length, len(data)) + data)
    while True:
        time.sleep(0.02)


class TimelineService(Service):
    def launch(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        helper = self.root / "timeline-helper"
        helper.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " " +
                          shlex.quote(str(Path(__file__).resolve())) + ' --helper "$@"\n')
        helper.chmod(0o700)
        # 使用临时静态文件，让后端测试不依赖前端下载。
        web = self.root / "web"
        for name in ["index.html", "app.css", "app.js", "timeline.js", "vendor/split.js", "vendor/echarts.min.js"] + [
                "vendor/devtools/" + name + ".svg" for name in
                ("record-start", "record-stop", "filter", "download", "clear-list", "search", "right-panel-close")]:
            target = web / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("/* test asset */")
        self.log = (self.root / "server.log").open("w+b")
        self.process = subprocess.Popen([str(self.args.server.resolve()), "--port", str(self.port),
            "--capture-helper", str(helper), "--web-dir", str(web), "--capacity", "1100"],
            stdout=self.log, stderr=self.log, start_new_session=True)

        def ready():
            require(self.process.poll() is None, "Server exited during startup")
            try:
                return self.request("/session", timeout=0.2)
            except ConnectionRefusedError:
                return None
        self.token = eventually(ready, "local startup", timeout=5)["token"]

    def replay(self, mode):
        self.request("/start", "POST", {"interface": mode})
        eventually(lambda: self.request("/status")["received"] == len(fixtures(mode)), "replay")
        self.request("/stop", "POST")

    def get(self, route, **params):
        return self.request(route + "?" + urllib.parse.urlencode(params))

    def all_packets(self, **params):
        result, cursor = [], params.pop("after", 0)
        while True:
            page = self.get("/packets", after=cursor, **params)
            result.extend(page["packets"])
            if page["cursor"] == cursor:
                return result
            require(page["cursor"] > cursor, "Cursor regressed")
            cursor = page["cursor"]


def check_timeline(s, packets, **params):
    timeline = s.get("/timeline", **params)
    require(timeline["matched"] == len(packets), "Matched count")
    require(timeline["bytes"] == sum(p["length"] for p in packets), "Wire bytes")
    bins = timeline["bins"]
    if not packets:
        require(bins == [] and timeline["start_us"] == timeline["end_us"] == 0, "Empty timeline")
        return
    start = min(p["timestamp_us"] for p in packets)
    end = max(start + 1000, max(p["timestamp_us"] for p in packets))
    require((timeline["start_us"], timeline["end_us"]) == (start, end), "Actual min/max")
    n = int(params.get("bins", 80))
    require(len(bins) == n, "Bin count")
    for i, bucket in enumerate(bins):
        lo, hi = start + (end - start) * i // n, start + (end - start) * (i + 1) // n
        require((bucket["start_us"], bucket["end_us"]) == (lo, hi), "Integer boundaries")
        selected = [p for p in packets if lo <= p["timestamp_us"] and
                    (p["timestamp_us"] < hi or i == n - 1 and p["timestamp_us"] == hi)]
        require(bucket["packets"] == len(selected), "Bucket packets")
        require(bucket["bytes"] == sum(p["length"] for p in selected), "Bucket wire bytes")
    require(sum(b["packets"] for b in bins) == timeline["matched"], "Packet conservation")
    require(sum(b["bytes"] for b in bins) == timeline["bytes"], "Byte conservation")
    status = s.request("/status")
    require(all(timeline[k] == status[k] for k in ("session", "oldest_id", "latest_id")), "Snapshot IDs")


def run(s):
    token = s.token
    s.token = ""
    s.request("/timeline", expected=401)
    s.token = token
    c = http.client.HTTPConnection("127.0.0.1", s.port)
    try:
        c.request("GET", "/api/timeline", headers={"Host": "evil.example", "X-Capture-Token": token})
        response = c.getresponse()
        require(response.status == 403, "Host guard")
        response.read()
    finally:
        c.close()
    check_timeline(s, [])
    for mode in ("empty", "single", "many"):
        s.replay(mode)
        packets = s.all_packets()
        check_timeline(s, packets, bins=16)
        check_timeline(s, packets, bins=200)
        check_timeline(s, packets, bins=17)
        if mode != "many":
            continue
        require(len(packets) == 1100, "Must aggregate more than 1000 retained packets")
        expected_frames = fixtures(mode)[-1100:]
        require([(p["timestamp_us"], p["length"]) for p in packets] ==
                [(t, length) for t, length, _ in expected_frames], "Replay content")
        require(len(s.all_packets(protocol="TCP")) == sum(i % 5 != 0 for i in range(101, 1201)),
                "TCP fixture classification")
        require(s.all_packets(protocol="TCP", search="NO-MATCH") == [], "Search intersection")
        first = packets[0]["id"]
        require(s.get("/packets", after=first - 2)["gap"], "Eviction gap")
        check_timeline(s, packets, after=first - 2)
        flow = next(p["flow_id"] for p in packets if p["flow_id"])
        for params in ({"protocol": "TCP"}, {"protocol": "IPv4", "search": "192.0.2.1"},
                       {"protocol": "TCP", "search": "192.0.2.1", "flow": flow},
                       {"protocol": "UNKNOWN"}, {"protocol": "UDP"},
                       {"search": "no-match"}, {"flow": "missing"},
                       {"after": packets[501]["id"]}, {"after": packets[-1]["id"]}):
            check_timeline(s, s.all_packets(**params), **params)
        for params in ({"from_us": BASE + 1000, "to_us": BASE + 2000},
                       {"from_us": BASE + 1000, "to_us": BASE + 1000},
                       {"from_us": BASE + 8000}, {"to_us": BASE + 8000},
                       {"from_us": BASE + 20000}, {"to_us": 1}):
            expected = [p for p in packets if params.get("from_us", 1) <= p["timestamp_us"] <=
                        params.get("to_us", 2**63 - 1)]
            require(s.all_packets(**params) == expected, "Closed interval / paged cursor")
            page = s.get("/packets", after=packets[-1]["id"] - 1, from_us=BASE + 20000)
            require(page["packets"] == [] and page["cursor"] == packets[-1]["id"], "Excluded scan cursor")
            check_timeline(s, packets, **params)  # Time selection never narrows context.
        # 时间端点可与其他显示过滤条件一起使用。
        selected = s.all_packets(protocol="TCP", search="192.0.2.1", flow=flow)
        require(s.all_packets(protocol="TCP", search="192.0.2.1", flow=flow, to_us=BASE + 8000) ==
                [p for p in selected if p["timestamp_us"] <= BASE + 8000], "Combined filters")
    for value in ("", "0", "15", "201", "-1", "1.5", "18446744073709551616"):
        s.request("/timeline?" + urllib.parse.urlencode({"bins": value}), expected=422)
    for name in ("from_us", "to_us"):
        for value in ("", "0", "-1", "1.5", "9223372036854775808", "18446744073709551616"):
            s.request("/packets?" + urllib.parse.urlencode({name: value}), expected=422)
    s.request("/packets?from_us=2&to_us=1", expected=422)
    s.get("/packets", from_us=2**63 - 1)
    for route in ("/packets", "/timeline"):
        for params in ({"protocol": "bogus"}, {"after": "-1"}, {"after": "18446744073709551616"},
                       {"search": "x" * 257}, {"flow": "x" * 65}):
            s.request(route + "?" + urllib.parse.urlencode(params), expected=422)
    print("PASS timeline boundaries, conservation, wire bytes, >1000 packets, filters, pagination, gap, auth and validation")
    failure_states = {'http-gap': 'missing_segments', 'http-conflict': 'conflicting_overlap',
                      'http-bad-chunk': 'invalid_framing', 'http-short-chunk': 'incomplete_message',
                      'http-unsupported': 'unsupported_framing', 'http-limit': 'analysis_limit',
                      'http-truncated': 'truncated_capture'}
    failure_states.update({'http-midstream-response-first': 'missing_handshake',
                           'http-midstream-body': 'missing_handshake'})
    success_modes = ('http-complete', 'http-chunked', 'http-midstream', 'http-midstream-syn')
    for mode in (*success_modes, *failure_states):
        s.replay(mode)
        flow = s.request('/flows')['flows'][0]['id']
        result = s.get('/flows/http', flow=flow)
        if mode in success_modes:
            require(result['state'] == 'complete', result)
            require(result['partial_capture'] == mode.startswith('http-midstream'), result)
            exchanges = result['exchanges']
            require([e['request'] for e in exchanges] == ['GET /index HTTP/1.1', 'HEAD /next HTTP/1.1'], result)
            require(all(e['response'] == 'HTTP/1.1 200 OK' for e in exchanges), result)
            packet = s.request('/packets/' + str(exchanges[0]['request_packet']))
            require(bytes.fromhex(packet['hex']).endswith(b'GET /in'), 'first request byte provenance')
            require(exchanges[0]['elapsed_us'] == 2000, result)
            require(exchanges[0]['target'] == '/index' and exchanges[0]['status'] == 200, result)
            require(exchanges[0]['request_details']['headers'] == 'Host: local.test', result)
            require(exchanges[0]['response_details']['body_bytes'] == 4, result)
            require(exchanges[1]['response_details']['body_bytes'] == 0, result)
            require(exchanges[0]['response_complete_us'] > exchanges[0]['response_us'], result)
            require(exchanges[0]['response_last_packet'] != exchanges[0]['response_packet'], result)
            expected = 'chunked' if mode == 'http-chunked' else 'content-length'
            require(exchanges[0]['response_details']['framing'] == expected, result)
        else:
            require(result['state'] == failure_states[mode], result)
            if mode != 'http-truncated':
                require(result['exchanges'] == [], result)
    for mode, state in {
        'http-close-fin': 'complete', 'http-close-early-fin': 'complete',
        'http-close-midstream': 'complete', 'http-close-fin-data': 'complete',
        'http-close-gap': 'awaiting_close', 'http-close-open': 'awaiting_close',
        'http-close-reset': 'awaiting_close', 'http-close-client': 'awaiting_close',
    }.items():
        s.replay(mode)
        flow = s.request('/flows')['flows'][0]['id']
        result = s.get('/flows/http', flow=flow)
        require(result['state'] == state, result)
        require(len(result['exchanges']) == int(state == 'complete'), result)
        if state == 'complete':
            exchange = result['exchanges'][0]
            require(exchange['response_details']['framing'] == 'close-delimited', result)
            require(exchange['response_details']['body_bytes'] == len(b'close-delimited'), result)
            require(result['partial_capture'] == mode.endswith('midstream'), result)
            fin = s.request('/packets/' + str(exchange['response_fin_packet']))
            last = s.request('/packets/' + str(exchange['response_last_packet']))
            require((fin['id'] == last['id']) == mode.endswith('fin-data'), result)
            require(exchange['response_complete_us'] == max(fin['timestamp_us'], last['timestamp_us']), result)
    print('PASS HTTP close-delimited framing, FIN, RST, missing bytes, and partial capture')
    print('PASS HTTP reassembly, out-of-order segments, retransmission, gap, conflicting overlap, fixed body, HEAD and packet provenance')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, default=Path("build/wirelens"))
    args = parser.parse_args()
    require(sys.platform.startswith("linux") and os.geteuid() != 0, "Run on Linux as an ordinary user")
    require(args.server.is_file(), "Build server first")
    with tempfile.TemporaryDirectory(prefix="wirelens-timeline-") as directory:
        service = TimelineService(args, Path(directory))
        try:
            service.launch()
            run(service)
        finally:
            service.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--helper":
        helper_main()
    else:
        main()
