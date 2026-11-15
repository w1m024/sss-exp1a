#!/usr/bin/env python3
"""Linux, ordinary-user fault regressions; no capture privileges or packages required.

Run: python3 tests/faults.py --server build/wirelens
Creates a temporary executable launcher, starts its own server on a loopback port,
and cleans up the server and workers on success and failure. Python -O is supported.
"""

import argparse
import contextlib
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


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def eventually(probe, description, timeout=3):
    deadline = time.monotonic() + timeout
    while True:
        result = probe()
        if result:
            return result
        if time.monotonic() >= deadline:
            raise AssertionError("Timed out: " + description)
        time.sleep(0.02)


class Service:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.token = ""
        self.workers = set()
        self.process = None

    def request(self, path, method="GET", params=None, expected=200, timeout=4.5):
        headers = {"X-Capture-Token": self.token}
        body = None
        if params is not None:
            body = urllib.parse.urlencode(params)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            connection.request(method, "/api" + path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            require(response.status == expected,
                    f"{method} {path}: expected {expected}, got {response.status}: {raw[:300]!r}")
            return json.loads(raw)
        finally:
            connection.close()

    def launch(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        helper = self.root / "replay-helper"
        source = Path(__file__).with_name("replay_helper.py").resolve()
        helper.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " " +
                          shlex.quote(str(source)) + ' "$@"\n', encoding="utf-8")
        helper.chmod(0o700)
        environment = dict(os.environ, WIRELENS_REPLAY_DIR=str(self.root))
        self.log = (self.root / "server.log").open("w+b")
        self.process = subprocess.Popen(
            [str(self.args.server.resolve()), "--port", str(self.port),
             "--capture-helper", str(helper), "--web-dir", str(self.args.web_dir.resolve())],
            env=environment, stdout=self.log, stderr=self.log, start_new_session=True)

        def ready():
            require(self.process.poll() is None, "Server exited during startup")
            try:
                return self.request("/session", timeout=0.2)
            except ConnectionRefusedError:
                return None  # Wait for this local process to bind, not an external network retry.

        self.token = eventually(ready, "local server startup", timeout=5)["token"]

    def pid(self, mode):
        path = self.root / (mode + ".pid")
        pid = eventually(lambda: int(path.read_text()) if path.exists() else None, "worker PID")
        self.workers.add(pid)
        return pid

    def start(self, mode):
        for suffix in (".pid", ".go"):
            (self.root / (mode + suffix)).unlink(missing_ok=True)
        result = self.request("/start", "POST", {"interface": mode, "filter": ""})
        self.pid(mode)
        return result

    def reaped(self, pid):
        # Unlike kill(pid, 0), this also fails while the child is a zombie.
        eventually(lambda: not Path(f"/proc/{pid}").exists(), f"worker {pid} reaped", timeout=2)
        self.workers.discard(pid)

    def error(self):
        def probe():
            status = self.request("/status")
            return status if status["state"] == "error" else None
        status = eventually(probe, "error state")
        require(bool(status["error"]), "error state must have a diagnostic")
        return status

    def close(self):
        # Always release stopped workers, even if an assertion or HTTP timeout failed.
        for path in self.root.glob("*.pid"):
            with contextlib.suppress(ValueError, OSError):
                self.workers.add(int(path.read_text()))
        for pid in self.workers:
            with contextlib.suppress(ProcessLookupError, FileNotFoundError):
                status = Path(f"/proc/{pid}/status").read_text()
                parent = next(line.split()[1] for line in status.splitlines() if line.startswith("PPid:"))
                # Old PID files may outlive a reaped child; never signal a reused PID.
                if self.process is not None and int(parent) == self.process.pid:
                    os.kill(pid, signal.SIGKILL)
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=3)
            else:
                self.process.wait()
        if hasattr(self, "log"):
            self.log.seek(0)
            output = self.log.read().decode("utf-8", errors="replace")
            self.log.close()
            if sys.exc_info()[0] is not None:
                print("Server log:\n" + output, file=sys.stderr)


def handshake_timeout(service):
    before = service.request("/status")
    started = time.monotonic()
    failure = service.request("/start", "POST", {"interface": "partial", "filter": ""}, expected=500)
    elapsed = time.monotonic() - started
    require(2.95 <= elapsed < 4, f"Partial handshake took {elapsed:.3f}s, expected about 3–4s")
    require("handshake" in failure["error"].lower(), "Expected a handshake diagnostic")
    service.reaped(service.pid("partial"))
    after = service.request("/status")
    require(after["session"] == before["session"], "Failed handshake changed session")
    service.start("idle")
    stopped = service.request("/stop", "POST")
    require(stopped["state"] == "stopped", "Server cannot stop after handshake failure")
    service.reaped(service.pid("idle"))
    print(f"PASS partial handshake deadline and subsequent start/stop ({elapsed:.3f}s)")


def stopped_worker(service):
    service.start("idle")
    pid = service.pid("idle")
    os.kill(pid, signal.SIGSTOP)
    def stopped():
        text = Path(f"/proc/{pid}/status").read_text()
        return any(line.startswith("State:") and line.split()[1] in {"T", "t"}
                   for line in text.splitlines())
    eventually(stopped, "worker entered SIGSTOP")
    started = time.monotonic()
    result = service.request("/stop", "POST", timeout=2)
    elapsed = time.monotonic() - started
    require(elapsed < 2, f"SIGSTOP worker stop took {elapsed:.3f}s")
    require(result["state"] == "error" and result["error"], "Forced stop must be diagnosed")
    service.reaped(pid)
    print(f"PASS SIGSTOP worker bounded stop and reap ({elapsed:.3f}s)")


def unexpected_exits(service):
    for mode in ("exit-zero", "exit-seven", "idle"):
        service.start(mode)
        pid = service.pid(mode)
        if mode == "idle":
            os.kill(pid, signal.SIGTERM)
        else:
            (service.root / (mode + ".go")).touch()
        service.error()
        service.reaped(pid)
    print("PASS unexpected exit(0), exit(7), and external SIGTERM report error")


def invalid_lengths(service):
    for mode in ("bad-wire", "oversize"):
        service.start(mode)
        status = service.error()
        require("packet frame" in status["error"].lower(), "Expected invalid-record diagnostic")
        require(status["received"] == 0 and status["retained"] == 0, "Invalid record was retained")
        require(service.request("/packets")["packets"] == [], "Invalid record reached packet API")
        service.reaped(service.pid(mode))
    print("PASS caplen > wirelen and caplen > 65535 rejected")


def replay(service, mode, count):
    service.start(mode)
    eventually(lambda: service.request("/status")["received"] == count, "replay records")
    stopped = service.request("/stop", "POST")
    require(stopped["state"] == "stopped", f"Unexpected replay failure: {stopped}")
    service.reaped(service.pid(mode))
    packets = service.request("/packets")["packets"]
    require(len(packets) == count, "Replay packet count differs")
    return packets


def grouping(service):
    packets = replay(service, "incomplete-tcp", 3)
    require(all(not p["flow_id"] for p in packets), "Incomplete TCP entered a flow")
    require(all(not p["ports_known"] for p in packets), "Incomplete TCP exposed guessed ports")
    require(all(p["fragmented"] for p in packets[:2]), "Fragment fixtures not recognized")
    require(packets[2]["truncated"], "Truncated TCP fixture not recognized")
    require(service.request("/flows")["flows"] == [], "Incomplete TCP produced flow summaries")
    packets = replay(service, "flows", 6)
    ids = [p["flow_id"] for p in packets]
    require(all(ids), "Complete TCP did not enter flows")
    require(ids[0] != ids[1], "New SYN merged with midstream ACK")
    require(ids[1] == ids[2] == ids[3] == ids[4],
            "SYN retransmission or opposite-direction simultaneous SYN split a flow")
    require(ids[5] != ids[1] and ids[5] != ids[0], "Changed SYN sequence reused an old flow")
    flows = service.request("/flows")["flows"]
    require({f["id"]: f["packets"] for f in flows} == {ids[0]: 1, ids[1]: 4, ids[5]: 1},
            "Flow summary counts disagree with packet grouping")
    print("PASS fragments/truncation excluded; new SYN, retransmission, simultaneous SYN grouping")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, default=Path("build/wirelens"))
    parser.add_argument("--web-dir", type=Path, default=Path(__file__).resolve().parents[1] / "web")
    args = parser.parse_args()
    require(sys.platform.startswith("linux"), "Run on Linux/WSL, without sudo")
    require(os.getuid() != 0 and os.geteuid() != 0, "Run as an ordinary user, without sudo")
    require(args.server.is_file(), f"Server binary not found: {args.server}")
    with tempfile.TemporaryDirectory(prefix="wirelens-faults-") as directory:
        service = Service(args, Path(directory))
        try:
            service.launch()
            handshake_timeout(service)
            stopped_worker(service)
            unexpected_exits(service)
            invalid_lengths(service)
            grouping(service)
        finally:
            service.close()
    print("PASS all fault regressions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
