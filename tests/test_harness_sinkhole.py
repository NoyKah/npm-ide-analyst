# tests/test_harness_sinkhole.py
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

HARNESS = Path("src/npm_ide_analyst/sandbox/harness")
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _run(tmp_path: Path, driver_src: str, env_extra: dict | None = None,
         with_preload: bool = True, timeout: int = 20):
    driver = tmp_path / "driver.js"
    driver.write_text(driver_src, encoding="utf-8")
    log = tmp_path / "events.jsonl"
    env = {**os.environ, "ANALYST_EVENT_LOG": str(log)}
    if env_extra:
        env.update(env_extra)
    cmd = ["node"]
    if with_preload:
        cmd += ["-r", str((HARNESS / "preload.js").resolve())]
    cmd += [str(driver)]
    proc = subprocess.run(cmd, env=env, timeout=timeout, capture_output=True, text=True)
    events = ([json.loads(l) for l in log.read_text().splitlines() if l.strip()]
              if log.exists() else [])
    return proc, events


def test_sinkhole_mode_delegates_real_http(tmp_path):
    # A local server + a client request to it. In sinkhole mode the http hook
    # must delegate to the real implementation, so the response comes back.
    driver = """
    const http = require('http');
    const srv = http.createServer((req, res) => { res.end('pong'); });
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      http.get('http://127.0.0.1:' + port + '/probe', (res) => {
        let d = ''; res.on('data', c => d += c);
        res.on('end', () => { process.stdout.write('GOT:' + d + '\\n'); srv.close(); process.exit(0); });
      }).on('error', (e) => { process.stdout.write('ERR:' + e.message + '\\n'); process.exit(1); });
    });
    """
    proc, events = _run(tmp_path, driver, env_extra={"ANALYST_SINKHOLE": "1"})
    assert "GOT:pong" in proc.stdout                       # real request completed
    assert any(e["kind"] == "network" for e in events)     # still logged


def _wait_ready(proc_stdout_path: Path, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc_stdout_path.exists() and "SINKHOLE READY" in proc_stdout_path.read_text():
            return True
        time.sleep(0.1)
    return False


def test_sinkhole_responds_to_dns_and_http(tmp_path):
    # Run sinkhole.js on HIGH ports (no root needed) with HTTPS disabled (no cert),
    # then hit its DNS and HTTP listeners and assert it answers + logs.
    log = tmp_path / "requests.jsonl"
    stdout_path = tmp_path / "stdout.txt"
    sink = (HARNESS / "sinkhole.js").resolve()
    env = {**os.environ,
           "ANALYST_EVENT_LOG": str(log),
           "ANALYST_SINK_DNS_PORT": "5354",
           "ANALYST_SINK_HTTP_PORT": "8081",
           "ANALYST_SINK_CERT": str(tmp_path / "nope.pem"),   # absent -> HTTPS skipped
           "ANALYST_SINK_KEY": str(tmp_path / "nope.key")}
    with open(stdout_path, "w") as out:
        proc = subprocess.Popen(["node", str(sink)], env=env, stdout=out,
                                 stderr=subprocess.STDOUT)
    try:
        assert _wait_ready(stdout_path), "sinkhole never signalled ready"

        # DNS: send a minimal A query for "evil.test", expect a 4-byte A answer.
        query = (b"\x12\x34" b"\x01\x00" b"\x00\x01" b"\x00\x00\x00\x00\x00\x00"
                 b"\x04evil\x04test\x00" b"\x00\x01\x00\x01")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(query, ("127.0.0.1", 5354))
        resp, _ = s.recvfrom(512)
        s.close()
        assert resp[:2] == b"\x12\x34"            # echoed id
        assert (resp[6] << 8 | resp[7]) == 1      # ANCOUNT == 1 (A answered)

        # HTTP: request, expect 200 + logged c2 event.
        with urllib.request.urlopen("http://127.0.0.1:8081/beacon", timeout=5) as r:
            assert r.status == 200
        time.sleep(0.3)
        events = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        assert any(e["kind"] == "dns" for e in events)
        assert any(e["kind"] == "c2" and "/beacon" in e["detail"] for e in events)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_sinkhole_stays_ready_when_a_listener_port_is_taken(tmp_path):
    # Occupy the HTTP port first so the sinkhole's HTTP listener fails to bind.
    # It must NOT crash: it should log, drop that listener, and still signal READY
    # via the DNS listener (graceful degradation, no hang).
    import socket as _socket
    log = tmp_path / "requests.jsonl"
    stdout_path = tmp_path / "stdout.txt"
    sink = (HARNESS / "sinkhole.js").resolve()

    blocker = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 8082))
    blocker.listen(1)
    try:
        env = {**os.environ,
               "ANALYST_EVENT_LOG": str(log),
               "ANALYST_SINK_DNS_PORT": "5356",
               "ANALYST_SINK_HTTP_PORT": "8082",     # already taken -> bind error
               "ANALYST_SINK_CERT": str(tmp_path / "nope.pem"),
               "ANALYST_SINK_KEY": str(tmp_path / "nope.key")}
        with open(stdout_path, "w") as out:
            proc = subprocess.Popen(["node", str(sink)], env=env, stdout=out,
                                    stderr=subprocess.STDOUT)
        try:
            assert _wait_ready(stdout_path), "sinkhole did not signal ready after a port conflict"
            assert proc.poll() is None, "sinkhole process crashed on a port conflict"
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        blocker.close()
