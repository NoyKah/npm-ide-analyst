# Optional Real Network Sinkhole — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a strictly opt-in mode that detonates a sample against a real DNS+HTTP(S) sinkhole on an internet-less Docker network, capturing live multi-round C2 dialog, while the default `--network none` in-process fakenet path is untouched.

**Architecture:** A trusted Node sinkhole container (DNS on :53, HTTP on :80, HTTPS on :443 with a baked self-signed cert) runs on a `docker network create --internal` net. The detonation container attaches to that net with `--dns <sinkhole-ip>` and two env vars that (a) tell `preload.js` to relax ONLY its network hooks so real requests reach the sinkhole and (b) accept the self-signed cert. The orchestrator ingests both the detonation event log and the sinkhole's capture log into one `list[BehaviorEvent]`, then force-tears-down the container and network in a `finally`.

**Tech Stack:** Python 3.11+ (orchestration/parsing), Node.js built-ins only (harness + sinkhole), Docker (Linux containers), openssl (build-time only, for the cert).

## Global Constraints

- Python floor **3.11+**; package import name `npm_ide_analyst`; CLI `npm-ide-analyst`.
- **Safety invariant:** the Python orchestrator may NOT import/exec/eval/require sample code. It interacts with detonation solely via `subprocess` → `docker` and by reading JSON-lines logs as data.
- **Detonation container isolation is mandatory and unchanged:** every detonation `docker run` keeps `--user 1000:1000`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only`, `--tmpfs` workdirs, `--memory 256m`, `--cpus 1`, `--pids-limit 128`, `--rm`, sample mounted `:ro`, wall-clock timeout with force-reap. In sinkhole mode the ONLY change vs default is `--network none` → `--network <net> --dns <ip>` plus `-e ANALYST_SINKHOLE=1 -e NODE_TLS_REJECT_UNAUTHORIZED=0`.
- **The sinkhole network MUST be created with `--internal`** (no route to the real internet).
- **Default behavior stays `--network none` + in-process fakenet.** The sinkhole is opt-in via `detonate(..., sinkhole=True)` / `analyze --sinkhole`.
- **`NODE_TLS_REJECT_UNAUTHORIZED=0` is set only inside the ephemeral detonation container**, never on the host — deliberate and scoped (see spec).
- TDD throughout: failing test first, minimal code, frequent commits. Docker/Node integration tests are **gated** (`orch.docker_available()` / `shutil.which("node")`) and skip cleanly when the tool is absent.
- Scope limit (documented, surfaced to user): hostname-based C2 is captured; hard-coded public IPs are not routed on the internal network.

**Spec:** `docs/superpowers/specs/2026-07-07-npm-ide-analyst-sinkhole-design.md`.

---

## File Structure

```
src/npm_ide_analyst/sandbox/
├── harness/
│   ├── preload.js          # MODIFY: sinkhole-mode branch relaxes ONLY net hooks
│   └── sinkhole.js         # CREATE: DNS+HTTP+HTTPS responder (Node built-ins)
├── docker/
│   └── Dockerfile          # MODIFY: openssl + baked self-signed cert
├── findings.py             # MODIFY: add "c2" -> HIGH mapping
└── orchestrator.py         # MODIFY: _detonation_flags helper, sinkhole lifecycle
src/npm_ide_analyst/
└── cli.py                  # MODIFY: --sinkhole flag on analyze
tests/
├── test_harness_sinkhole.py       # CREATE (gated on node): preload delegation + sinkhole responder
├── test_sandbox_findings.py       # MODIFY: c2 mapping test
├── test_sandbox_orchestrator.py   # MODIFY (gated on docker): flag vectors + multi-round dialog + teardown
└── test_cli_dynamic.py            # MODIFY: --sinkhole wiring (ungated)
```

---

### Task 1: `preload.js` — sinkhole-mode network relaxation

**Files:**
- Modify: `src/npm_ide_analyst/sandbox/harness/preload.js`
- Test: `tests/test_harness_sinkhole.py` (gated on `node`)

**Interfaces:**
- Consumes: `emit.js` (`emit(kind, detail, data)`), env `ANALYST_SINKHOLE`.
- Produces: when `process.env.ANALYST_SINKHOLE` is set, the `http`/`https` `request`/`get`, `net.Socket.prototype.connect`, and `dns` `lookup`/`resolve*` hooks LOG then delegate to the original implementation (real I/O). When unset, behavior is byte-for-byte unchanged (neutered stubs). `child_process`, `fs`, `eval`, `decode` hooks are unchanged in both modes.

- [ ] **Step 1: Write the failing test**

Create `tests/test_harness_sinkhole.py`:

```python
# tests/test_harness_sinkhole.py
import json
import os
import shutil
import subprocess
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_harness_sinkhole.py::test_sinkhole_mode_delegates_real_http -v`
Expected: FAIL — without the sinkhole branch, `http.get` returns a neutered stub, the server never receives the request, `GOT:pong` is absent (test times out or asserts false).

- [ ] **Step 3: Add the sinkhole branch to `preload.js`**

At the top of `src/npm_ide_analyst/sandbox/harness/preload.js`, right after the `emit` require, add the flag:

```javascript
const { emit } = require('./emit.js');

// When ANALYST_SINKHOLE is set, the detonation runs on an internet-less internal
// Docker network with a real sinkhole. Network hooks then LOG and DELEGATE to the
// real implementation so traffic reaches the sinkhole. Everything else stays neutered.
const SINKHOLE = !!process.env.ANALYST_SINKHOLE;
```

Replace the `hookHttp` function body's neuter block with a delegate-when-sinkhole branch:

```javascript
// --- network: http/https request/get: log + (neuter | delegate) ---
function hookHttp(mod, scheme) {
  for (const fn of ['request', 'get']) {
    const orig = mod[fn];
    if (typeof orig !== 'function') continue;
    mod[fn] = function (...args) {
      let url = args[0];
      if (typeof url === 'object' && url) {
        url = `${url.protocol || scheme + ':'}//${url.host || url.hostname}${url.path || ''}`;
      }
      emit('network', `${scheme} ${fn}: ${url}`, { scheme, url: String(url) });
      if (SINKHOLE) {
        return orig.apply(mod, args); // real request → sinkhole captures the dialog
      }
      const { EventEmitter } = require('events');
      const req = new EventEmitter();
      req.write = (chunk) => { emit('network', `body: ${chunk}`, { body: String(chunk).slice(0, 2000) }); return true; };
      req.end = () => {};
      req.setHeader = () => {};
      req.abort = () => {};
      return req; // neutered: never opens a socket
    };
  }
}
hookHttp(require('http'), 'http');
hookHttp(require('https'), 'https');
```

Replace the `net.Socket.prototype.connect` hook:

```javascript
// --- net.Socket.connect: log + (neuter | delegate) ---
const net = require('net');
const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const opt = args[0];
  const target = typeof opt === 'object' ? `${opt.host || opt.path}:${opt.port || ''}` : String(opt);
  emit('network', `socket connect: ${target}`, { target });
  if (SINKHOLE) {
    return origConnect.apply(this, args); // real connect → sinkhole
  }
  this.destroy && this.destroy();
  return this; // neutered
};
```

Replace the `dns` hook loop (capture and reuse the original per fn):

```javascript
// --- dns: log; sinkhole -> real resolver (hits sinkhole via --dns), else synthetic ---
const dns = require('dns');
for (const fn of ['lookup', 'resolve', 'resolve4', 'resolve6']) {
  if (typeof dns[fn] !== 'function') continue;
  const orig = dns[fn];
  dns[fn] = function (host, ...rest) {
    emit('dns', `${fn}: ${host}`, { host });
    if (SINKHOLE) {
      return orig.apply(dns, [host, ...rest]); // real resolve → sinkhole DNS
    }
    const cb = rest.find((a) => typeof a === 'function');
    if (cb) process.nextTick(() => cb(null, fn === 'lookup' ? '127.0.0.1' : ['127.0.0.1']));
  };
}
```

Leave `child_process`, `fs`, decode, and `eval`/`Function` hooks exactly as they are.

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/test_harness_sinkhole.py::test_sinkhole_mode_delegates_real_http -v`
Expected: PASS (or skip if `node` absent).

- [ ] **Step 5: Verify default-mode neutering is intact**

Run: `python -m pytest tests/test_harness_hooks.py -v`
Expected: PASS — the existing hook tests run WITHOUT `ANALYST_SINKHOLE`, proving default neutering is byte-for-byte unchanged.

- [ ] **Step 6: Commit**

```bash
git add src/npm_ide_analyst/sandbox/harness/preload.js tests/test_harness_sinkhole.py
git commit -m "feat: preload sinkhole mode relaxes only network hooks (delegate to real I/O)"
```

---

### Task 2: `sinkhole.js` responder + Dockerfile cert

**Files:**
- Create: `src/npm_ide_analyst/sandbox/harness/sinkhole.js`
- Modify: `src/npm_ide_analyst/sandbox/docker/Dockerfile`
- Test: `tests/test_harness_sinkhole.py` (append; gated on `node`)

**Interfaces:**
- Consumes: `emit.js`; env `ANALYST_EVENT_LOG` (capture log path), optional `ANALYST_SINK_DNS_PORT`/`ANALYST_SINK_HTTP_PORT`/`ANALYST_SINK_HTTPS_PORT` (default 53/80/443), optional `ANALYST_SINK_CERT`/`ANALYST_SINK_KEY` (default `/harness/sink-cert.pem` / `/harness/sink-key.pem`).
- Produces: a process that binds a UDP DNS server (answers every A query with its own IPv4, discovered via `os.networkInterfaces()`), an HTTP server, and (if the cert files exist) an HTTPS server. Each HTTP/HTTPS request → `emit('c2', ...)`; each DNS query → `emit('dns', ...)`. Prints `SINKHOLE READY` to stdout once all attempted listeners are bound.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_harness_sinkhole.py`:

```python
import socket
import time
import urllib.request


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_harness_sinkhole.py::test_sinkhole_responds_to_dns_and_http -v`
Expected: FAIL — `sinkhole.js` does not exist (node exits non-zero, never prints ready).

- [ ] **Step 3: Write `sinkhole.js`**

Create `src/npm_ide_analyst/sandbox/harness/sinkhole.js`:

```javascript
// src/npm_ide_analyst/sandbox/harness/sinkhole.js
'use strict';
// Trusted sinkhole responder. Runs in its own container on an --internal Docker
// network. NO untrusted sample code runs here. Answers all DNS A queries with its
// own IP and all HTTP/HTTPS requests with a benign 200, logging each via emit.js.
const os = require('os');
const fs = require('fs');
const dgram = require('dgram');
const http = require('http');
const https = require('https');
const { emit } = require('./emit.js');

const DNS_PORT = parseInt(process.env.ANALYST_SINK_DNS_PORT || '53', 10);
const HTTP_PORT = parseInt(process.env.ANALYST_SINK_HTTP_PORT || '80', 10);
const HTTPS_PORT = parseInt(process.env.ANALYST_SINK_HTTPS_PORT || '443', 10);
const CERT = process.env.ANALYST_SINK_CERT || '/harness/sink-cert.pem';
const KEY = process.env.ANALYST_SINK_KEY || '/harness/sink-key.pem';

function ownIP() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const a of ifaces[name] || []) {
      if (a.family === 'IPv4' && !a.internal) return a.address;
    }
  }
  return '127.0.0.1';
}
const IP = ownIP();

// --- minimal DNS ---
function qname(msg) {
  let off = 12;
  const labels = [];
  while (off < msg.length && msg[off] !== 0) {
    const len = msg[off];
    labels.push(msg.slice(off + 1, off + 1 + len).toString('latin1'));
    off += len + 1;
  }
  return labels.join('.');
}

function dnsResponse(msg) {
  let off = 12;
  while (off < msg.length && msg[off] !== 0) off += msg[off] + 1;
  off += 1;                          // past the null terminator
  const qtype = msg.readUInt16BE(off);
  const qend = off + 4;              // qtype(2) + qclass(2)
  const question = msg.slice(12, qend);
  const header = Buffer.alloc(12);
  msg.copy(header, 0, 0, 2);         // echo transaction id
  header.writeUInt16BE(0x8180, 2);   // QR=1, RD=1, RA=1
  header.writeUInt16BE(1, 4);        // QDCOUNT
  const isA = qtype === 1;
  header.writeUInt16BE(isA ? 1 : 0, 6); // ANCOUNT
  if (!isA) return Buffer.concat([header, question]);
  const ans = Buffer.alloc(16);
  ans.writeUInt16BE(0xC00C, 0);      // name pointer -> offset 12
  ans.writeUInt16BE(1, 2);           // TYPE A
  ans.writeUInt16BE(1, 4);           // CLASS IN
  ans.writeUInt32BE(30, 6);          // TTL
  ans.writeUInt16BE(4, 10);          // RDLENGTH
  IP.split('.').forEach((o, i) => { ans[12 + i] = parseInt(o, 10) & 0xff; });
  return Buffer.concat([header, question, ans]);
}

function httpHandler(scheme) {
  return (req, res) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => { size += c.length; if (size <= 65536) chunks.push(c); });
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8').slice(0, 2000);
      const host = req.headers.host || '';
      emit('c2', `${scheme.toUpperCase()} ${req.method} ${host}${req.url}`, {
        scheme, method: req.method, host, path: req.url,
        headers: req.headers, body,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"ok":true}');
    });
    req.on('error', () => { try { res.end(); } catch (_) {} });
  };
}

let pending = 0;
let done = 0;
function ready() {
  done += 1;
  if (done >= pending) process.stdout.write('SINKHOLE READY\n');
}

// DNS listener
pending += 1;
const udp = dgram.createSocket('udp4');
udp.on('message', (msg, rinfo) => {
  try {
    emit('dns', `query ${qname(msg)}`, { name: qname(msg), from: rinfo.address });
    udp.send(dnsResponse(msg), rinfo.port, rinfo.address);
  } catch (_) { /* never throw out of the responder */ }
});
udp.on('error', (e) => process.stderr.write(`dns error: ${e.message}\n`));
udp.bind(DNS_PORT, () => ready());

// HTTP listener
pending += 1;
http.createServer(httpHandler('http')).listen(HTTP_PORT, () => ready());

// HTTPS listener (only if the baked cert is present)
if (fs.existsSync(CERT) && fs.existsSync(KEY)) {
  pending += 1;
  try {
    const opts = { cert: fs.readFileSync(CERT), key: fs.readFileSync(KEY) };
    https.createServer(opts, httpHandler('https')).listen(HTTPS_PORT, () => ready());
  } catch (e) {
    process.stderr.write(`https disabled: ${e.message}\n`);
    pending -= 1; // do not wait on a listener we failed to start
  }
}
```

- [ ] **Step 4: Modify the Dockerfile to bake the cert**

In `src/npm_ide_analyst/sandbox/docker/Dockerfile`, add an openssl install after the `useradd` line, and a cert-generation step after `COPY harness/`:

```dockerfile
# src/npm_ide_analyst/sandbox/docker/Dockerfile
FROM node:22-bookworm-slim

# Non-root user for detonation
RUN useradd -m -u 1000 analyst || true

# Build-time only: openssl to mint the sinkhole's self-signed TLS cert.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*

# Harness lives in the image (read-only rootfs at runtime)
WORKDIR /harness
COPY harness/ /harness/

# Self-signed cert for the sinkhole HTTPS responder. The detonation side runs with
# NODE_TLS_REJECT_UNAUTHORIZED=0 on an --internal (internet-less) network, so the
# CN/chain are irrelevant and this cert can never enable a real MITM.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=*" \
      -keyout /harness/sink-key.pem -out /harness/sink-cert.pem \
 && chmod 0644 /harness/sink-key.pem /harness/sink-cert.pem

# Canary/decoy secrets so theft is observable and traceable
RUN mkdir -p /home/analyst/.ssh /home/analyst/.aws \
 && echo "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY-DO-NOT-USE\n-----END OPENSSH PRIVATE KEY-----" > /home/analyst/.ssh/id_rsa \
 && echo "[default]\naws_access_key_id=CANARYAKIA000000\naws_secret_access_key=canary000000" > /home/analyst/.aws/credentials \
 && echo "//registry.npmjs.org/:_authToken=CANARY-NPM-TOKEN" > /home/analyst/.npmrc \
 && chown -R 1000:1000 /home/analyst

USER 1000:1000
ENV ANALYST_EVENT_LOG=/work/out/events.jsonl
# Entry is chosen at run time via command args (run-npm.js, run-vsix.js, or an
# --entrypoint override to node sinkhole.js).
ENTRYPOINT ["node", "-r", "/harness/preload.js"]
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `python -m pytest tests/test_harness_sinkhole.py::test_sinkhole_responds_to_dns_and_http -v`
Expected: PASS (or skip if `node` absent). The test runs HTTPS-disabled (no cert), so it needs only `node`, not Docker.

- [ ] **Step 6: Commit**

```bash
git add src/npm_ide_analyst/sandbox/harness/sinkhole.js src/npm_ide_analyst/sandbox/docker/Dockerfile tests/test_harness_sinkhole.py
git commit -m "feat: sinkhole responder (DNS+HTTP+HTTPS) + baked self-signed cert"
```

---

### Task 3: `findings.py` — map `c2` events to HIGH findings

**Files:**
- Modify: `src/npm_ide_analyst/sandbox/findings.py`
- Test: `tests/test_sandbox_findings.py` (append)

**Interfaces:**
- Consumes: `BehaviorEvent`, `Finding`, `Severity`.
- Produces: `behavior_to_findings` maps `kind == "c2"` to a HIGH finding with `category == "c2"`, title `"C2 server dialog"`. Existing mappings unchanged.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_sandbox_findings.py`:

```python
def test_c2_event_maps_to_high_finding():
    from npm_ide_analyst.models import BehaviorEvent, Severity
    from npm_ide_analyst.sandbox.findings import behavior_to_findings
    findings = behavior_to_findings([
        BehaviorEvent(kind="c2", detail="HTTP GET c2.evil.test/a"),
    ])
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].category == "c2"
    assert findings[0].location == "[dynamic]"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_sandbox_findings.py::test_c2_event_maps_to_high_finding -v`
Expected: FAIL — `c2` is not in `_MAP`, so no finding is produced (`len == 0`).

- [ ] **Step 3: Add the mapping**

In `src/npm_ide_analyst/sandbox/findings.py`, add one row to `_MAP` (place it just after the `"network"` row):

```python
_MAP = {
    "process": ("process-exec", Severity.HIGH, "Runtime process execution"),
    "network": ("network", Severity.HIGH, "Runtime outbound network"),
    "c2": ("c2", Severity.HIGH, "C2 server dialog"),
    "secret": ("secret-access", Severity.HIGH, "Runtime secret/credential access"),
    "eval": ("dynamic-code", Severity.HIGH, "Runtime dynamic code execution"),
    "decode": ("obfuscation", Severity.MEDIUM, "Runtime payload decoding"),
    "dns": ("network", Severity.LOW, "Runtime DNS lookup"),
    "vscode": ("extension-behavior", Severity.MEDIUM, "Editor API use during activation"),
    "file": ("file-write", Severity.LOW, "Runtime file write"),
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_sandbox_findings.py -v`
Expected: PASS (new test + all existing findings tests).

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/sandbox/findings.py tests/test_sandbox_findings.py
git commit -m "feat: map c2 dialog events to HIGH findings"
```

---

### Task 4: `orchestrator.py` — `_detonation_flags` helper + refactor

**Files:**
- Modify: `src/npm_ide_analyst/sandbox/orchestrator.py`
- Test: `tests/test_sandbox_orchestrator.py` (append; these tests are UNGATED — pure flag logic, no Docker)

**Interfaces:**
- Produces:
  - `_ISOLATION_FLAGS: list[str]` — every isolation flag EXCEPT the network selection.
  - `DOCKER_RUN_FLAGS` — kept as `_ISOLATION_FLAGS + ["--network", "none"]` (back-compat alias).
  - `def _detonation_flags(network: str | None = None, dns_ip: str | None = None) -> list[str]` — default (`network is None`) → `... + ["--network", "none"]`, no `--dns`; sinkhole → `... + ["--network", network, "--dns", dns_ip, "-e", "ANALYST_SINKHOLE=1", "-e", "NODE_TLS_REJECT_UNAUTHORIZED=0"]`. All `_ISOLATION_FLAGS` present in both.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_sandbox_orchestrator.py` (these do NOT require Docker — add them ABOVE the `pytestmark`-gated tests or in a separate ungated section; import is already present):

```python
def _has_pair(flags, a, b):
    return any(flags[i] == a and flags[i + 1] == b
              for i in range(len(flags) - 1))


def test_default_detonation_flags_use_network_none():
    flags = orch._detonation_flags()
    assert _has_pair(flags, "--network", "none")
    assert "--dns" not in flags
    assert "ANALYST_SINKHOLE=1" not in flags
    for req in ["--cap-drop", "ALL", "--read-only", "--pids-limit", "128"]:
        assert req in flags
    assert _has_pair(flags, "--user", "1000:1000")


def test_sinkhole_detonation_flags_keep_isolation_and_route_to_sinkhole():
    flags = orch._detonation_flags("analyst-net-abc", "10.9.8.7")
    # Never network none in sinkhole mode
    assert not _has_pair(flags, "--network", "none")
    assert _has_pair(flags, "--network", "analyst-net-abc")
    assert _has_pair(flags, "--dns", "10.9.8.7")
    assert "ANALYST_SINKHOLE=1" in flags
    assert "NODE_TLS_REJECT_UNAUTHORIZED=0" in flags
    # Every isolation flag still present
    assert _has_pair(flags, "--user", "1000:1000")
    for req in ["--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--read-only", "--memory", "256m", "--cpus", "1",
                "--pids-limit", "128", "--rm"]:
        assert req in flags
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_sandbox_orchestrator.py::test_default_detonation_flags_use_network_none tests/test_sandbox_orchestrator.py::test_sinkhole_detonation_flags_keep_isolation_and_route_to_sinkhole -v`
Expected: FAIL — `orch._detonation_flags` does not exist (`AttributeError`).

- [ ] **Step 3: Refactor `orchestrator.py` flags**

In `src/npm_ide_analyst/sandbox/orchestrator.py`, replace the `DOCKER_RUN_FLAGS = [...]` block with a shared isolation list plus the helper:

```python
_ISOLATION_FLAGS = [
    "--rm",
    "--user", "1000:1000",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--read-only",
    "--tmpfs", "/work/out:rw,size=16m",
    "--tmpfs", "/tmp:rw,size=16m",
    "--memory", "256m",
    "--cpus", "1",
    "--pids-limit", "128",
]

# Back-compat alias: the default (no-sinkhole) flag vector.
DOCKER_RUN_FLAGS = _ISOLATION_FLAGS + ["--network", "none"]


def _detonation_flags(network: str | None = None,
                      dns_ip: str | None = None) -> list[str]:
    """Full ``docker run`` flag vector for the detonation container.

    Default mode isolates the container with ``--network none``. Sinkhole mode
    attaches it to an internal network with the sinkhole as DNS resolver and sets
    the two env vars the harness needs; EVERY other isolation flag is identical.
    """
    flags = list(_ISOLATION_FLAGS)
    if network:
        flags += ["--network", network]
        if dns_ip:
            flags += ["--dns", dns_ip]
        flags += ["-e", "ANALYST_SINKHOLE=1",
                  "-e", "NODE_TLS_REJECT_UNAUTHORIZED=0"]
    else:
        flags += ["--network", "none"]
    return flags
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_sandbox_orchestrator.py::test_default_detonation_flags_use_network_none tests/test_sandbox_orchestrator.py::test_sinkhole_detonation_flags_keep_isolation_and_route_to_sinkhole -v`
Expected: PASS (these run even without Docker).

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/sandbox/orchestrator.py tests/test_sandbox_orchestrator.py
git commit -m "refactor: extract _detonation_flags with sinkhole-aware network selection"
```

---

### Task 5: `orchestrator.py` — sinkhole lifecycle in `detonate()`

**Files:**
- Modify: `src/npm_ide_analyst/sandbox/orchestrator.py`
- Test: `tests/test_sandbox_orchestrator.py` (append; gated on Docker)

**Interfaces:**
- Consumes: `_detonation_flags` (Task 4), `load_event_log`, `IMAGE_TAG`, `ArtifactType`, `sinkhole.js` (Task 2), `preload.js` sinkhole mode (Task 1).
- Produces:
  - `detonate(payload_root: Path, artifact_type: ArtifactType, timeout: int = 30, sinkhole: bool = False) -> list[BehaviorEvent]` — new `sinkhole` kwarg; default path unchanged.
  - Internal helpers: `_detonate_isolated(payload_root, runner, timeout, flags)`, `_detonate_with_sinkhole(payload_root, runner, timeout)`, `_wait_for_sinkhole(name, timeout)`, `_sinkhole_ip(name, net_name)`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_sandbox_orchestrator.py` (below the existing gated tests — these are covered by the module-level `pytestmark` skip and the `_image` autouse fixture):

```python
import subprocess as _sp


def test_detonate_sinkhole_captures_multi_request_dialog(tmp_path):
    # The SECOND request is issued only inside the response handler of the first,
    # so it can exist only if a real reply came back — proving a live dialog that
    # the --network none path structurally cannot produce.
    sample = tmp_path / "ext"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps({"name": "e", "main": "./extension.js"}))
    (sample / "extension.js").write_text(
        "exports.activate=()=>new Promise((resolve)=>{"
        "const http=require('http');"
        "http.get('http://c2.evil.test/a',(res)=>{"
        "  let d='';res.on('data',c=>d+=c);"
        "  res.on('end',()=>{"
        "    http.get('http://c2.evil.test/b?ack='+res.statusCode,(r2)=>{"
        "      r2.on('data',()=>{});r2.on('end',resolve);"
        "    }).on('error',resolve);"
        "  });"
        "}).on('error',resolve);"
        "});",
        encoding="utf-8")
    events = orch.detonate(sample, ArtifactType.EXTENSION, timeout=60, sinkhole=True)
    c2 = " ".join(e.detail for e in events if e.kind == "c2")
    assert "/a" in c2
    assert "/b?ack=200" in c2          # second hop fired after a real 200 reply


def test_detonate_sinkhole_captures_https(tmp_path):
    sample = tmp_path / "ext"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps({"name": "e", "main": "./extension.js"}))
    (sample / "extension.js").write_text(
        "exports.activate=()=>new Promise((resolve)=>{"
        "require('https').get('https://c2.evil.test/tls',(res)=>{"
        "  res.on('data',()=>{});res.on('end',resolve);"
        "}).on('error',resolve);"
        "});",
        encoding="utf-8")
    events = orch.detonate(sample, ArtifactType.EXTENSION, timeout=60, sinkhole=True)
    assert any(e.kind == "c2" and "/tls" in e.detail for e in events)


def test_sinkhole_teardown_leaves_no_containers_or_networks(tmp_path):
    sample = tmp_path / "ext"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps({"name": "e", "main": "./extension.js"}))
    (sample / "extension.js").write_text(
        "exports.activate=()=>{require('http').get('http://c2.evil.test/x');};",
        encoding="utf-8")
    orch.detonate(sample, ArtifactType.EXTENSION, timeout=60, sinkhole=True)
    nets = _sp.run(["docker", "network", "ls", "--format", "{{.Name}}"],
                   capture_output=True, text=True, timeout=30).stdout
    ps = _sp.run(["docker", "ps", "-a", "--format", "{{.Names}}"],
                 capture_output=True, text=True, timeout=30).stdout
    assert "analyst-net-" not in nets
    assert "analyst-sink-" not in ps
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_sandbox_orchestrator.py::test_detonate_sinkhole_captures_multi_request_dialog -v`
Expected: FAIL — `detonate()` has no `sinkhole` kwarg (`TypeError: unexpected keyword argument 'sinkhole'`). If Docker is absent, the test skips.

- [ ] **Step 3: Add imports and refactor `detonate`**

In `src/npm_ide_analyst/sandbox/orchestrator.py`, add `import json` and `import time` to the imports at the top (alongside the existing `shutil`, `subprocess`, `tempfile`, `uuid`):

```python
import json
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
```

Replace the existing `detonate(...)` function with the following (keeps the current body verbatim inside `_detonate_isolated`, adds the sinkhole path):

```python
def detonate(payload_root: Path, artifact_type: ArtifactType,
             timeout: int = 30, sinkhole: bool = False) -> list[BehaviorEvent]:
    if not docker_available():
        raise SandboxUnavailable("docker is not available")
    runner = "run-vsix.js" if artifact_type == ArtifactType.EXTENSION else "run-npm.js"
    if sinkhole:
        return _detonate_with_sinkhole(payload_root, runner, timeout)
    return _detonate_isolated(payload_root, runner, timeout, _detonation_flags())


def _detonate_isolated(payload_root: Path, runner: str, timeout: int,
                       flags: list[str]) -> list[BehaviorEvent]:
    out_dir = Path(tempfile.mkdtemp(prefix="analyst-out-"))
    container_name = f"analyst-det-{uuid.uuid4().hex[:12]}"
    try:
        # KNOWN ISSUE: the harness writes the event log as the in-container
        # non-root user (uid 1000). Loosen the host out-dir perms (not the
        # container's isolation flags) so uid 1000 can create the log file.
        # The sample mount stays :ro and every isolation flag stays intact.
        out_dir.chmod(0o777)
        cmd = [
            "docker", "run",
            *flags,
            "--name", container_name,
            "-v", f"{payload_root.resolve()}:/work/sample:ro",
            "-v", f"{out_dir.resolve()}:/work/hostout:rw",
            "-e", "ANALYST_SAMPLE_DIR=/work/sample",
            "-e", "ANALYST_EVENT_LOG=/work/hostout/events.jsonl",
            IMAGE_TAG,
            f"/harness/{runner}",
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout + 15)
        except subprocess.TimeoutExpired:
            # Force-reap the named container; partial log is still ingested.
            subprocess.run(["docker", "rm", "-f", container_name],
                           capture_output=True, timeout=30)
        return load_event_log(out_dir / "events.jsonl")
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def _wait_for_sinkhole(name: str, timeout: int = 20) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = subprocess.run(["docker", "logs", name],
                           capture_output=True, timeout=15)
        if b"SINKHOLE READY" in (r.stdout or b"") + (r.stderr or b""):
            return True
        time.sleep(0.3)
    return False


def _sinkhole_ip(name: str, net_name: str) -> str | None:
    r = subprocess.run(["docker", "inspect", name],
                       capture_output=True, timeout=15)
    try:
        data = json.loads(r.stdout.decode("utf-8", "replace"))
        return data[0]["NetworkSettings"]["Networks"][net_name]["IPAddress"]
    except (json.JSONDecodeError, KeyError, IndexError):
        return None


def _detonate_with_sinkhole(payload_root: Path, runner: str,
                            timeout: int) -> list[BehaviorEvent]:
    net_name = f"analyst-net-{uuid.uuid4().hex[:12]}"
    sink_name = f"analyst-sink-{uuid.uuid4().hex[:12]}"
    sink_out = Path(tempfile.mkdtemp(prefix="analyst-sink-"))
    try:
        sink_out.chmod(0o777)
        # 1. Internal network: no route to the real internet.
        subprocess.run(["docker", "network", "create", "--internal",
                        "--driver", "bridge", net_name],
                       capture_output=True, timeout=60, check=True)
        # 2. Sinkhole container. Runs as root SOLELY so CAP_NET_BIND_SERVICE is
        #    effective for binding 53/80/443 (Docker does not add caps to the
        #    ambient set for non-root). No sample code runs here; read-only,
        #    cap-dropped, resource-limited, on an internet-less network.
        subprocess.run([
            "docker", "run", "-d", "--rm", "--name", sink_name,
            "--network", net_name,
            "--user", "0:0",
            "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE",
            "--security-opt", "no-new-privileges",
            "--read-only", "--tmpfs", "/tmp:rw,size=8m",
            "--memory", "128m", "--cpus", "1", "--pids-limit", "64",
            "-v", f"{sink_out.resolve()}:/work/sinkout:rw",
            "-e", "ANALYST_EVENT_LOG=/work/sinkout/requests.jsonl",
            "--entrypoint", "node",
            IMAGE_TAG, "/harness/sinkhole.js",
        ], capture_output=True, timeout=60, check=True)
        # 3. Wait for readiness; degrade to isolated detonation if it never binds.
        if not _wait_for_sinkhole(sink_name, timeout=20):
            return _detonate_isolated(payload_root, runner, timeout,
                                      _detonation_flags())
        # 4. Discover the sinkhole IP for the detonation container's resolver.
        sink_ip = _sinkhole_ip(sink_name, net_name)
        flags = _detonation_flags(net_name, sink_ip)
        # 5. Detonate on the internal network, DNS -> sinkhole.
        det_events = _detonate_isolated(payload_root, runner, timeout, flags)
        # 6. Merge detonation events with the sinkhole's captured dialog.
        sink_events = load_event_log(sink_out / "requests.jsonl")
        return det_events + sink_events
    finally:
        # Force-reap the sinkhole container and remove the network no matter what.
        subprocess.run(["docker", "rm", "-f", sink_name],
                       capture_output=True, timeout=30)
        subprocess.run(["docker", "network", "rm", net_name],
                       capture_output=True, timeout=30)
        shutil.rmtree(sink_out, ignore_errors=True)
```

- [ ] **Step 4: Run the sinkhole integration tests**

Run: `python -m pytest tests/test_sandbox_orchestrator.py -v`
Expected: on a Docker host, the module fixture rebuilds the image (now with `sinkhole.js` + cert), and all tests PASS — including the two existing `--network none` tests (default path unchanged) and the three new sinkhole tests. Skips cleanly if Docker is absent.

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/sandbox/orchestrator.py tests/test_sandbox_orchestrator.py
git commit -m "feat: sinkhole detonation lifecycle (internal net, responder, ingest, teardown)"
```

---

### Task 6: CLI — `--sinkhole` flag on `analyze`

**Files:**
- Modify: `src/npm_ide_analyst/cli.py`
- Test: `tests/test_cli_dynamic.py` (append; ungated — uses monkeypatch, no Docker)

**Interfaces:**
- Consumes: `detonate(..., sinkhole=...)` (Task 5), `docker_available`, `build_image`, `behavior_to_findings`, `build_timeline`.
- Produces: `analyze` gains `--sinkhole/--no-sinkhole` (default off). `--sinkhole` implies detonation (runs the dynamic branch even without `--dynamic`) and calls `detonate(..., sinkhole=True)`. Docker-absent → warn + static-only (exit 0). On success with sinkhole, prints a note that hard-coded-IP C2 is out of scope.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_cli_dynamic.py`:

```python
def test_analyze_sinkhole_degrades_without_docker(tmp_path, monkeypatch):
    import npm_ide_analyst.cli as climod
    monkeypatch.setattr(climod, "docker_available", lambda: False)
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(json.dumps({"name": "evil"}))
    out = tmp_path / "out"
    result = CliRunner().invoke(cli, ["analyze", str(pkg), "--out", str(out), "--sinkhole"])
    assert result.exit_code == 0, result.output
    data = json.loads((out / "report.json").read_text())
    assert data["behavior"] == []          # degraded to static-only


def test_analyze_sinkhole_passes_flag_to_detonate(tmp_path, monkeypatch):
    import npm_ide_analyst.cli as climod
    calls = {}
    monkeypatch.setattr(climod, "docker_available", lambda: True)
    monkeypatch.setattr(climod, "build_image", lambda: None)

    def fake_detonate(root, artifact_type, sinkhole=False):
        calls["sinkhole"] = sinkhole
        return []

    monkeypatch.setattr(climod, "detonate", fake_detonate)
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(json.dumps({"name": "evil"}))
    out = tmp_path / "out"
    result = CliRunner().invoke(cli, ["analyze", str(pkg), "--out", str(out), "--sinkhole"])
    assert result.exit_code == 0, result.output
    assert calls["sinkhole"] is True       # --sinkhole implied detonation + passed flag
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli_dynamic.py::test_analyze_sinkhole_passes_flag_to_detonate -v`
Expected: FAIL — `analyze` has no `--sinkhole` option (Click errors with "no such option", non-zero exit).

- [ ] **Step 3: Wire the CLI**

In `src/npm_ide_analyst/cli.py`, add the `--sinkhole` option to `analyze` and update its body. Replace the `analyze` decorator stack + signature + dynamic block:

```python
@cli.command()
@click.argument("input_path", type=click.Path(exists=True, path_type=Path))
@click.option("--out", "out_dir", required=True, type=click.Path(path_type=Path))
@click.option("--dynamic/--no-dynamic", default=False,
              help="Detonate the sample in a hardened Docker sandbox.")
@click.option("--sinkhole/--no-sinkhole", default=False,
              help="Detonate against a real DNS+HTTP(S) sinkhole on an internal, "
                   "internet-less network to capture live C2 dialog for "
                   "hostname-based traffic. Implies --dynamic.")
def analyze(input_path: Path, out_dir: Path, dynamic: bool, sinkhole: bool) -> None:
    """Static analysis of a .vsix, npm .tgz, or directory."""
    out_dir.mkdir(parents=True, exist_ok=True)
    work = out_dir / "_work"
    payload_root = unpack(input_path, work)
    manifest = json.loads(
        (payload_root / "package.json").read_text(encoding="utf-8", errors="replace")
    ) if (payload_root / "package.json").exists() else {}
    sha256, sha512 = hash_file(input_path) if input_path.is_file() else ("", "")
    sample = Sample(
        name=manifest.get("name", input_path.stem),
        version=manifest.get("version"),
        artifact_type=detect_artifact_type(payload_root),
        root=payload_root, sha256=sha256, sha512=sha512,
    )
    findings = run_static(payload_root)
    behavior = []
    timeline = []
    if dynamic or sinkhole:
        if not docker_available():
            click.echo("WARNING: dynamic/sinkhole requested but Docker is "
                       "unavailable; running static-only.", err=True)
        else:
            try:
                build_image()
                behavior = detonate(payload_root, sample.artifact_type,
                                    sinkhole=sinkhole)
                findings = findings + behavior_to_findings(behavior)
                timeline = build_timeline(behavior)
                if sinkhole:
                    click.echo("NOTE: the sinkhole captures hostname-based C2; "
                               "hard-coded public IPs are not routed on the "
                               "internal network.", err=True)
            except (SandboxUnavailable, subprocess.CalledProcessError, Exception) as exc:
                click.echo(f"WARNING: detonation failed ({exc}); "
                           "continuing static-only.", err=True)
                behavior = []
                timeline = []
    report = Report(sample=sample, findings=findings, generated_at=_now(),
                    behavior=behavior, timeline=timeline)
    write_json(report, out_dir / "report.json")
    write_html(report, out_dir / "report.html")
    click.echo(f"verdict={report.verdict} score={report.score} "
               f"findings={len(findings)} -> {out_dir}")
```

- [ ] **Step 4: Run tests + full suite**

Run: `python -m pytest tests/test_cli_dynamic.py -v && python -m pytest -q`
Expected: new CLI tests PASS; full suite green; Docker/Node-gated tests skip cleanly when the tools are absent.

- [ ] **Step 5: Verify the CLI end to end (manual, gated on Docker)**

Run (only on a Docker host, with a sample that beacons to a hostname):
`npm-ide-analyst analyze <path-to-sample> --out ./out --sinkhole`
Expected: stderr prints the hostname-scope NOTE; `out/report.json` has `behavior` entries with `kind` `"c2"`/`"dns"` and a HIGH `c2` finding; `out/report.html` shows them under "Dynamic Behavior". No leftover `analyst-net-*` network or `analyst-sink-*` container (`docker network ls`, `docker ps -a`).

- [ ] **Step 6: Commit**

```bash
git add src/npm_ide_analyst/cli.py tests/test_cli_dynamic.py
git commit -m "feat: analyze --sinkhole flag (implies detonation; graceful degradation)"
```

---

## Self-Review (completed during authoring)

- **Spec coverage:**
  - Sinkhole container on internal network + responder (spec §Components 1, §Architecture) → Task 2 (`sinkhole.js`) + Task 5 (`docker network create --internal`, sinkhole `docker run`).
  - Resolve all DNS A → self; answer all HTTP/HTTPS with benign 200 + log line/headers/body (spec §Components 1) → Task 2 (`dnsResponse`, `httpHandler`).
  - Detonation attaches to internal net with sinkhole as DNS; relax ONLY network hooks (spec §Components 2, §Safety invariants) → Task 1 (`preload.js` `SINKHOLE` branch) + Task 4/5 (`--dns`, `-e ANALYST_SINKHOLE=1`). `child_process`/`fs`/`eval` untouched — verified by Step 5 of Task 1 (existing hook tests stay green).
  - Ingest sinkhole requests as BehaviorEvents `kind "c2"/"dns"` merged into report (spec §Components 4/5) → Task 5 (`det_events + sink_events`) + Task 3 (`c2` finding).
  - Teardown container AND network in `finally` (spec §Teardown) → Task 5 `_detonate_with_sinkhole` finally + `test_sinkhole_teardown_...`.
  - Isolation flags intact, `--internal`, default stays `--network none`, opt-in only (spec §Safety invariants, §Global Constraints) → Task 4 flag tests + Task 6 default-off flag.
  - HTTPS via baked self-signed cert + `NODE_TLS_REJECT_UNAUTHORIZED=0` (spec §Components 3) → Task 2 Dockerfile + Task 4 flags + `test_detonate_sinkhole_captures_https`.
  - Gated integration test asserting a multi-request exchange (task brief) → Task 5 `test_detonate_sinkhole_captures_multi_request_dialog`.
  - CLI `--sinkhole` (task brief) → Task 6.
- **Placeholder scan:** none — every code step carries complete code; every command lists expected output.
- **Type/name consistency:** `detonate(..., sinkhole=False)`, `_detonation_flags(network, dns_ip)`, `_detonate_isolated/_detonate_with_sinkhole/_wait_for_sinkhole/_sinkhole_ip`, env `ANALYST_SINKHOLE`, kinds `c2`/`dns`, and the `SINKHOLE` preload flag are referenced identically across Tasks 1, 4, 5, 6. Sinkhole log path `/work/sinkout/requests.jsonl` matches between Task 5 (`-e ANALYST_EVENT_LOG=`) and the ingest (`load_event_log(sink_out / "requests.jsonl")`).
- **Safety invariant:** Python never executes sample code — sinkhole and detonation are `subprocess` → `docker` only; the sinkhole runs only `sinkhole.js` (our code); the detonation container keeps every isolation flag with only the network selection changed.
- **Gating:** flag-vector tests (Task 4) and CLI tests (Task 6) are ungated; harness tests (Tasks 1–2) skip without `node`; orchestrator sinkhole tests (Task 5) skip without Docker.
```
