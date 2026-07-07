# Native-Binary Syscall Tracing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in, default-OFF mode that actually executes an exec'd (dropped/native) binary inside the detonation container under `strace`, capturing its syscalls as `BehaviorEvent`s merged into the report.

**Architecture:** A new `--trace-native` CLI flag threads through `orchestrator.detonate` to (a) add exactly `--cap-add SYS_PTRACE` to the hardened `docker run` flags and (b) set `ANALYST_TRACE_NATIVE=1`. Inside the container, the Node harness `child_process` hook branches on that env var: default → today's log+neuter; enabled → run the attempted exec synchronously under `strace`, parse notable syscalls, and `emit()` them as `native`/`syscall` events. Those flow through the existing `parse_event_log` → `behavior_to_findings` → `Report` pipeline unchanged.

**Tech Stack:** Python 3.11+ (orchestration, flag/finding mapping), Node.js (in-container harness), Docker (Linux), `strace` (apt, in-image). No new Python or npm dependencies.

**Design doc:** `docs/superpowers/specs/2026-07-07-native-syscall-tracing-design.md`

## Global Constraints

- Python floor **3.11+**; package import name `npm_ide_analyst`; CLI `npm-ide-analyst`.
- **Safety invariant (unchanged):** the Python orchestrator may NOT import/exec/eval/require or run sample code. The ONLY place sample code executes is inside the Docker container via the Node harness. Python interacts with detonation solely via `subprocess` → `docker` and by reading the JSON-lines event log as data.
- **Isolation is mandatory and fixed:** every `docker run` MUST include `--network none`, non-root `--user 1000:1000`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only` rootfs (writable `--tmpfs` only), `--memory`, `--cpus`, `--pids-limit`, and a wall-clock timeout that force-reaps the container. **The ONLY permitted relaxation is a single `--cap-add SYS_PTRACE`, and only when `--trace-native` is explicitly requested.** Everything else stays intact in both modes.
- **`--trace-native` is opt-in and default OFF.** It requires `--dynamic`; passing it alone is an error. When active, the CLI prints a warning that it adds `CAP_SYS_PTRACE` (weakening isolation) and executes native payload code.
- **Detonation runtime is Linux** (Docker Desktop, Linux containers).
- TDD throughout: failing test first, minimal code, frequent commits. Docker/Node/strace integration tests are **gated** behind availability checks and skip cleanly when the tool is absent (unit tests never require Docker/Node/strace).

---

## File Structure

```
src/npm_ide_analyst/
├── sandbox/
│   ├── orchestrator.py          # MODIFY: run_flags(trace_native); detonate(trace_native)
│   ├── findings.py              # MODIFY: _MAP gains native/syscall kinds
│   ├── docker/
│   │   └── Dockerfile           # MODIFY: apt-get install strace
│   └── harness/
│       ├── preload.js           # MODIFY: child_process hook branches on ANALYST_TRACE_NATIVE
│       └── trace.js             # CREATE: traceExec() — strace runner + syscall parser + emitter
├── cli.py                       # MODIFY: --trace-native flag, warning, error-without-dynamic
tests/
├── test_sandbox_findings.py         # MODIFY: assert native/syscall mapping
├── test_sandbox_orchestrator.py     # MODIFY: run_flags unit test + gated detonate(trace_native=True)
├── test_cli_dynamic.py              # MODIFY: --trace-native without --dynamic errors
└── test_harness_native_trace.py     # CREATE: gated on node+strace
```

Task order: findings mapping (pure, no deps) → orchestrator flags (pure) → Dockerfile → harness trace.js + preload wiring → CLI wiring. Each task ends green and committed.

---

### Task 1: Map `native`/`syscall` behavior events to findings

**Files:**
- Modify: `src/npm_ide_analyst/sandbox/findings.py`
- Test: `tests/test_sandbox_findings.py`

**Interfaces:**
- Consumes: `BehaviorEvent`, `Finding`, `Severity` (existing).
- Produces: `behavior_to_findings` now additionally maps `kind="native"` → (`native-exec`, HIGH, "Native binary execution (traced)") and `kind="syscall"` → (`native-syscall`, MEDIUM, "Notable syscall (traced)"). Signature unchanged: `behavior_to_findings(events: list[BehaviorEvent]) -> list[Finding]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_sandbox_findings.py`:

```python
def test_maps_native_and_syscall():
    events = [
        BehaviorEvent(kind="native", detail="strace ./dropped -> exit 0"),
        BehaviorEvent(kind="syscall", detail="connect: 1.2.3.4:443"),
    ]
    findings = behavior_to_findings(events)
    cats = {f.category: f.severity for f in findings}
    assert cats["native-exec"] == Severity.HIGH
    assert cats["native-syscall"] == Severity.MEDIUM
    assert all(f.location == "[dynamic]" for f in findings)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_sandbox_findings.py::test_maps_native_and_syscall -v`
Expected: FAIL — `KeyError`/missing categories (`native-exec` not in `cats`).

- [ ] **Step 3: Add the mappings**

In `src/npm_ide_analyst/sandbox/findings.py`, add two entries to the `_MAP` dict (after the `"file"` line):

```python
    "native": ("native-exec", Severity.HIGH, "Native binary execution (traced)"),
    "syscall": ("native-syscall", Severity.MEDIUM, "Notable syscall (traced)"),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_sandbox_findings.py -v`
Expected: PASS (all, including the three existing tests).

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/sandbox/findings.py tests/test_sandbox_findings.py
git commit -m "feat: map native/syscall behavior events to findings"
```

---

### Task 2: `run_flags(trace_native)` — gate the ptrace capability

**Files:**
- Modify: `src/npm_ide_analyst/sandbox/orchestrator.py`
- Test: `tests/test_sandbox_orchestrator.py`

**Interfaces:**
- Consumes: existing module constant `DOCKER_RUN_FLAGS: list[str]`.
- Produces:
  - `PTRACE_CAP_FLAGS: list[str] = ["--cap-add", "SYS_PTRACE"]` (module constant).
  - `def run_flags(trace_native: bool = False) -> list[str]` — returns `DOCKER_RUN_FLAGS` verbatim when `False`; returns `DOCKER_RUN_FLAGS + PTRACE_CAP_FLAGS` when `True`. Returns a fresh list (never mutates `DOCKER_RUN_FLAGS`).

**Note:** This test is a **pure unit test** — no Docker. It must run even when Docker is absent, so it must NOT sit under the module-level `skipif`. Place it in a separate file-level location OR override the marker. Simplest: add a new **un-skipped** test file `tests/test_sandbox_run_flags.py` so the module `pytestmark` in `test_sandbox_orchestrator.py` does not gate it.

- [ ] **Step 1: Write the failing test**

Create `tests/test_sandbox_run_flags.py`:

```python
# tests/test_sandbox_run_flags.py — pure unit tests, no docker required
from npm_ide_analyst.sandbox import orchestrator as orch


def test_run_flags_default_has_no_ptrace_and_keeps_hardening():
    flags = orch.run_flags(False)
    assert "--cap-add" not in flags          # no capability re-added by default
    # Hardening intact:
    for required in ["--network", "none", "--cap-drop", "ALL",
                     "no-new-privileges", "--read-only"]:
        assert required in flags


def test_run_flags_trace_native_adds_only_sys_ptrace():
    base = orch.run_flags(False)
    traced = orch.run_flags(True)
    # Exactly the ptrace cap is added, nothing removed:
    assert traced == base + ["--cap-add", "SYS_PTRACE"]
    # Base constant not mutated:
    assert "--cap-add" not in orch.DOCKER_RUN_FLAGS


def test_run_flags_returns_fresh_list():
    a = orch.run_flags(True)
    a.append("--tampered")
    assert "--tampered" not in orch.run_flags(True)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_sandbox_run_flags.py -v`
Expected: FAIL — `AttributeError: module 'orchestrator' has no attribute 'run_flags'`.

- [ ] **Step 3: Add `PTRACE_CAP_FLAGS` and `run_flags`**

In `src/npm_ide_analyst/sandbox/orchestrator.py`, after the `DOCKER_RUN_FLAGS = [...]` block, add:

```python
PTRACE_CAP_FLAGS = ["--cap-add", "SYS_PTRACE"]


def run_flags(trace_native: bool = False) -> list[str]:
    """Return the hardened docker run flag vector.

    Only when trace_native is True is a single capability re-added
    (SYS_PTRACE, required for strace/ptrace under Docker's default seccomp).
    Every other isolation flag is unchanged. Returns a fresh list.
    """
    flags = list(DOCKER_RUN_FLAGS)
    if trace_native:
        flags += PTRACE_CAP_FLAGS
    return flags
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_sandbox_run_flags.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/sandbox/orchestrator.py tests/test_sandbox_run_flags.py
git commit -m "feat: run_flags gates SYS_PTRACE behind trace_native"
```

---

### Task 3: Thread `trace_native` through `detonate`

**Files:**
- Modify: `src/npm_ide_analyst/sandbox/orchestrator.py`
- Test: `tests/test_sandbox_orchestrator.py` (gated on docker)

**Interfaces:**
- Consumes: `run_flags` (Task 2), `load_event_log` (existing), `ArtifactType`, `BehaviorEvent`.
- Produces: `def detonate(payload_root: Path, artifact_type: ArtifactType, timeout: int = 30, trace_native: bool = False) -> list[BehaviorEvent]` — uses `run_flags(trace_native)` instead of the literal `DOCKER_RUN_FLAGS`, and adds `-e ANALYST_TRACE_NATIVE=1` to the run env when `trace_native` is True. All other behavior (mounts, container naming, force-reap on timeout, log ingest) unchanged.

- [ ] **Step 1: Write the failing test (gated on docker)**

Append to `tests/test_sandbox_orchestrator.py`:

```python
def test_detonate_trace_native_captures_syscalls(tmp_path):
    sample = tmp_path / "pkg"
    sample.mkdir()
    # postinstall execs a real in-image ELF that makes identifiable syscalls
    (sample / "package.json").write_text(json.dumps(
        {"name": "p", "scripts": {"postinstall": "node ./evil.js"}}))
    (sample / "evil.js").write_text(
        "require('child_process').exec('/bin/echo NPMIDE_TRACE_CANARY');",
        encoding="utf-8")
    events = orch.detonate(sample, ArtifactType.NPM, timeout=60, trace_native=True)
    # The native binary actually ran under strace: a native and/or syscall event.
    assert any(e.kind in ("native", "syscall") for e in events)
    assert any("NPMIDE_TRACE_CANARY" in e.detail
               or "execve" in e.detail for e in events)


def test_detonate_default_still_neuters(tmp_path):
    sample = tmp_path / "pkg2"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps(
        {"name": "p", "scripts": {"postinstall": "node ./evil.js"}}))
    (sample / "evil.js").write_text(
        "require('child_process').exec('/bin/echo NPMIDE_TRACE_CANARY');",
        encoding="utf-8")
    events = orch.detonate(sample, ArtifactType.NPM, timeout=60)  # default: no trace
    # Intent still logged, but no native execution / syscalls.
    assert any(e.kind == "process" for e in events)
    assert not any(e.kind in ("native", "syscall") for e in events)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_sandbox_orchestrator.py -k trace_native -v`
Expected: FAIL (if Docker present) — `detonate()` got an unexpected keyword `trace_native`; or SKIP if Docker absent. (Full green requires Tasks 4–5; this task only makes the signature/plumbing exist. If Docker is present, `test_detonate_trace_native_captures_syscalls` stays red until Task 5 lands the harness — that is expected and noted in Step 4.)

- [ ] **Step 3: Update `detonate`**

In `src/npm_ide_analyst/sandbox/orchestrator.py`, change the `detonate` signature and the two lines that build the command. Replace the existing `detonate` definition's signature line and the `cmd = [...]` construction:

Signature:
```python
def detonate(payload_root: Path, artifact_type: ArtifactType,
             timeout: int = 30, trace_native: bool = False) -> list[BehaviorEvent]:
```

Inside `detonate`, build the env-extension and use `run_flags`. Replace the `cmd = [ ... ]` list with:

```python
        trace_env = ["-e", "ANALYST_TRACE_NATIVE=1"] if trace_native else []
        cmd = [
            "docker", "run",
            *run_flags(trace_native),
            "--name", container_name,
            "-v", f"{payload_root.resolve()}:/work/sample:ro",
            "-v", f"{out_dir.resolve()}:/work/hostout:rw",
            "-e", "ANALYST_SAMPLE_DIR=/work/sample",
            "-e", "ANALYST_EVENT_LOG=/work/hostout/events.jsonl",
            *trace_env,
            IMAGE_TAG,
            f"/harness/{runner}",
        ]
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_sandbox_orchestrator.py -k "trace_native or default_still_neuters" -v`
Expected (Docker absent): SKIP. Expected (Docker present): `test_detonate_default_still_neuters` PASSES now; `test_detonate_trace_native_captures_syscalls` still FAILS until Task 5 (harness) + Task 4 (Dockerfile) land. This is acceptable — the signature plumbing is done; commit and continue.

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/sandbox/orchestrator.py tests/test_sandbox_orchestrator.py
git commit -m "feat: detonate threads trace_native (ptrace flags + env)"
```

---

### Task 4: Install `strace` in the sandbox image

**Files:**
- Modify: `src/npm_ide_analyst/sandbox/docker/Dockerfile`

**Interfaces:**
- Produces: the `npm-ide-analyst-sandbox:latest` image now contains `/usr/bin/strace`. No Python interface change.

- [ ] **Step 1: Add the apt install**

In `src/npm_ide_analyst/sandbox/docker/Dockerfile`, insert this block immediately after the `FROM node:22-bookworm-slim` line (before `useradd`):

```dockerfile
# strace is required only for the opt-in --trace-native mode (runs under
# --cap-add SYS_PTRACE at runtime). Installed unconditionally; harmless unless
# that mode is enabled.
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace \
 && rm -rf /var/lib/apt/lists/*
```

- [ ] **Step 2: Build the image to verify (gated on docker — manual)**

Run (only if Docker present):
```bash
python -c "from npm_ide_analyst.sandbox import orchestrator as o; o.build_image()"
docker run --rm --entrypoint /usr/bin/strace npm-ide-analyst-sandbox:latest -V
```
Expected: prints a `strace -- version ...` line (confirms strace is installed). If Docker is absent, skip — Task 5's gated tests cover it on a Docker/strace host.

- [ ] **Step 3: Commit**

```bash
git add src/npm_ide_analyst/sandbox/docker/Dockerfile
git commit -m "feat: install strace in sandbox image for native tracing"
```

---

### Task 5: Harness — `trace.js` runner + `preload.js` branch

**Files:**
- Create: `src/npm_ide_analyst/sandbox/harness/trace.js`
- Modify: `src/npm_ide_analyst/sandbox/harness/preload.js`
- Test: `tests/test_harness_native_trace.py` (gated on node + strace)

**Interfaces:**
- Consumes: `emit` from `./emit.js`.
- Produces (`trace.js`):
  - `module.exports = { traceExec }`.
  - `traceExec(fnName, args, origFn)` — synchronously runs the exec described by
    `(fnName, args)` under `strace`, emits one `native` event (command + exit
    status) and up to a bounded number of `syscall` events, then returns a value
    shaped like `origFn`'s return: for `*Sync` names a `Buffer` (real stdout);
    for async names an `EventEmitter` stub that fires the callback / `close` with
    real stdout on `process.nextTick`.
- Produces (`preload.js`): the `child_process` hook checks
  `process.env.ANALYST_TRACE_NATIVE`. When set (and `fn !== 'fork'`), it emits
  the existing `process` intent event, then delegates to `traceExec(fn, args,
  orig)` and returns its result. When unset (or `fn === 'fork'`), today's
  log+neuter path runs unchanged.

- [ ] **Step 1: Write the failing test (gated on node + strace)**

Create `tests/test_harness_native_trace.py`:

```python
# tests/test_harness_native_trace.py
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path("src/npm_ide_analyst/sandbox/harness")
pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or shutil.which("strace") is None,
    reason="node or strace not installed",
)


def _run_driver(tmp_path: Path, driver_src: str, trace: bool) -> list[dict]:
    driver = tmp_path / "driver.js"
    driver.write_text(driver_src, encoding="utf-8")
    log = tmp_path / "events.jsonl"
    preload = (HARNESS / "preload.js").resolve()
    env = {**os.environ, "ANALYST_EVENT_LOG": str(log)}
    if trace:
        env["ANALYST_TRACE_NATIVE"] = "1"
    subprocess.run(["node", "-r", str(preload), str(driver)],
                   env=env, timeout=30, capture_output=True)
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


def test_trace_native_runs_binary_and_emits_syscalls(tmp_path):
    events = _run_driver(
        tmp_path,
        "require('child_process').exec('/bin/echo NPMIDE_TRACE_CANARY', ()=>{});",
        trace=True)
    assert any(e["kind"] == "native" for e in events)
    assert any(e["kind"] == "syscall" for e in events)
    # The binary actually executed: execve of echo and/or the canary is visible.
    assert any("execve" in e["detail"] or "NPMIDE_TRACE_CANARY" in e["detail"]
               for e in events if e["kind"] in ("native", "syscall"))


def test_default_mode_still_neuters(tmp_path):
    events = _run_driver(
        tmp_path,
        "require('child_process').exec('/bin/echo NPMIDE_TRACE_CANARY', ()=>{});",
        trace=False)
    assert any(e["kind"] == "process" for e in events)          # intent logged
    assert not any(e["kind"] in ("native", "syscall") for e in events)  # never ran
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_harness_native_trace.py -v`
Expected: FAIL — `test_trace_native_runs_binary_and_emits_syscalls` finds no `native`/`syscall` events (preload does not yet branch); `test_default_mode_still_neuters` PASSES already. (Skips entirely if node or strace absent.)

- [ ] **Step 3: Write `trace.js`**

Create `src/npm_ide_analyst/sandbox/harness/trace.js`:

```javascript
// src/npm_ide_analyst/sandbox/harness/trace.js
'use strict';
// Runs an attempted child_process exec under strace (opt-in --trace-native
// mode only). Emits a `native` event (command + exit) and bounded `syscall`
// events. Uses the ORIGINAL, unhooked child_process fns passed in as origFn,
// and reads the strace output via unhooked fs.openSync/readSync/closeSync so
// the fs hooks in preload.js do not fire on our own trace file.
const fs = require('fs');
const { spawnSync } = require('child_process');
const { emit } = require('./emit.js');

const MAX_SYSCALL_EVENTS = 200;
const PER_NAME_CAP = 25;
// Syscalls worth surfacing for triage:
const NOTABLE = new Set([
  'execve', 'execveat', 'connect', 'socket', 'bind', 'sendto', 'sendmsg',
  'open', 'openat', 'unlink', 'unlinkat', 'chmod', 'fchmod', 'fchmodat',
  'rename', 'renameat', 'ptrace', 'clone', 'fork', 'vfork', 'kill',
]);
const SENSITIVE = /\.ssh|\.aws|\.npmrc|\.env|credentials|id_rsa|cookies|Login Data|\.docker/i;

let _seq = 0;

// argv reconstruction per child_process function shape.
function toArgv(fnName, args) {
  const a0 = args[0];
  // exec / execSync: single command string run via the shell.
  if (fnName === 'exec' || fnName === 'execSync') {
    return ['/bin/sh', '-c', String(a0)];
  }
  // spawn / spawnSync / execFile / execFileSync: (file, [args], ...)
  const file = String(a0);
  const rest = Array.isArray(args[1]) ? args[1].map(String) : [];
  return [file, ...rest];
}

function rawRead(path) {
  const fd = fs.openSync(path, 'r');
  try {
    const chunks = [];
    const buf = Buffer.alloc(65536);
    let n;
    while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
      chunks.push(Buffer.from(buf.slice(0, n)));
    }
    return Buffer.concat(chunks).toString('utf8');
  } finally {
    fs.closeSync(fd);
  }
}

function parseAndEmit(traceText, argv) {
  const lines = traceText.split('\n');
  const counts = Object.create(null);
  let emitted = 0;
  // strace -f prefixes lines with a pid; capture the syscall name.
  const re = /^(?:\[pid\s+\d+\]\s+|\d+\s+)?(\w+)\(/;
  for (const line of lines) {
    if (emitted >= MAX_SYSCALL_EVENTS) {
      emit('syscall', `[truncated: >${MAX_SYSCALL_EVENTS} notable syscalls]`, {});
      break;
    }
    const m = re.exec(line);
    if (!m) continue;
    const name = m[1];
    if (!NOTABLE.has(name)) continue;
    counts[name] = (counts[name] || 0) + 1;
    if (counts[name] > PER_NAME_CAP) continue;
    const sensitive = SENSITIVE.test(line);
    const detail = line.trim().slice(0, 300);
    emit('syscall', `${name}: ${detail}`, {
      syscall: name,
      sensitive,
      argv: argv.slice(0, 3),
    });
    emitted += 1;
  }
}

function traceExec(fnName, args, origFn) {
  _seq += 1;
  const tracePath = `/tmp/analyst-trace-${process.pid}-${_seq}.log`;
  const argv = toArgv(fnName, args);
  // strace -f (follow forks) -qq (quiet) -o file -- <argv>
  const straceArgs = ['-f', '-qq', '-o', tracePath, '--', ...argv];
  let result;
  try {
    result = spawnSync('strace', straceArgs, {
      encoding: 'buffer',
      timeout: 20000,
      maxBuffer: 8 * 1024 * 1024,
    });
  } catch (e) {
    emit('native', `strace failed to launch: ${e && e.message}`, { argv });
    result = { status: null, stdout: Buffer.from(''), stderr: Buffer.from('') };
  }

  const exit = result && result.status;
  emit('native', `strace ${argv.join(' ').slice(0, 200)} -> exit ${exit}`, {
    argv, exit,
  });

  try {
    const traceText = rawRead(tracePath);
    parseAndEmit(traceText, argv);
  } catch (_) { /* trace file may be absent if strace never wrote it */ }
  try { fs.unlinkSync(tracePath); } catch (_) {}

  const stdout = (result && result.stdout) || Buffer.from('');

  // Shape the return value like the original function.
  if (fnName.endsWith('Sync')) {
    return stdout; // execSync/spawnSync/execFileSync callers expect stdout buffer
  }
  const { EventEmitter } = require('events');
  const stub = new EventEmitter();
  stub.stdout = new EventEmitter();
  stub.stderr = new EventEmitter();
  stub.kill = () => {};
  const cb = args.find((a) => typeof a === 'function');
  process.nextTick(() => {
    const out = stdout.toString('utf8');
    if (out) stub.stdout.emit('data', stdout);
    stub.stdout.emit('end');
    if (cb) cb(null, out, (result && result.stderr || Buffer.from('')).toString('utf8'));
    stub.emit('close', typeof exit === 'number' ? exit : 0);
    stub.emit('exit', typeof exit === 'number' ? exit : 0);
  });
  return stub;
}

module.exports = { traceExec };
```

- [ ] **Step 4: Wire the `preload.js` branch**

In `src/npm_ide_analyst/sandbox/harness/preload.js`, at the top (after the existing `const { emit } = require('./emit.js');` line), add:

```javascript
const { traceExec } = require('./trace.js');
const TRACE_NATIVE = process.env.ANALYST_TRACE_NATIVE === '1';
```

Then replace the entire `child_process` hook loop body. The existing loop is:

```javascript
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
```

Replace it with (adds the trace branch; `fork` always neutered):

```javascript
for (const fn of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) {
  if (typeof cp[fn] !== 'function') continue;
  const orig = cp[fn];
  cp[fn] = function (...args) {
    emit('process', `${fn}: ${JSON.stringify(args[0])}`, { fn, args: args.slice(0, 2) });
    // Opt-in native tracing: actually run the exec under strace (except fork,
    // which re-execs node and is not a native drop). Default: log + neuter.
    if (TRACE_NATIVE && fn !== 'fork') {
      return traceExec(fn, args, orig);
    }
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_harness_native_trace.py -v`
Expected: PASS (2 tests) on a host with node + strace; SKIP otherwise.

- [ ] **Step 6: Run the full harness + unit suite for regressions**

Run: `python -m pytest tests/test_harness_hooks.py tests/test_harness_entrypoints.py tests/test_sandbox_findings.py tests/test_sandbox_run_flags.py -v`
Expected: all PASS or SKIP (node-gated). Confirms the preload edit didn't break the default neuter path.

- [ ] **Step 7: Commit**

```bash
git add src/npm_ide_analyst/sandbox/harness/trace.js src/npm_ide_analyst/sandbox/harness/preload.js tests/test_harness_native_trace.py
git commit -m "feat: harness runs exec under strace in trace-native mode"
```

---

### Task 6: CLI — `--trace-native` flag, warning, and guard

**Files:**
- Modify: `src/npm_ide_analyst/cli.py`
- Test: `tests/test_cli_dynamic.py`

**Interfaces:**
- Consumes: `detonate` (now accepts `trace_native`), `docker_available`, `build_image`, `behavior_to_findings`, `build_timeline` (all existing).
- Produces: `analyze` gains `--trace-native/--no-trace-native` (default False). Rules:
  - `--trace-native` without `--dynamic` → `click` error, non-zero exit, no analysis run.
  - When active, print a stderr warning naming the isolation weakening, then call `detonate(payload_root, sample.artifact_type, trace_native=True)`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_cli_dynamic.py`:

```python
def test_trace_native_requires_dynamic(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(json.dumps({"name": "e"}))
    out = tmp_path / "out"
    result = CliRunner().invoke(
        cli, ["analyze", str(pkg), "--out", str(out), "--trace-native"])
    assert result.exit_code != 0
    assert "trace-native" in result.output.lower()
    assert "dynamic" in result.output.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli_dynamic.py::test_trace_native_requires_dynamic -v`
Expected: FAIL — no such option `--trace-native` (Click errors differently / exit code mismatch).

- [ ] **Step 3: Add the flag, guard, and warning**

In `src/npm_ide_analyst/cli.py`, add the option decorator to `analyze` (after the `--dynamic` option):

```python
@click.option("--trace-native/--no-trace-native", default=False,
              help="Under --dynamic: run dropped/native binaries under strace "
                   "(adds CAP_SYS_PTRACE, weakening isolation; executes native "
                   "payload code). Opt-in, default off.")
```

Update the `analyze` signature to accept it:

```python
def analyze(input_path: Path, out_dir: Path, dynamic: bool,
            trace_native: bool) -> None:
```

At the start of `analyze`'s body (before `out_dir.mkdir(...)`), add the guard:

```python
    if trace_native and not dynamic:
        raise click.UsageError(
            "--trace-native requires --dynamic (it deepens detonation, "
            "which only runs under --dynamic).")
```

In the `if dynamic:` / `else:` detonation block, replace the `detonate(...)` call and add the warning. The current block is:

```python
        else:
            try:
                build_image()
                behavior = detonate(payload_root, sample.artifact_type)
                findings = findings + behavior_to_findings(behavior)
                timeline = build_timeline(behavior)
```

Replace those lines with:

```python
        else:
            try:
                if trace_native:
                    click.echo(
                        "WARNING: --trace-native adds CAP_SYS_PTRACE (weakening "
                        "container isolation) and EXECUTES native payload code "
                        "under strace. Network stays disabled; all other limits "
                        "hold. Proceeding.", err=True)
                build_image()
                behavior = detonate(payload_root, sample.artifact_type,
                                    trace_native=trace_native)
                findings = findings + behavior_to_findings(behavior)
                timeline = build_timeline(behavior)
```

(The `except` clause below stays unchanged.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cli_dynamic.py -v`
Expected: PASS (new test plus all existing `test_cli_dynamic.py` tests).

- [ ] **Step 5: Run the full unit suite**

Run: `python -m pytest -q`
Expected: green; Docker/node/strace-gated tests skip cleanly when tools absent.

- [ ] **Step 6: Commit**

```bash
git add src/npm_ide_analyst/cli.py tests/test_cli_dynamic.py
git commit -m "feat: --trace-native CLI flag with isolation warning and guard"
```

---

### Task 7: End-to-end verification + docs (gated on docker+strace, manual)

**Files:**
- Modify: `docs/superpowers/plans/2026-07-06-npm-ide-analyst-plan-b-dynamic-sandbox.md` (mark native tracing done in "Out of scope")

**Interfaces:** none (verification + doc bookkeeping).

- [ ] **Step 1: Full gated integration run (only if Docker + strace present)**

Run:
```bash
python -m pytest tests/test_sandbox_orchestrator.py -k "trace_native or default_still_neuters" -v
```
Expected: both PASS (image builds with strace; `trace_native=True` yields `native`/`syscall` events; default run has none). If Docker absent, SKIP — note it and rely on the node+strace harness tests from Task 5.

- [ ] **Step 2: Manual CLI smoke (only if Docker + strace present)**

Run:
```bash
mkdir -p /tmp/smoke/pkg && cd /tmp/smoke
printf '{"name":"p","scripts":{"postinstall":"node ./x.js"}}' > pkg/package.json
printf "require('child_process').exec('/bin/echo NPMIDE_TRACE_CANARY');" > pkg/x.js
npm-ide-analyst analyze ./pkg --out ./out --dynamic --trace-native
```
Expected: stderr prints the CAP_SYS_PTRACE warning; `out/report.json` `behavior` contains `native`/`syscall` events; `out/report.html` "Dynamic Behavior" section lists them.

- [ ] **Step 3: Update the Plan B doc's Out-of-scope note**

In `docs/superpowers/plans/2026-07-06-npm-ide-analyst-plan-b-dynamic-sandbox.md`, change the out-of-scope bullet:

```
- Native-binary tracing (Frida/strace) for payloads that drop and run an ELF.
```
to:
```
- Native-binary tracing: strace syscall tracing implemented (opt-in `--trace-native`, see `docs/superpowers/specs/2026-07-07-native-syscall-tracing-design.md`). Frida/API-level tracing remains future work.
```

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/plans/2026-07-06-npm-ide-analyst-plan-b-dynamic-sandbox.md
git commit -m "docs: mark strace native tracing done in Plan B backlog"
```

---

## Self-Review

- **Spec coverage:**
  - Isolation tradeoff design note → written & committed (`specs/2026-07-07-...`), referenced in header.
  - Minimal `--cap-add SYS_PTRACE` gated behind opt-in → Task 2 (`run_flags`) + Task 3 (`detonate`) + Task 6 (CLI flag/guard/warning).
  - Keep `--network none` + all other limits → Task 2 asserts hardening intact; only ptrace added.
  - Opt-in, default OFF, labeled → Task 6 (`--trace-native` default False, warning, `--dynamic` guard); Task 3/5 default path unchanged (asserted by `test_detonate_default_still_neuters`, `test_default_mode_still_neuters`).
  - Dockerfile installs strace → Task 4.
  - Parse tracer output into BehaviorEvents merged into report → Task 5 (`trace.js` parse + emit `native`/`syscall`) → existing `parse_event_log`/`Report`; Task 1 maps them to findings.
  - Gated integration test with benign in-image ELF making an identifiable syscall (`/bin/echo`, execve/write) → Task 3 (docker) + Task 5 (node+strace).
  - TDD workflow, gated tests skip cleanly → every task: failing test → minimal code → commit; gates on `docker_available` / `which("node")` / `which("strace")`.
- **Placeholder scan:** none — every code step carries complete code; caps are concrete (`MAX_SYSCALL_EVENTS=200`, `PER_NAME_CAP=25`).
- **Type consistency:** `run_flags(trace_native: bool) -> list[str]` and `PTRACE_CAP_FLAGS` (Task 2) used verbatim in Task 3; `detonate(..., trace_native=False)` (Task 3) called with `trace_native=` in Task 6; `traceExec(fnName, args, origFn)` (Task 5 `trace.js`) called identically in `preload.js`; event kinds `native`/`syscall` emitted in Task 5 match the `_MAP` keys added in Task 1 and the assertions in Tasks 3 & 5.
- **Known cross-task ordering:** Task 3's docker test `test_detonate_trace_native_captures_syscalls` only goes green after Tasks 4+5; called out explicitly in Task 3 Step 4 and re-verified in Task 7 Step 1.
```
