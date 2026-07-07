# Native-Binary Syscall Tracing for the Detonation Sandbox

**Status:** Design approved — ready for implementation plan
**Date:** 2026-07-07
**Backlog origin:** "Option B" / native tracing, listed under *Out of scope (future work)* in
`docs/superpowers/plans/2026-07-06-npm-ide-analyst-plan-b-dynamic-sandbox.md`.

## Problem

The dynamic sandbox detonates JS payloads under an instrumented Node harness
(`sandbox/harness/preload.js`) inside a hardened Linux container. The
`child_process` hook **logs the intended exec but neuters it** — it never runs
the target. So when a payload drops an ELF binary and executes it, we record the
*intent* (`process` event) but see nothing of what the binary actually does:
its syscalls, network attempts, file access, and secondary execs are invisible.

## Goal

Add an **opt-in, default-OFF** deeper-tracing mode. When enabled, an attempted
exec inside the container is **actually executed under `strace`**, and the
resulting syscalls are captured as `BehaviorEvent`s (kinds `native` and
`syscall`) and merged into the report exactly like every other behavior event.

Non-goals for this change: Frida/API-level tracing, Windows-container
detonation, live multi-round C2 dialog capture. Frida remains documented future
work.

## The capability / isolation tradeoff (the crux)

`strace` uses `ptrace(2)`. Docker's **default seccomp profile gates the
`ptrace` syscall (and `process_vm_readv`/`process_vm_writev`) behind the
`CAP_SYS_PTRACE` capability**. The current sandbox runs `--cap-drop ALL`, so
`ptrace` is blocked and `strace` cannot attach. The minimal, sufficient change:

- **Add exactly one capability: `--cap-add SYS_PTRACE`.** Nothing else.
- `--security-opt no-new-privileges` **stays.** It blocks privilege *escalation*
  via setuid/setgid binaries; it does not remove an explicitly-added capability,
  so `strace` still works with it on.
- **Every other isolation control is unchanged and mandatory:** `--network none`,
  non-root `--user 1000:1000`, `--cap-drop ALL` (the base — `SYS_PTRACE` is the
  sole re-add), `--read-only` rootfs, `--tmpfs` writable workdirs, `--memory`,
  `--cpus`, `--pids-limit`, and the wall-clock timeout that force-reaps the
  container.

### Why this is genuinely higher-risk (and therefore opt-in)

Two things change together in this mode:

1. `SYS_PTRACE` lets a process trace and read/write the memory of other
   processes **within the same container**. It does not grant host access, but it
   widens the in-container attack surface (e.g. against the Node harness process).
2. **We actually execute the native payload** rather than neutering it. That is
   the whole point — but it means untrusted native code runs, not just untrusted
   JS under neutering hooks.

Containment still holds via the untouched controls: no network can leave
(`--network none`), the process cannot escalate (`no-new-privileges`, non-root),
the rootfs is read-only, resources are capped, and a wall-clock timeout kills
runaways. But because the blast radius is strictly larger than the default
neutering path, this mode is:

- **Opt-in only**, behind an explicit `--trace-native` flag.
- **Default OFF.** The default `--dynamic` path is byte-for-byte today's behavior.
- **Loudly labeled.** The CLI prints a warning when the mode is active, stating
  that it adds `CAP_SYS_PTRACE` (weakening isolation) and executes native payload
  code.
- **Refuses to run without `--dynamic`.** `--trace-native` on its own is an error,
  not a silent implication of detonation.

## Architecture

```
CLI:  analyze --dynamic --trace-native
        │  (errors if --trace-native without --dynamic; prints isolation warning)
        ▼
orchestrator.detonate(payload_root, artifact_type, trace_native=True)
        │  run_flags(trace_native=True) → DOCKER_RUN_FLAGS + ["--cap-add","SYS_PTRACE"]
        │  env ANALYST_TRACE_NATIVE=1
        ▼
docker run … node -r preload.js run-{npm,vsix}.js
        │
        ▼
preload.js child_process hook
        │  if ANALYST_TRACE_NATIVE unset → emit 'process' + neuter (today's behavior)
        │  else → emit 'process' (intent) + trace.js traceExec(...)
        ▼
trace.js: spawnSync strace -f -o /tmp/trace-N.log -- <argv>
        │  read trace via UNHOOKED openSync/readSync/closeSync
        │  parse notable syscalls → emit('native', …) + emit('syscall', …) (bounded)
        ▼
events.jsonl (host bind mount) → parse_event_log → BehaviorEvents
        → behavior_to_findings (native→HIGH, syscall→MEDIUM) → Report
```

### Why synchronous strace

`traceExec` runs `strace` **synchronously** (`spawnSync`) even for async
`cp.exec`/`spawn` calls, then delivers real stdout to the payload's callback on
`process.nextTick`. Rationale:

- **Determinism for tests** — all `native`/`syscall` events are emitted before
  control returns, so ordering is fixed and nothing races the harness exit timer.
- **No lost events** — the async harness's short post-run exit timer can't cut off
  a still-running trace.
- Runaway native payloads are bounded by the **container wall-clock timeout**
  (the existing backstop), so blocking synchronously is safe.

### Reading the trace file without tripping the fs hooks

`preload.js` hooks `fs.readFile*`/`createReadStream` (logging/neutering). The
trace file is read via `fs.openSync`/`readSync`/`closeSync`, which are **not
hooked** — the same technique `emit.js` already uses for its raw log append.
This avoids both recursion and spurious `file` events for the trace log itself.

## Components

| File | Change |
|---|---|
| `sandbox/docker/Dockerfile` | `apt-get install -y --no-install-recommends strace` (bookworm), before the `USER 1000` switch; clean apt lists. |
| `sandbox/harness/trace.js` | **New.** `traceExec(fnName, args, origFn)` → spawnSync strace, parse, emit `native`/`syscall`, return a sync buffer or async stub delivering real stdout. |
| `sandbox/harness/preload.js` | child_process hook branches on `process.env.ANALYST_TRACE_NATIVE`: neuter (default) vs `traceExec`. `fork` stays neutered (it re-execs node, not a native drop). |
| `sandbox/orchestrator.py` | `run_flags(trace_native: bool) -> list[str]` (pure, unit-testable) adds `--cap-add SYS_PTRACE` only when true; `detonate(..., trace_native=False)` uses it and sets `ANALYST_TRACE_NATIVE=1`. |
| `sandbox/findings.py` | `_MAP` gains `native` → (`native-exec`, HIGH) and `syscall` → (`native-syscall`, MEDIUM). |
| `cli.py` | `--trace-native/--no-trace-native` (default off); error if set without `--dynamic`; print isolation warning when active; thread `trace_native` into `detonate`. |

No `models.py` change: `BehaviorEvent` already carries arbitrary `kind`, and
`parse_event_log` is generic.

### New event kinds

- **`native`** — a native/dropped binary was actually executed under trace.
  Detail: the command + exit status. Maps to a HIGH `native-exec` finding.
- **`syscall`** — one notable syscall observed under trace. Curated set:
  `execve`/`execveat`, `connect`, `socket`, `bind`, `sendto`, `open`/`openat`
  (flagged when the path is sensitive), `unlink`/`unlinkat`, `chmod`/`fchmod`,
  `rename`, `ptrace`, `clone`/`fork`/`vfork`, `kill`. Bounded to a cap (e.g. 200
  emitted events total, and a per-syscall-name cap) to keep the log finite; the
  cap is logged when hit so truncation is never silent. Maps to a MEDIUM
  `native-syscall` finding (deduped by detail).

## Testing (TDD)

- **Unit, ungated:**
  - `run_flags(True)` contains `--cap-add SYS_PTRACE`; `run_flags(False)` does not
    and is otherwise identical to `DOCKER_RUN_FLAGS`.
  - `behavior_to_findings` maps `native` → HIGH `native-exec` and `syscall` →
    MEDIUM `native-syscall`.
  - `cli` errors when `--trace-native` is passed without `--dynamic`.
- **Gated on node + strace** (`shutil.which("node")` and `which("strace")`): a
  trusted test driver execs `/bin/echo NPMIDE_TRACE_CANARY` with
  `ANALYST_TRACE_NATIVE=1`; assert a `native` event and a `syscall` event
  (execve, and the canary/`write` visible).
- **Gated on docker** (`orch.docker_available()`): `detonate(sample, NPM,
  trace_native=True)` on a package whose `postinstall` execs
  `/bin/echo NPMIDE_TRACE_CANARY`; assert a `syscall`/`native` event surfaces and
  that the run used the ptrace cap.

The test binary is **`/bin/echo`** — an ELF already in the image. No compilation,
no external/synthetic malware; `execve` + `write` are the identifiable syscalls.

## Safety invariants preserved

- Python still **never** imports/execs/evals sample code — it only shells
  `docker` and reads the event log as data.
- The default (non-`--trace-native`) path is unchanged: neutering, `--cap-drop
  ALL` with no re-adds.
- Node+strace unit tests run trusted, test-authored drivers executing a benign
  in-image binary; no untrusted sample runs on the host.
- If `--trace-native` is requested but Docker is unavailable, behavior degrades
  to the existing static/dynamic warning path (no crash).
