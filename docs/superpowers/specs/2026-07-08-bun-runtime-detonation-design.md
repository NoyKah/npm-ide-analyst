# npm-ide-analyst — Bun / alt-runtime payload detonation (design)

**Status:** approved for planning (2026-07-08)
**Extends:** `docs/superpowers/plans/2026-07-06-npm-ide-analyst-plan-b-dynamic-sandbox.md`
(the dynamic detonation harness) and
`docs/superpowers/specs/2026-07-07-npm-ide-analyst-sinkhole-design.md`
(the sinkhole network mode this reuses).

## Problem

A real-world npm supply-chain family (observed sample: `tiaan@1.0.2`) evades the
Node-based detonation sandbox by running its actual payload under **Bun**, a
separate JS runtime, rather than Node:

1. `package.json` → `preinstall: node setup_bun.js`
2. `setup_bun.js` → `execSync("which bun")`, then
   `spawn("bun", ["bun_environment.js"])`
3. `bun_environment.js` — the real, heavily obfuscated payload (C2 / exfil /
   secret theft)
4. `index.js` (`main`) — a benign `require('chalk')` facade

The current harness (`harness/preload.js`, injected via `node -r`) **neuters all
`child_process` calls** — every `spawn`/`exec` returns a benign stub and never
actually launches. Consequences observed in a live run:

- `spawn("bun", ["bun_environment.js"])` was faked → **the payload never
  executed.** The `DYN-process-exec spawn: "bun"` finding is logged *intent*, not
  a real launch.
- Even if it had launched: Bun is absent from the image and `--network none`
  blocks the payload's `curl … bun.sh/install | bash` fallback.
- Even if Bun ran: `node -r` preload injection is Node-specific, so a Bun
  subprocess would run **completely un-instrumented** — zero visibility.

Net: the `malicious / 420` verdict came almost entirely from **static** regex
IOCs on the obfuscated blob. The **dynamic engine contributed nothing about the
payload** — it only watched the Node setup shim. Against this family the dynamic
sandbox is blind.

## Goal

Actually detonate Bun-based (and Node self-re-exec) payloads **under
instrumentation**, so their runtime behavior (decoded strings, network targets,
secret reads, recursive spawns, file writes) is captured and merged into the
existing behavior timeline — with no reduction in container-level containment.

Scope decision (approved): the "actually execute" allowlist covers
**`bun`/`bunx`/`node`/`nodejs`** re-execs whose target script resolves *inside
the sample dir*. Everything else stays fully neutered exactly as today.

## Non-goals / documented limits

- **Other interpreters out of scope.** `deno`, `python`, `sh`, and arbitrary
  binaries stay neutered. Revisit per-runtime later.
- No transport rearchitecture (isolated / stream / sinkhole modes unchanged).
- No changes to static analysis, verdict scoring, or thresholds beyond emitting
  one new behavior event kind (`runtime-reexec`).
- Hard-coded public-IP C2 is still only captured in `--sinkhole` mode for
  hostname-based traffic (inherited limit from the sinkhole design).

## Safety invariants (unchanged)

- The Python orchestrator still never imports/execs/evals sample code — it only
  shells `docker` and reads JSON-lines logs as data.
- The detonation container remains the hard boundary and keeps **every**
  isolation flag: `--user 1000:1000`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, `--read-only` rootfs, `--memory 256m`,
  `--cpus 1`, `--pids-limit 128`, and `--network none` (or the internal sinkhole
  network). Running the allow-listed payload *inside* this boundary, under
  in-runtime hooks, is strictly **more** visibility and **no less** containment
  than the current neuter-all behavior.
- In-runtime hooks keep neutering the dangerous primitives for the executed
  payload too: filesystem writes outside `/work/*` are dropped; network is
  neutered+logged (`--network none`) or delegated to the sinkhole
  (`--sinkhole`); recursively spawned non-allowlisted processes stay stubbed.

## Design

### 1. Bun in the sandbox image

Add a **pinned** Bun release to `sandbox/docker/Dockerfile` at build time (build
has network; runtime stays offline). Requirements:

- Pin an explicit Bun version via a `BUN_VERSION` build arg (default = the
  current stable release chosen at implementation time) — no floating `latest`,
  for reproducibility. Install the pinned versioned binary (not the unpinned
  `bun.sh/install` fetch) so rebuilds are deterministic.
- Install to a fixed path on `PATH` for uid 1000; `chmod -R a+rX` (same
  world-readable concern already documented for `/harness`).
- Verify `bun --version` matches `BUN_VERSION` in the build (fail the build
  otherwise).

Cost: ~90 MB image growth (accepted). Side effect: the malware's own
`which bun` check now passes naturally.

### 2. Shared hook core + per-runtime entrypoints

Refactor the harness so the hook logic is shared and each runtime gets a thin
injector:

- **`harness/hooks-core.js`** — the existing neuter/log/sinkhole logic extracted
  verbatim from `preload.js`: `child_process`, `http`/`https`, `net`, `dns`,
  `fs`, `Buffer.from`, `atob`, `eval`, `Function`. Behavior is byte-for-byte the
  same as today except the `child_process` branch in §3 and the child registry
  in §5. Exports `{ waitForChildren }` (see §5).
- **`harness/preload.js`** (Node, `node -r`) — now just requires
  `hooks-core.js`. No behavior change beyond §3/§5.
- **`harness/preload-bun.js`** (Bun, `bun --preload`) — requires
  `hooks-core.js` **plus** Bun-native hooks (approved):
  - `Bun.spawn` / `Bun.spawnSync` → same allowlist/neuter path as node
    `child_process` (§3).
  - global `fetch` → log + neuter under `--network none`; delegate to real
    (→ sinkhole) when `ANALYST_SINKHOLE` is set — mirroring the existing
    `http`/`https` hook semantics.

  Rationale: Bun payloads commonly use `Bun.spawn` and global `fetch` instead of
  `node:child_process`/`node:http`; without these hooks the executed payload
  would bypass instrumentation.

The node-compat hooks in `hooks-core.js` are expected to apply under Bun (Bun
implements `node:child_process`, `node:fs`, `node:http`, etc.). Any hook that
does not take effect under Bun is a known gap covered by the Bun-native hooks
above; the plan will verify each core hook fires under Bun via the integration
fixture (§7).

### 3. `child_process` hook: neuter → allow-listed re-exec

In `hooks-core.js`, the `child_process` wrapper (and the Bun-native
`Bun.spawn*`) gains a branch evaluated **before** the neuter stub:

```
Given the invoked command + argv (or the exec command string):
  cmd0    = basename of the executable
  script  = first script-like argument
  IF cmd0 ∈ {bun, bunx, node, nodejs}
     AND resolveWithin(SAMPLE_DIR, script) !== null:
       → REWRITE to inject our preload:
           bun/bunx : bun  --preload /harness/preload-bun.js  <script> <args...>
           node     : node -r        /harness/preload.js       <script> <args...>
         with ANALYST_* env passed through (see §4) and stdio per §4;
       → actually invoke the ORIGINAL spawn/exec; register the child (§5);
       → emit('runtime-reexec', `<runtime> <script>`, …).
  ELSE:
       → unchanged neuter stub (today's behavior).
```

Notes:
- Covers `spawn`, `spawnSync`, `exec`, `execSync`, `execFile`, `execFileSync`,
  and `Bun.spawn`/`Bun.spawnSync`. `exec`/`execSync` take a command **string**
  (parse `argv[0]` + first script token); `spawn`/`execFile` take
  `(file, argsArray)`.
- `SAMPLE_DIR` comes from `ANALYST_SAMPLE_DIR` (already set), reusing
  `resolve-within.js` for containment — the same escape check already trusted by
  `run-npm.js`.
- `--trace-native` is orthogonal and unchanged: when `ANALYST_TRACE_NATIVE=1`,
  the existing strace path still wins for non-allowlisted execs.
- The malware's `which bun` (a non-allowlisted `execSync`) stays neutered and
  returns an empty buffer (no throw), which — as observed — makes the loader
  believe Bun is present and proceed straight to the re-exec.

### 4. Cross-process event correlation

The re-exec'd child must land its events in the same stream as the parent:

- **Env passthrough:** the rewritten spawn injects/preserves `ANALYST_SAMPLE_DIR`,
  `ANALYST_EVENT_LOG`, `ANALYST_SINKHOLE`, `ANALYST_TRACE_NATIVE`,
  `ANALYST_DETONATE_MS` into the child env.
- **Mount modes (isolated / sinkhole):** `ANALYST_EVENT_LOG` points at the
  shared `events.jsonl`. `emit.js`'s `rawAppend` opens with `O_APPEND` per line;
  single-line appends are atomic on Linux, so parent + child interleave without
  corruption. No change to `emit.js`.
- **Stream mode (remote daemon):** `ANALYST_EVENT_LOG=""` → `emit` writes to
  **stdout**. The rewritten spawn forces the child's stdout to **inherit** the
  parent's stdout (overriding any `stdio:'ignore'` the payload requested), so the
  child's JSON-lines reach the same stdout the collector parses.
- Events already carry a `stack` field, so parent-frame vs child-frame origin
  stays distinguishable in the timeline. No `events.py` schema change required.

### 5. Wait for children before exit (correctness fix)

Today `run-npm.js` ends with `setTimeout(() => process.exit(0), 200)`, which
would **kill an executing Bun child ~200 ms in**, truncating the payload.

- `hooks-core.js` maintains a registry of live allow-listed children and exports
  `waitForChildren(deadlineMs)` → resolves when all registered children exit or
  the deadline elapses (then best-effort `kill` on stragglers).
- `run-npm.js` and `run-vsix.js` replace the blind `setTimeout(exit, 200)` with:
  run the lifecycle/main, then `await waitForChildren(deadline)`, then exit.
- Deadline source: new `ANALYST_DETONATE_MS`, derived by the orchestrator as
  `max(1000, timeout*1000 − 2000)` (leaving ~2 s of slack under the
  orchestrator's `timeout + 15s` hard kill). When no allow-listed children were
  launched, `waitForChildren` resolves immediately, preserving today's fast
  exit.
- Backstops against hangs / fork bombs are unchanged: container `--pids-limit`,
  `--memory`, `--cpus`, and the orchestrator's `timeout + 15s` hard kill.

### 6. Orchestrator + reporting

- **`orchestrator.py`:** pass `-e ANALYST_DETONATE_MS=<derived>` into all three
  detonation transports (`_detonate_isolated`, `_detonate_via_stream`,
  `_detonate_with_sinkhole`). No transport/flag-vector changes otherwise. The
  `run_argv` already recorded in `debug` will show the new env var.
- **Reporting:** the new `runtime-reexec` behavior event surfaces as a finding
  (e.g. "Payload handed to bun and detonated under instrumentation") so the
  report shows the re-exec explicitly instead of a bare neutered `spawn`. Maps
  through the existing `findings.py`/report pipeline. Severity: **`high`** when
  the target runtime is an alt-runtime (`bun`/`bunx` — a known evasion signal),
  **`info`** for a `node` self-re-exec.

### 7. Testing

- **Unit (no Docker):** a fixture package whose `preinstall` spawns
  `node subscript.js`, where `subscript.js` performs an observable hooked action
  (e.g. read a canary path). Assert the subscript's events appear in the merged
  log — this exercises the full re-exec → preload-inject → env-passthrough →
  event-merge → `waitForChildren` pipeline **without needing Bun**.
- **Docker-gated (sandbox):** a synthetic **`bun-loader`** fixture mirroring
  `tiaan`'s structure (`preinstall` → `bun payload.js`; `payload.js` reads a
  canary + issues a `fetch`). Assert the payload's runtime behavior is captured
  and merged. Gated on Docker availability; per project memory, these tests must
  pass `dangerouslyDisableSandbox` or they skip silently.
- **Regression (Docker-gated):** assert non-allowlisted spawns (`curl`, `rm`,
  `which`) stay neutered — the allowlist does not widen general execution.
- **Existing suite:** the `preload.js` → `hooks-core.js` refactor must keep all
  current harness tests green (`test_harness_hooks`, `test_harness_entrypoints`,
  `test_safety_invariant`, etc.).

## Open items for the plan

- Confirm each `hooks-core.js` node-compat hook actually fires under Bun via the
  integration fixture; document any that require a Bun-native fallback.
- Final report copy for the `runtime-reexec` finding.
