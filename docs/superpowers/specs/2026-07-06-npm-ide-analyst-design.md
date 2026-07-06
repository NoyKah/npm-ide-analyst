# npm-ide-analyst — Design Spec

**Date:** 2026-07-06
**Status:** Approved design, pre-implementation

## 1. Purpose

A DFIR triage tool that automates analysis of malicious npm packages and VS Code–family
IDE extensions, based on the investigation flow in
`malicious-npm-and-ide-extension-investigation-guide.md`. It performs artifact
collection, static IOC analysis, and — critically for heavily obfuscated payloads —
**dynamic detonation in an isolated Docker sandbox** that produces a behavioral report of
what the payload actually does at runtime (network, process, filesystem, secret access),
de-obfuscated by virtue of executing the code.

The Python orchestrator **never executes payload code itself**. It reads files as data and
shells out to Docker for all detonation. This is the core safety invariant.

## 2. Locked design decisions

| Axis | Decision |
|---|---|
| Detonation engine | **Option A** — instrumented Node preload inside a hardened, network-isolated Docker container |
| Scope | Full DFIR pipeline: collect → static → dynamic → correlate → report |
| Implementation language | Python orchestrator + Node.js detonation harness |
| Collection modes | Both: `collect` (live host) and `analyze` (evidence dir or single sample) |
| Network during detonation | Sinkhole / fakenet (DNS + HTTP(S) responder on an internal network) |
| Report output | Machine-readable JSON + self-contained offline HTML |
| Threat-intel enrichment | None (fully offline) |
| Platform | **Windows-first `collect`**; `analyze` is cross-platform (operates on files) |

## 3. CLI surface

Single CLI, `npm-ide-analyst`:

- `collect` — live host, **read-only** artifact acquisition into a timestamped evidence
  directory. Hash-on-copy, chain of custody. Windows-first (per-IDE + npm paths from the
  guide). Never detonates.
- `analyze` — input is either a `collect` evidence dir OR a single sample
  (`.vsix`, npm `.tgz`, or a directory). Runs static + dynamic analysis and emits a report.
- `report` — re-render HTML from a previously produced JSON result.

## 4. Pipeline stages (each an independently testable module)

### 4.1 Acquire / Normalize (`acquire/`)
- Detect input type: VSIX (zip), npm tarball (tgz), directory, or `collect` evidence dir.
- Unpack into a normalized working tree.
- Hash everything with `sha256` + `sha512` (sha512 to match `_cacache`/lockfile `integrity`).
- Classify npm vs extension from the manifest.
- **Live collection (Windows-first):** read-only copy of the guide's recover-even-if-deleted
  sources first — `CachedExtensionVSIXs\`, npm `_cacache\content-v2\sha512\`,
  `extensions\.obsolete`, `_logs\` — plus `node_modules`, `extensions\`, `settings.json`,
  `.npmrc`. macOS/Linux live collection paths are stubbed (not day-one).

### 4.2 Static analysis (`static/`)
- **Manifest parse:** publisher, `main`, `activationEvents` (flag `"*"` / `onStartupFinished`),
  lifecycle scripts (`preinstall`/`install`/`postinstall`), dependencies, declared capabilities.
- **IOC regex sweep** across all JS (guide Part D): `child_process`, `eval`, `Function`, `vm`,
  `atob`, dynamic `require`, URLs / raw IPs, `.ssh`/`.aws`/`.npmrc`/`.env`, base64/hex blobs,
  Discord/Telegram/webhook endpoints.
- **AST pass** (robust against obfuscation): parse JS to locate `eval`/`Function`/dynamic-`require`
  call sites and runtime string assembly regex misses; includes a beautify/de-minify step for
  the report.
- **Config-hijack checks:** `settings.json` marketplace override
  (`extensions.gallery.serviceUrl`, `extensionsGallery`, Windsurf gallery URL); `.npmrc`
  registry override.

### 4.3 Dynamic detonation (`sandbox/`) — Option A
- **Detonation container:** hardened Node image — non-root, read-only rootfs + tmp workdir,
  dropped capabilities, `--security-opt no-new-privileges`, seccomp, cpu/mem/pids limits,
  wall-clock timeout. Sample **copied in** (never a writable host bind-mount). Attached only to
  an internal Docker network with no route to the internet.
- **Sinkhole container** on that internal network: DNS + HTTP(S) responder resolving all
  domains to itself; answers and **logs every request** (domain, URL, method, headers, body).
  Captures C2 without reaching the internet.
- **Instrumented harness** (`node -r preload.js`): hooks `child_process` (exec/spawn/execSync/fork),
  `net`/`tls`, `http`/`https`, `dns`, `fs` (sensitive-path reads), `process.env`, `require`, and
  global `eval`/`Function` (wrapped to log the **de-obfuscated** code strings). Each hook emits a
  structured JSON event with args + stack + timestamp; harmful ops are stubbed so execution
  continues and reveals more behavior.
- **Canary/decoy secrets** planted in the container (`~/.ssh/id_rsa`, `~/.aws/credentials`,
  `.npmrc` token) so theft is observed and exfiltrated values are traceable in sinkhole logs.
- **npm** → run lifecycle scripts + `require` main under the harness.
  **VSIX** → inject a mocked `vscode` module + mock `ExtensionContext`
  (globalState, secrets, subscriptions, env), call `activate(context)`, fire common activation events.
- Collect: sinkhole logs + harness event log + any files the payload dropped/wrote.

### 4.4 Correlate / Timeline (`correlate/`)
- Merge filesystem MAC times, IDE `exthost.log` activation times, npm `_logs` install times,
  and detonation events into a single timeline.
- Surface the guide's Part-C pivot: npm `_log` entry near an unexplained extension install.

### 4.5 Report (`report/`)
- Consolidate into schema-stable JSON.
- Render a self-contained **offline** HTML (inline CSS/JS): verdict/score, sample identity +
  hashes, static findings, dynamic behavior (network / process / file / secrets-accessed /
  de-obfuscated strings), timeline, IOC list, recovered artifacts.

## 5. Package layout

```
npm_ide_analyst/
├── cli.py            # argument parsing, subcommands
├── models.py         # dataclasses: Sample, Finding, Event, Timeline, Report
├── acquire/          # collectors (Windows-first live host) + unpackers (vsix, tgz, dir)
├── static/           # manifest parser, ioc scanner, ast analyzer, config-hijack checks
├── sandbox/
│   ├── orchestrator.py   # docker lifecycle, results ingestion
│   ├── harness/          # Node: preload.js, vscode-mock.js, run-npm.js, run-vsix.js
│   ├── sinkhole/         # DNS + HTTP(S) responder
│   └── docker/           # Dockerfile(s), compose/network definitions
├── correlate/        # timeline builder
└── report/           # json schema + html renderer + templates
```

## 6. Safety / isolation invariants
- Python orchestrator never `import`s/`require`s or executes the sample; it treats sample
  contents strictly as data.
- Static analysis reads files as bytes/text only.
- Detonation is the **only** place code runs, always inside Docker, always non-root, always on
  an internal network with no internet route, always resource- and time-limited.
- Sample is copied into the container, never mounted writable from the host.
- Real user directories are never mounted into the detonation container.

## 7. Explicitly out of scope (YAGNI, for now)
- Native-binary syscall tracing (Frida/strace, "Option B") — future extension for samples that
  drop an ELF/EXE.
- Online threat-intel enrichment (VirusTotal/OTX).
- macOS/Linux **live collection** beyond stubs (`analyze` is already cross-platform).

## 8. Testing strategy
- **Unit:** each module (manifest parse, IOC scan, AST analysis, config-hijack, timeline merge,
  report render) tested on fixtures.
- **Fixtures:** hand-crafted benign + synthetic-malicious samples (a fake npm pkg with a
  `postinstall` that "reads" a canary and "beacons" to a domain; a fake VSIX whose `activate()`
  spawns a process and hits a URL). No real malware in the repo.
- **Sandbox integration:** detonate the synthetic-malicious fixtures and assert the report
  contains the expected network/process/file/secret events. Gated behind a Docker-available check.
- **Safety test:** assert the orchestrator never executes sample code outside Docker (e.g. a
  fixture whose mere import would touch a canary file must leave the canary untouched during
  static analysis).
