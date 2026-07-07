# npm-ide-analyst — Optional Real Network Sinkhole (design)

**Status:** approved for planning (2026-07-07)
**Extends:** `docs/superpowers/plans/2026-07-06-npm-ide-analyst-plan-b-dynamic-sandbox.md`
(the "Out of scope" item: *"A real DNS+HTTP sinkhole container for live multi-round C2 dialog capture"*).

## Problem

Today the detonation sandbox runs with `--network none` and captures outbound
traffic via **in-process fakenet** hooks in `harness/preload.js`
(`http`/`https`/`net`/`dns` are logged and neutered, returning synthetic
responses). This captures the outbound request + body but **not** multi-round C2
dialogs that depend on real server replies — the payload never receives a live
answer, so any second request gated on the first reply never fires.

## Goal

Add a **strictly opt-in** mode that stands up a real, internet-less sinkhole so
hostname-based C2 completes a live back-and-forth and is captured in full.
Default behavior is unchanged: `--network none` + in-process fakenet.

- New `sinkhole: bool = False` parameter to `detonate()` in
  `sandbox/orchestrator.py`.
- New `--sinkhole/--no-sinkhole` CLI flag on `analyze` (default off).

## Non-goals / documented limits

- **Hard-coded public IPs are not captured.** On an `--internal` Docker network
  there is no route to an arbitrary IP, and transparent redirection would need
  `iptables`/`CAP_NET_ADMIN`, which would violate `--cap-drop ALL` on the
  detonation container. Only **hostname-based** C2 (which resolves via the
  sinkhole's DNS) reaches the sinkhole. This is surfaced to the user (warning +
  report note).
- No native-binary tracing, no Windows containers (unchanged from Plan B).

## Safety invariants (unchanged)

- The Python orchestrator still never imports/execs/evals sample code — it only
  shells `docker` and reads JSON-lines logs as data.
- The **detonation** container (the only place sample code runs) keeps **every**
  existing isolation flag: non-root `--user 1000:1000`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, `--read-only`, `--tmpfs` workdirs,
  `--memory`, `--cpus`, `--pids-limit`, `--rm`, sample mounted `:ro`, wall-clock
  timeout with force-reap. In sinkhole mode the **only** change is that
  `--network none` is replaced by `--network <internal-net> --dns <sinkhole-ip>`
  plus two env vars; nothing is loosened.
- The sinkhole network is created with `--internal` → **no route to the real
  internet**. Even with the preload network hooks relaxed, nothing can exfiltrate.
- **`NODE_TLS_REJECT_UNAUTHORIZED=0` is deliberate and tightly scoped.** It is set
  as an env var **only inside the ephemeral detonation container** (never on the
  host, never persisted), whose entire job is to let a malware sample's HTTPS
  reach our self-signed sinkhole. The alternative — provisioning the sample's
  code to trust a CA — is neither possible (we don't control the sample) nor
  desirable. Because the network is `--internal`, disabling verification cannot
  enable a real MITM: there is no real server to impersonate and nowhere for
  traffic to go but the sinkhole. This is the correct call for a detonation
  sandbox and is confined to that container's environment.

## Architecture

```
docker network create --internal analyst-net-<uuid>
        │
        ├── sinkhole container  (our trusted code, NO sample runs here)
        │     entrypoint: node /harness/sinkhole.js
        │     DNS :53  → answers every A query with its own IP
        │     HTTP :80 / HTTPS :443 (baked self-signed cert)
        │              → 200 {"ok":true}, logs full request
        │     writes requests.jsonl (via emit.js) to a bind-mounted host dir
        │
        └── detonation container (sample runs here, full isolation)
              --dns <sinkhole-ip>  -e ANALYST_SINKHOLE=1
              -e NODE_TLS_REJECT_UNAUTHORIZED=0
              preload relaxes ONLY network hooks → traffic hits the sinkhole
              writes events.jsonl to its own bind-mounted host dir

orchestrator ingests events.jsonl + requests.jsonl → merged list[BehaviorEvent]
finally: force-rm sinkhole container, docker network rm, rmtree temp dirs
```

## Components

### 1. `src/npm_ide_analyst/sandbox/harness/sinkhole.js` (new)

Node built-ins only. Reuses `emit.js` for its capture log (identical JSON-lines
schema the Python parser already reads), by setting
`ANALYST_EVENT_LOG=/work/sinkout/requests.jsonl` for the sinkhole container.

- **DNS** — `dgram` UDP socket on `:53`. Minimal DNS parse: for any A query,
  answer with the sinkhole's own IP (from `ANALYST_SINKHOLE_IP` env, injected by
  the orchestrator). Non-A queries get an empty answer. Emits `emit('dns', ...)`.
- **HTTP** — `http.createServer` on `:80`. Buffers the body (capped, e.g. 64 KB),
  logs method + path + headers + body, responds `200` with `{"ok":true}`.
  Emits `emit('c2', 'HTTP <method> <host><path>', {method, host, path, headers, body})`.
- **HTTPS** — `https.createServer` on `:443` with the baked cert. Same handling
  and same `c2` kind.
- **Readiness** — after all three listeners are bound, writes `SINKHOLE READY\n`
  to real stdout (`process.stdout.write`, *not* via emit) so the orchestrator can
  poll `docker logs` and avoid a start-order race.
- The sinkhole does **not** load `preload.js` (no `-r`), so `fs`/`net` are
  unpatched inside it.

### 2. `src/npm_ide_analyst/sandbox/harness/preload.js` (modify)

Add a sinkhole branch gated on `process.env.ANALYST_SINKHOLE`. When set, the
network hooks **log then delegate to the real implementation** instead of
returning a neutered stub:

- `http`/`https` `request`/`get`: emit the outbound intent, then
  `return orig.apply(mod, args)` so a real socket opens to the sinkhole.
- `net.Socket.prototype.connect`: emit, then call the original `connect`.
- `dns` `lookup`/`resolve*`: emit, then call the original resolver (which uses
  `/etc/resolv.conf` → the sinkhole via `--dns`).

**Everything else stays neutered exactly as today**: `child_process`, `fs`
writes, `eval`/`Function` (still log-then-run), `Buffer.from`/`atob` decode
logging. When `ANALYST_SINKHOLE` is unset the file behaves byte-for-byte as now.

### 3. `src/npm_ide_analyst/sandbox/docker/Dockerfile` (modify)

- `apt-get install -y --no-install-recommends openssl` (build only; cleaned).
- Generate a self-signed cert at build:
  `openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=*"
   -keyout /harness/sink-key.pem -out /harness/sink-cert.pem`.
  `chown` so the runtime user can read them. `CN` is irrelevant because the
  detonation side runs with `NODE_TLS_REJECT_UNAUTHORIZED=0`.
- Entrypoint unchanged; the sinkhole run overrides it with `--entrypoint node`.

### 4. `src/npm_ide_analyst/sandbox/orchestrator.py` (modify)

- Split the flag list so isolation flags are shared and network flags are
  per-mode. Add a pure helper:
  `_detonation_flags(network: str | None, dns_ip: str | None) -> list[str]`
  returning the full `docker run` flag vector. Default mode →
  `--network none`; sinkhole mode → `--network <net> --dns <ip>`
  `-e ANALYST_SINKHOLE=1 -e NODE_TLS_REJECT_UNAUTHORIZED=0`. All other isolation
  flags identical in both.
- `detonate(payload_root, artifact_type, timeout=30, sinkhole=False)`:
  - `sinkhole=False` → current behavior, untouched.
  - `sinkhole=True` → run `_run_with_sinkhole(...)`:
    1. `docker network create --internal --driver bridge <net>`.
    2. `docker run -d --rm --name <sink> --network <net> --user 0:0
       --cap-drop ALL --cap-add NET_BIND_SERVICE
       --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,size=8m
       --memory 128m --cpus 1 --pids-limit 64
       -v <sinkout>:/work/sinkout:rw
       -e ANALYST_EVENT_LOG=/work/sinkout/requests.jsonl
       -e ANALYST_SINKHOLE_IP=<resolved after start>
       --entrypoint node <IMAGE> /harness/sinkhole.js`.
       (Sinkhole runs as **root** solely so `CAP_NET_BIND_SERVICE` is effective
       for binding 53/80/443 — Docker does not grant added caps to the ambient
       set for non-root. It runs only our code, no sample, on an internet-less
       net, read-only, cap-dropped, resource-limited.)
    3. Poll `docker logs <sink>` until `SINKHOLE READY` (bounded, ~15 s); on
       timeout, tear down and fall back to `--network none` detonation
       (graceful degradation, warn).
    4. Read the sinkhole IP from `docker inspect <sink>` JSON
       (`NetworkSettings.Networks[<net>].IPAddress`).
    5. Run the detonation container with the sinkhole flag vector + `--dns <ip>`;
       same force-reap-on-timeout logic as today.
    6. `return load_event_log(events.jsonl) + load_event_log(requests.jsonl)`.
  - `finally`: `docker rm -f <sink>`, `docker network rm <net>` (best-effort,
    small retry), `shutil.rmtree` both temp dirs.

### 5. `src/npm_ide_analyst/sandbox/findings.py` (modify)

Add one row: `"c2": ("c2", Severity.HIGH, "C2 server dialog")`. DNS already maps
to LOW `network`. No other changes.

### 6. `src/npm_ide_analyst/cli.py` (modify)

`analyze` gains `--sinkhole/--no-sinkhole` (default off). `--sinkhole` implies
detonation (runs the dynamic branch even without `--dynamic`) and is passed as
`detonate(..., sinkhole=True)`. If Docker is unavailable, warn and degrade to
static-only (exit 0), same pattern as `--dynamic`. A note is emitted that
hard-coded-IP C2 is out of scope for the sinkhole.

## Testing (TDD, gating preserved)

- **Unit (ungated, no Docker):** `test_detonation_flags` asserts the sinkhole
  flag vector keeps `--cap-drop ALL`, `--read-only`, `--user 1000:1000`, mem/cpu/
  pids limits, contains `--dns` pointing at the sinkhole, and **never** contains
  `--network none`; and that default mode **does** contain `--network none` and
  no `--dns`. (`--internal` lives on the separate `docker network create`, not on
  the run vector.) Also `test_c2_finding_mapping` asserts a `c2` event → HIGH
  finding.
- **Integration (gated on `docker_available()`), new in
  `tests/test_sandbox_orchestrator.py`:**
  `test_detonate_sinkhole_captures_multi_request_dialog` — a sample whose
  `activate()` issues `http.get('http://evil.test/a', ...)` and, **only inside
  the response handler** (i.e. after a real reply), issues a second request
  `http://evil.test/b?ack=<statusCode>`. Assert the sinkhole `requests.jsonl`
  captured **both** `/a` and `/b?ack=200` → proves a live multi-round dialog that
  the `--network none` path cannot produce. Assert teardown leaves no leftover
  container/network (`docker ps -a` / `docker network ls` clean for the uuid).
- Existing gated tests (`test_detonate_vsix_captures_network`,
  `test_detonate_npm_captures_process`) must stay green — default path unchanged.

## Teardown / failure handling

- All sinkhole lifecycle is inside `try/finally`; the `finally` force-removes the
  container and the network even if detonation raised or timed out.
- If the sinkhole never signals ready, the run degrades to a normal
  `--network none` detonation and warns — the tool never hangs or hard-fails on
  sinkhole trouble.
