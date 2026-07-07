# `colorz-utill` — simulated malicious npm package (lab artifact)

> ⚠️ **NOT REAL MALWARE, but do not `npm install` it.** This is a synthetic
> sample for exercising **npm-ide-analyst**. Detonate it only with the tool's
> isolated sandbox, which neuters every dangerous operation. Running it directly
> (`npm install`) would attempt the (harmless, documentation-IP) actions on your
> own machine and defeats the point.

## What it simulates

A typosquat of a popular color library that chains a classic supply-chain attack:

| Stage | Behavior | Detector it trips |
|-------|----------|-------------------|
| Install | `postinstall` → `node ./scripts/setup.js` auto-run | `lifecycle-script` (HIGH) |
| Obfuscation | `lib/loader.js` base64 blob + `eval` | `obfuscation` (MEDIUM), `dynamic-code` (HIGH) |
| Recon | `child_process.exec('whoami && hostname')` | `process-exec` (HIGH) |
| Credential theft | reads `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.npmrc` | `secret-access` (HIGH) |
| Stage-2 | `eval(base64)` → resolves hidden C2 `c2.evil-collector.xyz` | `dynamic-code` / runtime `decode` |
| Exfil | `POST https://198.51.100.14/collect` + Discord webhook | `network` (HIGH), `exfil-channel` (HIGH) |
| Config hijack | bundled `.npmrc` with rogue `registry=` + `_authToken` | `registry-override` (HIGH) |
| Env harvest | `process.env` | `env-harvest` (LOW) |

All network targets are **RFC 5737** documentation addresses (`198.51.100.0/24`)
and a placeholder webhook — nothing real is contacted. The secret paths are
**canaries** that only exist as decoys inside the tool's container.

## Build & analyze

```bash
# 1. build the tarball
python samples/colorz-utill/build.py --out ./out

# 2a. static only
npm-ide-analyst analyze ./out/colorz-utill-2.3.9.tgz --out ./report

# 2b. static + dynamic detonation (requires Docker Desktop, Linux containers)
npm-ide-analyst analyze ./out/colorz-utill-2.3.9.tgz --out ./report --dynamic

# open ./report/report.html
```

Expected verdict: **malicious** (multiple HIGH findings). Static analysis flags
the indicators; dynamic detonation additionally de-obfuscates the stage-2 blob
to reveal the hidden C2 domain and captures the live beacon — behavior the
obfuscation hides from static analysis alone.
