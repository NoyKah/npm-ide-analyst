# Setup scripts

One-shot installers that provision everything `npm-ide-analyst` needs — Python,
Node.js, Docker, the tool itself (in a virtualenv), and the detonation sandbox
image — then run a smoke test.

| Platform | Script | Installs via |
|----------|--------|--------------|
| Windows 10/11 | `setup.ps1` | winget (Python, Node.js, Docker Desktop) |
| Linux (apt/dnf/yum/pacman/zypper) | `setup.sh` | distro package manager + get.docker.com |

Both are **idempotent** — safe to re-run; they skip anything already installed.

## Windows

Run in an **elevated** PowerShell (installing Docker Desktop requires admin):

```powershell
# from the repo root
Set-ExecutionPolicy -Scope Process Bypass -Force   # if scripts are blocked
.\scripts\setup.ps1
```

The script prefers **winget**, but doesn't require it: if winget is missing — or
just hidden from your elevated shell (App Installer is per-user, so an admin
session often can't see it) — it locates winget under `Program Files\WindowsApps`,
tries to bootstrap it, and otherwise falls back to each vendor's **official
silent installer**. So the old "winget not found" dead end no longer happens.

Docker Desktop needs **WSL2 and usually a reboot** on first install. The script
runs `wsl --update` for you (Docker's Linux backend needs a current WSL kernel;
a stale one triggers Docker's "WSL needs updating" dialog). If the script reports
Docker isn't ready, reboot, start Docker Desktop (wait for the whale icon to
settle, Linux containers), and **re-run the script** — it will build the sandbox
image and finish. Static analysis works without Docker; only `--dynamic` needs it.

If WSL isn't installed at all, run `wsl --install --no-distribution` in an
elevated shell, reboot, then re-run the setup script.

## Linux

```bash
# from the repo root
./scripts/setup.sh
```

Docker is installed via Docker's official `get.docker.com` script on mainstream
distros; on **Kali/Parrot** (rolling derivatives `get.docker.com` can't serve)
the script installs the distro's `docker.io` package instead. Your user is added
to the `docker` group — **log out and back in** (or `newgrp docker`) before using
`--dynamic`, so Docker works without `sudo`. (As root, e.g. on Kali, that step
isn't needed.)

## What you get

Both scripts create a `.venv/` in the repo and install the tool there. After
setup:

```bash
# Linux
./.venv/bin/npm-ide-analyst analyze <sample.tgz|.vsix|dir> --out out --dynamic
# Windows
.\.venv\Scripts\npm-ide-analyst.exe analyze <sample> --out out --dynamic
```

Try it on the bundled lab sample:

```bash
python samples/colorz-utill/build.py --out ./out
./.venv/bin/npm-ide-analyst analyze ./out/colorz-utill-2.3.9.tgz --out ./report --dynamic
# open report/report.html
```

## Requirements the scripts satisfy

- **Python ≥ 3.11** with the package deps (`click`, `esprima`, `jsbeautifier`, `jinja2`).
- **Docker** with **Linux containers** (the detonation sandbox is a Linux image).
- **Node.js** — only needed for the harness *dev tests*; the analyzer itself runs
  Node inside the container, so a host Node is optional for normal use.

## Remote Docker host (avoids nested virtualization)

If you run the analyzer inside a **Windows VM**, Docker Desktop needs WSL2 — a VM
inside your VM (nested virtualization), which is often painful or unavailable.
You can sidestep it entirely: orchestrate from Windows but **detonate on a
separate Linux Docker daemon**. Your Windows side needs no virtualization at all.

**On the Linux box** (a spare host, another VM, or a cloud instance): install
Docker Engine (`./scripts/setup.sh`, or `curl -fsSL https://get.docker.com | sh`),
and make sure you can SSH into it with key-based auth.

**On Windows** (needs the `docker` CLI and the built-in OpenSSH client):

```powershell
$env:DOCKER_HOST = "ssh://user@linux-box"     # point the CLI at the remote daemon
docker info                                    # should report the remote engine
.\.venv\Scripts\npm-ide-analyst.exe analyze <sample> --out out --dynamic
```

When `DOCKER_HOST` is set, the tool automatically switches to a **mount-free
stream transport** — the sample is piped to the container over stdin and events
come back over stdout, so no local paths need to exist on the remote host. Every
isolation flag (`--network none`, `--read-only`, non-root, `--cap-drop ALL`,
resource limits) is preserved. You'll see `NOTE: detonating on remote Docker
daemon ...`. The sandbox image builds on the remote daemon on first run (the
build context is streamed).

Notes:
- `--sinkhole` is **not** supported against a remote daemon (it provisions a
  local internal network); it falls back to isolated detonation with a warning.
- `--dynamic` and `--trace-native` work normally over the remote daemon.

## Manual fallback

If you'd rather not auto-install Docker:

```bash
python -m venv .venv && ./.venv/bin/pip install -e ".[dev]"   # tool only
# install Docker yourself, then:
./.venv/bin/python -c "from npm_ide_analyst.sandbox.orchestrator import build_image; build_image()"
```
