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

Docker is installed via Docker's official `get.docker.com` script and your user
is added to the `docker` group. **Log out and back in** (or `newgrp docker`)
before using `--dynamic`, so Docker works without `sudo`.

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

## Manual fallback

If you'd rather not auto-install Docker:

```bash
python -m venv .venv && ./.venv/bin/pip install -e ".[dev]"   # tool only
# install Docker yourself, then:
./.venv/bin/python -c "from npm_ide_analyst.sandbox.orchestrator import build_image; build_image()"
```
