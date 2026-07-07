#!/usr/bin/env bash
#
# npm-ide-analyst - Linux setup
# Installs Python 3 + venv, Node.js, and Docker Engine, sets up the tool in a
# virtualenv, builds the sandbox image, and runs a smoke test.
#
# Usage:   ./scripts/setup.sh
# Re-runnable: safe to run again (it skips what is already installed).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

[ -f pyproject.toml ] || die "run from the repo (pyproject.toml not found at $REPO_ROOT)"

# ---- privilege ----
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  have sudo || die "this script needs root; install sudo or run as root."
  SUDO="sudo"
fi

# ---- package manager ----
if   have apt-get; then PM=apt
elif have dnf;     then PM=dnf
elif have yum;     then PM=yum
elif have pacman;  then PM=pacman
elif have zypper;  then PM=zypper
else die "unsupported distro: need apt/dnf/yum/pacman/zypper"; fi

pminstall() {
  case "$PM" in
    apt)    $SUDO apt-get update -y && $SUDO apt-get install -y "$@" ;;
    dnf)    $SUDO dnf install -y "$@" ;;
    yum)    $SUDO yum install -y "$@" ;;
    pacman) $SUDO pacman -Sy --noconfirm "$@" ;;
    zypper) $SUDO zypper install -y "$@" ;;
  esac
}

# ---- Python 3 + venv + pip ----
log "Python 3 (+ venv, pip)"
if have python3; then
  echo "found $(python3 --version)"
else
  case "$PM" in
    apt) pminstall python3 python3-venv python3-pip ;;
    *)   pminstall python3 python3-pip ;;
  esac
fi
# Debian/Ubuntu ship venv separately; make sure it is present.
if [ "$PM" = "apt" ]; then pminstall python3-venv || true; fi
python3 -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)' \
  || warn "Python >= 3.11 recommended; found $(python3 --version)"

# ---- Node.js (only used by the harness dev tests; the analyzer runs Node in the container) ----
log "Node.js (optional, for harness tests)"
if have node; then echo "found $(node --version)"; else
  pminstall nodejs || warn "could not install nodejs (non-fatal; only affects harness unit tests)"
fi

# ---- Docker Engine ----
log "Docker Engine"
if have docker; then
  echo "found $(docker --version)"
else
  echo "installing via the official get.docker.com convenience script"
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  $SUDO sh /tmp/get-docker.sh
  rm -f /tmp/get-docker.sh
  $SUDO usermod -aG docker "$USER" 2>/dev/null || true
  $SUDO systemctl enable --now docker 2>/dev/null || warn "could not enable docker via systemd (WSL/container?)"
fi

# Decide how we can talk to the daemon.
DOCKER="docker"; NEED_RELOGIN=0
if docker info >/dev/null 2>&1; then
  :
elif $SUDO docker info >/dev/null 2>&1; then
  DOCKER="$SUDO docker"; NEED_RELOGIN=1
  warn "docker needs group membership; using sudo for this run. Log out/in to use docker without sudo."
else
  die "Docker installed but the daemon is not reachable. Start it and re-run."
fi

# ---- virtualenv + package ----
log "Virtualenv + npm-ide-analyst (editable install)"
[ -d .venv ] || python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip >/dev/null
./.venv/bin/python -m pip install -e ".[dev]"

# ---- build the sandbox image ----
log "Building the sandbox Docker image (npm-ide-analyst-sandbox:latest)"
$DOCKER build \
  -f src/npm_ide_analyst/sandbox/docker/Dockerfile \
  -t npm-ide-analyst-sandbox:latest \
  src/npm_ide_analyst/sandbox

# ---- smoke test ----
log "Smoke test"
./.venv/bin/python -m pytest -q tests/test_smoke.py tests/test_sample_fixture.py

log "Done."
echo
echo "Run the tool with:"
echo "    ./.venv/bin/npm-ide-analyst analyze <sample.tgz|.vsix|dir> --out out --dynamic"
echo "  or activate the venv first:  source .venv/bin/activate"
if [ "$NEED_RELOGIN" -eq 1 ]; then
  echo
  warn "Log out and back in (or run 'newgrp docker') before using --dynamic, so Docker works without sudo."
fi
