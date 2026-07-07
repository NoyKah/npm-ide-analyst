#Requires -Version 5.1
<#
    npm-ide-analyst - Windows setup

    Installs Python 3, Node.js, and Docker Desktop (via winget), sets up the tool
    in a virtualenv, builds the sandbox image, and runs a smoke test.

    Usage (in an ELEVATED / Administrator PowerShell):
        .\scripts\setup.ps1

    Re-runnable: safe to run again. If Docker Desktop was just installed, reboot
    and start Docker Desktop, then re-run to finish (build image + full check).
#>

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

function Log($m)  { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[warn] $m" -ForegroundColor Yellow }
function Have($c) { $null -ne (Get-Command $c -ErrorAction SilentlyContinue) }

if (-not (Test-Path (Join-Path $RepoRoot 'pyproject.toml'))) {
    throw "Run from the repo: pyproject.toml not found at $RepoRoot"
}

# ---- prerequisites: admin + winget ----
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this in an elevated (Administrator) PowerShell - installing Docker Desktop requires it."
}
if (-not (Have winget)) {
    throw "winget not found. Install 'App Installer' from the Microsoft Store, then re-run."
}

function Winget-Install($id) {
    winget install -e --id $id --accept-source-agreements --accept-package-agreements `
        --disable-interactivity | Out-Host
}

function Refresh-Path {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [Environment]::GetEnvironmentVariable('Path', 'User')
}

# ---- Python ----
Log "Python 3"
if (Have python) { Write-Host "found $(python --version)" }
else { Winget-Install 'Python.Python.3.12'; Refresh-Path }
if (-not (Have python)) {
    Warn "Python installed but not on PATH in this session. Open a NEW PowerShell and re-run."
    return
}

# ---- Node.js (only for harness dev tests; the analyzer runs Node in the container) ----
Log "Node.js LTS (optional)"
if (Have node) { Write-Host "found $(node --version)" }
else { try { Winget-Install 'OpenJS.NodeJS.LTS'; Refresh-Path } catch { Warn "Node install skipped (non-fatal)." } }

# ---- Docker Desktop ----
Log "Docker Desktop"
if (Have docker) { Write-Host "found $(docker --version)" }
else {
    Winget-Install 'Docker.DockerDesktop'
    Refresh-Path
    Warn "Docker Desktop was just installed. It needs WSL2 and usually a REBOOT."
}

# ---- virtualenv + package ----
Log "Virtualenv + npm-ide-analyst (editable install)"
if (-not (Test-Path '.venv')) { python -m venv .venv }
$venvPy = Join-Path $RepoRoot '.venv\Scripts\python.exe'
& $venvPy -m pip install --upgrade pip | Out-Host
& $venvPy -m pip install -e ".[dev]" | Out-Host

# ---- Docker readiness + image build ----
Log "Checking Docker daemon"
$dockerReady = $false
if (Have docker) {
    try { docker info *> $null; if ($LASTEXITCODE -eq 0) { $dockerReady = $true } } catch { }
}
if ($dockerReady) {
    Log "Building the sandbox image (npm-ide-analyst-sandbox:latest)"
    docker build -f src/npm_ide_analyst/sandbox/docker/Dockerfile `
        -t npm-ide-analyst-sandbox:latest src/npm_ide_analyst/sandbox | Out-Host
} else {
    Warn "Docker Desktop is not ready yet. To finish dynamic-analysis setup:"
    Write-Host "    1. Reboot if Docker Desktop was just installed (it enables WSL2)."
    Write-Host "    2. Launch Docker Desktop; wait for the whale icon to settle (Linux containers)."
    Write-Host "    3. Re-run this script - it will build the sandbox image and finish."
}

# ---- smoke test (static pipeline, no Docker needed) ----
Log "Smoke test (static pipeline)"
& $venvPy -m pytest -q tests/test_smoke.py tests/test_sample_fixture.py | Out-Host

Log "Done."
Write-Host ""
Write-Host "Run the tool with:"
Write-Host "    .\.venv\Scripts\npm-ide-analyst.exe analyze <sample.tgz|.vsix|dir> --out out --dynamic"
if (-not $dockerReady) {
    Write-Host ""
    Warn "Static analysis works now. For --dynamic, complete the Docker steps above and re-run this script."
}
