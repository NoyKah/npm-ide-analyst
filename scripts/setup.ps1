#Requires -Version 5.1
<#
    npm-ide-analyst - Windows setup

    Installs Python 3, Node.js, and Docker Desktop, sets up the tool in a
    virtualenv, builds the sandbox image, and runs a smoke test.

    Prefers winget; if winget is missing (or hidden from an elevated shell) it is
    located under Program Files\WindowsApps, bootstrapped, or bypassed in favour
    of each vendor's official silent installer. No manual App Installer step.

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
function Refresh-Path {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [Environment]::GetEnvironmentVariable('Path', 'User')
}

function Download($url, $out) {
    Log "downloading $url"
    $old = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
    try { Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing } finally { $ProgressPreference = $old }
}

function Get-WingetPath {
    $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # winget is often installed but invisible to an ELEVATED shell: App Installer
    # is per-user, and an admin session may not have the logged-in user's PATH.
    # Look where winget actually lives before giving up.
    $userApp = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
    if (Test-Path $userApp) { return $userApp }
    $machine = Get-ChildItem 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*\winget.exe' `
        -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    if ($machine) { return $machine.FullName }
    return $null
}

function Ensure-Winget {
    $wg = Get-WingetPath
    if ($wg) { return $wg }
    Warn "winget not found; attempting to install the App Installer (winget)..."
    try {
        $bundle = Join-Path $env:TEMP 'AppInstaller.msixbundle'
        Download 'https://aka.ms/getwinget' $bundle
        Add-AppxPackage -Path $bundle -ErrorAction Stop
        Remove-Item $bundle -ErrorAction SilentlyContinue
    } catch {
        Warn "could not auto-install winget ($($_.Exception.Message)); using direct downloads instead."
    }
    return (Get-WingetPath)
}

function WingetInstall($id) {
    & $script:Winget install -e --id $id --accept-source-agreements `
        --accept-package-agreements --disable-interactivity | Out-Host
}

# Resolve winget (locate -> bootstrap); if still unavailable, each install below
# falls back to the vendor's official silent installer. Either way, no dead end.
$script:Winget = Ensure-Winget
if ($script:Winget) { Log "using winget: $script:Winget" }
else { Warn "winget unavailable; using direct official installers." }

function Install-Python {
    if (Have python) { Write-Host "found $(python --version)"; return }
    Log "installing Python 3"
    if ($script:Winget) { WingetInstall 'Python.Python.3.12' }
    else {
        $ver = '3.12.8'
        $exe = Join-Path $env:TEMP "python-$ver-amd64.exe"
        Download "https://www.python.org/ftp/python/$ver/python-$ver-amd64.exe" $exe
        Start-Process $exe -ArgumentList '/quiet', 'InstallAllUsers=1', 'PrependPath=1', 'Include_test=0' -Wait
        Remove-Item $exe -ErrorAction SilentlyContinue
    }
    Refresh-Path
}

function Install-Node {
    if (Have node) { Write-Host "found $(node --version)"; return }
    Log "installing Node.js LTS (optional)"
    try {
        if ($script:Winget) { WingetInstall 'OpenJS.NodeJS.LTS' }
        else {
            $idx = Invoke-RestMethod 'https://nodejs.org/dist/index.json' -UseBasicParsing
            $lts = ($idx | Where-Object { $_.lts } | Select-Object -First 1).version
            $msi = Join-Path $env:TEMP "node-$lts-x64.msi"
            Download "https://nodejs.org/dist/$lts/node-$lts-x64.msi" $msi
            Start-Process msiexec.exe -ArgumentList '/i', "`"$msi`"", '/qn' -Wait
            Remove-Item $msi -ErrorAction SilentlyContinue
        }
    } catch { Warn "Node install skipped (non-fatal): $($_.Exception.Message)" }
    Refresh-Path
}

function Install-Docker {
    if (Have docker) { Write-Host "found $(docker --version)"; return }
    Log "installing Docker Desktop"
    if ($script:Winget) { WingetInstall 'Docker.DockerDesktop' }
    else {
        $exe = Join-Path $env:TEMP 'DockerDesktopInstaller.exe'
        Download 'https://desktop.docker.com/win/main/amd64/Docker Desktop Installer.exe' $exe
        Start-Process $exe -ArgumentList 'install', '--quiet', '--accept-license' -Wait
        Remove-Item $exe -ErrorAction SilentlyContinue
    }
    Refresh-Path
    Warn "Docker Desktop needs WSL2 and usually a REBOOT."
}

# ---- install runtimes ----
Install-Python
if (-not (Have python)) {
    Warn "Python installed but not on PATH in this session. Open a NEW PowerShell and re-run."
    return
}
Install-Node
Install-Docker

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

# ---- smoke test (dynamic detonation, only when Docker is ready) ----
if ($dockerReady) {
    Log "Smoke test (dynamic detonation)"
    $smoke = Join-Path $env:TEMP ("npmide-smoke-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $smoke | Out-Null
    try {
        $tgz = (& $venvPy samples/colorz-utill/build.py --out $smoke | Select-Object -Last 1).Trim()
        & (Join-Path $RepoRoot '.venv\Scripts\npm-ide-analyst.exe') `
            analyze $tgz --out (Join-Path $smoke 'report') --dynamic | Out-Host
        $rpt = Join-Path $smoke 'report\report.json'
        if (Test-Path $rpt) {
            $n = @((Get-Content $rpt -Raw | ConvertFrom-Json).behavior).Count
            if ($n -gt 0) {
                Write-Host "detonation OK: $n behavior events captured" -ForegroundColor Green
            } else {
                Warn "dynamic run produced no behavior events - check that Docker uses Linux containers."
            }
        }
    } finally {
        Remove-Item -Recurse -Force $smoke -ErrorAction SilentlyContinue
    }
}

Log "Done."
Write-Host ""
Write-Host "Run the tool with:"
Write-Host "    .\.venv\Scripts\npm-ide-analyst.exe analyze <sample.tgz|.vsix|dir> --out out --dynamic"
if (-not $dockerReady) {
    Write-Host ""
    Warn "Static analysis works now. For --dynamic, complete the Docker steps above and re-run this script."
}
