# src/npm_ide_analyst/sandbox/orchestrator.py
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from ..models import ArtifactType, BehaviorEvent
from .events import load_event_log

IMAGE_TAG = "npm-ide-analyst-sandbox:latest"
_DOCKER_DIR = Path(__file__).parent / "docker"
_HARNESS_DIR = Path(__file__).parent / "harness"

_ISOLATION_FLAGS = [
    "--rm",
    "--user", "1000:1000",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--read-only",
    "--tmpfs", "/work/out:rw,size=16m",
    "--tmpfs", "/tmp:rw,size=16m",
    "--memory", "256m",
    "--cpus", "1",
    "--pids-limit", "128",
]

# Back-compat alias: the default (no-sinkhole) flag vector.
DOCKER_RUN_FLAGS = _ISOLATION_FLAGS + ["--network", "none"]


def _detonation_flags(network: str | None = None,
                      dns_ip: str | None = None) -> list[str]:
    """Full ``docker run`` flag vector for the detonation container.

    Default mode isolates the container with ``--network none``. Sinkhole mode
    attaches it to an internal network with the sinkhole as DNS resolver and sets
    the two env vars the harness needs; EVERY other isolation flag is identical.
    """
    flags = list(_ISOLATION_FLAGS)
    if network:
        flags += ["--network", network]
        if dns_ip:
            flags += ["--dns", dns_ip]
        flags += ["-e", "ANALYST_SINKHOLE=1",
                  "-e", "NODE_TLS_REJECT_UNAUTHORIZED=0"]
    else:
        flags += ["--network", "none"]
    return flags


class SandboxUnavailable(RuntimeError):
    pass


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=15)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def build_image() -> None:
    if not docker_available():
        raise SandboxUnavailable("docker is not available")
    # Build context is the sandbox dir so the Dockerfile can COPY harness/.
    ctx = Path(__file__).parent
    subprocess.run(
        ["docker", "build", "-f", str(_DOCKER_DIR / "Dockerfile"),
         "-t", IMAGE_TAG, str(ctx)],
        check=True, capture_output=True, timeout=600,
    )


def detonate(payload_root: Path, artifact_type: ArtifactType,
             timeout: int = 30, sinkhole: bool = False) -> list[BehaviorEvent]:
    if not docker_available():
        raise SandboxUnavailable("docker is not available")
    runner = "run-vsix.js" if artifact_type == ArtifactType.EXTENSION else "run-npm.js"
    if sinkhole:
        return _detonate_with_sinkhole(payload_root, runner, timeout)
    return _detonate_isolated(payload_root, runner, timeout, _detonation_flags())


def _detonate_isolated(payload_root: Path, runner: str, timeout: int,
                       flags: list[str]) -> list[BehaviorEvent]:
    out_dir = Path(tempfile.mkdtemp(prefix="analyst-out-"))
    container_name = f"analyst-det-{uuid.uuid4().hex[:12]}"
    try:
        # KNOWN ISSUE: the harness writes the event log as the in-container
        # non-root user (uid 1000). Loosen the host out-dir perms (not the
        # container's isolation flags) so uid 1000 can create the log file.
        # The sample mount stays :ro and every isolation flag stays intact.
        out_dir.chmod(0o777)
        cmd = [
            "docker", "run",
            *flags,
            "--name", container_name,
            "-v", f"{payload_root.resolve()}:/work/sample:ro",
            "-v", f"{out_dir.resolve()}:/work/hostout:rw",
            "-e", "ANALYST_SAMPLE_DIR=/work/sample",
            "-e", "ANALYST_EVENT_LOG=/work/hostout/events.jsonl",
            IMAGE_TAG,
            f"/harness/{runner}",
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout + 15)
        except subprocess.TimeoutExpired:
            # Force-reap the named container; partial log is still ingested.
            subprocess.run(["docker", "rm", "-f", container_name],
                           capture_output=True, timeout=30)
        return load_event_log(out_dir / "events.jsonl")
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def _wait_for_sinkhole(name: str, timeout: int = 20) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = subprocess.run(["docker", "logs", name],
                           capture_output=True, timeout=15)
        if b"SINKHOLE READY" in (r.stdout or b"") + (r.stderr or b""):
            return True
        time.sleep(0.3)
    return False


def _sinkhole_ip(name: str, net_name: str) -> str | None:
    r = subprocess.run(["docker", "inspect", name],
                       capture_output=True, timeout=15)
    try:
        data = json.loads(r.stdout.decode("utf-8", "replace"))
        return data[0]["NetworkSettings"]["Networks"][net_name]["IPAddress"]
    except (json.JSONDecodeError, KeyError, IndexError):
        return None


def _detonate_with_sinkhole(payload_root: Path, runner: str,
                            timeout: int) -> list[BehaviorEvent]:
    net_name = f"analyst-net-{uuid.uuid4().hex[:12]}"
    sink_name = f"analyst-sink-{uuid.uuid4().hex[:12]}"
    sink_out = Path(tempfile.mkdtemp(prefix="analyst-sink-"))
    try:
        sink_out.chmod(0o777)
        sink_ip = None
        ready = False
        try:
            # 1. Internal network: no route to the real internet.
            subprocess.run(["docker", "network", "create", "--internal",
                            "--driver", "bridge", net_name],
                           capture_output=True, timeout=60, check=True)
            # 2. Sinkhole container. Runs as root SOLELY so CAP_NET_BIND_SERVICE is
            #    effective for binding 53/80/443 (Docker does not add caps to the
            #    ambient set for non-root). No sample code runs here; read-only,
            #    cap-dropped, resource-limited, on an internet-less network.
            subprocess.run([
                "docker", "run", "-d", "--rm", "--name", sink_name,
                "--network", net_name,
                "--user", "0:0",
                "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE",
                "--security-opt", "no-new-privileges",
                "--read-only", "--tmpfs", "/tmp:rw,size=8m",
                "--memory", "128m", "--cpus", "1", "--pids-limit", "64",
                "-v", f"{sink_out.resolve()}:/work/sinkout:rw",
                "-e", "ANALYST_EVENT_LOG=/work/sinkout/requests.jsonl",
                "--entrypoint", "node",
                IMAGE_TAG, "/harness/sinkhole.js",
            ], capture_output=True, timeout=60, check=True)
            # 3. Wait for readiness.
            ready = _wait_for_sinkhole(sink_name, timeout=20)
            # 4. Discover the sinkhole IP for the detonation container's resolver.
            if ready:
                sink_ip = _sinkhole_ip(sink_name, net_name)
        except (subprocess.SubprocessError, OSError):
            ready = False
        # Could not stand up a usable sinkhole (provision failed, never became
        # ready, or IP undiscoverable) -> degrade to a normal --network none
        # isolated detonation rather than a DNS-less, capture-less internal run.
        if not ready or not sink_ip:
            return _detonate_isolated(payload_root, runner, timeout,
                                      _detonation_flags())
        # 5. Detonate on the internal network, DNS -> sinkhole.
        flags = _detonation_flags(net_name, sink_ip)
        det_events = _detonate_isolated(payload_root, runner, timeout, flags)
        # 6. Merge detonation events with the sinkhole's captured dialog.
        sink_events = load_event_log(sink_out / "requests.jsonl")
        return det_events + sink_events
    finally:
        # Force-reap the sinkhole container and remove the network no matter what.
        subprocess.run(["docker", "rm", "-f", sink_name],
                       capture_output=True, timeout=30)
        subprocess.run(["docker", "network", "rm", net_name],
                       capture_output=True, timeout=30)
        shutil.rmtree(sink_out, ignore_errors=True)
