# src/npm_ide_analyst/sandbox/orchestrator.py
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

from ..models import ArtifactType, BehaviorEvent
from .events import load_event_log, parse_event_log

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

PTRACE_CAP_FLAGS = ["--cap-add", "SYS_PTRACE"]


def run_flags(trace_native: bool = False) -> list[str]:
    """Return the hardened docker run flag vector (default --network none).

    Only when trace_native is True is a single capability re-added
    (SYS_PTRACE, required for strace/ptrace under Docker's default seccomp).
    Every other isolation flag is unchanged. Returns a fresh list. Equivalent
    to ``_detonation_flags(trace_native=trace_native)`` for the default network.
    """
    flags = list(DOCKER_RUN_FLAGS)
    if trace_native:
        flags += PTRACE_CAP_FLAGS
    return flags


def _detonate_ms(timeout: int) -> int:
    """Milliseconds the harness waits for re-exec'd children before exiting.

    Leaves ~2s slack under the orchestrator's ``timeout + 15s`` hard kill; never
    below 1s so a zero/negative timeout still yields a valid deadline.
    """
    return max(1000, int(timeout) * 1000 - 2000)


def _detonation_flags(network: str | None = None,
                      dns_ip: str | None = None,
                      trace_native: bool = False) -> list[str]:
    """Full ``docker run`` flag vector for the detonation container.

    Default mode isolates the container with ``--network none``. Sinkhole mode
    attaches it to an internal network with the sinkhole as DNS resolver and sets
    the two env vars the harness needs; EVERY other isolation flag is identical.
    Opt-in native tracing re-adds the single ``SYS_PTRACE`` capability (required
    for strace under Docker's default seccomp) and nothing else.
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
    if trace_native:
        flags += PTRACE_CAP_FLAGS
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


def image_exists() -> bool:
    """True if the sandbox image is already built locally.

    Lets callers skip the per-run `docker build` (which reaches the registry to
    load base-image metadata even when cached) so detonation needs no network
    after the first build.
    """
    try:
        r = subprocess.run(["docker", "image", "inspect", IMAGE_TAG],
                           capture_output=True, timeout=15)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def build_image(*, assume_docker: bool = False) -> None:
    # `assume_docker` lets a caller that already ran docker_available() skip the
    # redundant ~15s `docker info` probe; standalone callers still verify.
    if not assume_docker and not docker_available():
        raise SandboxUnavailable("docker is not available")
    # Build context is the sandbox dir so the Dockerfile can COPY harness/.
    ctx = Path(__file__).parent
    subprocess.run(
        ["docker", "build", "-f", str(_DOCKER_DIR / "Dockerfile"),
         "-t", IMAGE_TAG, str(ctx)],
        check=True, capture_output=True, timeout=600,
    )


def _is_remote_docker() -> bool:
    """True when the docker CLI targets a non-local daemon (DOCKER_HOST set).

    Bind mounts and `docker cp` of local paths don't work against a remote
    daemon, so remote detonation uses the mount-free stream transport instead.
    """
    return bool(os.environ.get("DOCKER_HOST"))


def detonate(payload_root: Path, artifact_type: ArtifactType,
             timeout: int = 30, *, assume_docker: bool = False,
             sinkhole: bool = False,
             trace_native: bool = False,
             remote: bool = False,
             debug: dict | None = None) -> list[BehaviorEvent]:
    # `assume_docker` lets a caller that already ran docker_available() skip the
    # redundant ~15s `docker info` probe; standalone callers still verify.
    # `debug`, when given, is populated with container diagnostics + raw log.
    if not assume_docker and not docker_available():
        raise SandboxUnavailable("docker is not available")
    runner = "run-vsix.js" if artifact_type == ArtifactType.EXTENSION else "run-npm.js"
    use_stream = remote or _is_remote_docker()
    if debug is not None:
        debug["mode"] = "sinkhole" if (sinkhole and not use_stream) else "isolated"
        debug["runner"] = runner
    # Sinkhole provisioning assumes a local daemon (internal network + IP
    # discovery); over a remote daemon we fall back to isolated stream detonation.
    if sinkhole and not use_stream:
        return _detonate_with_sinkhole(payload_root, runner, timeout,
                                       trace_native=trace_native, debug=debug)
    flags = _detonation_flags(trace_native=trace_native)
    if use_stream:
        return _detonate_via_stream(payload_root, runner, timeout, flags,
                                    trace_native=trace_native, debug=debug)
    return _detonate_isolated(payload_root, runner, timeout, flags,
                              trace_native=trace_native, debug=debug)


def _detonate_via_stream(payload_root: Path, runner: str, timeout: int,
                         flags: list[str], trace_native: bool = False,
                         debug: dict | None = None) -> list[BehaviorEvent]:
    """Mount-free transport for a REMOTE docker daemon.

    The sample is piped in as a gzip tar on the container's stdin (extracted into
    a tmpfs), and behavior events come back on stdout. No bind mounts and no
    `docker cp`, so local host paths are irrelevant to the remote daemon. Every
    isolation flag is preserved (incl. --read-only and --network none).
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        # Add the sample's CONTENTS (not a top-level "." entry): the non-root
        # user can't chmod/utime the tmpfs mount point itself, and tar would
        # fail on that entry. Its own children extract fine.
        for item in sorted(payload_root.iterdir()):
            tf.add(item, arcname=item.name)
    tar_bytes = buf.getvalue()

    trace_env = ["-e", "ANALYST_TRACE_NATIVE=1"] if trace_native else []
    # Extract stdin into the sample tmpfs, then exec the harness. ANALYST_EVENT_LOG
    # is cleared so emit.js writes JSON-lines to stdout instead of a file.
    inner = (f"tar xzf - -C /work/sample && "
             f"exec node -r /harness/preload.js /harness/{runner}")
    cmd = [
        "docker", "run", "-i",
        *flags,
        # mode=1777 so the non-root detonation user can extract into the tmpfs.
        "--tmpfs", "/work/sample:rw,size=64m,mode=1777",
        "-e", "ANALYST_SAMPLE_DIR=/work/sample",
        "-e", "ANALYST_EVENT_LOG=",
        "-e", f"ANALYST_DETONATE_MS={_detonate_ms(timeout)}",
        *trace_env,
        "--entrypoint", "sh",
        IMAGE_TAG, "-c", inner,
    ]
    if debug is not None:
        debug["transport"] = "stream"
        debug["run_argv"] = cmd
        debug["image"] = IMAGE_TAG
    events_text = ""
    try:
        proc = subprocess.run(cmd, input=tar_bytes, capture_output=True,
                              timeout=timeout + 15)
        events_text = proc.stdout.decode("utf-8", "replace")
        if debug is not None:
            debug["returncode"] = proc.returncode
            debug["stderr"] = proc.stderr.decode("utf-8", "replace")[:6000]
    except subprocess.TimeoutExpired as exc:
        # --rm reaps the container when the docker client is killed; keep partial.
        if debug is not None:
            debug["timed_out"] = True
        events_text = (exc.stdout or b"").decode("utf-8", "replace") if exc.stdout else ""
    if debug is not None:
        debug["raw_event_log"] = events_text[:40000]
    return parse_event_log(events_text)


def _detonate_isolated(payload_root: Path, runner: str, timeout: int,
                       flags: list[str],
                       trace_native: bool = False,
                       debug: dict | None = None) -> list[BehaviorEvent]:
    out_dir = Path(tempfile.mkdtemp(prefix="analyst-out-"))
    container_name = f"analyst-det-{uuid.uuid4().hex[:12]}"
    try:
        # KNOWN ISSUE: the harness writes the event log as the in-container
        # non-root user (uid 1000). Loosen the host out-dir perms (not the
        # container's isolation flags) so uid 1000 can create the log file.
        # The sample mount stays :ro and every isolation flag stays intact.
        out_dir.chmod(0o777)
        trace_env = ["-e", "ANALYST_TRACE_NATIVE=1"] if trace_native else []
        cmd = [
            "docker", "run",
            *flags,
            "--name", container_name,
            "-v", f"{payload_root.resolve()}:/work/sample:ro",
            "-v", f"{out_dir.resolve()}:/work/hostout:rw",
            "-e", "ANALYST_SAMPLE_DIR=/work/sample",
            "-e", "ANALYST_EVENT_LOG=/work/hostout/events.jsonl",
            "-e", f"ANALYST_DETONATE_MS={_detonate_ms(timeout)}",
            *trace_env,
            IMAGE_TAG,
            f"/harness/{runner}",
        ]
        if debug is not None:
            debug["run_argv"] = cmd
            debug["image"] = IMAGE_TAG
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 15)
            if debug is not None:
                debug["returncode"] = proc.returncode
                debug["stdout"] = proc.stdout.decode("utf-8", "replace")[:6000]
                debug["stderr"] = proc.stderr.decode("utf-8", "replace")[:6000]
        except subprocess.TimeoutExpired:
            # Force-reap the named container; partial log is still ingested.
            if debug is not None:
                debug["timed_out"] = True
            subprocess.run(["docker", "rm", "-f", container_name],
                           capture_output=True, timeout=30)
        log_file = out_dir / "events.jsonl"
        if debug is not None and log_file.exists():
            # Raw (unfiltered) event log, including internal 'harness' events.
            debug["raw_event_log"] = log_file.read_text(
                encoding="utf-8", errors="replace")[:40000]
        return load_event_log(log_file)
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
                            timeout: int,
                            trace_native: bool = False,
                            debug: dict | None = None) -> list[BehaviorEvent]:
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
            if debug is not None:
                debug["sinkhole_degraded"] = True
            return _detonate_isolated(payload_root, runner, timeout,
                                      _detonation_flags(trace_native=trace_native),
                                      trace_native=trace_native, debug=debug)
        # 5. Detonate on the internal network, DNS -> sinkhole.
        flags = _detonation_flags(net_name, sink_ip, trace_native=trace_native)
        det_events = _detonate_isolated(payload_root, runner, timeout, flags,
                                        trace_native=trace_native, debug=debug)
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
