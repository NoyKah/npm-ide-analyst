# src/npm_ide_analyst/sandbox/orchestrator.py
from __future__ import annotations

import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from ..models import ArtifactType, BehaviorEvent
from .events import load_event_log

IMAGE_TAG = "npm-ide-analyst-sandbox:latest"
_DOCKER_DIR = Path(__file__).parent / "docker"
_HARNESS_DIR = Path(__file__).parent / "harness"

DOCKER_RUN_FLAGS = [
    "--rm",
    "--network", "none",
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


def detonate(payload_root: Path, artifact_type: ArtifactType,
             timeout: int = 30, *, assume_docker: bool = False) -> list[BehaviorEvent]:
    # `assume_docker` lets a caller that already ran docker_available() skip the
    # redundant ~15s `docker info` probe; standalone callers still verify.
    if not assume_docker and not docker_available():
        raise SandboxUnavailable("docker is not available")
    runner = "run-vsix.js" if artifact_type == ArtifactType.EXTENSION else "run-npm.js"
    out_dir = Path(tempfile.mkdtemp(prefix="analyst-out-"))
    container_name = f"analyst-det-{uuid.uuid4().hex[:12]}"
    try:
        # KNOWN ISSUE: the harness writes the event log as the in-container
        # non-root user (uid 1000). The host-created out_dir is owned by
        # whatever user Python runs as, so uid 1000 inside the container may
        # not have write permission on the bind mount. Loosen the directory
        # permissions (not the container's isolation flags) so the container
        # user can create the log file. The sample mount stays :ro and every
        # DOCKER_RUN_FLAGS entry stays intact.
        out_dir.chmod(0o777)
        cmd = [
            "docker", "run",
            *DOCKER_RUN_FLAGS,
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
            # Defense in depth: the docker run client process was killed by
            # our wall-clock timeout, so --rm never got a chance to fire.
            # Force-reap the named container directly; partial log still ingested.
            subprocess.run(["docker", "rm", "-f", container_name],
                           capture_output=True, timeout=30)
        return load_event_log(out_dir / "events.jsonl")
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
