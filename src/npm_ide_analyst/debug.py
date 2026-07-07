"""Diagnostic bundle for `analyze --debug`.

Collects everything needed to diagnose and improve the tool on a given sample:
per-stage timings, environment/versions, static diagnostics, the raw harness
event log + container diagnostics, and any exception tracebacks. Written as a
single `debug.json` the user can hand back for analysis.
"""
from __future__ import annotations

import json
import platform
import subprocess
import sys
import time
import traceback
from contextlib import contextmanager, nullcontext
from pathlib import Path

from . import __version__


def _cmd_version(cmd: str) -> str | None:
    try:
        r = subprocess.run([cmd, "--version"], capture_output=True, timeout=10)
        out = (r.stdout or r.stderr).decode("utf-8", "replace").strip()
        return out.splitlines()[0] if out else None
    except (OSError, subprocess.SubprocessError, IndexError):
        return None


def collect_env() -> dict:
    """Tool + runtime versions, for reproducing a report."""
    return {
        "tool_version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "node": _cmd_version("node"),
        "docker": _cmd_version("docker"),
    }


class DebugCollector:
    """Accumulates a debug bundle across an analyze run."""

    def __init__(self) -> None:
        self.data: dict = {
            "env": collect_env(),
            "timings_sec": {},
            "sample": {},
            "static": {},
            "dynamic": {},
            "errors": [],
        }

    @contextmanager
    def stage(self, name: str):
        start = time.perf_counter()
        try:
            yield
        finally:
            self.data["timings_sec"][name] = round(time.perf_counter() - start, 4)

    def error(self, where: str, exc: BaseException) -> None:
        self.data["errors"].append({
            "where": where,
            "error": str(exc),
            "traceback": "".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)),
        })

    def write(self, path: Path) -> None:
        path.write_text(json.dumps(self.data, indent=2, default=str), encoding="utf-8")


def stage(collector: DebugCollector | None, name: str):
    """Time `name` if collecting, else a no-op context manager."""
    return collector.stage(name) if collector is not None else nullcontext()
