# tests/test_harness_native_trace.py
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HARNESS = Path("src/npm_ide_analyst/sandbox/harness")
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or shutil.which("node") is None or shutil.which("strace") is None,
    reason="native-trace host test requires a Linux host with node + strace",
)


def _run_driver(tmp_path: Path, driver_src: str, trace: bool) -> list[dict]:
    driver = tmp_path / "driver.js"
    driver.write_text(driver_src, encoding="utf-8")
    log = tmp_path / "events.jsonl"
    preload = (HARNESS / "preload.js").resolve()
    env = {**os.environ, "ANALYST_EVENT_LOG": str(log)}
    if trace:
        env["ANALYST_TRACE_NATIVE"] = "1"
    subprocess.run(["node", "-r", str(preload), str(driver)],
                   env=env, timeout=30, capture_output=True)
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


def test_trace_native_runs_binary_and_emits_syscalls(tmp_path):
    events = _run_driver(
        tmp_path,
        "require('child_process').exec('/bin/echo NPMIDE_TRACE_CANARY', ()=>{});",
        trace=True)
    assert any(e["kind"] == "native" for e in events)
    assert any(e["kind"] == "syscall" for e in events)
    # The binary actually executed: execve of echo and/or the canary is visible.
    assert any("execve" in e["detail"] or "NPMIDE_TRACE_CANARY" in e["detail"]
               for e in events if e["kind"] in ("native", "syscall"))


def test_default_mode_still_neuters(tmp_path):
    events = _run_driver(
        tmp_path,
        "require('child_process').exec('/bin/echo NPMIDE_TRACE_CANARY', ()=>{});",
        trace=False)
    assert any(e["kind"] == "process" for e in events)          # intent logged
    assert not any(e["kind"] in ("native", "syscall") for e in events)  # never ran
