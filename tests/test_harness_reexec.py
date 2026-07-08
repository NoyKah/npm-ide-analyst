import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

HARNESS = Path("src/npm_ide_analyst/sandbox/harness")
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _run_sample(tmp_path: Path, files: dict[str, str], detonate_ms: str = "8000") -> list[dict]:
    """Lay down a sample dir + driver that re-execs an in-sample script under
    the preload, run it via run-npm.js, and return merged events."""
    sample = tmp_path / "sample"
    sample.mkdir()
    for name, body in files.items():
        (sample / name).write_text(body, encoding="utf-8")
    log = tmp_path / "events.jsonl"
    preload = (HARNESS / "preload.js").resolve()
    runner = (HARNESS / "run-npm.js").resolve()
    env = {
        **os.environ,
        "ANALYST_EVENT_LOG": str(log),
        "ANALYST_SAMPLE_DIR": str(sample),
        "ANALYST_DETONATE_MS": detonate_ms,
    }
    subprocess.run(["node", "-r", str(preload), str(runner)],
                   env=env, timeout=30, capture_output=True)
    return ([json.loads(l) for l in log.read_text().splitlines() if l.strip()]
            if log.exists() else [])


def test_node_reexec_of_in_sample_script_runs_and_merges(tmp_path):
    # preinstall spawns `node child.js`; child.js reads a canary (hooked as a
    # 'file'/'secret' event). If the re-exec truly ran under our preload, the
    # child's event appears in the SAME merged log.
    events = _run_sample(tmp_path, {
        "package.json": json.dumps({
            "name": "reexec-fixture", "version": "1.0.0",
            "scripts": {"preinstall": "node scripts.js"},
        }),
        "scripts.js": (
            "const cp=require('child_process');\n"
            "cp.spawn('node',['child.js'],{stdio:'ignore'});\n"
        ),
        "child.js": (
            "try{require('fs').readFileSync('/root/.aws/credentials')}catch(e){}\n"
            "require('child_process').execSync('echo from-child');\n"
        ),
    })
    # The re-exec itself is announced.
    assert any(e["kind"] == "runtime-reexec" and "node" in e["detail"] for e in events)
    # The CHILD's hooked behavior reached the merged log (proves it ran hooked).
    assert any(e["kind"] in ("file", "secret") and "credentials" in e["detail"]
               for e in events), "child re-exec did not run under instrumentation"


def test_non_allowlisted_spawn_stays_neutered(tmp_path):
    # `curl` is not a JS runtime -> must stay a neutered 'process' event, and
    # `node ../escape.js` (outside the sample) must NOT be re-exec'd.
    events = _run_sample(tmp_path, {
        "package.json": json.dumps({
            "name": "neuter-fixture", "version": "1.0.0",
            "scripts": {"preinstall": "node scripts.js"},
        }),
        "scripts.js": (
            "const cp=require('child_process');\n"
            "cp.exec('curl http://1.2.3.4/x',()=>{});\n"
            "cp.spawn('node',['../escape.js'],{stdio:'ignore'});\n"
        ),
    })
    assert any(e["kind"] == "process" and "curl" in e["detail"] for e in events)
    assert not any(e["kind"] == "runtime-reexec" for e in events), \
        "out-of-sample or non-runtime spawn was wrongly re-exec'd"


def test_spawnsync_reexec_of_in_sample_script_runs_and_merges(tmp_path):
    # preinstall uses the SYNC allow-listed re-exec path (spawnSync), which
    # must return a SpawnSyncReturns-shaped object (not a bare Buffer) so
    # callers reading r.status/r.stdout don't bail out early. child.js reads a
    # canary (hooked as a 'file'/'secret' event); if it appears in the SAME
    # merged log, the sync re-exec truly ran the child under instrumentation.
    events = _run_sample(tmp_path, {
        "package.json": json.dumps({
            "name": "reexec-sync-fixture", "version": "1.0.0",
            "scripts": {"preinstall": "node scripts.js"},
        }),
        "scripts.js": (
            "const cp=require('child_process');\n"
            "const r=cp.spawnSync('node',['child.js'],{stdio:'ignore'});\n"
            "if (r.status !== 0) { throw new Error('unexpected spawnSync status: ' + r.status); }\n"
        ),
        "child.js": (
            "try{require('fs').readFileSync('/root/.aws/credentials')}catch(e){}\n"
        ),
    })
    assert any(e["kind"] == "runtime-reexec" and "node" in e["detail"] for e in events)
    assert any(e["kind"] in ("file", "secret") and "credentials" in e["detail"]
               for e in events), "sync child re-exec did not run under instrumentation"


def test_spawnsync_reexec_is_bounded_by_detonate_ms(tmp_path):
    # I1: the sync re-exec must be bounded by ANALYST_DETONATE_MS so a hung
    # in-sample child (spawnSync('node', ['hang.js']) where hang.js never
    # exits) can't block detonation past the orchestrator's outer hard-kill.
    started = time.monotonic()
    events = _run_sample(tmp_path, {
        "package.json": json.dumps({
            "name": "reexec-sync-hang-fixture", "version": "1.0.0",
            "scripts": {"preinstall": "node scripts.js"},
        }),
        "scripts.js": (
            "const cp=require('child_process');\n"
            "cp.spawnSync('node',['hang.js']);\n"
        ),
        "hang.js": "setInterval(()=>{}, 1000);\n",
    }, detonate_ms="1500")
    elapsed = time.monotonic() - started
    assert any(e["kind"] == "runtime-reexec" and "node" in e["detail"] for e in events)
    assert elapsed < 6, \
        f"sync spawnSync was not bounded by ANALYST_DETONATE_MS (elapsed={elapsed:.2f}s)"
