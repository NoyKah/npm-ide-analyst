# tests/test_harness_entrypoints.py
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path("src/npm_ide_analyst/sandbox/harness")
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _detonate(entry: str, sample_dir: Path, tmp_path: Path) -> list[dict]:
    log = tmp_path / "events.jsonl"
    preload = (HARNESS / "preload.js").resolve()
    runner = (HARNESS / entry).resolve()
    env = {**os.environ, "ANALYST_EVENT_LOG": str(log),
           "ANALYST_SAMPLE_DIR": str(sample_dir)}
    subprocess.run(["node", "-r", str(preload), str(runner)],
                   env=env, timeout=30, capture_output=True)
    return [json.loads(l) for l in log.read_text().splitlines() if l.strip()] if log.exists() else []


def test_vsix_activate_is_called(tmp_path):
    sample = tmp_path / "ext"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps({"name": "e", "main": "./extension.js"}))
    (sample / "extension.js").write_text(
        "const vscode=require('vscode');"
        "exports.activate=(ctx)=>{require('http').get('http://1.2.3.4/beacon');};",
        encoding="utf-8")
    events = _detonate("run-vsix.js", sample, tmp_path)
    assert any(e["kind"] == "network" and "1.2.3.4" in e["detail"] for e in events)
    assert any(e["kind"] == "detonation" for e in events)


def test_npm_postinstall_script_runs(tmp_path):
    sample = tmp_path / "pkg"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps(
        {"name": "p", "main": "./index.js", "scripts": {"postinstall": "node ./evil.js"}}))
    (sample / "evil.js").write_text(
        "require('child_process').exec('whoami');", encoding="utf-8")
    (sample / "index.js").write_text("", encoding="utf-8")
    events = _detonate("run-npm.js", sample, tmp_path)
    assert any(e["kind"] == "process" and "whoami" in e["detail"] for e in events)
