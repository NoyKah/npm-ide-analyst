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


def test_npm_blocks_main_escaping_sample(tmp_path):
    # Decoy sitting OUTSIDE any sample dir; if it were ever require()'d it would
    # beacon to a marker host that we can detect via the neutered network hook.
    (tmp_path / "outside.js").write_text(
        "require('http').get('http://6.6.6.6/pwned');", encoding="utf-8")

    evil = tmp_path / "pkg"
    evil.mkdir()
    (evil / "package.json").write_text(json.dumps({"name": "p", "main": "../outside.js"}))
    evil_log = tmp_path / "evil"
    evil_log.mkdir()
    evil_events = _detonate("run-npm.js", evil, evil_log)
    # The path-escaping main must never be loaded ...
    assert not any(e["kind"] == "network" and "6.6.6.6" in e["detail"] for e in evil_events)
    # ... and the block must be reported as a detonation event.
    assert any(e["kind"] == "detonation" and "blocked" in e["detail"] for e in evil_events)

    # A legitimate in-dir main still loads and runs.
    good = tmp_path / "goodpkg"
    good.mkdir()
    (good / "package.json").write_text(json.dumps({"name": "g", "main": "./index.js"}))
    (good / "index.js").write_text(
        "require('http').get('http://7.7.7.7/ok');", encoding="utf-8")
    good_log = tmp_path / "good"
    good_log.mkdir()
    good_events = _detonate("run-npm.js", good, good_log)
    assert any(e["kind"] == "network" and "7.7.7.7" in e["detail"] for e in good_events)


def test_npm_blocks_lifecycle_script_escaping_sample(tmp_path):
    (tmp_path / "outside.js").write_text(
        "require('http').get('http://6.6.6.6/pwned');", encoding="utf-8")
    evil = tmp_path / "pkg"
    evil.mkdir()
    (evil / "package.json").write_text(json.dumps(
        {"name": "p", "scripts": {"postinstall": "node ../outside.js"}}))
    events = _detonate("run-npm.js", evil, tmp_path)
    assert not any(e["kind"] == "network" and "6.6.6.6" in e["detail"] for e in events)
    assert any(e["kind"] == "detonation" and "blocked" in e["detail"] for e in events)


def test_vsix_blocks_main_escaping_sample(tmp_path):
    (tmp_path / "outside.js").write_text(
        "require('http').get('http://6.6.6.6/pwned');", encoding="utf-8")
    evil = tmp_path / "ext"
    evil.mkdir()
    (evil / "package.json").write_text(json.dumps({"name": "e", "main": "../outside.js"}))
    events = _detonate("run-vsix.js", evil, tmp_path)
    assert not any(e["kind"] == "network" and "6.6.6.6" in e["detail"] for e in events)
    assert any(e["kind"] == "detonation" and "blocked" in e["detail"] for e in events)
