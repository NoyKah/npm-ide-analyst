# tests/test_harness_sinkhole.py
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path("src/npm_ide_analyst/sandbox/harness")
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _run(tmp_path: Path, driver_src: str, env_extra: dict | None = None,
         with_preload: bool = True, timeout: int = 20):
    driver = tmp_path / "driver.js"
    driver.write_text(driver_src, encoding="utf-8")
    log = tmp_path / "events.jsonl"
    env = {**os.environ, "ANALYST_EVENT_LOG": str(log)}
    if env_extra:
        env.update(env_extra)
    cmd = ["node"]
    if with_preload:
        cmd += ["-r", str((HARNESS / "preload.js").resolve())]
    cmd += [str(driver)]
    proc = subprocess.run(cmd, env=env, timeout=timeout, capture_output=True, text=True)
    events = ([json.loads(l) for l in log.read_text().splitlines() if l.strip()]
              if log.exists() else [])
    return proc, events


def test_sinkhole_mode_delegates_real_http(tmp_path):
    # A local server + a client request to it. In sinkhole mode the http hook
    # must delegate to the real implementation, so the response comes back.
    driver = """
    const http = require('http');
    const srv = http.createServer((req, res) => { res.end('pong'); });
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      http.get('http://127.0.0.1:' + port + '/probe', (res) => {
        let d = ''; res.on('data', c => d += c);
        res.on('end', () => { process.stdout.write('GOT:' + d + '\\n'); srv.close(); process.exit(0); });
      }).on('error', (e) => { process.stdout.write('ERR:' + e.message + '\\n'); process.exit(1); });
    });
    """
    proc, events = _run(tmp_path, driver, env_extra={"ANALYST_SINKHOLE": "1"})
    assert "GOT:pong" in proc.stdout                       # real request completed
    assert any(e["kind"] == "network" for e in events)     # still logged
