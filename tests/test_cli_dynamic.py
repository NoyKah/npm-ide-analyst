import json
from pathlib import Path
from click.testing import CliRunner

from npm_ide_analyst.cli import cli
from npm_ide_analyst.report.json_report import load_report, write_json
from npm_ide_analyst.models import Report, Sample, Finding, Severity, ArtifactType, BehaviorEvent
from npm_ide_analyst.sandbox.orchestrator import SandboxUnavailable


def _report():
    s = Sample(name="evil", version="1.0.0", artifact_type=ArtifactType.EXTENSION,
               root=Path("/tmp/x"), sha256="a" * 64, sha512="b" * 128)
    return Report(sample=s,
                  findings=[Finding(id="D1", title="beacon", severity=Severity.HIGH,
                                    category="network", detail="POST 1.2.3.4")],
                  generated_at="t",
                  behavior=[BehaviorEvent(kind="network", detail="beacon")])


def test_load_report_roundtrip(tmp_path):
    p = tmp_path / "report.json"
    write_json(_report(), p)
    r = load_report(p)
    assert r.sample.name == "evil"
    assert r.findings[0].severity == Severity.HIGH
    assert r.behavior[0].kind == "network"


def test_report_subcommand_rerenders_html(tmp_path):
    p = tmp_path / "report.json"
    write_json(_report(), p)
    out = tmp_path / "report.html"
    result = CliRunner().invoke(cli, ["report", str(p), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "beacon" in out.read_text(encoding="utf-8")


def test_analyze_static_only_when_no_dynamic(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(json.dumps(
        {"name": "evil", "scripts": {"postinstall": "node ./s.js"}}))
    (pkg / "s.js").write_text("require('child_process')", encoding="utf-8")
    out = tmp_path / "out"
    result = CliRunner().invoke(cli, ["analyze", str(pkg), "--out", str(out)])
    assert result.exit_code == 0
    data = json.loads((out / "report.json").read_text())
    assert data["behavior"] == []          # no dynamic requested


def test_analyze_dynamic_degrades_gracefully_when_detonation_fails(tmp_path, monkeypatch):
    def _boom(*args, **kwargs):
        raise SandboxUnavailable("boom")

    monkeypatch.setattr("npm_ide_analyst.cli.docker_available", lambda: True)
    monkeypatch.setattr("npm_ide_analyst.cli.detonate", _boom)

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(json.dumps(
        {"name": "evil", "scripts": {"postinstall": "node ./s.js"}}))
    (pkg / "s.js").write_text("require('child_process')", encoding="utf-8")
    out = tmp_path / "out"

    result = CliRunner().invoke(cli, ["analyze", str(pkg), "--out", str(out), "--dynamic"])

    assert result.exit_code == 0, result.output
    assert "WARNING" in result.output
    assert "boom" in result.output
    assert (out / "report.json").exists()
    data = json.loads((out / "report.json").read_text())
    assert data["behavior"] == []


def test_analyze_dynamic_probes_docker_only_once(tmp_path, monkeypatch):
    calls = {"n": 0}

    def _probe():
        calls["n"] += 1
        return True

    monkeypatch.setattr("npm_ide_analyst.cli.docker_available", _probe)
    monkeypatch.setattr("npm_ide_analyst.cli.build_image", lambda *a, **k: None)
    monkeypatch.setattr("npm_ide_analyst.cli.detonate", lambda *a, **k: [])

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(json.dumps({"name": "evil"}))
    out = tmp_path / "out"

    result = CliRunner().invoke(cli, ["analyze", str(pkg), "--out", str(out), "--dynamic"])

    assert result.exit_code == 0, result.output
    assert calls["n"] == 1
