import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from npm_ide_analyst.cli import cli
from npm_ide_analyst.debug import collect_env
from npm_ide_analyst.sandbox import orchestrator as orch


def test_collect_env_has_versions():
    env = collect_env()
    assert env["tool_version"]
    assert env["python"]
    assert "platform" in env


def _make_pkg(tmp_path: Path) -> Path:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(json.dumps(
        {"name": "evil", "version": "1.0.0",
         "scripts": {"postinstall": "node ./s.js"}}))
    (pkg / "s.js").write_text("require('child_process').exec('id')", encoding="utf-8")
    return pkg


def test_debug_bundle_written_static_only(tmp_path):
    out = tmp_path / "out"
    result = CliRunner().invoke(
        cli, ["analyze", str(_make_pkg(tmp_path)), "--out", str(out), "--debug"])
    assert result.exit_code == 0, result.output
    dbg = json.loads((out / "debug.json").read_text(encoding="utf-8"))

    assert dbg["env"]["tool_version"]
    # every static stage was timed
    assert {"acquire", "static", "report"} <= set(dbg["timings_sec"])
    # static diagnostics captured
    assert "s.js" in dbg["static"]["js_files_scanned"]
    assert dbg["static"]["findings_by_category"]          # non-empty
    assert dbg["sample"]["name"] == "evil"
    assert dbg["verdict"] in ("suspicious", "malicious")
    # no detonation requested -> no runtime behavior, no errors
    assert dbg["dynamic"]["behavior_event_count"] == 0
    assert dbg["errors"] == []


def test_debug_omitted_without_flag(tmp_path):
    out = tmp_path / "out"
    CliRunner().invoke(cli, ["analyze", str(_make_pkg(tmp_path)), "--out", str(out)])
    assert not (out / "debug.json").exists()


@pytest.mark.skipif(not orch.docker_available(), reason="docker not available")
def test_debug_bundle_captures_container_diagnostics(tmp_path):
    out = tmp_path / "out"
    result = CliRunner().invoke(
        cli, ["analyze", str(_make_pkg(tmp_path)), "--out", str(out),
              "--dynamic", "--debug"])
    assert result.exit_code == 0, result.output
    dyn = json.loads((out / "debug.json").read_text(encoding="utf-8"))["dynamic"]
    assert "--network" in dyn["run_argv"] and "none" in dyn["run_argv"]
    assert "returncode" in dyn
    assert dyn["raw_event_log"]                      # raw JSONL captured
    assert dyn["behavior_event_count"] > 0
