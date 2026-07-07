import json
import types
from pathlib import Path

from click.testing import CliRunner

import npm_ide_analyst.cli as climod
from npm_ide_analyst.cli import cli
from npm_ide_analyst.sandbox import orchestrator as orch


def _pkg(tmp_path: Path) -> Path:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(json.dumps(
        {"name": "x", "scripts": {"postinstall": "node ./s.js"}}))
    (pkg / "s.js").write_text("1", encoding="utf-8")
    return pkg


def test_image_exists_reflects_docker_inspect(monkeypatch):
    monkeypatch.setattr(orch.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=0))
    assert orch.image_exists() is True
    monkeypatch.setattr(orch.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=1))
    assert orch.image_exists() is False


def test_build_skipped_when_image_exists(tmp_path, monkeypatch):
    calls = {}
    monkeypatch.setattr(climod, "docker_available", lambda: True)
    monkeypatch.setattr(climod, "image_exists", lambda: True)
    monkeypatch.setattr(climod, "build_image",
                        lambda *a, **k: calls.setdefault("build", True))
    monkeypatch.setattr(climod, "detonate", lambda *a, **k: [])
    r = CliRunner().invoke(cli, ["analyze", str(_pkg(tmp_path)),
                                 "--out", str(tmp_path / "o"), "--dynamic"])
    assert r.exit_code == 0, r.output
    assert "build" not in calls                       # image reused, no rebuild
    assert "using cached sandbox image" in r.output


def test_build_runs_when_image_absent(tmp_path, monkeypatch):
    calls = {}
    monkeypatch.setattr(climod, "docker_available", lambda: True)
    monkeypatch.setattr(climod, "image_exists", lambda: False)
    monkeypatch.setattr(climod, "build_image",
                        lambda *a, **k: calls.setdefault("build", True))
    monkeypatch.setattr(climod, "detonate", lambda *a, **k: [])
    r = CliRunner().invoke(cli, ["analyze", str(_pkg(tmp_path)),
                                 "--out", str(tmp_path / "o"), "--dynamic"])
    assert r.exit_code == 0, r.output
    assert calls.get("build") is True


def test_progress_default_and_quiet(tmp_path):
    pkg = _pkg(tmp_path)
    shown = CliRunner().invoke(cli, ["analyze", str(pkg), "--out", str(tmp_path / "o1")])
    assert "[*]" in shown.output
    quiet = CliRunner().invoke(cli, ["analyze", str(pkg),
                                     "--out", str(tmp_path / "o2"), "--quiet"])
    assert "[*]" not in quiet.output


def test_timeout_passed_through(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(climod, "docker_available", lambda: True)
    monkeypatch.setattr(climod, "image_exists", lambda: True)

    def fake_detonate(root, artifact_type, timeout=30, **k):
        captured["timeout"] = timeout
        return []

    monkeypatch.setattr(climod, "detonate", fake_detonate)
    r = CliRunner().invoke(cli, ["analyze", str(_pkg(tmp_path)),
                                 "--out", str(tmp_path / "o"), "--dynamic",
                                 "--timeout", "12"])
    assert r.exit_code == 0, r.output
    assert captured["timeout"] == 12
