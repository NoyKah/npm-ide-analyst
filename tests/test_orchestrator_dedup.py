"""Docker-availability is checked once per run: build_image/detonate can
trust a caller that already verified Docker (assume_docker=True) and skip
their own ~15s `docker info` probe, without weakening SandboxUnavailable
semantics when called standalone."""
import pytest

from npm_ide_analyst.models import ArtifactType
from npm_ide_analyst.sandbox import orchestrator as orch


def _count_docker_available(monkeypatch):
    calls = {"n": 0}

    def _probe():
        calls["n"] += 1
        return True

    monkeypatch.setattr(orch, "docker_available", _probe)
    return calls


def test_build_image_skips_docker_probe_when_assume_docker(monkeypatch):
    calls = _count_docker_available(monkeypatch)
    monkeypatch.setattr(orch.subprocess, "run", lambda *a, **k: None)

    orch.build_image(assume_docker=True)

    assert calls["n"] == 0


def test_detonate_skips_docker_probe_when_assume_docker(monkeypatch, tmp_path):
    calls = _count_docker_available(monkeypatch)
    monkeypatch.setattr(orch.subprocess, "run", lambda *a, **k: None)

    sample = tmp_path / "pkg"
    sample.mkdir()
    events = orch.detonate(sample, ArtifactType.NPM, assume_docker=True)

    assert calls["n"] == 0
    assert events == []  # no container ran, so no event log


def test_build_image_still_probes_and_raises_when_docker_absent(monkeypatch):
    monkeypatch.setattr(orch, "docker_available", lambda: False)
    with pytest.raises(orch.SandboxUnavailable):
        orch.build_image()


def test_detonate_still_probes_and_raises_when_docker_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(orch, "docker_available", lambda: False)
    with pytest.raises(orch.SandboxUnavailable):
        orch.detonate(tmp_path, ArtifactType.NPM)
