# tests/test_sandbox_orchestrator.py
import json
from pathlib import Path

import pytest

from npm_ide_analyst.models import ArtifactType
from npm_ide_analyst.sandbox import orchestrator as orch

pytestmark = pytest.mark.skipif(not orch.docker_available(), reason="docker not available")


@pytest.fixture(scope="module", autouse=True)
def _image():
    orch.build_image()


def test_detonate_vsix_captures_network(tmp_path):
    sample = tmp_path / "ext"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps({"name": "e", "main": "./extension.js"}))
    (sample / "extension.js").write_text(
        "exports.activate=()=>{require('http').get('http://1.2.3.4/beacon');};",
        encoding="utf-8")
    events = orch.detonate(sample, ArtifactType.EXTENSION, timeout=60)
    assert any(e.kind == "network" and "1.2.3.4" in e.detail for e in events)


def test_detonate_npm_captures_process(tmp_path):
    sample = tmp_path / "pkg"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps(
        {"name": "p", "scripts": {"postinstall": "node ./evil.js"}}))
    (sample / "evil.js").write_text("require('child_process').exec('whoami');", encoding="utf-8")
    events = orch.detonate(sample, ArtifactType.NPM, timeout=60)
    assert any(e.kind == "process" and "whoami" in e.detail for e in events)


def test_detonate_trace_native_captures_syscalls(tmp_path):
    sample = tmp_path / "pkg"
    sample.mkdir()
    # postinstall execs a real in-image ELF that makes identifiable syscalls
    (sample / "package.json").write_text(json.dumps(
        {"name": "p", "scripts": {"postinstall": "node ./evil.js"}}))
    (sample / "evil.js").write_text(
        "require('child_process').exec('/bin/echo NPMIDE_TRACE_CANARY');",
        encoding="utf-8")
    events = orch.detonate(sample, ArtifactType.NPM, timeout=60, trace_native=True)
    # The native binary actually ran under strace: a native and/or syscall event.
    assert any(e.kind in ("native", "syscall") for e in events)
    assert any("NPMIDE_TRACE_CANARY" in e.detail
               or "execve" in e.detail for e in events)


def test_detonate_default_still_neuters(tmp_path):
    sample = tmp_path / "pkg2"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps(
        {"name": "p", "scripts": {"postinstall": "node ./evil.js"}}))
    (sample / "evil.js").write_text(
        "require('child_process').exec('/bin/echo NPMIDE_TRACE_CANARY');",
        encoding="utf-8")
    events = orch.detonate(sample, ArtifactType.NPM, timeout=60)  # default: no trace
    # Intent still logged, but no native execution / syscalls.
    assert any(e.kind == "process" for e in events)
    assert not any(e.kind in ("native", "syscall") for e in events)
