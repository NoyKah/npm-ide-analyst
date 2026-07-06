import json
from pathlib import Path
from npm_ide_analyst.models import Report, Sample, Finding, Severity, ArtifactType
from npm_ide_analyst.report.json_report import report_to_dict, write_json


def _report():
    s = Sample(name="evil", version="1.0.0", artifact_type=ArtifactType.NPM,
               root=Path("/tmp/x"), sha256="a" * 64, sha512="b" * 128)
    f = Finding(id="F1", title="eval", severity=Severity.HIGH,
                category="dynamic-code", detail="eval() call")
    return Report(sample=s, findings=[f], generated_at="2026-07-06T00:00:00Z")


def test_report_to_dict_shape():
    d = report_to_dict(_report())
    assert d["verdict"] == "suspicious"
    assert d["score"] == 40
    assert d["sample"]["sha256"] == "a" * 64
    assert d["findings"][0]["category"] == "dynamic-code"


def test_write_json_roundtrips(tmp_path):
    out = tmp_path / "r.json"
    write_json(_report(), out)
    loaded = json.loads(out.read_text())
    assert loaded["sample"]["name"] == "evil"
