from pathlib import Path
from npm_ide_analyst.models import (
    Report, Sample, Finding, Severity, ArtifactType, BehaviorEvent, TimelineEntry,
)
from npm_ide_analyst.report.json_report import report_to_dict
from npm_ide_analyst.report.html_report import write_html


def _sample():
    return Sample(name="evil", version="1.0.0", artifact_type=ArtifactType.EXTENSION,
                  root=Path("/tmp/x"), sha256="a" * 64, sha512="b" * 128)


def test_report_dict_includes_behavior_and_timeline():
    r = Report(
        sample=_sample(),
        findings=[Finding(id="D1", title="C2 beacon", severity=Severity.HIGH,
                          category="network", detail="POST to 1.2.3.4")],
        generated_at="t",
        behavior=[BehaviorEvent(kind="network", detail="POST http://1.2.3.4/x",
                                data={"host": "1.2.3.4", "body": "stolen"})],
        timeline=[TimelineEntry(ts="t0", source="detonation", event="activate() called")],
    )
    d = report_to_dict(r)
    assert d["behavior"][0]["kind"] == "network"
    assert d["behavior"][0]["data"]["host"] == "1.2.3.4"
    assert d["timeline"][0]["source"] == "detonation"


def test_html_renders_behavior_section(tmp_path):
    r = Report(sample=_sample(), findings=[], generated_at="t",
               behavior=[BehaviorEvent(kind="process", detail="spawn curl")],
               timeline=[TimelineEntry(ts="t0", source="detonation", event="spawn curl")])
    out = tmp_path / "r.html"
    write_html(r, out)
    html = out.read_text(encoding="utf-8")
    assert "Dynamic Behavior" in html
    assert "spawn curl" in html
