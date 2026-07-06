from pathlib import Path
from npm_ide_analyst.models import Report, Sample, Finding, Severity, ArtifactType
from npm_ide_analyst.report.html_report import write_html


def test_html_contains_findings_and_no_external_refs(tmp_path):
    s = Sample(name="evil", version="1.0.0", artifact_type=ArtifactType.NPM,
               root=Path("/tmp/x"), sha256="a" * 64, sha512="b" * 128)
    f = Finding(id="F1", title="Process execution", severity=Severity.HIGH,
                category="process-exec", detail="child_process used", evidence="cp.exec()")
    out = tmp_path / "r.html"
    write_html(Report(sample=s, findings=[f], generated_at="t"), out)
    html = out.read_text(encoding="utf-8")
    assert "Process execution" in html
    assert "suspicious" in html
    assert "http://" not in html and "https://" not in html  # self-contained
