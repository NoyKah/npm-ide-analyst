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


def test_html_masthead_summary_and_no_emdash(tmp_path):
    s = Sample(name="colorz-utill", version="2.3.9", artifact_type=ArtifactType.NPM,
               root=Path("/tmp/x"), sha256="c" * 64, sha512="d" * 128)
    highs = [Finding(id=f"H{i}", title="Runtime outbound network", severity=Severity.HIGH,
                     category="network", detail="beacon") for i in range(3)]
    out = tmp_path / "r.html"
    write_html(Report(sample=s, findings=highs, generated_at="2026-07-07T00:00:00Z"), out)
    html = out.read_text(encoding="utf-8")
    assert "malicious" in html                      # 3 HIGH -> escalated verdict
    assert 'class="mast v-malicious"' in html       # verdict drives the masthead band
    assert "Risk score" in html and "120" in html   # stat strip is rendered
    assert "Static indicators" in html
    assert "—" not in html                      # no em-dash anywhere in the report
