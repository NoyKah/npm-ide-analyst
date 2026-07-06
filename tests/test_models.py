from pathlib import Path
from npm_ide_analyst.models import Severity, ArtifactType, Finding, Sample, Report


def make_sample():
    return Sample(name="evil", version="1.0.0", artifact_type=ArtifactType.NPM,
                  root=Path("/tmp/x"), sha256="a" * 64, sha512="b" * 128)


def test_report_verdict_and_score():
    s = make_sample()
    findings = [
        Finding(id="F1", title="eval used", severity=Severity.HIGH,
                category="dynamic-code", detail="eval() call"),
        Finding(id="F2", title="minified", severity=Severity.LOW,
                category="obfuscation", detail="one-line file"),
    ]
    r = Report(sample=s, findings=findings, generated_at="2026-07-06T00:00:00Z")
    assert r.verdict == "suspicious"          # HIGH present, no CRITICAL
    assert r.score == 40 + 5                   # HIGH=40, LOW=5


def test_clean_report_verdict():
    r = Report(sample=make_sample(), findings=[], generated_at="t")
    assert r.verdict == "clean"
    assert r.score == 0
