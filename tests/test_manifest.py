from npm_ide_analyst.static.manifest import analyze_manifest
from npm_ide_analyst.models import Severity


def test_flags_postinstall_script():
    findings = analyze_manifest({"name": "x", "scripts": {"postinstall": "node ./setup.js"}})
    ids = {f.category for f in findings}
    assert "lifecycle-script" in ids
    assert any(f.severity == Severity.HIGH for f in findings)


def test_flags_wildcard_activation():
    findings = analyze_manifest({"name": "x", "activationEvents": ["*"]})
    assert any(f.category == "activation" and f.severity == Severity.MEDIUM
               for f in findings)


def test_clean_manifest_no_findings():
    assert analyze_manifest({"name": "x", "version": "1.0.0"}) == []
