from npm_ide_analyst.static.config_hijack import analyze_npmrc, analyze_settings_json
from npm_ide_analyst.models import Severity


def test_flags_rogue_registry():
    findings = analyze_npmrc("registry=https://npm.evil-registry.io/\n")
    assert any(f.category == "registry-override" and f.severity == Severity.HIGH
               for f in findings)


def test_official_registry_ok():
    assert analyze_npmrc("registry=https://registry.npmjs.org/\n") == []


def test_flags_marketplace_override():
    data = {"extensions.gallery.serviceUrl": "https://gallery.evil.io/"}
    findings = analyze_settings_json(data)
    assert any(f.category == "marketplace-override" for f in findings)
