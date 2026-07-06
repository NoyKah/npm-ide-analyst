from __future__ import annotations

import re

from ..models import Finding, Severity

_REGISTRY_LINE = re.compile(r"^\s*(?:@[\w-]+:)?registry\s*=\s*(\S+)", re.MULTILINE)
_OFFICIAL = "registry.npmjs.org"
_MARKETPLACE_KEYS = ("extensions.gallery.serviceurl", "extensionsgallery",
                     "marketplaceextensiongalleryserviceurl")


def analyze_npmrc(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _REGISTRY_LINE.finditer(text):
        url = match.group(1)
        if _OFFICIAL not in url:
            findings.append(Finding(
                id="NPMRC-REGISTRY-OVERRIDE",
                title="Non-standard npm registry",
                severity=Severity.HIGH,
                category="registry-override",
                detail="A registry override points away from registry.npmjs.org.",
                location=".npmrc",
                evidence=match.group(0).strip(),
            ))
    if "_authToken" in text:
        findings.append(Finding(
            id="NPMRC-AUTHTOKEN",
            title="npm auth token present",
            severity=Severity.MEDIUM,
            category="secret-access",
            detail="An _authToken is stored in .npmrc — a theft target.",
            location=".npmrc",
        ))
    return findings


def analyze_settings_json(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    for key, value in data.items():
        if key.lower() in _MARKETPLACE_KEYS:
            findings.append(Finding(
                id=f"SETTINGS-MARKETPLACE-{key}",
                title="Editor marketplace override",
                severity=Severity.HIGH,
                category="marketplace-override",
                detail="A settings key repoints the extension gallery to a custom URL.",
                location="settings.json",
                evidence=f"{key} = {value}",
            ))
    return findings
