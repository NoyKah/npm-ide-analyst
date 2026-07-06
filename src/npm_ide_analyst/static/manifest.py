from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding, Severity

_LIFECYCLE = ("preinstall", "install", "postinstall")


def parse_manifest(payload_root: Path) -> dict:
    manifest = payload_root / "package.json"
    if not manifest.exists():
        return {}
    try:
        return json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}


def analyze_manifest(manifest: dict) -> list[Finding]:
    findings: list[Finding] = []
    scripts = manifest.get("scripts") or {}
    for hook in _LIFECYCLE:
        if hook in scripts:
            findings.append(Finding(
                id=f"MANIFEST-SCRIPT-{hook}",
                title=f"Install-time lifecycle script: {hook}",
                severity=Severity.HIGH,
                category="lifecycle-script",
                detail=f"'{hook}' runs automatically during npm install.",
                location="package.json",
                evidence=str(scripts[hook]),
            ))
    events = manifest.get("activationEvents") or []
    if "*" in events or "onStartupFinished" in events:
        findings.append(Finding(
            id="MANIFEST-ACTIVATION-BROAD",
            title="Broad extension activation",
            severity=Severity.MEDIUM,
            category="activation",
            detail="Extension activates on every editor launch ('*' / onStartupFinished).",
            location="package.json",
            evidence=json.dumps(events),
        ))
    return findings
