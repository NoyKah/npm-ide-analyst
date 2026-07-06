from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding
from .ast_analysis import analyze_ast
from .config_hijack import analyze_npmrc, analyze_settings_json
from .ioc_scan import scan_iocs
from .manifest import analyze_manifest, parse_manifest


def run_static(payload_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings += analyze_manifest(parse_manifest(payload_root))
    findings += scan_iocs(payload_root)
    findings += analyze_ast(payload_root)

    for npmrc in payload_root.rglob(".npmrc"):
        if npmrc.is_file():
            findings += analyze_npmrc(npmrc.read_text(encoding="utf-8", errors="replace"))
    for settings in payload_root.rglob("settings.json"):
        if settings.is_file():
            try:
                data = json.loads(settings.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                findings += analyze_settings_json(data)

    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.id, f)
    return list(seen.values())
