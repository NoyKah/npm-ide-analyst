from __future__ import annotations

from ..models import BehaviorEvent, Finding, Severity

# kind -> (category, severity, title)
_MAP = {
    "process": ("process-exec", Severity.HIGH, "Runtime process execution"),
    "network": ("network", Severity.HIGH, "Runtime outbound network"),
    "secret": ("secret-access", Severity.HIGH, "Runtime secret/credential access"),
    "eval": ("dynamic-code", Severity.HIGH, "Runtime dynamic code execution"),
    "decode": ("obfuscation", Severity.MEDIUM, "Runtime payload decoding"),
    "dns": ("network", Severity.LOW, "Runtime DNS lookup"),
    "vscode": ("extension-behavior", Severity.MEDIUM, "Editor API use during activation"),
    "file": ("file-write", Severity.LOW, "Runtime file write"),
}


def behavior_to_findings(events: list[BehaviorEvent]) -> list[Finding]:
    seen: dict[tuple[str, str], Finding] = {}
    for ev in events:
        mapping = _MAP.get(ev.kind)
        if mapping is None:
            continue
        category, severity, title = mapping
        key = (category, ev.detail)
        if key in seen:
            continue
        seen[key] = Finding(
            id=f"DYN-{category}-{len(seen)}",
            title=title,
            severity=severity,
            category=category,
            detail=f"{title} (observed during detonation): {ev.detail}",
            location="[dynamic]",
            evidence=ev.detail,
        )
    return list(seen.values())
