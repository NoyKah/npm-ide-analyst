from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from ..models import Finding, Severity

_JS_EXT = {".js", ".cjs", ".mjs"}

# (regex, category, severity, human title)
_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    (re.compile(r"\bchild_process\b|\.exec(?:Sync)?\s*\(|\.spawn(?:Sync)?\s*\("),
     "process-exec", Severity.HIGH, "Process execution"),
    (re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(|\brequire\(\s*vm\b|\bvm\.runIn"),
     "dynamic-code", Severity.HIGH, "Dynamic code evaluation"),
    (re.compile(r"\batob\s*\(|Buffer\.from\([^)]*base64|[A-Za-z0-9+/]{80,}={0,2}"),
     "obfuscation", Severity.MEDIUM, "Base64 / encoded blob"),
    (re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}"),
     "network", Severity.HIGH, "Hardcoded raw-IP URL"),
    (re.compile(r"https?://[^\s'\"]+"),
     "network", Severity.LOW, "Outbound URL"),
    (re.compile(r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org|hastebin|pastebin\.com"),
     "exfil-channel", Severity.HIGH, "Known exfil / paste / messaging channel"),
    (re.compile(r"\.ssh/|\.aws/credentials|\.npmrc|\.env\b|\.docker/config\.json|Login Data|cookies"),
     "secret-access", Severity.HIGH, "Access to credentials / secrets"),
    (re.compile(r"process\.env\b"),
     "env-harvest", Severity.LOW, "Environment variable access"),
]


def iter_js_files(root: Path) -> Iterator[Path]:
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in _JS_EXT:
            yield p


def _first_match_line(text: str, pattern: re.Pattern) -> str | None:
    for line in text.splitlines():
        if pattern.search(line):
            return line.strip()[:200]
    return None


def scan_iocs(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for js in iter_js_files(root):
        try:
            text = js.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(js.relative_to(root))
        for pattern, category, severity, title in _PATTERNS:
            line = _first_match_line(text, pattern)
            if line is not None:
                findings.append(Finding(
                    id=f"IOC-{category}-{rel}",
                    title=title,
                    severity=severity,
                    category=category,
                    detail=f"{title} found in {rel}.",
                    location=rel,
                    evidence=line,
                ))
    return findings
