from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ArtifactType(StrEnum):
    NPM = "npm"
    EXTENSION = "extension"
    UNKNOWN = "unknown"


_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 40,
    Severity.CRITICAL: 80,
}

_RANK = {s: i for i, s in enumerate(
    [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])}


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    detail: str
    location: str | None = None
    evidence: str | None = None


@dataclass
class BehaviorEvent:
    kind: str
    detail: str
    data: dict = field(default_factory=dict)
    ts: float | None = None
    stack: str | None = None


@dataclass
class TimelineEntry:
    ts: str
    source: str
    event: str


@dataclass
class Sample:
    name: str
    version: str | None
    artifact_type: ArtifactType
    root: Path
    sha256: str
    sha512: str


@dataclass
class Report:
    sample: Sample
    findings: list[Finding] = field(default_factory=list)
    generated_at: str = ""
    behavior: list[BehaviorEvent] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(_WEIGHT[f.severity] for f in self.findings)

    @property
    def verdict(self) -> str:
        if not self.findings:
            return "clean"
        top = max(self.findings, key=lambda f: _RANK[f.severity]).severity
        if top == Severity.CRITICAL:
            return "malicious"
        if top in (Severity.HIGH, Severity.MEDIUM):
            return "suspicious"
        return "low-risk"
