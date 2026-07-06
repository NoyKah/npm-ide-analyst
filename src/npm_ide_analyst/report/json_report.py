from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from ..models import (
    Report, Sample, Finding, Severity, ArtifactType, BehaviorEvent, TimelineEntry,
)


def report_to_dict(report: Report) -> dict:
    sample = asdict(report.sample)
    sample["root"] = str(sample["root"])
    sample["artifact_type"] = str(report.sample.artifact_type)
    result = {
        "generated_at": report.generated_at,
        "verdict": report.verdict,
        "score": report.score,
        "sample": sample,
        "findings": [
            {**asdict(f), "severity": str(f.severity)} for f in report.findings
        ],
        "behavior": [asdict(b) for b in report.behavior],
        "timeline": [asdict(t) for t in report.timeline],
    }
    return result


def write_json(report: Report, out_path: Path) -> None:
    out_path.write_text(json.dumps(report_to_dict(report), indent=2), encoding="utf-8")


def load_report(path: Path) -> Report:
    data = json.loads(path.read_text(encoding="utf-8"))
    s = data["sample"]
    sample = Sample(
        name=s["name"], version=s.get("version"),
        artifact_type=ArtifactType(s["artifact_type"]),
        root=Path(s["root"]), sha256=s["sha256"], sha512=s["sha512"],
    )
    findings = [
        Finding(id=f["id"], title=f["title"], severity=Severity(f["severity"]),
                category=f["category"], detail=f["detail"],
                location=f.get("location"), evidence=f.get("evidence"))
        for f in data.get("findings", [])
    ]
    behavior = [
        BehaviorEvent(kind=b["kind"], detail=b["detail"], data=b.get("data") or {},
                      ts=b.get("ts"), stack=b.get("stack"))
        for b in data.get("behavior", [])
    ]
    timeline = [
        TimelineEntry(ts=t["ts"], source=t["source"], event=t["event"])
        for t in data.get("timeline", [])
    ]
    return Report(sample=sample, findings=findings,
                  generated_at=data.get("generated_at", ""),
                  behavior=behavior, timeline=timeline)
