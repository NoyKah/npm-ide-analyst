from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from ..models import Report


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
