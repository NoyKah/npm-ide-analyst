from __future__ import annotations

import re
from pathlib import Path

from ..models import BehaviorEvent, TimelineEntry

_EVIDENCE_PAT = re.compile(r"install|activat", re.IGNORECASE)


def build_timeline(behavior: list[BehaviorEvent],
                   evidence_dir: Path | None = None) -> list[TimelineEntry]:
    entries: list[TimelineEntry] = []
    for ev in behavior:
        ts = f"{ev.ts:.1f}ms" if ev.ts is not None else "-"
        entries.append(TimelineEntry(ts=ts, source="detonation",
                                     event=f"[{ev.kind}] {ev.detail}"))
    if evidence_dir is not None and evidence_dir.exists():
        for log in sorted(evidence_dir.rglob("*.log")):
            if not log.is_file():
                continue
            for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
                if _EVIDENCE_PAT.search(line):
                    entries.append(TimelineEntry(
                        ts="-", source="evidence-log",
                        event=f"{log.name}: {line.strip()[:200]}"))
    return entries
