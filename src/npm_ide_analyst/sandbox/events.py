from __future__ import annotations

import json
from pathlib import Path

from ..models import BehaviorEvent

_INTERNAL = {"harness"}


def parse_event_log(text: str) -> list[BehaviorEvent]:
    events: list[BehaviorEvent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or "kind" not in rec:
            continue
        if rec["kind"] in _INTERNAL:
            continue
        events.append(BehaviorEvent(
            kind=str(rec.get("kind", "")),
            detail=str(rec.get("detail", "")),
            data=rec.get("data") or {},
            ts=rec.get("ts"),
            stack=rec.get("stack"),
        ))
    return events


def load_event_log(path: Path) -> list[BehaviorEvent]:
    if not path.exists():
        return []
    return parse_event_log(path.read_text(encoding="utf-8", errors="replace"))
