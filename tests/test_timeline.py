from pathlib import Path
from npm_ide_analyst.models import BehaviorEvent
from npm_ide_analyst.correlate.timeline import build_timeline


def test_timeline_from_behavior_events():
    behavior = [
        BehaviorEvent(kind="detonation", detail="activate() called", ts=1.0),
        BehaviorEvent(kind="network", detail="http request: http://1.2.3.4", ts=2.0),
    ]
    tl = build_timeline(behavior)
    assert len(tl) == 2
    assert tl[0].source == "detonation"
    assert "activate" in tl[0].event


def test_timeline_includes_evidence_logs(tmp_path):
    (tmp_path / "exthost.log").write_text(
        "2026-07-06 10:00:00 activating extension evil.ext\n"
        "unrelated line\n", encoding="utf-8")
    behavior = [BehaviorEvent(kind="network", detail="beacon", ts=1.0)]
    tl = build_timeline(behavior, evidence_dir=tmp_path)
    sources = {e.source for e in tl}
    assert "evidence-log" in sources
    assert "detonation" in sources


def test_empty_inputs():
    assert build_timeline([]) == []
