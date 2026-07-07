from npm_ide_analyst.models import BehaviorEvent, Severity
from npm_ide_analyst.sandbox.findings import behavior_to_findings


def test_maps_process_and_network_to_high():
    events = [
        BehaviorEvent(kind="process", detail="exec: curl http://1.2.3.4"),
        BehaviorEvent(kind="network", detail="http request: http://1.2.3.4/steal"),
        BehaviorEvent(kind="secret", detail="readFileSync: /root/.aws/credentials"),
        BehaviorEvent(kind="decode", detail="base64 -> http://evil"),
    ]
    findings = behavior_to_findings(events)
    cats = {f.category: f.severity for f in findings}
    assert cats["process-exec"] == Severity.HIGH
    assert cats["network"] == Severity.HIGH
    assert cats["secret-access"] == Severity.HIGH
    assert cats["obfuscation"] == Severity.MEDIUM
    assert all(f.location == "[dynamic]" for f in findings)


def test_dedupes_repeated_behavior():
    events = [BehaviorEvent(kind="process", detail="exec: whoami")] * 3
    findings = behavior_to_findings(events)
    assert len(findings) == 1


def test_no_events_no_findings():
    assert behavior_to_findings([]) == []


def test_c2_event_maps_to_high_finding():
    findings = behavior_to_findings([
        BehaviorEvent(kind="c2", detail="HTTP GET c2.evil.test/a"),
    ])
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].category == "c2"
    assert findings[0].location == "[dynamic]"


def test_maps_native_and_syscall():
    events = [
        BehaviorEvent(kind="native", detail="strace ./dropped -> exit 0"),
        BehaviorEvent(kind="syscall", detail="connect: 1.2.3.4:443"),
    ]
    findings = behavior_to_findings(events)
    cats = {f.category: f.severity for f in findings}
    assert cats["native-exec"] == Severity.HIGH
    assert cats["native-syscall"] == Severity.MEDIUM
    assert all(f.location == "[dynamic]" for f in findings)
