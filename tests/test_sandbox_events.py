from npm_ide_analyst.sandbox.events import parse_event_log


def test_parses_jsonl_and_skips_bad_lines():
    text = (
        '{"kind":"process","detail":"exec: curl","data":{"fn":"exec"},"ts":1.5}\n'
        '\n'
        'not-json\n'
        '{"kind":"network","detail":"http request: http://1.2.3.4","data":{},"ts":2.0}\n'
        '{"kind":"harness","detail":"preload installed","data":{}}\n'
    )
    events = parse_event_log(text)
    kinds = [e.kind for e in events]
    assert kinds == ["process", "network"]         # bad lines skipped, 'harness' filtered
    assert events[0].detail == "exec: curl"
    assert events[1].data == {}
