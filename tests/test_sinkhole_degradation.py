# tests/test_sinkhole_degradation.py
import subprocess
import types

from npm_ide_analyst.sandbox import orchestrator as orch


def _ok(*a, **k):
    return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")


def test_sinkhole_degrades_to_isolated_when_ip_unavailable(monkeypatch, tmp_path):
    # Provisioning "succeeds" and the sinkhole signals ready, but the IP cannot be
    # discovered. The run must degrade to a --network none isolated detonation
    # (no --dns, no sinkhole env), not attach to the internal net without DNS.
    monkeypatch.setattr(orch.subprocess, "run", _ok)
    monkeypatch.setattr(orch, "_wait_for_sinkhole", lambda name, timeout=20: True)
    monkeypatch.setattr(orch, "_sinkhole_ip", lambda name, net: None)
    captured = {}
    monkeypatch.setattr(orch, "_detonate_isolated",
                        lambda pr, r, t, flags: (captured.__setitem__("flags", flags) or []))

    orch._detonate_with_sinkhole(tmp_path, "run-vsix.js", 30)

    assert captured["flags"][-2:] == ["--network", "none"]
    assert "--dns" not in captured["flags"]
    assert "ANALYST_SINKHOLE=1" not in captured["flags"]


def test_sinkhole_degrades_when_provisioning_raises(monkeypatch, tmp_path):
    # A docker provisioning command fails -> degrade to isolated, do not propagate.
    def raising_run(*a, **k):
        cmd = a[0] if a else k.get("args", [])
        if "create" in cmd:
            raise subprocess.CalledProcessError(1, cmd)
        return _ok()
    monkeypatch.setattr(orch.subprocess, "run", raising_run)
    captured = {}
    monkeypatch.setattr(orch, "_detonate_isolated",
                        lambda pr, r, t, flags: (captured.__setitem__("flags", flags) or []))

    orch._detonate_with_sinkhole(tmp_path, "run-vsix.js", 30)

    assert captured["flags"][-2:] == ["--network", "none"]
