# tests/test_detonation_flags.py
from npm_ide_analyst.sandbox import orchestrator as orch
from npm_ide_analyst.sandbox.orchestrator import _detonate_ms


def _has_pair(flags, a, b):
    return any(flags[i] == a and flags[i + 1] == b
              for i in range(len(flags) - 1))


def test_default_detonation_flags_use_network_none():
    flags = orch._detonation_flags()
    assert _has_pair(flags, "--network", "none")
    assert "--dns" not in flags
    assert "ANALYST_SINKHOLE=1" not in flags
    for req in ["--cap-drop", "ALL", "--read-only", "--pids-limit", "128"]:
        assert req in flags
    assert _has_pair(flags, "--user", "1000:1000")


def test_sinkhole_detonation_flags_keep_isolation_and_route_to_sinkhole():
    flags = orch._detonation_flags("analyst-net-abc", "10.9.8.7")
    # Never network none in sinkhole mode
    assert not _has_pair(flags, "--network", "none")
    assert _has_pair(flags, "--network", "analyst-net-abc")
    assert _has_pair(flags, "--dns", "10.9.8.7")
    assert "ANALYST_SINKHOLE=1" in flags
    assert "NODE_TLS_REJECT_UNAUTHORIZED=0" in flags
    # Every isolation flag still present
    assert _has_pair(flags, "--user", "1000:1000")
    for req in ["--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--read-only", "--memory", "256m", "--cpus", "1",
                "--pids-limit", "128", "--rm"]:
        assert req in flags


def test_detonate_ms_derives_from_timeout():
    assert _detonate_ms(30) == 28000        # 30*1000 - 2000
    assert _detonate_ms(1) == 1000          # floor at 1000
    assert _detonate_ms(0) == 1000          # floor
