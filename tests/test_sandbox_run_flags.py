# tests/test_sandbox_run_flags.py — pure unit tests, no docker required
from npm_ide_analyst.sandbox import orchestrator as orch


def test_run_flags_default_has_no_ptrace_and_keeps_hardening():
    flags = orch.run_flags(False)
    assert "--cap-add" not in flags          # no capability re-added by default
    # Hardening intact:
    for required in ["--network", "none", "--cap-drop", "ALL",
                     "no-new-privileges", "--read-only"]:
        assert required in flags


def test_run_flags_trace_native_adds_only_sys_ptrace():
    base = orch.run_flags(False)
    traced = orch.run_flags(True)
    # Exactly the ptrace cap is added, nothing removed:
    assert traced == base + ["--cap-add", "SYS_PTRACE"]
    # Base constant not mutated:
    assert "--cap-add" not in orch.DOCKER_RUN_FLAGS


def test_run_flags_returns_fresh_list():
    a = orch.run_flags(True)
    a.append("--tampered")
    assert "--tampered" not in orch.run_flags(True)
